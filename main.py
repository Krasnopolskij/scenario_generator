import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from py2neo import Graph
from dotenv import load_dotenv
from cpe import search as cpe_search
from scenario_generation.generator import generate_scenarios
from targets import (
    build_target_uri,
    check_cves_in_db,
    collect_cves,
    ensure_target_constraints,
    parse_cves_from_xml_bytes,
    resolve_name,
    target_exists,
    upsert_target,
)
import datetime as dt

ROOT = Path(__file__).parent.resolve()
load_dotenv() 

app = FastAPI(title="Scenario Generator UI")

# Статика UI
ui_dir = ROOT / "ui"
static_dir = ui_dir / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/")
def index() -> FileResponse:
    return RedirectResponse(url="/generation", status_code=307)

@app.get("/data")
def index() -> FileResponse:
    index_file = ui_dir / "data.html"
    return FileResponse(str(index_file))


@app.get("/cpe")
def cpe_page() -> FileResponse:
    page = ui_dir / "cpe.html"
    return FileResponse(str(page))


@app.get("/generation")
def graph_page() -> FileResponse:
    page = ui_dir / "generation.html"
    return FileResponse(str(page))


@app.get("/targets")
def targets_page() -> FileResponse:
    page = ui_dir / "targets.html"
    return FileResponse(str(page))


ALLOWED_LOADERS = {"techniques", "capec", "cwe", "cve"}

# Регистрация запущенных процессов: run_id -> Popen
RUNS: Dict[str, subprocess.Popen] = {}
RUNS_LOCK = threading.Lock()

# Neo4j connection (cached)
_GRAPH: Optional[Graph] = None

def get_graph() -> Graph:
    global _GRAPH
    if _GRAPH is not None:
        return _GRAPH
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    _GRAPH = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)
    return _GRAPH


def normalize_object_uri(raw: str) -> Tuple[str, bool]:
    s = (raw or "").strip()
    low = s.lower()
    idx_custom = low.find("custom:")
    if idx_custom != -1:
        s = s[idx_custom:]
        return s, True
    idx = low.find("cpe:2.3")
    if idx != -1:
        s = s[idx:]
    return s, False


@app.get("/api/graph/subgraph")
def api_graph_subgraph(cpe: str, mode: str = "full", limit: int = 1000):
    g = get_graph()
    limit = max(1, min(int(limit or 1000), 5000))

    # Нормализация входа
    cpe_in, is_target = normalize_object_uri(cpe)
    node_label = "Target" if is_target else "CPE"
    node_prop = "targetUri" if is_target else "cpe23Uri"

    if mode == "simple":
        cypher = (
            f"MATCH p=(v:CVE)-[:AFFECTS]->(obj:{node_label} {{{node_prop}:$cpe}}) "
            "RETURN p LIMIT $limit"
        )
        params = {"cpe": cpe_in, "limit": limit}
    elif mode == "full_relaxed":
        # Полный нестрогий: допускаем 0..1 шаг CAPEC_PARENT_TO_CAPEC_CHILD
        cypher = (
            f"MATCH (obj:{node_label} {{{node_prop}: $cpe}}) "
            "MATCH p1 = (v:CVE)-[:AFFECTS]->(obj) "
            "OPTIONAL MATCH p2 = (w:CWE)-[:CWE_TO_CVE]->(v) "
            "OPTIONAL MATCH p3 = (cap_cwe:CAPEC)-[:CAPEC_TO_CWE]->(w) "
            "OPTIONAL MATCH p4 = (w)<-[:CAPEC_TO_CWE]-(cap_cwe2:CAPEC) "
            "-[:CAPEC_PARENT_TO_CAPEC_CHILD*0..1]- (cap_tech:CAPEC)"
            "-[:CAPEC_TO_TECHNIQUE]->(t:Technique) "
            "WITH collect(p1) + collect(p2) + collect(p3) + collect(p4) AS paths "
            "UNWIND paths AS p "
            "WITH p WHERE p IS NOT NULL "
            "RETURN DISTINCT p LIMIT $limit"
        )
        params = {"cpe": cpe_in, "limit": limit}
    elif mode == "full_gnn":
        # Полный строгий + предсказанные связи CAPEC_TO_TECHNIQUE_PRED
        cypher = (
            f"MATCH (obj:{node_label} {{{node_prop}: $cpe}}) "
            "MATCH p1=(v:CVE)-[:AFFECTS]->(obj) "
            "OPTIONAL MATCH p2=(w:CWE)-[:CWE_TO_CVE]->(v) "
            "OPTIONAL MATCH p3=(cap:CAPEC)-[:CAPEC_TO_CWE]->(w) "
            "OPTIONAL MATCH p4=(cap)-[:CAPEC_TO_TECHNIQUE]->(t:Technique) "
            "WITH collect(p1)+collect(p2)+collect(p3)+collect(p4) AS paths "
            "UNWIND paths AS p "
            "WITH p WHERE p IS NOT NULL "
            "RETURN DISTINCT p LIMIT $limit"
        )
        params = {"cpe": cpe_in, "limit": limit}
    else:
        cypher = (
            f"MATCH (obj:{node_label} {{{node_prop}: $cpe}}) "
            "MATCH p1=(v:CVE)-[:AFFECTS]->(obj) "
            "OPTIONAL MATCH p2=(w:CWE)-[:CWE_TO_CVE]->(v) "
            "OPTIONAL MATCH p3=(cap:CAPEC)-[:CAPEC_TO_CWE]->(w) "
            "OPTIONAL MATCH p4=(cap)-[:CAPEC_TO_TECHNIQUE]->(t:Technique) "
            "WITH collect(p1)+collect(p2)+collect(p3)+collect(p4) AS paths "
            "UNWIND paths AS p "
            "WITH p WHERE p IS NOT NULL "
            "RETURN DISTINCT p LIMIT $limit"
        )
        params = {"cpe": cpe_in, "limit": limit}

    rows = g.run(cypher, **params)

    nodes = {}
    edges = {}

    def add_node(n):
        try:
            nid = str(int(n.identity))
        except Exception:
            nid = str(n.identity)
        if nid in nodes:
            return
        labels = list(n.labels) if hasattr(n, "labels") else []
        props = dict(n)
        label = labels[0] if labels else "Node"
        # Короткая подпись на узле: CPE, Target, CVE, CWE, Tech, CAPEC
        short = {
            "CPE": "CPE",
            "Target": "Target",
            "CVE": "CVE",
            "CWE": "CWE",
            "Technique": "Tech",
            "CAPEC": "CAPEC",
        }.get(label, label or "Node")
        nodes[nid] = {"id": nid, "group": label, "label": short, "props": props}

    def add_edge(r):
        try:
            rid = str(int(r.identity))
        except Exception:
            rid = str(r.identity)
        if rid in edges:
            return
        try:
            s = str(int(r.start_node.identity))
            t = str(int(r.end_node.identity))
        except Exception:
            s = str(r.start_node.identity)
            t = str(r.end_node.identity)
        etype = r.__class__.__name__
        edges[rid] = {"id": rid, "source": s, "target": t, "type": etype}

    for row in rows:
        # py2neo Record supports key access by column name
        p = None
        try:
            p = row["p"]
        except Exception:
            try:
                p = row[0]
            except Exception:
                p = None
        if p is None:
            continue
        for n in getattr(p, "nodes", []):
            add_node(n)
        for r in getattr(p, "relationships", []):
            add_edge(r)

    # Для режима full_gnn дополнительно добавляем предсказанные связи CAPEC_TO_TECHNIQUE_PRED
    if mode == "full_gnn":
        pred_cypher = (
            f"MATCH (obj:{node_label} {{{node_prop}: $cpe}}) "
            "MATCH (cve:CVE)-[:AFFECTS]->(obj) "
            "MATCH (w:CWE)-[:CWE_TO_CVE]->(cve) "
            "MATCH (cap:CAPEC)-[:CAPEC_TO_CWE]->(w) "
            "MATCH (cap)-[r:CAPEC_TO_TECHNIQUE_PRED]->(t:Technique) "
            "RETURN DISTINCT r, cap, t LIMIT $limit"
        )
        for row in g.run(pred_cypher, cpe=cpe_in, limit=limit):
            try:
                r = row.get("r") if hasattr(row, "get") else row[0]
                cap = row.get("cap") if hasattr(row, "get") else row[1]
                t = row.get("t") if hasattr(row, "get") else row[2]
            except Exception:
                r = cap = t = None
            if cap is not None:
                add_node(cap)
            if t is not None:
                add_node(t)
            if r is not None:
                add_edge(r)

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def build_load_command(only: Optional[List[str]], skip: Optional[List[str]], cve_from_year: Optional[int]) -> List[str]:
    cmd = [sys.executable, "-u", str(ROOT / "data_collection" / "loader.py")]
    if only:
        safe = [x for x in only if x in ALLOWED_LOADERS]
        if safe:
            cmd += ["--only", ",".join(safe)]
    if skip:
        safe = [x for x in skip if x in ALLOWED_LOADERS]
        if safe:
            cmd += ["--skip", ",".join(safe)]
    if cve_from_year is not None:
        try:
            year = int(cve_from_year)
            cmd += ["--cve-from-year", str(year)]
        except Exception:
            pass
    return cmd


def build_refresh_command() -> List[str]:
    return [sys.executable, "-u", str(ROOT / "data_collection" / "refresh_epss_kev.py")]


def build_gnn_command(
    epochs: Optional[int] = None,
    top_k: Optional[int] = None,
    min_score: Optional[float] = None,
    sentence_model: Optional[str] = None,
    device: Optional[str] = None,
    mode: Optional[str] = None,
    dry_run: bool = False,
) -> List[str]:
    cmd: List[str] = [sys.executable, "-u", str(ROOT / "gnn" / "capec_tech_gnn.py")]
    if epochs is not None:
        try:
            cmd += ["--epochs", str(int(epochs))]
        except Exception:
            pass
    if top_k is not None:
        try:
            cmd += ["--top-k", str(int(top_k))]
        except Exception:
            pass
    if min_score is not None:
        try:
            cmd += ["--min-score", str(float(min_score))]
        except Exception:
            pass
    if isinstance(sentence_model, str) and sentence_model.strip():
        cmd += ["--sentence-model", sentence_model.strip()]
    if isinstance(device, str) and device.strip():
        cmd += ["--device", device.strip()]
    if isinstance(mode, str) and mode.strip():
        cmd += ["--mode", mode.strip()]
    if dry_run:
        cmd.append("--dry-run")
    return cmd


def stream_process(cmd: List[str], run_id: str, tty_columns: Optional[int] = None, tty_rows: Optional[int] = None, extra_env: Optional[Dict[str, str]] = None):
    # POSIX: используем PTY, чтобы дочерний процесс видел TTY и tqdm печатал с \r
    if os.name != "nt":
        import pty
        # Настраиваем размер TTY, чтобы прогресс-бар (tqdm) рисовался полноценно
        try:
            import fcntl, termios, struct  # posix only
        except Exception:
            fcntl = termios = struct = None
        master_fd, slave_fd = pty.openpty()
        if fcntl and termios and struct:
            try:
                # Приоритет: значение из запроса -> переменные окружения -> дефолты
                cols = int(tty_columns or os.environ.get("UI_TTY_COLUMNS") or os.environ.get("COLUMNS", "100"))
                rows = int(tty_rows or os.environ.get("UI_TTY_ROWS") or os.environ.get("LINES", "24"))
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass
        env = os.environ.copy()
        if tty_columns:
            env["COLUMNS"] = str(int(tty_columns))
        else:
            env.setdefault("COLUMNS", os.environ.get("UI_TTY_COLUMNS", "100"))
        if tty_rows:
            env["LINES"] = str(int(tty_rows))
        else:
            env.setdefault("LINES", os.environ.get("UI_TTY_ROWS", "24"))
        if extra_env:
            # Принудительно строковые значения
            for k, v in extra_env.items():
                try:
                    env[str(k)] = str(v)
                except Exception:
                    pass
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=slave_fd,
            stderr=slave_fd,
            bufsize=0,
            text=False,
            close_fds=True,
            env=env,
        )
        os.close(slave_fd)
        with RUNS_LOCK:
            RUNS[run_id] = proc
        try:
            while True:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in r:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        break
                    yield chunk.decode("utf-8", errors="replace")
                if proc.poll() is not None:
                    # Дочерний завершился; дочитываем остаток
                    try:
                        while True:
                            chunk = os.read(master_fd, 4096)
                            if not chunk:
                                break
                            yield chunk.decode("utf-8", errors="replace")
                    except OSError:
                        pass
                    break
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            code = proc.wait()
            with RUNS_LOCK:
                RUNS.pop(run_id, None)
            yield f"\n[exit code: {code}]\n"
    else:
        # Windows
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        with RUNS_LOCK:
            RUNS[run_id] = proc
        try:
            if proc.stdout is not None:
                for line in iter(proc.stdout.readline, ""):
                    yield line
        finally:
            if proc.stdout:
                proc.stdout.close()
            code = proc.wait()
            with RUNS_LOCK:
                RUNS.pop(run_id, None)
            yield f"\n[exit code: {code}]\n"


@app.post("/run/load")
async def run_loader(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    only = payload.get("only") or []
    skip = payload.get("skip") or []
    cve_from_year = payload.get("cve_from_year")
    tty_columns = payload.get("columns")
    tty_rows = payload.get("rows")
    run_id = payload.get("run_id")
    check_hash = payload.get("check_hash")

    if not isinstance(only, list) or not all(isinstance(x, str) for x in only):
        only = []
    if not isinstance(skip, list) or not all(isinstance(x, str) for x in skip):
        skip = []

    # Запретить пересечение ONLY и SKIP
    overlap = sorted(set(only) & set(skip))
    if overlap:
        return JSONResponse(
            {
                "error": f"Нельзя одновременно выбрать и исключить: {', '.join(overlap)}",
                "conflict": overlap,
            },
            status_code=400,
        )

    cmd = build_load_command(
        only, 
        skip, cve_from_year
    )

    # Определяем/проверяем run_id
    if not isinstance(run_id, str) or not run_id:
        run_id = str(int(time.time() * 1000))
    with RUNS_LOCK:
        if run_id in RUNS and RUNS[run_id].poll() is None:
            return JSONResponse(
                {"error": "Уже есть активный процесс с таким run_id", "run_id": run_id},
                status_code=409,
            )

    # В ответ добавим команду и run_id
    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        extra_env = {}
        # Если фронт передал check_hash=true/false, пробрасываем в env дочернего процесса
        if isinstance(check_hash, bool):
            extra_env["NVD_CHECK_HASH"] = "true" if check_hash else "false"
        for chunk in stream_process(cmd, run_id, tty_columns=tty_columns, tty_rows=tty_rows, extra_env=extra_env or None):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/run/refresh_epss_kev")
async def run_refresh_epss_kev(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    tty_columns = payload.get("columns")
    tty_rows = payload.get("rows")
    run_id = payload.get("run_id")

    if not isinstance(run_id, str) or not run_id:
        run_id = str(int(time.time() * 1000))
    with RUNS_LOCK:
        if run_id in RUNS and RUNS[run_id].poll() is None:
            return JSONResponse(
                {"error": "Уже есть активный процесс с таким run_id", "run_id": run_id},
                status_code=409,
            )

    cmd = build_refresh_command()

    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        for chunk in stream_process(cmd, run_id, tty_columns=tty_columns, tty_rows=tty_rows, extra_env=None):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/run/gnn")
async def run_gnn(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    tty_columns = payload.get("columns")
    tty_rows = payload.get("rows")
    run_id = payload.get("run_id")
    dry_run = bool(payload.get("dry_run"))

    epochs = payload.get("epochs")
    top_k = payload.get("top_k")
    min_score = payload.get("min_score")
    sentence_model = payload.get("sentence_model")
    device = payload.get("device")
    mode = payload.get("mode")

    if not isinstance(run_id, str) or not run_id:
        run_id = str(int(time.time() * 1000))
    with RUNS_LOCK:
        if run_id in RUNS and RUNS[run_id].poll() is None:
            return JSONResponse(
                {"error": "Уже есть активный процесс с таким run_id", "run_id": run_id},
                status_code=409,
            )

    cmd = build_gnn_command(
        epochs=epochs,
        top_k=top_k,
        min_score=min_score,
        sentence_model=sentence_model,
        device=device,
        mode=mode,
        dry_run=dry_run,
    )

    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        for chunk in stream_process(cmd, run_id, tty_columns=tty_columns, tty_rows=tty_rows, extra_env=None):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/gnn/clear")
def clear_gnn_predictions():
    try:
        g = get_graph()
    except Exception as e:
        return JSONResponse(
            {
                "status": "error",
                "error": f"Не удалось подключиться к Neo4j: {e}",
            },
            status_code=500,
        )

    cypher = "MATCH ()-[r:CAPEC_TO_TECHNIQUE_PRED]->() DELETE r"
    try:
        g.run(cypher)
    except Exception as e:
        return JSONResponse(
            {
                "status": "error",
                "error": f"Ошибка при удалении связей CAPEC_TO_TECHNIQUE_PRED: {e}",
            },
            status_code=500,
        )
    return JSONResponse({"status": "ok"})


@app.post("/stop")
async def stop_run(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return JSONResponse({"error": "run_id обязателен"}, status_code=400)

    with RUNS_LOCK:
        proc = RUNS.get(run_id)
    if not proc or proc.poll() is not None:
        return JSONResponse({"status": "not-found-or-exited", "run_id": run_id})

    # Пытаемся мягко остановить
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    finally:
        with RUNS_LOCK:
            RUNS.pop(run_id, None)
    return JSONResponse({"status": "stopped", "run_id": run_id})


@app.get("/health")
def health():
    return JSONResponse({"status": "ok"})


# CPE APIs
@app.get("/api/cpe/vendors")
def api_cpe_vendors(part: str, q: str = "", limit: int = 100, offset: int = 0):
    g = get_graph()
    items = cpe_search.vendors(
        g,
        part=part,
        q=q,
        limit=min(max(limit, 1), 200),
        offset=max(0, int(offset)),
    )
    return {"items": items}


@app.get("/api/cpe/products")
def api_cpe_products(part: str, vendor: str, q: str = "", limit: int = 100, offset: int = 0):
    g = get_graph()
    items = cpe_search.products(
        g,
        part=part,
        vendor=vendor,
        q=q,
        limit=min(max(limit, 1), 200),
        offset=max(0, int(offset)),
    )
    return {"items": items}


@app.get("/api/cpe/versions")
def api_cpe_versions(part: str, vendor: str, product: str, q: str = "", limit: int = 100, offset: int = 0):
    g = get_graph()
    items = cpe_search.versions(
        g,
        part=part,
        vendor=vendor,
        product=product,
        q=q,
        limit=min(max(limit, 1), 200),
        offset=max(0, int(offset)),
    )
    return {"items": items}


@app.get("/api/cpe/search")
def api_cpe_search(part: str, vendor: str = "", product: str = "", version: str = "", limit: int = 50):
    g = get_graph()
    items = cpe_search.search(g, part=part, vendor=vendor, product=product, version=version, limit=min(max(limit, 1), 200))
    return {"items": items}


# API для Target
@app.post("/api/targets/parse")
async def api_targets_parse(file: UploadFile = File(...)):
    data = await file.read()
    cves = parse_cves_from_xml_bytes(data)
    if not cves:
        return JSONResponse({"error": "Не удалось найти CVE в файле"}, status_code=400)
    return {"items": cves, "total": len(cves)}


@app.post("/api/targets/check")
async def api_targets_check(request: Request):
    g = get_graph()
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    name = payload.get("name") or ""
    cves_text = payload.get("cves_text") or ""
    file_cves = payload.get("file_cves") or []
    if not isinstance(file_cves, list):
        file_cves = []

    cves, err = collect_cves(cves_text, file_cves)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    try:
        resolved_name, generated = resolve_name(name, cves)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    target_uri = build_target_uri(resolved_name)
    ensure_target_constraints(g)
    exists = target_exists(g, target_uri)

    found_ids = check_cves_in_db(g, cves)
    missing = max(0, len(cves) - len(found_ids))

    return {
        "name": resolved_name,
        "target_uri": target_uri,
        "generated_name": generated,
        "total": len(cves),
        "found": len(found_ids),
        "missing": missing,
        "exists": exists,
    }


@app.post("/api/targets/create")
async def api_targets_create(request: Request):
    g = get_graph()
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    name = payload.get("name") or ""
    cves_text = payload.get("cves_text") or ""
    file_cves = payload.get("file_cves") or []
    if not isinstance(file_cves, list):
        file_cves = []

    cves, err = collect_cves(cves_text, file_cves)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    try:
        resolved_name, generated = resolve_name(name, cves)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    target_uri = build_target_uri(resolved_name)
    ensure_target_constraints(g)

    found_ids = check_cves_in_db(g, cves)
    if not found_ids:
        return JSONResponse({"error": "В базе не найдено ни одной CVE"}, status_code=400)
    missing = max(0, len(cves) - len(found_ids))

    res = upsert_target(
        g,
        name=resolved_name,
        target_uri=target_uri,
        input_total=len(cves),
        found_count=len(found_ids),
        missing_count=missing,
        found_ids=found_ids,
    )

    return {
        "name": resolved_name,
        "target_uri": target_uri,
        "generated_name": generated,
        "total": len(cves),
        "found": len(found_ids),
        "missing": missing,
        "created": bool(res.get("created")),
        "updated": bool(res.get("updated")),
    }


@app.get("/api/targets/search")
def api_targets_search(q: str = "", limit: int = 50, offset: int = 0):
    g = get_graph()
    limit = min(max(int(limit or 50), 1), 200)
    offset = max(0, int(offset or 0))
    q = (q or "").strip()
    rows = g.run(
        """
        MATCH (t:Target)
        WHERE $q = '' OR toLower(t.name) CONTAINS toLower($q)
        RETURN
          t.name AS name,
          t.targetUri AS target_uri,
          coalesce(t.input_total, 0) AS input_total,
          coalesce(t.found_count, 0) AS found_count,
          coalesce(t.missing_count, 0) AS missing_count
        ORDER BY t.name
        SKIP $offset LIMIT $limit
        """,
        q=q,
        offset=offset,
        limit=limit,
    )
    return {"items": rows.data()}


@app.post("/api/targets/cleanup")
async def api_targets_cleanup(request: Request):
    g = get_graph()
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    mode = (payload.get("mode") or "").strip().lower()
    days = payload.get("days")

    if mode == "all":
        rows = g.run(
            """
            MATCH (t:Target)
            WITH collect(t) AS items, count(t) AS c
            FOREACH (x IN items | DETACH DELETE x)
            RETURN c AS deleted
            """
        ).data()
    elif mode == "older_than":
        try:
            days = int(days)
        except Exception:
            days = 10
        if days < 1:
            days = 1
        cutoff = int(time.time()) - days * 86400
        rows = g.run(
            """
            MATCH (t:Target)
            WHERE coalesce(t.updated_ts, t.created_ts, 0) < $cutoff
            WITH collect(t) AS items, count(t) AS c
            FOREACH (x IN items | DETACH DELETE x)
            RETURN c AS deleted
            """,
            cutoff=cutoff,
        ).data()
    else:
        return JSONResponse({"error": "Некорректный режим очистки"}, status_code=400)

    deleted = (rows or [{}])[0].get("deleted") or 0
    return {"deleted": int(deleted)}


# Scenarios API
@app.get("/api/scenarios")
def api_scenarios(cpe: str, mode: str = "strict", max_per_tactic: int = 3):
    g = get_graph()
    # Нормализуем вход
    cpe_in, _ = normalize_object_uri(cpe)

    m = (mode or "strict").strip().lower()
    if m not in ("strict", "relaxed", "gnn"):
        m = "strict"
    try:
        mpt = int(max_per_tactic)
        if mpt <= 0:
            mpt = 1
        if mpt > 10:
            mpt = 10
    except Exception:
        mpt = 3

    data = generate_scenarios(g, cpe_in, mode=m, max_per_tactic=mpt)
    return data


@app.get("/api/export")
def api_export(cpe: str, mode: str = "strict", max_per_tactic: int = 3):
    """Экспорт сценариев в облегчённом JSON-формате:
    - primary: группы тактик с техниками и списками CVE (полный набор метрик)
    """
    g = get_graph()
    # Нормализуем вход
    cpe_in, is_target = normalize_object_uri(cpe)

    m = (mode or "strict").strip().lower()
    if m not in ("strict", "relaxed", "gnn"):
        m = "strict"
    try:
        mpt = int(max_per_tactic)
        if mpt <= 0:
            mpt = 1
        if mpt > 10:
            mpt = 10
    except Exception:
        mpt = 3

    data = generate_scenarios(g, cpe_in, mode=m, max_per_tactic=mpt)
    mega = list(data.get("mega") or [])

    # primary -> тактики -> техники (id) -> cves (полный набор метрик)
    primary = []
    for col in sorted(mega, key=lambda x: (x.get("tactic_order") or 0)):
        tactic = col.get("tactic")
        order = col.get("tactic_order")
        items = []
        for st in (col.get("techniques") or []):
            tech = (st or {}).get("technique") or {}
            tprops = tech.get("props") or {}
            tid = tprops.get("identifier")
            if not tid:
                continue
            cves = []
            for cv in (st.get("cves") or []):
                cprops = (cv or {}).get("props") or {}
                cid = cprops.get("identifier")
                if not cid:
                    continue
                src = "first.org" if bool(cprops.get("epss_from_first")) else "generated"
                cves.append({
                    "cve_id": cid,
                    "epss": cprops.get("epss"),
                    "epss_source": src,
                    "cvss": cprops.get("cvss") or 0,
                    "cvss_C_score": cprops.get("cvss_C_score") or 0,
                    "cvss_A_score": cprops.get("cvss_A_score") or 0,
                    "cvss_I_score": cprops.get("cvss_I_score") or 0,
                    "epss_norm": cprops.get("epss_norm") or 0,
                    "damage": cprops.get("damage") or 0,
                    "risk": cprops.get("risk") or 0,
                })
            items.append({
                "technique_id": tid,
                "cves": cves,
            })
        primary.append({
            "tactic": tactic,
            "tactic_order": order,
            "techniques": items,
        })

    # Заголовок и метаданные (локальное время с часовым поясом)
    now_iso = dt.datetime.now().astimezone().replace(microsecond=0).isoformat()
    if is_target:
        meta = {
            "cpe": "none",
            "target": cpe_in,
            "date_created": now_iso,
            "mode": m,
            "max_per_tactic": mpt,
        }
    else:
        meta = {
            "cpe": cpe_in,
            "date_created": now_iso,
            "mode": m,
            "max_per_tactic": mpt,
        }

    payload = {
        "schema": "scenario-export",
        "schema_version": 1,
        "metadata": meta,
        "primary": primary,
    }

    import json as _json
    body = _json.dumps(payload, ensure_ascii=False)

    # Формирование имени файла: vendor_product_version_ddmmyyyy_hhmmss.json
    def _safe_part(s: str) -> str:
        t = (s or '').strip()
        if t == '*':
            t = 'any'
        elif t == '-':
            t = 'none'
        t = t.lower()
        out = []
        for ch in t:
            if ch.isalnum() or ch in ('-', '_', '.'):
                out.append(ch)
            else:
                out.append('_')
        t2 = ''.join(out).strip('_')
        return t2 or 'none'

    def _parse_cpe_parts(cpe_uri: str):
        try:
            parts = cpe_uri.split(':')
            vendor = parts[3] if len(parts) > 3 else 'vendor'
            product = parts[4] if len(parts) > 4 else 'product'
            version = parts[5] if len(parts) > 5 else 'none'
            return _safe_part(vendor), _safe_part(product), _safe_part(version)
        except Exception:
            return 'vendor', 'product', 'none'

    ts = dt.datetime.now().astimezone()
    if is_target:
        name = cpe_in.replace("custom:", "", 1)
        safe = _safe_part(name)
        fname = f"target_{safe}_{ts.strftime('%d%m%Y_%H%M%S')}.json"
    else:
        v, p, ver = _parse_cpe_parts(cpe_in)
        fname = f"{v}_{p}_{ver}_{ts.strftime('%d%m%Y_%H%M%S')}.json"

    return Response(
        content=body,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={fname}",
        },
    )
