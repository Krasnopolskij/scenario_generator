import json
import logging
import math
from logging.config import dictConfig
import os
import socket
import select
import subprocess
import sys
import threading
import time
import uuid
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple

import httpx
from uvicorn.logging import DefaultFormatter, AccessFormatter
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from py2neo import Graph
from dotenv import load_dotenv
from cpe import search as cpe_search
from scenario_generation.generator import generate_scenarios
from link_utils import external_link_for
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

load_dotenv()


def setup_logging():
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    uvicorn_level = os.getenv("UVICORN_LOG_LEVEL", level_name).upper()
    access_level = os.getenv("UVICORN_ACCESS_LEVEL", uvicorn_level).upper()
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "()": DefaultFormatter,
                    "fmt": "%(levelprefix)s %(asctime)s [%(name)s] %(message)s",
                    "use_colors": True,
                },
                "access": {
                    "()": AccessFormatter,
                    "fmt": '%(levelprefix)s %(client_addr)s [%(name)s] "%(request_line)s" %(status_code)s',
                    "use_colors": True,
                },
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                },
                "access": {
                    "class": "logging.StreamHandler",
                    "formatter": "access",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {"handlers": ["console"], "level": level_name},
            "loggers": {
                "uvicorn": {"handlers": ["console"], "level": uvicorn_level, "propagate": False},
                "uvicorn.error": {"handlers": ["console"], "level": uvicorn_level, "propagate": False},
                "uvicorn.access": {"handlers": ["access"], "level": access_level, "propagate": False},
            },
        }
    )


ROOT = Path(__file__).parent.resolve()
setup_logging()

logger = logging.getLogger("scenario.app")
graph_logger = logging.getLogger("scenario.graph")
runner_logger = logging.getLogger("scenario.runner")
logger.info("logging initialized level=%s", logging.getLevelName(logger.getEffectiveLevel()))

app = FastAPI(title="Scenario Generator UI")

# Статика UI
ui_dir = ROOT / "ui"
static_dir = ui_dir / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Жёсткий кеш для критичных статических файлов (баннер health)
class CacheControlMiddleware(BaseHTTPMiddleware):
    TARGETS = {"/static/js/health.js", "/static/css/health.css"}
    CACHE_VALUE = "public, max-age=31536000, immutable"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.path in self.TARGETS:
            response.headers["Cache-Control"] = self.CACHE_VALUE
        return response

app.add_middleware(CacheControlMiddleware)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request failed %s %s client=%s",
            request.method,
            request.url.path,
            request.client.host if request.client else "-",
        )
        raise
    duration_ms = (time.perf_counter() - start) * 1000.0
    try:
        status_int = int(getattr(response, "status_code", 0) or 0)
    except Exception:
        status_int = 0
    try:
        reason = HTTPStatus(status_int).phrase
    except Exception:
        reason = "unknown"
    if 200 <= status_int < 300:
        log_fn = logger.info
    elif 300 <= status_int < 400:
        log_fn = logger.info
    else:
        log_fn = logger.error
    log_fn(
        "request %s %s status=%s reason=%s duration_ms=%.2f client=%s",
        request.method,
        request.url.path,
        status_int or "unknown",
        reason,
        duration_ms,
        request.client.host if request.client else "-",
    )
    response.headers["X-Request-Id"] = request_id
    return response


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


@app.get("/api/ui-config")
def ui_config() -> JSONResponse:
    allow_export = os.getenv("ALLOW_EXPORT_TO_MEASURES_MODULE", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    measures_api = os.getenv("MEASURES_MODULE_API", "").strip()
    if not allow_export:
        measures_api = ""
    return JSONResponse(
        {
            "allow_export_to_measures": allow_export,
            "measures_module_api": measures_api,
        }
    )


ALLOWED_LOADERS = {"techniques", "capec", "cwe", "cve"}

# Регистрация запущенных процессов: run_id -> Popen
RUNS: Dict[str, subprocess.Popen] = {}
RUNS_LOCK = threading.Lock()
RUN_KINDS: Dict[str, str] = {}

# Neo4j connection (cached)
_GRAPH: Optional[Graph] = None
_GRAPH_QUERY_TIMEOUT = 10

def get_graph() -> Graph:
    global _GRAPH
    if _GRAPH is not None:
        return _GRAPH
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        graph_logger.error("NEO4J env vars are missing")
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    graph_logger.info("connecting to Neo4j uri=%s db=%s", neo4j_uri, neo4j_db)
    try:
        _GRAPH = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)
    except Exception:
        graph_logger.exception("failed to connect to Neo4j uri=%s db=%s", neo4j_uri, neo4j_db)
        raise
    graph_logger.info("connected to Neo4j uri=%s db=%s", neo4j_uri, neo4j_db)
    return _GRAPH


def _cleanup_runs_locked():
    """Удаляем завершённые процессы из реестра под блокировкой."""
    finished = [rid for rid, proc in RUNS.items() if proc.poll() is not None]
    for rid in finished:
        RUNS.pop(rid, None)
        RUN_KINDS.pop(rid, None)


def _reset_graph():
    global _GRAPH
    _GRAPH = None


def _active_run_of_kind(kind: str, exclude_run_id: Optional[str] = None) -> Optional[str]:
    """Возвращает run_id активного процесса указанного типа или None."""
    with RUNS_LOCK:
        _cleanup_runs_locked()
        for rid, proc in RUNS.items():
            if proc.poll() is None and RUN_KINDS.get(rid) == kind and rid != exclude_run_id:
                return rid
    return None


def _gnn_service_url() -> Optional[str]:
    raw = (os.getenv("GNN_SERVICE_URL") or "").strip()
    if not raw:
        return None
    return raw.rstrip("/")


async def _fetch_gnn_status(timeout_s: float = 3.0) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    base_url = _gnn_service_url()
    if not base_url:
        return None, "GNN_SERVICE_URL не задан"
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(f"{base_url}/status")
    except httpx.RequestError as exc:
        return None, f"Не удалось получить статус GNN: {exc}"
    try:
        data = resp.json()
    except Exception:
        return None, "Некорректный ответ статуса GNN"
    if not isinstance(data, dict):
        return None, "Некорректный формат статуса GNN"
    return data, None


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

    try:
        rows = g.run(cypher, timeout=_GRAPH_QUERY_TIMEOUT, **params)
    except Exception as e:
        graph_logger.exception(
            "graph subgraph failed cpe=%s mode=%s limit=%s err=%s", cpe_in, mode, limit, e
        )
        _reset_graph()
        return JSONResponse(
            {"error": "Neo4j недоступен", "details": str(e)}, status_code=503
        )

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
        link = external_link_for(label, props.get("identifier"))
        if link:
            props["external_link"] = link
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
        try:
            pred_rows = g.run(pred_cypher, cpe=cpe_in, limit=limit, timeout=_GRAPH_QUERY_TIMEOUT)
        except Exception as e:
            graph_logger.exception(
                "graph subgraph pred failed cpe=%s mode=%s limit=%s err=%s", cpe_in, mode, limit, e
            )
            _reset_graph()
            return JSONResponse(
                {"error": "Neo4j недоступен", "details": str(e)}, status_code=503
            )
        for row in pred_rows:
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


def stream_process(
    cmd: List[str],
    run_id: str,
    tty_columns: Optional[int] = None,
    tty_rows: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
    kind: Optional[str] = None,
):
    cmd_display = " ".join(str(x) for x in cmd)
    runner_logger.info("spawn process run_id=%s kind=%s cmd=%s", run_id, kind or "-", cmd_display)
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
            if kind:
                RUN_KINDS[run_id] = kind
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
                RUN_KINDS.pop(run_id, None)
            level = logging.INFO if code == 0 else logging.ERROR
            runner_logger.log(level, "process finished run_id=%s kind=%s code=%s", run_id, kind or "-", code)
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
            if kind:
                RUN_KINDS[run_id] = kind
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
                RUN_KINDS.pop(run_id, None)
            level = logging.INFO if code == 0 else logging.ERROR
            runner_logger.log(level, "process finished run_id=%s kind=%s code=%s", run_id, kind or "-", code)
            yield f"\n[exit code: {code}]\n"


@app.post("/run/load")
async def run_loader(request: Request):
    load_dotenv()
    allow_loader = os.getenv("ALLOW_LOADER_CONTROL", "false").lower() in {"1", "true", "yes"}
    if not allow_loader:
        logger.warning("loader control denied by config")
        return JSONResponse(
            {"error": "Управление загрузчиками отключено администатором"},
            status_code=403,
        )

    gnn_status, gnn_err = await _fetch_gnn_status()
    if gnn_status and gnn_status.get("status") == "running":
        return JSONResponse(
            {"error": "Нельзя запускать загрузчики, пока выполняется GNN", "run_id": gnn_status.get("run_id")},
            status_code=409,
        )
    if gnn_err:
        logger.warning("gnn status unavailable: %s", gnn_err)
        
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
    active_loader = _active_run_of_kind("loader", exclude_run_id=run_id)
    if active_loader:
        return JSONResponse(
            {"error": "Уже выполняется другой процесс загрузчика", "run_id": active_loader},
            status_code=409,
        )
    with RUNS_LOCK:
        _cleanup_runs_locked()
        if run_id in RUNS and RUNS[run_id].poll() is None:
            return JSONResponse(
                {"error": "Уже есть активный процесс с таким run_id", "run_id": run_id},
                status_code=409,
            )

    cmd_display = " ".join(cmd)
    logger.info(
        "start loader run_id=%s only=%s skip=%s cve_from_year=%s check_hash=%s cmd=%s",
        run_id,
        only,
        skip,
        cve_from_year,
        check_hash,
        cmd_display,
    )

    # В ответ добавим команду и run_id
    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        extra_env = {}
        # Если фронт передал check_hash=true/false, пробрасываем в env дочернего процесса
        if isinstance(check_hash, bool):
            extra_env["NVD_CHECK_HASH"] = "true" if check_hash else "false"
        for chunk in stream_process(
            cmd,
            run_id,
            tty_columns=tty_columns,
            tty_rows=tty_rows,
            extra_env=extra_env or None,
            kind="loader",
        ):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/run/refresh_epss_kev")
async def run_refresh_epss_kev(request: Request):
    allow_update = os.getenv("ALLOW_UPDATE_CONTROL", "false").lower() in {"1", "true", "yes"}
    if not allow_update:
        logger.warning("EPSS/KEV control denied by config")
        return JSONResponse(
            {"error": "Управление обновлениями EPSS и CISA KEV отключено администатором"},
            status_code=403,
        )

    gnn_status, gnn_err = await _fetch_gnn_status()
    if gnn_status and gnn_status.get("status") == "running":
        return JSONResponse(
            {"error": "Нельзя запускать обновления, пока выполняется GNN", "run_id": gnn_status.get("run_id")},
            status_code=409,
        )
    if gnn_err:
        logger.warning("gnn status unavailable: %s", gnn_err)
    
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    tty_columns = payload.get("columns")
    tty_rows = payload.get("rows")
    run_id = payload.get("run_id")

    if not isinstance(run_id, str) or not run_id:
        run_id = str(int(time.time() * 1000))
    active_loader = _active_run_of_kind("loader", exclude_run_id=run_id)
    if active_loader:
        return JSONResponse(
            {"error": "Уже выполняется другой процесс загрузчика", "run_id": active_loader},
            status_code=409,
        )
    with RUNS_LOCK:
        _cleanup_runs_locked()
        if run_id in RUNS and RUNS[run_id].poll() is None:
            return JSONResponse(
                {"error": "Уже есть активный процесс с таким run_id", "run_id": run_id},
                status_code=409,
            )

    cmd = build_refresh_command()
    logger.info("start refresh EPSS/KEV run_id=%s cmd=%s", run_id, " ".join(cmd))

    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        for chunk in stream_process(
            cmd,
            run_id,
            tty_columns=tty_columns,
            tty_rows=tty_rows,
            extra_env=None,
            kind="loader",
        ):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/run/gnn")
async def run_gnn(request: Request):
    allow_gnn = os.getenv("ALLOW_GNN_CONTROL", "false").lower() in {"1", "true", "yes"}
    if not allow_gnn:
        logger.warning("GNN control denied by config")
        return JSONResponse(
            {"error": "Управление GNN отключено администатором"},
            status_code=403,
        )
    
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        run_id = str(int(time.time() * 1000))
        payload["run_id"] = run_id

    active_loader = _active_run_of_kind("loader", exclude_run_id=run_id)
    if active_loader:
        return JSONResponse(
            {"error": "Уже выполняется процесс загрузчика", "run_id": active_loader},
            status_code=409,
        )

    gnn_url = _gnn_service_url()
    if not gnn_url:
        return JSONResponse(
            {"error": "GNN сервис не настроен (GNN_SERVICE_URL)"},
            status_code=503,
        )

    logger.info("proxy gnn run_id=%s -> %s", run_id, gnn_url)
    timeout = httpx.Timeout(connect=3.0, read=None, write=10.0, pool=10.0)
    client = httpx.AsyncClient(timeout=timeout)
    stream_cm = client.stream("POST", f"{gnn_url}/run", json=payload)
    try:
        resp = await stream_cm.__aenter__()
    except httpx.RequestError as exc:
        await client.aclose()
        logger.warning("gnn service request failed: %s", exc)
        return JSONResponse(
            {"error": f"Не удалось связаться с GNN сервисом: {exc}"},
            status_code=503,
        )

    if resp.status_code >= 400:
        msg = f"{resp.status_code} {resp.reason_phrase}"
        try:
            body = await resp.aread()
            if body:
                data = json.loads(body.decode("utf-8"))
                if isinstance(data, dict) and data.get("error"):
                    msg = f"{msg} — {data['error']}"
        except Exception:
            pass
        await stream_cm.__aexit__(None, None, None)
        await client.aclose()
        return JSONResponse({"error": msg}, status_code=resp.status_code)

    hdr_id = resp.headers.get("x-run-id") or run_id

    async def generator():
        try:
            async for chunk in resp.aiter_bytes():
                if not chunk:
                    continue
                yield chunk
        finally:
            await stream_cm.__aexit__(None, None, None)
            await client.aclose()

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": hdr_id},
    )


@app.post("/gnn/clear")
def clear_gnn_predictions():
    allow_gnn = os.getenv("ALLOW_GNN_CONTROL", "false").lower() in {"1", "true", "yes"}
    if not allow_gnn:
        logger.warning("GNN clear request denied by config")
        return JSONResponse(
            {"error": "Управление GNN отключено администатором"},
            status_code=403,
        )
    
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
        logger.exception("failed to clear GNN predictions: %s", e)
        return JSONResponse(
            {
                "status": "error",
                "error": f"Ошибка при удалении связей CAPEC_TO_TECHNIQUE_PRED: {e}",
            },
            status_code=500,
        )
    logger.info("cleared GNN predictions")
    return JSONResponse({"status": "ok"})


@app.get("/gnn/status")
async def get_gnn_status():
    data, err = await _fetch_gnn_status()
    if err:
        return JSONResponse({"status": "unavailable", "error": err}, status_code=503)
    return JSONResponse(data)


@app.get("/gnn/roc-auc")
async def get_gnn_roc_auc():
    allow_gnn = os.getenv("ALLOW_GNN_CONTROL", "false").lower() in {"1", "true", "yes"}
    if not allow_gnn:
        logger.warning("GNN ROC-AUC request denied by config")
        return JSONResponse(
            {"error": "Управление GNN отключено администатором"},
            status_code=403,
        )

    gnn_url = _gnn_service_url()
    if not gnn_url:
        return JSONResponse(
            {"status": "error", "error": "GNN сервис не настроен (GNN_SERVICE_URL)"},
            status_code=503,
        )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{gnn_url}/roc-auc")
    except httpx.RequestError as exc:
        logger.warning("gnn roc-auc request failed: %s", exc)
        return JSONResponse(
            {"status": "error", "error": f"Не удалось связаться с GNN сервисом: {exc}"},
            status_code=503,
        )
    try:
        payload = resp.json()
    except Exception:
        return JSONResponse(
            {"status": "error", "error": "Некорректный ответ GNN сервиса"},
            status_code=502,
        )
    return JSONResponse(payload, status_code=resp.status_code)


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
        _cleanup_runs_locked()
        proc = RUNS.get(run_id)
    if not proc or proc.poll() is not None:
        gnn_url = _gnn_service_url()
        if not gnn_url:
            runner_logger.info("stop requested for missing run_id=%s", run_id)
            return JSONResponse({"status": "not-found-or-exited", "run_id": run_id})
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(f"{gnn_url}/stop", json={"run_id": run_id})
        except httpx.RequestError as exc:
            runner_logger.warning("gnn stop request failed run_id=%s err=%s", run_id, exc)
            return JSONResponse(
                {"status": "gnn-unavailable", "run_id": run_id},
                status_code=503,
            )
        try:
            payload = resp.json()
        except Exception:
            return JSONResponse(
                {"status": "gnn-error", "run_id": run_id},
                status_code=502,
            )
        return JSONResponse(payload, status_code=resp.status_code)

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
            RUN_KINDS.pop(run_id, None)
    runner_logger.info("stopped run_id=%s", run_id)
    return JSONResponse({"status": "stopped", "run_id": run_id})


@app.get("/health")
def health():
    # Быстрый TCP-пинг, чтобы не зависнуть на попытке установить Bolt-сессию
    uri = os.getenv("NEO4J_URI", "")
    parsed = urlparse(uri)
    host = parsed.hostname or ""
    port = parsed.port
    if not host:
        logger.error("health: NEO4J_URI missing host")
        return JSONResponse({"status": "db_unavailable", "error": "Некорректный NEO4J_URI"}, status_code=503)
    if port is None:
        port = 7687 if (parsed.scheme or "").startswith("bolt") else 7474
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except Exception as e:
        logger.error("health: socket error host=%s port=%s err=%s", host, port, e)
        return JSONResponse(
            {"status": "db_unavailable", "error": f"socket: {e}"},
            status_code=503,
        )

    try:
        g = get_graph()
        # Лёгкий пинг: проверяем, что сессия жива, без обхода графа
        g.run("RETURN 1", timeout=4).evaluate()
    except Exception as e:
        logger.error("health: graph ping failed err=%s", e)
        return JSONResponse(
            {"status": "db_unavailable", "error": str(e)},
            status_code=503,
        )
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
    logger.info("targets parse filename=%s size=%s", getattr(file, "filename", None), len(data or b""))
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
    logger.info(
        "targets check name=%s resolved=%s generated=%s total=%s found=%s missing=%s exists=%s",
        name,
        resolved_name,
        generated,
        len(cves),
        len(found_ids),
        missing,
        exists,
    )

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
    logger.info(
        "targets create name=%s resolved=%s generated=%s total=%s found=%s missing=%s created=%s updated=%s",
        name,
        resolved_name,
        generated,
        len(cves),
        len(found_ids),
        missing,
        bool(res.get("created")),
        bool(res.get("updated")),
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
    logger.info("targets search q=%s limit=%s offset=%s", q, limit, offset)
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
        logger.warning("targets cleanup invalid mode=%s", mode)
        return JSONResponse({"error": "Некорректный режим очистки"}, status_code=400)

    deleted = (rows or [{}])[0].get("deleted") or 0
    logger.info("targets cleanup mode=%s days=%s deleted=%s", mode, days, deleted)
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

    logger.info("scenarios request cpe=%s mode=%s max_per_tactic=%s", cpe_in, m, mpt)
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

    logger.info("export request cpe=%s mode=%s max_per_tactic=%s", cpe_in, m, mpt)
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
                    "damage_C": cprops.get("damage_C") or 0,
                    "damage_I": cprops.get("damage_I") or 0,
                    "damage_A": cprops.get("damage_A") or 0,
                    "risk_C": cprops.get("risk_C") or 0,
                    "risk_I": cprops.get("risk_I") or 0,
                    "risk_A": cprops.get("risk_A") or 0,
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
