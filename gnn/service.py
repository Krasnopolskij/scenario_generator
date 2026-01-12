from __future__ import annotations

import json
import logging
import math
import os
import select
import subprocess
import sys
import threading
import time
import pty
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Iterator

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parents[1]

RUNS: Dict[str, subprocess.Popen] = {}
RUN_STARTED_AT: Dict[str, float] = {}
RUNS_LOCK = threading.Lock()

logger = logging.getLogger("gnn_service")


def _log_level() -> int:
    raw = (os.getenv("LOG_LEVEL") or "info").strip().lower()
    return {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(raw, logging.INFO)


logging.basicConfig(level=_log_level())
load_dotenv()

app = FastAPI()


def _cleanup_runs_locked() -> None:
    finished = [rid for rid, proc in RUNS.items() if proc.poll() is not None]
    for rid in finished:
        RUNS.pop(rid, None)
        RUN_STARTED_AT.pop(rid, None)


def _active_run_id(exclude_run_id: Optional[str] = None) -> Optional[str]:
    with RUNS_LOCK:
        _cleanup_runs_locked()
        for rid, proc in RUNS.items():
            if proc.poll() is None and rid != exclude_run_id:
                return rid
    return None


def _started_at_iso(run_id: str) -> Optional[str]:
    ts = RUN_STARTED_AT.get(run_id)
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


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
) -> Iterator[str]:
    cmd_display = " ".join(str(x) for x in cmd)
    logger.info("spawn process run_id=%s cmd=%s", run_id, cmd_display)

    try:
        import fcntl, termios, struct
    except Exception:
        fcntl = termios = struct = None

    master_fd, slave_fd = pty.openpty()
    if fcntl and termios and struct:
        try:
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
        RUN_STARTED_AT[run_id] = time.time()
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
            RUN_STARTED_AT.pop(run_id, None)
        level = logging.INFO if code == 0 else logging.ERROR
        logger.log(level, "process finished run_id=%s code=%s", run_id, code)
        yield f"\n[exit code: {code}]\n"


@app.get("/status")
def status():
    active = _active_run_id()
    if not active:
        return JSONResponse({"status": "idle"})
    return JSONResponse(
        {
            "status": "running",
            "run_id": active,
            "started_at": _started_at_iso(active),
        }
    )


@app.post("/run")
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

    active = _active_run_id(exclude_run_id=run_id)
    if active:
        return JSONResponse(
            {"error": "Уже выполняется другой процесс GNN", "run_id": active},
            status_code=409,
        )
    with RUNS_LOCK:
        _cleanup_runs_locked()
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
    logger.info("start gnn run_id=%s cmd=%s", run_id, " ".join(cmd))

    def generator():
        yield f"$ {' '.join(cmd)}\n[run_id: {run_id}]\n\n"
        for chunk in stream_process(
            cmd,
            run_id,
            tty_columns=tty_columns,
            tty_rows=tty_rows,
        ):
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/plain; charset=utf-8",
        headers={"X-Run-Id": run_id},
    )


@app.post("/stop")
async def stop_run(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        run_id = _active_run_id()
        if not run_id:
            return JSONResponse({"status": "not-found-or-exited"})

    with RUNS_LOCK:
        _cleanup_runs_locked()
        proc = RUNS.get(run_id)
    if not proc or proc.poll() is not None:
        logger.info("stop requested for missing run_id=%s", run_id)
        return JSONResponse({"status": "not-found-or-exited", "run_id": run_id})

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
            RUN_STARTED_AT.pop(run_id, None)
    logger.info("stopped run_id=%s", run_id)
    return JSONResponse({"status": "stopped", "run_id": run_id})


@app.get("/roc-auc")
def roc_auc():
    path = ROOT / "gnn_data" / "roc_auc_last.json"
    if not path.exists():
        return JSONResponse(
            {"status": "missing", "error": "Файл ROC-AUC не найден."},
            status_code=404,
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.exception("failed to read ROC-AUC JSON: %s", exc)
        return JSONResponse(
            {"status": "error", "error": "Не удалось прочитать файл ROC-AUC."},
            status_code=500,
        )

    try:
        payload = json.loads(raw)
    except Exception as exc:
        logger.exception("failed to parse ROC-AUC JSON: %s", exc)
        return JSONResponse(
            {"status": "error", "error": "Некорректный формат JSON ROC-AUC."},
            status_code=500,
        )

    def sanitize(obj):
        if isinstance(obj, float):
            return obj if math.isfinite(obj) else None
        if isinstance(obj, list):
            return [sanitize(item) for item in obj]
        if isinstance(obj, dict):
            return {key: sanitize(value) for key, value in obj.items()}
        return obj

    return JSONResponse(sanitize(payload))
