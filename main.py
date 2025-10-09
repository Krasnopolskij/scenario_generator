import sys
import json
import subprocess
import os
import select
from pathlib import Path
from typing import List, Optional

import threading
from typing import Dict
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).parent.resolve()

app = FastAPI(title="Scenario Generator UI")

# Статика UI
ui_dir = ROOT / "ui"
static_dir = ui_dir / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def index() -> FileResponse:
    index_file = ui_dir / "index.html"
    return FileResponse(str(index_file))


ALLOWED_LOADERS = {"techniques", "capec", "cwe", "cve"}

# Регистрация запущенных процессов: run_id -> Popen
RUNS: Dict[str, subprocess.Popen] = {}
RUNS_LOCK = threading.Lock()


def build_command(only: Optional[List[str]], skip: Optional[List[str]], cve_from_year: Optional[int]) -> List[str]:
    cmd = [sys.executable, "-u", str(ROOT / "app.py")]
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


def stream_process(cmd: List[str], run_id: str, tty_columns: Optional[int] = None, tty_rows: Optional[int] = None):
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


@app.post("/run")
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

    cmd = build_command(only, skip, cve_from_year)

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
        for chunk in stream_process(cmd, run_id, tty_columns=tty_columns, tty_rows=tty_rows):
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
