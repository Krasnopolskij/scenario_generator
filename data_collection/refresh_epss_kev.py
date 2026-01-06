import csv
import gzip
import io
import os
import sys
import time
from typing import Dict, Optional
import requests
from dotenv import load_dotenv
from py2neo import Graph
from tqdm import tqdm

# Реиспользуем готовые процедуры обновления KEV и fallback EPSS
from load_cve import apply_epss_fallback_min, update_cisa_kev

EPSS_CSV_URL = os.getenv(
    "EPSS_CSV_URL",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
)
EPSS_REFRESH_BATCH = int(os.getenv("EPSS_REFRESH_BATCH", 5000))


def _connect_graph() -> Graph:
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")

    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    print(f"Подключение к базе Neo4j: {neo4j_db}")
    return Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)


def _cve_count(graph: Graph) -> int:
    try:
        rec = graph.run("MATCH (v:CVE) RETURN count(v) AS c").data()
        if rec and isinstance(rec, list):
            return int(rec[0].get("c") or 0)
    except Exception:
        return 0
    return 0


def fetch_epss_map(url: str = EPSS_CSV_URL) -> Dict[str, float]:
    """Скачивает CSV EPSS и возвращает словарь CVE -> epss."""
    print(f"[EPSS] Загрузка CSV: {url}")
    resp = requests.get(url, timeout=180)
    resp.raise_for_status()
    raw = resp.content
    try:
        data = gzip.decompress(raw)
    except Exception:
        data = raw
    text = data.decode("utf-8", errors="replace")
    # Убираем комментарии вида "#model_version:...,score_date:..."
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        raise RuntimeError("Не удалось распарсить EPSS CSV: пустой файл после очистки комментариев")
    cleaned_text = "\n".join(lines)
    # Пытаемся угадать разделитель (некоторые зеркала могут отдавать ; вместо ,)
    sample = "\n".join(lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        delimiter = dialect.delimiter
    except Exception:
        delimiter = ","
    reader = csv.DictReader(io.StringIO(cleaned_text), delimiter=delimiter)
    result: Dict[str, float] = {}
    for row in reader:
        norm = {(k or "").strip().lstrip("\ufeff").lower(): v for k, v in row.items()}
        cve_id = (
            norm.get("cve")
            or norm.get("cveid")
            or norm.get("cve_id")
            or norm.get("cve id")
            or ""
        ).strip().upper()
        if not cve_id:
            continue
        epss_raw = norm.get("epss") or norm.get("score") or norm.get("score_numeric")
        try:
            epss_val = float(epss_raw)
        except Exception:
            continue
        result[cve_id] = epss_val
    print(f"[EPSS] Загружено записей: {len(result)}")
    if not result:
        preview = sample.replace("\n", "\\n")[:200]
        raise RuntimeError(f"Не удалось распарсить EPSS CSV: 0 записей (delimiter='{delimiter}', preview='{preview}')")
    return result


def update_epss(graph: Graph, epss_map: Dict[str, float], batch_size: int = EPSS_REFRESH_BATCH):
    """Обновляет EPSS для существующих CVE, не создавая новые узлы."""
    total = _cve_count(graph)
    if total <= 0:
        print("[EPSS] В базе нет узлов CVE — обновление не требуется")
        sys.exit(1)

    print(f"[EPSS] Обновление значений для {total} CVE...")
    cursor = graph.run("MATCH (v:CVE) RETURN v.identifier AS id")
    rows = []
    pbar = tqdm(total=total, desc="EPSS", unit="cve", leave=True)

    def flush(rows_buf):
        if not rows_buf:
            return
        graph.run(
            """
            UNWIND $rows AS r
            MATCH (v:CVE {identifier: r.id})
            SET v.epss = r.epss,
                v.epss_from_first = CASE WHEN r.epss IS NULL THEN false ELSE true END
            """,
            rows=rows_buf,
        )

    for rec in cursor:
        try:
            cid = rec.get("id") if hasattr(rec, "get") else rec[0]
        except Exception:
            cid = None
        if not cid:
            pbar.update(1)
            continue
        cid_norm = str(cid).strip().upper()
        epss_val: Optional[float] = epss_map.get(cid_norm)
        rows.append({"id": cid_norm, "epss": epss_val})
        if len(rows) >= batch_size:
            flush(rows)
            pbar.update(len(rows))
            rows.clear()
    if rows:
        flush(rows)
        pbar.update(len(rows))
        rows.clear()
    if pbar.n < total:
        pbar.update(total - pbar.n)
    pbar.close()
    print("[EPSS] Обновление завершено")


def main():
    load_dotenv()
    try:
        graph = _connect_graph()
    except Exception as e:
        print(f"[CRITICAL] Не удалось подключиться к Neo4j: {e}")
        sys.exit(1)

    total_cves = _cve_count(graph)
    if total_cves <= 0:
        print("[EPSS] В базе нет узлов CVE — обновление прервано")
        sys.exit(1)

    t0 = time.time()
    try:
        epss_map = fetch_epss_map()
    except Exception as e:
        print(f"[EPSS] Ошибка загрузки CSV: {e}")
        sys.exit(1)

    try:
        update_epss(graph, epss_map, batch_size=EPSS_REFRESH_BATCH)
    except Exception as e:
        print(f"[EPSS] Ошибка обновления: {e}")
        sys.exit(1)

    # Присваиваем EPSS по 1-му перцентилю там, где он отсутствует
    try:
        apply_epss_fallback_min(graph)
    except Exception as e:
        print(f"[EPSS] Ошибка применения fallback: {e}")

    # Обновление CISA KEV
    try:
        update_cisa_kev(graph)
    except Exception as e:
        print(f"[KEV] Ошибка обновления: {e}")

    print(f"Обновление EPSS/KEV завершено за {time.time() - t0:.1f}с")


if __name__ == "__main__":
    main()
