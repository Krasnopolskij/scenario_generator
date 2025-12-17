import datetime as dt
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from py2neo import Graph


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


def parse_cves_from_text(text: str) -> List[str]:
    if not text:
        return []
    found = {m.upper() for m in CVE_RE.findall(text)}
    return sorted(found)


def parse_cves_from_xml_bytes(data: bytes) -> List[str]:
    if not data:
        return []
    text = data.decode("utf-8", errors="ignore")
    return parse_cves_from_text(text)


def normalize_cve_list(items: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in (items or []):
        s = str(raw or "").strip().upper()
        if not s:
            continue
        if not CVE_RE.fullmatch(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def collect_cves(text: str, file_cves: Optional[List[str]]) -> Tuple[List[str], Optional[str]]:
    text = text or ""
    cves_text = parse_cves_from_text(text)
    if text.strip() and not cves_text:
        return [], "Не удалось распознать CVE в ручном вводе"

    cves_file = normalize_cve_list(file_cves)
    merged = set(cves_text)
    merged.update(cves_file)
    if not merged:
        return [], "Список CVE пуст"
    return sorted(merged), None


def resolve_name(name: str, cves: List[str]) -> Tuple[str, bool]:
    name = (name or "").strip()
    if name:
        if not NAME_RE.fullmatch(name):
            raise ValueError("Некорректное имя объекта")
        return name, False
    if not cves:
        raise ValueError("Невозможно сгенерировать имя без CVE")
    base = "|".join(sorted(cves)).encode("utf-8")
    digest = hashlib.sha256(base).hexdigest()[:12]
    return f"auto_{digest}", True


def build_target_uri(name: str) -> str:
    return f"custom:{name}"


def ensure_target_constraints(graph: Graph) -> None:
    statements_new = [
        "CREATE CONSTRAINT target_uri IF NOT EXISTS FOR (t:Target) REQUIRE t.targetUri IS UNIQUE",
    ]
    for stmt in statements_new:
        try:
            graph.run(stmt)
        except Exception:
            pass
    statements_old = [
        "CREATE CONSTRAINT target_uri IF NOT EXISTS ON (t:Target) ASSERT t.targetUri IS UNIQUE",
    ]
    for stmt in statements_old:
        try:
            graph.run(stmt)
        except Exception:
            pass


def target_exists(graph: Graph, target_uri: str) -> bool:
    row = graph.run(
        "MATCH (t:Target {targetUri: $uri}) RETURN count(t) AS c",
        uri=target_uri,
    ).data()
    try:
        return int((row or [{}])[0].get("c") or 0) > 0
    except Exception:
        return False


def check_cves_in_db(graph: Graph, cves: List[str]) -> List[str]:
    if not cves:
        return []
    rows = graph.run(
        "UNWIND $ids AS id MATCH (v:CVE {identifier: id}) RETURN v.identifier AS id",
        ids=cves,
    )
    found = set()
    for row in rows:
        cid = None
        try:
            cid = row.get("id") if hasattr(row, "get") else row[0]
        except Exception:
            cid = None
        if cid:
            found.add(str(cid).upper())
    return sorted(found)


def upsert_target(
    graph: Graph,
    name: str,
    target_uri: str,
    input_total: int,
    found_count: int,
    missing_count: int,
    found_ids: List[str],
) -> Dict[str, bool]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now_iso = now.isoformat()
    now_ts = int(now.timestamp())

    row = graph.run(
        "MATCH (t:Target {targetUri: $uri}) RETURN t.created_at AS created_at, t.created_ts AS created_ts",
        uri=target_uri,
    ).data()
    created_at = (row or [{}])[0].get("created_at")
    created_ts = (row or [{}])[0].get("created_ts")
    created = not bool(created_at or created_ts)

    graph.run(
        """
        MERGE (t:Target {targetUri: $uri})
        SET
          t.name = $name,
          t.input_total = $input_total,
          t.found_count = $found_count,
          t.missing_count = $missing_count,
          t.updated_at = $updated_at,
          t.updated_ts = $updated_ts,
          t.created_at = coalesce(t.created_at, $created_at),
          t.created_ts = coalesce(t.created_ts, $created_ts)
        """,
        uri=target_uri,
        name=name,
        input_total=int(input_total),
        found_count=int(found_count),
        missing_count=int(missing_count),
        updated_at=now_iso,
        updated_ts=now_ts,
        created_at=created_at or now_iso,
        created_ts=created_ts or now_ts,
    )

    graph.run(
        """
        MATCH (t:Target {targetUri: $uri})
        OPTIONAL MATCH (v:CVE)-[r:AFFECTS]->(t)
        DELETE r
        """,
        uri=target_uri,
    )

    if found_ids:
        graph.run(
            """
            UNWIND $ids AS id
            MATCH (v:CVE {identifier: id})
            MATCH (t:Target {targetUri: $uri})
            MERGE (v)-[:AFFECTS]->(t)
            """,
            ids=found_ids,
            uri=target_uri,
        )

    return {"created": created, "updated": not created}

