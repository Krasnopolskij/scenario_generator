from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Tuple
from py2neo import Graph

# Максимум сценариев возвращаем из API
MAX_SCENARIOS: int = 30


def _node_to_json(n) -> Dict[str, Any]:
    """Приводит py2neo Node к сериализуемому виду с полным набором полей.

    Возвращает:
      - id: строковый identity узла Neo4j (для связи с графом на UI)
      - labels: список меток
      - props: все свойства узла
    """
    if n is None:
        return {}
    try:
        nid = str(int(n.identity))
    except Exception:
        nid = str(n.identity)
    labels = list(n.labels) if hasattr(n, "labels") else []
    props = dict(n)
    return {"id": nid, "labels": labels, "props": props}


def _max_base_cvss_from_cves(cves: List[Dict[str, Any]]) -> float:
    """Возвращает максимальный базовый CVSS среди списка CVE.

    Базовый CVSS здесь трактуем как сумму компонент C/I/A,
    т.к. в модели CVE хранятся отдельные вклады (cvss_C_score, cvss_I_score, cvss_A_score).
    """
    max_val = 0.0
    for c in cves:
        p = c.get("props") or {}
        try:
            base = float(p.get("cvss_C_score") or 0.0) \
                 + float(p.get("cvss_I_score") or 0.0) \
                 + float(p.get("cvss_A_score") or 0.0)
        except Exception:
            base = 0.0
        if base > max_val:
            max_val = base
    return max_val


def _ensure_order(v) -> int:
    try:
        if v is None:
            return 9999
        return int(v)
    except Exception:
        return 9999


def _collect_evidence(
    graph: Graph,
    cpe_uri: str,
    relaxed: bool,
) -> Dict[str, Dict[str, Any]]:
    """Возвращает словарь по технике: {tech_id: {technique, cves[], cwes[], capecs[]}}.

    Источники путей:
      - 0 CAPEC: (t)-[:TECHNIQUE_TO_CWE]->(w)-[:CWE_TO_CVE]->(cve)-[:AFFECTS]->(cpe)
      - 1..2 CAPEC: (cap1)-[:CAPEC_TO_TECHNIQUE]->(t), (cap2)-[:CAPEC_TO_CWE]->(w),
                    cap1 = cap2 ИЛИ (cap1)-[:CAPEC_PARENT_TO_CAPEC_CHILD]-(cap2) при relaxed,
                    далее (w)-[:CWE_TO_CVE]->(cve)-[:AFFECTS]->(cpe)
    """

    # Прямые связи Technique -> CWE -> CVE -> CPE (0 CAPEC)
    q_direct = (
        """
        MATCH (cpe:CPE {cpe23Uri: $cpe})
        MATCH (cve:CVE)-[:AFFECTS]->(cpe)
        MATCH (w:CWE)-[:CWE_TO_CVE]->(cve)
        MATCH (t:Technique)-[:TECHNIQUE_TO_CWE]->(w)
        RETURN DISTINCT t, cve, w
        """
    )
    # Через CAPEC, допускаем cap1=cap2 (1 CAPEC) и при relaxed одну связь parent<->child (2 CAPEC)
    q_capec = (
        """
        MATCH (cpe:CPE {cpe23Uri: $cpe})
        MATCH (cve:CVE)-[:AFFECTS]->(cpe)
        MATCH (w:CWE)-[:CWE_TO_CVE]->(cve)
        MATCH (cap2:CAPEC)-[:CAPEC_TO_CWE]->(w)
        MATCH (cap1:CAPEC)-[:CAPEC_TO_TECHNIQUE]->(t:Technique)
        WHERE cap1 = cap2 OR ($relaxed AND (cap1)-[:CAPEC_PARENT_TO_CAPEC_CHILD]-(cap2))
        RETURN DISTINCT t, cve, w, cap1, cap2
        """
    )

    entries: Dict[str, Dict[str, Any]] = {}

    # helper to upsert evidence per technique
    def add_evidence(t, cve=None, w=None, caps: Optional[List] = None):
        if t is None:
            return
        tj = _node_to_json(t)
        tid = tj.get("id")
        if not tid:
            return
        rec = entries.get(tid)
        if rec is None:
            rec = {
                "technique": tj,
                "cves": [],
                "cwes": [],
                "capecs": [],
            }
            entries[tid] = rec
        if cve is not None:
            cv = _node_to_json(cve)
            if cv and cv not in rec["cves"]:
                rec["cves"].append(cv)
        if w is not None:
            wj = _node_to_json(w)
            if wj and wj not in rec["cwes"]:
                rec["cwes"].append(wj)
        for cap in (caps or []):
            cj = _node_to_json(cap)
            if cj and cj not in rec["capecs"]:
                rec["capecs"].append(cj)

    # Выполняем прямой запрос
    for row in graph.run(q_direct, cpe=cpe_uri):
        t = row.get("t") if hasattr(row, "get") else row[0]
        cve = row.get("cve") if hasattr(row, "get") else row[1]
        w = row.get("w") if hasattr(row, "get") else row[2]
        add_evidence(t, cve=cve, w=w, caps=[])

    # Через CAPEC
    for row in graph.run(q_capec, cpe=cpe_uri, relaxed=bool(relaxed)):
        t = row.get("t") if hasattr(row, "get") else row[0]
        cve = row.get("cve") if hasattr(row, "get") else row[1]
        w = row.get("w") if hasattr(row, "get") else row[2]
        cap1 = row.get("cap1") if hasattr(row, "get") else row[3]
        cap2 = row.get("cap2") if hasattr(row, "get") else row[4]
        caps = []
        if cap1 is not None:
            caps.append(cap1)
        if cap2 is not None and cap2 is not cap1:
            caps.append(cap2)
        add_evidence(t, cve=cve, w=w, caps=caps)

    # Удаляем техники без CVE (нет доказательной базы для данного CPE)
    for tid in list(entries.keys()):
        if not entries[tid]["cves"]:
            entries.pop(tid, None)

    return entries


def generate_scenarios(
    graph: Graph,
    cpe_uri: str,
    mode: Literal["strict", "relaxed"] = "strict",
    max_per_tactic: int = 3,
    max_scenarios: Optional[int] = None,
) -> Dict[str, Any]:
    relaxed = mode == "relaxed"
    max_scen = int(MAX_SCENARIOS if max_scenarios is None else max_scenarios)

    evidence = _collect_evidence(graph, cpe_uri=cpe_uri, relaxed=relaxed)

    # Группируем техники по тактикам
    buckets: List[Tuple[int, str, List[Dict[str, Any]]]] = []
    # temp map: (order, tactic) -> list
    tmp: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}

    for tid, rec in evidence.items():
        tech = rec["technique"]
        props = tech.get("props", {})
        tactic_order = _ensure_order(props.get("tactic_order"))
        primary_tactic = (props.get("primary_tactic") or "?")
        # вес шага — максимальный базовый CVSS среди связанных CVE
        weight = _max_base_cvss_from_cves(rec["cves"]) if rec.get("cves") else 0.0
        step = {
            "tactic_order": tactic_order,
            "tactic": primary_tactic,
            "technique": tech,
            "cves": rec["cves"],
            "cwes": rec["cwes"],
            "capecs": rec["capecs"],
            "weight": weight,
        }
        tmp.setdefault((tactic_order, primary_tactic), []).append(step)

    # Сортируем внутри тактики по весу, ограничиваем max_per_tactic
    for (order, tactic), items in tmp.items():
        items.sort(key=lambda x: (-(x.get("weight") or 0.0), x["technique"]["props"].get("identifier", "")))
        if isinstance(max_per_tactic, int) and max_per_tactic > 0:
            items = items[:max_per_tactic]
        buckets.append((order, tactic, items))

    # Сортировка тактик по порядку
    buckets.sort(key=lambda x: x[0])

    # Мега-сценарий для UI (все кандидаты по тактикам)
    mega = [
        {
            "tactic_order": order,
            "tactic": tactic,
            "techniques": items,
        }
        for (order, tactic, items) in buckets
        if items
    ]

    # Генерация последовательностей: одна техника на тактику, beam-ограничение
    scenarios: List[Dict[str, Any]] = []
    current: List[Tuple[float, List[Dict[str, Any]]]] = [(0.0, [])]
    for _, _, items in buckets:
        if not items:
            continue
        nxt: List[Tuple[float, List[Dict[str, Any]]]] = []
        for score, seq in current:
            for step in items:
                nxt.append((score + float(step.get("weight") or 0.0), seq + [step]))
        # Оставляем топ по суммарному весу, чтобы не разрасталось
        nxt.sort(key=lambda x: -x[0])
        if len(nxt) > max_scen:
            nxt = nxt[:max_scen]
        current = nxt

    for idx, (score, seq) in enumerate(current, start=1):
        scenarios.append(
            {
                "id": f"S{idx}",
                "score": score,
                "steps": seq,
            }
        )

    return {
        "cpe": cpe_uri,
        "mode": mode,
        "max_per_tactic": max_per_tactic,
        "max_scenarios": max_scen,
        "mega": mega,
        "scenarios": scenarios,
    }
