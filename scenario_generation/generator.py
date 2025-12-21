from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Tuple, Set
from collections import defaultdict
from py2neo import Graph
import heapq
from scenario_generation.metrics import enrich_cves_with_scores_tactic, compute_scenario_risk

# Максимум сценариев возвращаем из API
MAX_SCENARIOS: int = 30

# Тактики ATT&CK, которые исключаем из построения сценариев
EXCLUDED_TACTICS = {
    "reconnaissance",
    "resource-development",
    "discovery",
    "command-and-control",
    "collection"
}


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


def _sum_base_cvss_from_cves(cves: List[Dict[str, Any]]) -> float:
    """Возвращает суммарный базовый CVSS по всем CVE из списка.

    Базовый CVSS CVE трактуется как сумма компонент C/I/A,
    т.к. в модели CVE хранятся отдельные вклады (cvss_C_score, cvss_I_score, cvss_A_score).
    Итоговый вес техники — сумма этих базовых значений по всем связанным CVE.
    """
    total = 0.0
    for c in cves:
        p = c.get("props") or {}
        try:
            base = float(p.get("cvss_C_score") or 0.0) \
                 + float(p.get("cvss_I_score") or 0.0) \
                 + float(p.get("cvss_A_score") or 0.0)
        except Exception:
            base = 0.0
        total += float(base)
    return total


def _ensure_order(v) -> int:
    try:
        if v is None:
            return 9999
        return int(v)
    except Exception:
        return 9999


def _norm(s: Any) -> str:
    try:
        return str(s or "").strip().lower()
    except Exception:
        return ""


def _is_target_uri(obj_uri: str) -> bool:
    try:
        return str(obj_uri or "").strip().lower().startswith("custom:")
    except Exception:
        return False


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _cve_ids(step: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set()
    try:
        for cv in step.get("cves") or []:
            props = (cv or {}).get("props") or {}
            cid = props.get("identifier") or cv.get("id")
            if cid is None:
                continue
            try:
                ids.add(str(cid))
            except Exception:
                continue
    except Exception:
        return set()
    return ids


def _select_techniques_with_limit(
    items: List[Dict[str, Any]],
    limit: int,
) -> List[Dict[str, Any]]:
    """Ограничивает число техник на тактику мягко: сохраняем покрытие всех CVE.

    - Строим минимальное покрытие всех CVE (жадно по приросту покрытых CVE).
    - Если покрывающих техник больше лимита, оставляем все из покрытия (лимит превышаем).
    - Если меньше лимита, добираем лучшие по числу CVE (а затем по идентификатору) до лимита.
    """
    if not items:
        return []
    if not isinstance(limit, int) or limit <= 0:
        return items

    cve_sets = [_cve_ids(it) for it in items]
    total_cves: Set[str] = set()
    for s in cve_sets:
        total_cves.update(s)

    # При отсутствии CVE — просто сортируем детерминированно и режем по лимиту
    if not total_cves:
        ordered = sorted(
            items,
            key=lambda x: (
                x.get("technique", {}).get("props", {}).get("identifier", ""),
            ),
        )
        return ordered[: min(limit, len(ordered))]

    # Приоритет: больше CVE на технику, затем id техники
    priority_order = sorted(
        range(len(items)),
        key=lambda idx: (
            -len(cve_sets[idx]),
            items[idx].get("technique", {}).get("props", {}).get("identifier", ""),
        ),
    )

    selected: List[int] = []
    covered: Set[str] = set()
    remaining = list(priority_order)

    # Минимальное покрытие всех CVE (жадно по наибольшему приросту)
    while remaining and covered != total_cves:
        best_pos = None
        best_gain = -1
        for pos, idx in enumerate(remaining):
            gain = len(cve_sets[idx] - covered)
            if gain > best_gain:
                best_gain = gain
                best_pos = pos
            elif gain == best_gain and best_pos is not None:
                # tie-break по общему числу CVE и идентификатору техники
                cur_idx = remaining[best_pos]
                cur_ids = cve_sets[cur_idx]
                if len(cve_sets[idx]) > len(cur_ids):
                    best_pos = pos
                elif len(cve_sets[idx]) == len(cur_ids):
                    id_cur = items[cur_idx].get("technique", {}).get("props", {}).get("identifier", "")
                    id_new = items[idx].get("technique", {}).get("props", {}).get("identifier", "")
                    if id_new < id_cur:
                        best_pos = pos
        if best_pos is None:
            break
        chosen_idx = remaining.pop(best_pos)
        selected.append(chosen_idx)
        covered |= cve_sets[chosen_idx]

    # Если покрытия меньше лимита — добираем лучшие по приоритету до лимита
    target = min(limit, len(items))
    if len(selected) < target:
        for idx in remaining:
            selected.append(idx)
            if len(selected) >= target:
                break

    # Если покрытие требует больше лимита — оставляем как есть (превышаем лимит)
    ordered_selected = sorted(
        selected,
        key=lambda idx: (
            -len(cve_sets[idx]),
            items[idx].get("technique", {}).get("props", {}).get("identifier", ""),
        ),
    )
    return [items[i] for i in ordered_selected]


def _collect_evidence(
    graph: Graph,
    obj_uri: str,
    relaxed: bool,
    use_gnn: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """Возвращает словарь по технике: {tech_id: {technique, cves[], cwes[], capecs[]}}.

    Источники путей:
      - 0 CAPEC: (t)-[:TECHNIQUE_TO_CWE]->(w)-[:CWE_TO_CVE]->(cve)-[:AFFECTS]->(cpe)
      - 1..2 CAPEC: (cap1)-[:CAPEC_TO_TECHNIQUE]->(t), (cap2)-[:CAPEC_TO_CWE]->(w),
                    cap1 = cap2 ИЛИ (cap1)-[:CAPEC_PARENT_TO_CAPEC_CHILD]-(cap2) при relaxed,
                    далее (w)-[:CWE_TO_CVE]->(cve)-[:AFFECTS]->(cpe)

    При use_gnn = True дополнительно учитываются предсказанные связи
    CAPEC_TO_TECHNIQUE_PRED (как CAPEC_TO_TECHNIQUE), при этом логика strict/relaxed
    остаётся прежней.
    """

    is_target = _is_target_uri(obj_uri)
    node_label = "Target" if is_target else "CPE"
    node_prop = "targetUri" if is_target else "cpe23Uri"

    # Прямые связи Technique -> CWE -> CVE -> объект (0 CAPEC)
    q_direct = (
        f"""
        MATCH (obj:{node_label} {{{node_prop}: $obj}})
        MATCH (cve:CVE)-[:AFFECTS]->(obj)
        MATCH (w:CWE)-[:CWE_TO_CVE]->(cve)
        MATCH (t:Technique)-[:TECHNIQUE_TO_CWE]->(w)
        RETURN DISTINCT t, cve, w
        """
    )
    # Через CAPEC, допускаем cap1=cap2 (1 CAPEC) и при relaxed одну связь parent<->child (2 CAPEC).
    # При включённом use_gnn добавляем CAPEC_TO_TECHNIQUE_PRED как альтернативу CAPEC_TO_TECHNIQUE.
    capec_to_tech_rel = "CAPEC_TO_TECHNIQUE|CAPEC_TO_TECHNIQUE_PRED" if use_gnn else "CAPEC_TO_TECHNIQUE"
    q_capec = (
        f"""
        MATCH (obj:{node_label} {{{node_prop}: $obj}})
        MATCH (cve:CVE)-[:AFFECTS]->(obj)
        MATCH (w:CWE)-[:CWE_TO_CVE]->(cve)
        MATCH (cap2:CAPEC)-[:CAPEC_TO_CWE]->(w)
        MATCH (cap1:CAPEC)-[:{capec_to_tech_rel}]->(t:Technique)
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
    for row in graph.run(q_direct, obj=obj_uri):
        t = row.get("t") if hasattr(row, "get") else row[0]
        cve = row.get("cve") if hasattr(row, "get") else row[1]
        w = row.get("w") if hasattr(row, "get") else row[2]
        add_evidence(t, cve=cve, w=w, caps=[])

    # Через CAPEC
    for row in graph.run(q_capec, obj=obj_uri, relaxed=bool(relaxed)):
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


def _build_candidate_buckets(
    buckets: List[Tuple[int, str, List[Dict[str, Any]]]],
    max_ratio_by_tactic: Dict[str, float],
) -> Tuple[List[Tuple[int, str, List[Dict[str, Any]]]], float]:
    """Готовит списки кандидатов (техника + один CVE) по каждой тактике и считает сумму max_ratio."""
    candidate_buckets: List[Tuple[int, str, List[Dict[str, Any]]]] = []
    tactics_in_use: Set[str] = set()

    for order, tactic, items in buckets:
        candidates: List[Dict[str, Any]] = []
        tactic_max_ratio = _safe_float(max_ratio_by_tactic.get(tactic, 0.0))
        for step in items:
            tech = step.get("technique")
            cwes = step.get("cwes") or []
            capecs = step.get("capecs") or []
            for cv in step.get("cves") or []:
                props = (cv or {}).get("props") or {}
                epss_norm = _safe_float(props.get("epss_norm"))
                ratio = _safe_float(props.get("cvss_epss_ratio"))
                if ratio <= 0:
                    epss = _safe_float(props.get("epss"))
                    cvss = _safe_float(props.get("cvss"))
                    ratio = (cvss / epss) if epss > 0 else 0.0
                candidates.append(
                    {
                        "tactic_order": order,
                        "tactic": tactic,
                        "technique": tech,
                        "cves": [cv],
                        "cwes": cwes,
                        "capecs": capecs,
                        "epss_norm": epss_norm,
                        "ratio": ratio,
                        "max_ratio": tactic_max_ratio,
                    }
                )
        if candidates:
            # Сортировка для детерминизма: surrogate по epss_norm * ratio, затем техника и CVE
            candidates.sort(
                key=lambda x: (
                    -(x.get("epss_norm") or 0.0) * (x.get("ratio") or 0.0),
                    x.get("technique", {}).get("props", {}).get("identifier", ""),
                    ((x.get("cves") or [{}])[0].get("props") or {}).get("identifier", ""),
                )
            )
            candidate_buckets.append((order, tactic, candidates))
            tactics_in_use.add(tactic)

    # Обеспечиваем порядок тактик
    candidate_buckets.sort(key=lambda x: x[0])
    sum_max_ratio = 0.0
    for tac in tactics_in_use:
        sum_max_ratio += _safe_float(max_ratio_by_tactic.get(tac, 0.0))
    return candidate_buckets, sum_max_ratio


def _make_steps_from_indices(
    buckets: List[Tuple[int, str, List[Dict[str, Any]]]],
    idx: Tuple[int, ...],
) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for bpos, choice in enumerate(idx):
        _, _, items = buckets[bpos]
        if 0 <= choice < len(items):
            steps.append(items[choice])
    return steps


def _k_best_scenarios(
    candidate_buckets: List[Tuple[int, str, List[Dict[str, Any]]]],
    max_results: int,
    max_ratio_by_tactic: Dict[str, float],
    sum_max_ratio: float,
) -> List[Dict[str, Any]]:
    if not candidate_buckets:
        return []

    total_buckets = len(candidate_buckets)
    start_idx: Tuple[int, ...] = tuple(0 for _ in range(total_buckets))
    start_steps = _make_steps_from_indices(candidate_buckets, start_idx)
    start_metrics = compute_scenario_risk(start_steps, max_ratio_by_tactic, sum_max_ratio)

    heap: List[Tuple[float, Tuple[int, ...], Dict[str, float]]] = []
    heapq.heappush(heap, (-start_metrics["risk"], start_idx, start_metrics))
    visited = {start_idx}

    scenarios: List[Dict[str, Any]] = []
    while heap and len(scenarios) < max_results:
        neg_risk, indices, metrics = heapq.heappop(heap)
        steps = _make_steps_from_indices(candidate_buckets, indices)
        scenarios.append(
            {
                "id": f"S{len(scenarios) + 1}",
                "score": metrics.get("risk", 0.0),
                "risk": metrics.get("risk", 0.0),
                "probability": metrics.get("probability", 0.0),
                "impact": metrics.get("impact", 0.0),
                "steps": steps,
            }
        )

        for bpos in range(total_buckets):
            next_idx = list(indices)
            next_idx[bpos] += 1
            if next_idx[bpos] >= len(candidate_buckets[bpos][2]):
                continue
            next_key = tuple(next_idx)
            if next_key in visited:
                continue

            next_steps = _make_steps_from_indices(candidate_buckets, next_key)
            next_metrics = compute_scenario_risk(next_steps, max_ratio_by_tactic, sum_max_ratio)
            heapq.heappush(heap, (-next_metrics["risk"], next_key, next_metrics))
            visited.add(next_key)

    return scenarios


def generate_scenarios(
    graph: Graph,
    obj_uri: str,
    mode: Literal["strict", "relaxed", "gnn"] = "strict",
    max_per_tactic: int = 3,
    max_scenarios: Optional[int] = None,
) -> Dict[str, Any]:
    relaxed = mode == "relaxed"
    max_scen = int(MAX_SCENARIOS if max_scenarios is None else max_scenarios)

    use_gnn = mode == "gnn"
    evidence = _collect_evidence(graph, obj_uri=obj_uri, relaxed=relaxed, use_gnn=use_gnn)

    # Группируем техники по тактикам
    buckets: List[Tuple[int, str, List[Dict[str, Any]]]] = []
    # temp map: (order, tactic) -> list
    tmp: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
    tactic_cves: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    # Сначала собираем CVE в разрезе тактик, исключая ненужные
    for rec in evidence.values():
        tech = rec.get("technique") or {}
        props = tech.get("props", {})
        primary_tactic = (props.get("primary_tactic") or "?")
        if _norm(primary_tactic) in EXCLUDED_TACTICS:
            continue
        tactic_cves[primary_tactic].extend(rec.get("cves") or [])

    # Считаем метрики по полной группе CVE каждой тактики и запоминаем max_ratio для знаменателя ущерба
    max_ratio_by_tactic: Dict[str, float] = {}
    for tactic_name, cves in tactic_cves.items():
        max_ratio = enrich_cves_with_scores_tactic(cves)
        max_ratio_by_tactic[tactic_name] = _safe_float(max_ratio)

    for tid, rec in evidence.items():
        tech = rec["technique"]
        props = tech.get("props", {})
        tactic_order = _ensure_order(props.get("tactic_order"))
        primary_tactic = (props.get("primary_tactic") or "?")
        if _norm(primary_tactic) in EXCLUDED_TACTICS:
            continue
        step = {
            "tactic_order": tactic_order,
            "tactic": primary_tactic,
            "technique": tech,
            "cves": rec["cves"],
            "cwes": rec["cwes"],
            "capecs": rec["capecs"],
        }
        tmp.setdefault((tactic_order, primary_tactic), []).append(step)

    # Сортируем внутри тактики детерминированно по идентификатору техники
    for (order, tactic), items in tmp.items():
        limited_items = _select_techniques_with_limit(items, int(max_per_tactic))
        buckets.append((order, tactic, limited_items))

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

    # Подготовка кандидатов (одна техника + один CVE) по каждой тактике
    candidate_buckets, sum_max_ratio = _build_candidate_buckets(buckets, max_ratio_by_tactic)
    scenarios = _k_best_scenarios(candidate_buckets, max_scen, max_ratio_by_tactic, sum_max_ratio)

    # Дополнительно ранжируем по риску, чтобы гарантировать корректный порядок даже при equal-score кейсах.
    scenarios.sort(
        key=lambda s: (
            -_safe_float(s.get("risk")),
            -_safe_float(s.get("impact")),
            -_safe_float(s.get("probability")),
            s.get("id", ""),
        )
    )
    for idx, scen in enumerate(scenarios):
        scen["id"] = f"S{idx + 1}"

    return {
        "cpe": obj_uri,
        "mode": mode,
        "max_per_tactic": max_per_tactic,
        "max_scenarios": max_scen,
        "mega": mega,
        "scenarios": scenarios,
    }
