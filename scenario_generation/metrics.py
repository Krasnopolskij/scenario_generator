from __future__ import annotations
from typing import Any, Dict, List, Tuple

EPSS_EFF_TRESHHOLD = 1e-3

def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _epss_list(cves: List[Dict[str, Any]]) -> List[float]:
    # Возвращает список EPSS по каждому CVE в шаге
    values: List[float] = []
    for cv in cves or []:
        props = (cv or {}).get("props") or {}
        values.append(_safe_float(props.get("epss")))
    return values


def _calc_epss_norm(cves: List[Dict[str, Any]]) -> List[float]:
    # Считает epss_norm по формуле полной группы событий
    epss_values = _epss_list(cves)
    if not epss_values:
        return []

    p_values: List[float] = []
    for idx, epss_i in enumerate(epss_values):
        prod = 1.0
        for j, epss_j in enumerate(epss_values):
            if j == idx:
                continue
            prod *= (1.0 - epss_j)
        p_values.append(epss_i * prod)

    total = sum(p_values)
    if total <= 0:
        # Равномерное распределение если сумма нулевая
        uniform = 1.0 / len(p_values)
        return [uniform for _ in p_values]
    return [p / total for p in p_values]


# def _calc_damage(cves: List[Dict[str, Any]]) -> List[float]:
#     # Считает damage по формуле cvss/epss с нормировкой на максимум
#     ratios, max_ratio = _calc_ratios(cves)
#     if not ratios:
#         return []
#     if max_ratio <= 0:
#         return [0.0 for _ in ratios]
#     return [r / max_ratio for r in ratios]


def _cve_key(cv: Dict[str, Any]) -> str:
    props = (cv or {}).get("props") or {}
    ident = props.get("identifier") or cv.get("id")
    if ident is None:
        return ""
    try:
        return str(ident)
    except Exception:
        return ""


def _unique_cves_by_key(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique: List[Dict[str, Any]] = []
    for cv in cves or []:
        key = _cve_key(cv)
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(cv)
    return unique


def _calc_ratios(cves: List[Dict[str, Any]]) -> Tuple[List[float], float]:
    ratios: List[float] = []
    for cv in cves or []:
        props = (cv or {}).get("props") or {}
        epss = _safe_float(props.get("epss"))
        base_cvss = _safe_float(props.get("cvss"))

        epss_eff = max(epss, EPSS_EFF_TRESHHOLD)
        # if epss <= 0:
        #     ratios.append(0.0)
        #     continue
        ratios.append(base_cvss / epss_eff)

    max_ratio = max(ratios) if ratios else 0.0
    return ratios, max_ratio


def _calc_scores_map(cves: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, float]], float]:
    # Считает epss_norm, damage, risk и ratio для уникальных CVE, возвращает также max_ratio тактики
    unique = _unique_cves_by_key(cves)
    if not unique:
        return {}, 0.0

    epss_norm_values = _calc_epss_norm(unique)
    ratio_values, max_ratio = _calc_ratios(unique)
    if max_ratio <= 0:
        damage_values = [0.0 for _ in ratio_values]
    else:
        damage_values = [r / max_ratio for r in ratio_values]
    risk_values: List[float] = []
    if epss_norm_values and damage_values:
        for idx in range(len(unique)):
            e = epss_norm_values[idx] if idx < len(epss_norm_values) else 0.0
            d = damage_values[idx] if idx < len(damage_values) else 0.0
            risk_values.append(e * d)

    scores: Dict[str, Dict[str, float]] = {}
    for idx, cv in enumerate(unique):
        key = _cve_key(cv)
        if not key:
            continue
        scores[key] = {
            "epss_norm": epss_norm_values[idx] if idx < len(epss_norm_values) else 0.0,
            "damage": damage_values[idx] if idx < len(damage_values) else 0.0,
            "risk": risk_values[idx] if idx < len(risk_values) else 0.0,
            "ratio": ratio_values[idx] if idx < len(ratio_values) else 0.0,
            "max_ratio": max_ratio,
        }
    return scores, max_ratio


def enrich_cves_with_scores_tactic(cves: List[Dict[str, Any]]) -> float:
    # Добавляет epss_norm, damage, risk, ratio и max_ratio в props по полной группе CVE тактики.
    # Возвращает max_ratio для этой тактики.
    scores, max_ratio = _calc_scores_map(cves)
    if not scores:
        return 0.0

    for cv in cves or []:
        key = _cve_key(cv)
        if not key or key not in scores:
            continue
        props = cv.setdefault("props", {})
        props["epss_norm"] = scores[key]["epss_norm"]
        props["damage"] = scores[key]["damage"]
        props["risk"] = scores[key]["risk"]
        props["cvss_epss_ratio"] = scores[key]["ratio"]
        props["cvss_epss_max_ratio"] = scores[key]["max_ratio"]
    return max_ratio


def compute_scenario_risk(
    steps: List[Dict[str, Any]],
    max_ratio_by_tactic: Dict[str, float],
    sum_max_ratio: float | None = None,
) -> Dict[str, float]:
    """Возвращает метрики сценария: risk, probability (произведение epss_norm), impact (Ū_s).

    steps: список шагов сценария, каждый содержит tactic и единственный CVE в steps[*].cves[0].
    max_ratio_by_tactic: заранее посчитанный максимум cvss/epss по каждой тактике.
    sum_max_ratio: предвычисленный знаменатель (сумма максимумов по всем учтённым тактикам); если не задан,
                   берётся из max_ratio_by_tactic только для встреченных в steps тактик.
    """
    if not steps:
        return {"risk": 0.0, "probability": 0.0, "impact": 0.0}

    denom = sum_max_ratio
    if denom is None:
        denom = 0.0
        for st in steps:
            tac = (st or {}).get("tactic")
            denom += _safe_float(max_ratio_by_tactic.get(tac, 0.0))

    ratio_sum = 0.0
    prob_prod = 1.0
    for st in steps:
        cve = None
        try:
            cves = (st or {}).get("cves") or []
            if cves:
                cve = cves[0]
        except Exception:
            cve = None
        props = (cve or {}).get("props") or {}
        epss_norm = _safe_float(props.get("epss_norm"))
        prob_prod *= epss_norm

        ratio = _safe_float(props.get("cvss_epss_ratio"))
        if ratio <= 0:
            epss = _safe_float(props.get("epss"))
            epss_eff = max(epss, EPSS_EFF_TRESHHOLD)
            cvss = _safe_float(props.get("cvss"))
            ratio = (cvss / epss_eff) #if epss > 0 else 0.0
        ratio_sum += ratio

    impact = (ratio_sum / denom) if denom and denom > 0 else 0.0
    risk = prob_prod * impact
    return {"risk": risk, "probability": prob_prod, "impact": impact}
