from __future__ import annotations

from typing import Any, Dict, List


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


def _calc_damage(cves: List[Dict[str, Any]]) -> List[float]:
    # Считает damage по формуле cvss/epss с нормировкой на максимум
    ratios: List[float] = []
    for cv in cves or []:
        props = (cv or {}).get("props") or {}
        epss = _safe_float(props.get("epss"))
        base_cvss = _safe_float(props.get("cvss"))
        if epss <= 0:
            ratios.append(0.0)
            continue
        ratios.append(base_cvss / epss)

    if not ratios:
        return []

    max_ratio = max(ratios)
    if max_ratio <= 0:
        return [0.0 for _ in ratios]
    return [r / max_ratio for r in ratios]


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


def _calc_scores_map(cves: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    # Считает epss_norm damage и risk для уникальных CVE
    unique = _unique_cves_by_key(cves)
    if not unique:
        return {}

    epss_norm_values = _calc_epss_norm(unique)
    damage_values = _calc_damage(unique)
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
        }
    return scores


def enrich_cves_with_scores_tactic(cves: List[Dict[str, Any]]) -> None:
    # Добавляет epss_norm damage и risk в props по полной группе CVE тактики
    scores = _calc_scores_map(cves)
    if not scores:
        return

    for cv in cves or []:
        key = _cve_key(cv)
        if not key or key not in scores:
            continue
        props = cv.setdefault("props", {})
        props["epss_norm"] = scores[key]["epss_norm"]
        props["damage"] = scores[key]["damage"]
        props["risk"] = scores[key]["risk"]
