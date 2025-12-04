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


def enrich_cves_with_scores(cves: List[Dict[str, Any]]) -> None:
    # Добавляет epss_norm и damage в props каждого CVE шага
    if not cves:
        return
    epss_norm_values = _calc_epss_norm(cves)
    damage_values = _calc_damage(cves)

    for idx, cv in enumerate(cves):
        if cv is None:
            continue
        props = cv.setdefault("props", {})
        if idx < len(epss_norm_values):
            props["epss_norm"] = epss_norm_values[idx]
        if idx < len(damage_values):
            props["damage"] = damage_values[idx]
