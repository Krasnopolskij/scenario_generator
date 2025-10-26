import os
import sys
import re
import gzip
import json
import time
import datetime as dt
from typing import List, Dict, Optional, Tuple
import requests
from py2neo import Graph
from tqdm import tqdm

NVD_BASE = os.getenv("NVD_FEED_BASE", "https://nvd.nist.gov/feeds/json/cve/2.0")
DEFAULT_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# EPSS
def _fetch_epss_batch(base_url: str, cve_batch: List[str]) -> Dict[str, Dict[str, Optional[float]]]:
    params = {"cve": ",".join(cve_batch)}
    try:
        response = requests.get(base_url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json().get("data", [])
        return {
            item["cve"]: {
                "epss": float(item["epss"]) if item.get("epss") else None,
            }
            for item in data
        }
    except Exception:
        return {cve: {"epss": None} for cve in cve_batch}


def get_epss_scores(cve_list: List[str]) -> Dict[str, Dict[str, Optional[float]]]:
    base_url = "https://api.first.org/data/v1/epss"
    results: Dict[str, Dict[str, Optional[float]]] = {}
    batch: List[str] = []
    batch_chars = 0
    for cve in cve_list:
        cve_len = len(cve) + 1
        if batch_chars + cve_len > 2000:
            if batch:
                results.update(_fetch_epss_batch(base_url, batch))
            batch = []
            batch_chars = 0
        batch.append(cve)
        batch_chars += cve_len
    if batch:
        results.update(_fetch_epss_batch(base_url, batch))
    return results


# Разложение CVSS на C/I/A
from itertools import permutations


def calculate_separate_scores(version: str, vector_string: str, base_score: float) -> Dict[str, float]:
    def calculate_cvss2_scores(vector):
        CVSS_LEVEL_MAP = {"N": 0, "P": 0.276, "C": 0.684}
        AV_MAP = {"N": 1.0, "A": 0.7, "L": 0.3}
        AC_MAP = {"L": 0.7, "M": 0.6, "H": 0.5}
        AU_MAP = {"N": 0.75, "S": 0.45, "M": 0.35}

        def calculate_impact(C, I, A):
            return 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))

        def calculate_exploitability(AV, AC, AU):
            return 20 * AV * AC * AU

        def calculate_base_score(impact, exploitability):
            if impact == 0:
                return 0.0
            return min((0.6 * impact + 0.4 * exploitability) * 1.176 - 1.5, 10.0)

        def shapley_impact_contribution(C, I, A):
            metrics = ["C", "I", "A"]
            perms = list(permutations(metrics))
            contributions = {"C": 0.0, "I": 0.0, "A": 0.0}
            for perm in perms:
                coalition = {"C": 0.0, "I": 0.0, "A": 0.0}
                for metric in perm:
                    impact_no = calculate_impact(**coalition)
                    coalition_with_metric = coalition.copy()
                    coalition_with_metric[metric] = locals()[metric]
                    impact_with = calculate_impact(**coalition_with_metric)
                    contributions[metric] += (impact_with - impact_no)
                    coalition = coalition_with_metric
            for metric in contributions:
                contributions[metric] /= len(perms)
            return contributions

        # Разбор вектора
        parts = vector.split("/")
        metric_dict = {}
        for part in parts:
            if ":" in part:
                k, v = part.split(":")
                metric_dict[k] = v
        C = CVSS_LEVEL_MAP.get(metric_dict.get("C", "N"), 0)
        I = CVSS_LEVEL_MAP.get(metric_dict.get("I", "N"), 0)
        A = CVSS_LEVEL_MAP.get(metric_dict.get("A", "N"), 0)
        AV = AV_MAP.get(metric_dict.get("AV", "L"), 0.3)
        AC = AC_MAP.get(metric_dict.get("AC", "M"), 0.6)
        AU = AU_MAP.get(metric_dict.get("Au", "N"), 0.75)

        contrib = shapley_impact_contribution(C, I, A)
        impact = calculate_impact(C, I, A)
        exploitability = calculate_exploitability(AV, AC, AU)
        base = calculate_base_score(impact, exploitability)

        total = contrib["C"] + contrib["I"] + contrib["A"]
        if total == 0:
            return {"Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0}
        return {
            "Contribution_C": round(base * contrib["C"] / total, 2),
            "Contribution_I": round(base * contrib["I"] / total, 2),
            "Contribution_A": round(base * contrib["A"] / total, 2),
        }

    def calculate_cvss3_scores(vector):
        CVSS_LEVEL_MAP = {"N": 0, "L": 0.22, "H": 0.56}
        AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        AC_MAP = {"L": 0.77, "H": 0.44}
        PR_MAP = {"N": 0.85, "L": {"U": 0.62, "C": 0.27}, "H": {"U": 0.27, "C": 0.20}}
        UI_MAP = {"N": 0.85, "R": 0.62}

        def calculate_impact(C, I, A, scope="U"):
            impact_score = 1 - (1 - C) * (1 - I) * (1 - A)
            if scope == "U":
                return 6.42 * impact_score
            return 7.52 * (impact_score - 0.029) - 3.25 * (impact_score - 0.02) ** 15

        def calculate_exploitability(AV, AC, PR, UI):
            return 8.22 * AV * AC * PR * UI

        def calculate_base_score(impact, exploitability):
            if impact == 0:
                return 0.0
            return min(impact + exploitability, 10.0)

        def shapley_impact_contribution(C, I, A, scope="U"):
            metrics = ["C", "I", "A"]
            perms = list(permutations(metrics))
            contributions = {"C": 0.0, "I": 0.0, "A": 0.0}
            for perm in perms:
                coalition = {"C": 0.0, "I": 0.0, "A": 0.0}
                for metric in perm:
                    impact_no = calculate_impact(**coalition, scope=scope)
                    coalition_with_metric = coalition.copy()
                    coalition_with_metric[metric] = locals()[metric]
                    impact_with = calculate_impact(**coalition_with_metric, scope=scope)
                    contributions[metric] += (impact_with - impact_no)
                    coalition = coalition_with_metric
            for metric in contributions:
                contributions[metric] /= len(perms)
            return contributions

        parts = vector.split("/")
        metric_dict = {}
        for part in parts:
            if ":" in part:
                k, v = part.split(":")
                metric_dict[k] = v
        C = CVSS_LEVEL_MAP.get(metric_dict.get("C", "N"), 0)
        I = CVSS_LEVEL_MAP.get(metric_dict.get("I", "N"), 0)
        A = CVSS_LEVEL_MAP.get(metric_dict.get("A", "N"), 0)
        scope = metric_dict.get("S", "U")
        AV = AV_MAP.get(metric_dict.get("AV", "L"), 0.55)
        AC = AC_MAP.get(metric_dict.get("AC", "L"), 0.77)
        UI = UI_MAP.get(metric_dict.get("UI", "N"), 0.85)
        pr_val = metric_dict.get("PR", "N")
        PR = PR_MAP[pr_val] if pr_val == "N" else PR_MAP[pr_val][scope]

        contrib = shapley_impact_contribution(C, I, A, scope=scope)
        impact = calculate_impact(C, I, A, scope=scope)
        exploitability = calculate_exploitability(AV, AC, PR, UI)
        base = calculate_base_score(impact, exploitability)

        total = contrib["C"] + contrib["I"] + contrib["A"]
        if total == 0:
            return {"Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0}
        return {
            "Contribution_C": round(base * contrib["C"] / total, 1),
            "Contribution_I": round(base * contrib["I"] / total, 1),
            "Contribution_A": round(base * contrib["A"] / total, 1),
        }

    def calculate_cvss4_scores(vector, base_score):
        CVSS_LEVEL_MAP = {"N": 0, "L": 1, "H": 2}
        if not vector.startswith("CVSS:4.0/"):
            return {"Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0}
        parts = vector.split("/")
        metric_dict = {}
        for part in parts[1:]:
            if ":" in part:
                k, v = part.split(":")
                metric_dict[k] = v
        C = CVSS_LEVEL_MAP.get(metric_dict.get("VC", "N"), 0)
        I = CVSS_LEVEL_MAP.get(metric_dict.get("VI", "N"), 0)
        A = CVSS_LEVEL_MAP.get(metric_dict.get("VA", "N"), 0)
        total = C + I + A
        if total == 0:
            return {"Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0}
        return {
            "Contribution_C": round(base_score * C / total, 2),
            "Contribution_I": round(base_score * I / total, 2),
            "Contribution_A": round(base_score * A / total, 2),
        }

    if version.startswith("2."):
        return calculate_cvss2_scores(vector_string)
    if version in ["3.0", "3.1"]:
        return calculate_cvss3_scores(vector_string)
    if version == "4.0":
        return calculate_cvss4_scores(vector_string, base_score)
    # Неизвестная версия CVSS -> нули
    return {"Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0}


# Вспомогательные функции разбора NVD
def best_cvss_vector_and_base(metrics: dict) -> Tuple[str, float, str]:
    if not metrics:
        return "", 0.0, ""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key)
        if arr:
            data = arr[0]
            if "cvssData" in data:
                base = float(data["cvssData"].get("baseScore", 0.0))
                vec = data["cvssData"].get("vectorString", "")
                ver = data["cvssData"].get("version", ver)
            else:
                base = float(data.get("baseScore", 0.0))
                vec = data.get("vectorString", "")
            return vec, base, ver
    return "", 0.0, ""


def extract_from_vuln(vuln: dict):
    cve = vuln.get("cve", {})
    cve_id = cve.get("id")
    published = cve.get("published")
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

    # Ссылки: патчи вендора/сторонние
    patch_vendor = None
    patch_third_party = None
    for ref in cve.get("references") or []:
        tags = ref.get("tags", [])
        if "Patch" in tags:
            if "Vendor Advisory" in tags:
                patch_vendor = ref.get("url")
            elif "Third Party Advisory" in tags:
                patch_third_party = ref.get("url")

    # Метрики -> CVSS‑вектор и базовая оценка
    metrics = cve.get("metrics") or {}
    vector, base, version = best_cvss_vector_and_base(metrics)
    cia = calculate_separate_scores(version, vector, base) if vector else {
        "Contribution_C": 0.0, "Contribution_I": 0.0, "Contribution_A": 0.0
    }

    # Уязвимости (CWE-*)
    weaknesses: List[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description", []):
            val = d.get("value")
            if val and re.search(r"CWE-\d+", val):
                weaknesses.append(re.search(r"CWE-\d+", val).group(0))

    # CPE (связь AFFECTS)
    cpes: List[str] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                uri = m.get("criteria") or m.get("cpe23Uri")
                if uri:
                    cpes.append(uri)

    return {
        "id": cve_id,
        "description": description,
        "cvss_C_score": cia.get("Contribution_C", 0.0),
        "cvss_I_score": cia.get("Contribution_I", 0.0),
        "cvss_A_score": cia.get("Contribution_A", 0.0),
        "published": published,
        "weaknesses": list(set(weaknesses)),
        "cpes": list(set(cpes)),
        "patch_vendor": patch_vendor,
        "patch_third_party": patch_third_party,
    }


# Импорт в Neo4j
def ensure_constraints(graph: Graph):
    # Создание ограничений (новый и старый синтаксис для совместимости)
    statements_new = [
        "CREATE CONSTRAINT cve_identifier IF NOT EXISTS FOR (v:CVE) REQUIRE v.identifier IS UNIQUE",
        "CREATE CONSTRAINT cwe_identifier IF NOT EXISTS FOR (c:CWE) REQUIRE c.identifier IS UNIQUE",
        "CREATE CONSTRAINT cpe_uri IF NOT EXISTS FOR (p:CPE) REQUIRE p.cpe23Uri IS UNIQUE",
    ]
    for stmt in statements_new:
        try:
            graph.run(stmt)
        except Exception:
            pass
    statements_old = [
        "CREATE CONSTRAINT cve_identifier IF NOT EXISTS ON (v:CVE) ASSERT v.identifier IS UNIQUE",
        "CREATE CONSTRAINT cwe_identifier IF NOT EXISTS ON (c:CWE) ASSERT c.identifier IS UNIQUE",
        "CREATE CONSTRAINT cpe_uri IF NOT EXISTS ON (p:CPE) ASSERT p.cpe23Uri IS UNIQUE",
    ]
    for stmt in statements_old:
        try:
            graph.run(stmt)
        except Exception:
            pass


# Парсинг CPE 2.3
def parse_cpe23(cpe_uri: str) -> Dict[str, str]:
    """Разбор CPE 2.3 URI в поля. Сохраняем исходную строку в cpe23Uri.

    Формат: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    result = {
        "cpe23Uri": cpe_uri,
        "part": None,
        "vendor": None,
        "product": None,
        "version": None,
        "update": None,
        "edition": None,
        "language": None,
        "sw_edition": None,
        "target_sw": None,
        "target_hw": None,
        "other": None,
    }
    try:
        if not cpe_uri or not cpe_uri.startswith("cpe:2.3:"):
            return result
        parts = cpe_uri.split(":", 12)  # "cpe","2.3", then 11 полей максимум
        # Ожидаем длину >= 13
        fields = parts[2:]  # отбрасываем префикс
        # Дополняем недостающие поля пустыми строками
        while len(fields) < 11:
            fields.append("")
        # Присваиваем
        (result["part"], result["vendor"], result["product"], result["version"],
         result["update"], result["edition"], result["language"], result["sw_edition"],
         result["target_sw"], result["target_hw"], result["other"]) = fields[:11]
        # Нормализуем пустые строки в None
        for k, v in list(result.items()):
            if k == "cpe23Uri":
                continue
            if v == "":
                result[k] = None
        return result
    except Exception:
        return result


def download_feed(url: str) -> dict:
    with requests.get(url, timeout=120, stream=True, headers={"User-Agent": "nvd-unified-import/1.0"}) as r:
        r.raise_for_status()
        data = gzip.decompress(r.content)
        return json.loads(data)


def upsert_batch(graph: Graph, batch: List[dict], epss_map: Dict[str, Dict[str, Optional[float]]]):
    # Прикрепляем EPSS к элементам пакета (не фильтруем, если нет)
    for item in batch:
        cve_id = item["id"]
        item["epss"] = (epss_map.get(cve_id) or {}).get("epss")
        # Парсим CPE 2.3 поля для каждого URI
        parsed_list = []
        for uri in item.get("cpes", []):
            parsed_list.append(parse_cpe23(uri))
        item["cpes_parsed"] = parsed_list

    # Узлы CVE
    query_nodes = """
    UNWIND $cves AS c
    MERGE (v:CVE {identifier: c.id})
    ON CREATE SET
      v.description = c.description,
      v.cvss_C_score = c.cvss_C_score,
      v.cvss_I_score = c.cvss_I_score,
      v.cvss_A_score = c.cvss_A_score,
      v.epss = c.epss,
      v.published = c.published,
      v.patch_vendor = c.patch_vendor,
      v.patch_third_party = c.patch_third_party
    ON MATCH SET
      v.description = c.description,
      v.cvss_C_score = c.cvss_C_score,
      v.cvss_I_score = c.cvss_I_score,
      v.cvss_A_score = c.cvss_A_score,
      v.epss = c.epss,
      v.published = c.published,
      v.patch_vendor = c.patch_vendor,
      v.patch_third_party = c.patch_third_party
    """
    graph.run(query_nodes, cves=batch)

    # Связи CWE (CWE)-[:CWE_TO_CVE]->(CVE)
    query_cwe = """
    UNWIND $cves AS c
    MATCH (v:CVE {identifier: c.id})
    WITH v, c.weaknesses AS cwes
    UNWIND cwes AS cwe_id
    MERGE (w:CWE {identifier: cwe_id})
    MERGE (w)-[:CWE_TO_CVE]->(v)
    """
    graph.run(query_cwe, cves=batch)

    # Связи CPE: (CVE)-[:AFFECTS]->(CPE) + заполнение полей CPE
    query_cpe = """
    UNWIND $cves AS c
    MATCH (v:CVE {identifier: c.id})
    WITH v, c.cpes_parsed AS cpes
    UNWIND cpes AS cp
    MERGE (p:CPE {cpe23Uri: cp.cpe23Uri})
    ON CREATE SET
      p.part = cp.part,
      p.vendor = cp.vendor,
      p.product = cp.product,
      p.version = cp.version,
      p.update = cp.update,
      p.edition = cp.edition,
      p.language = cp.language,
      p.sw_edition = cp.sw_edition,
      p.target_sw = cp.target_sw,
      p.target_hw = cp.target_hw,
      p.other = cp.other
    ON MATCH SET
      p.part = coalesce(cp.part, p.part),
      p.vendor = coalesce(cp.vendor, p.vendor),
      p.product = coalesce(cp.product, p.product),
      p.version = coalesce(cp.version, p.version),
      p.update = coalesce(cp.update, p.update),
      p.edition = coalesce(cp.edition, p.edition),
      p.language = coalesce(cp.language, p.language),
      p.sw_edition = coalesce(cp.sw_edition, p.sw_edition),
      p.target_sw = coalesce(cp.target_sw, p.target_sw),
      p.target_hw = coalesce(cp.target_hw, p.target_hw),
      p.other = coalesce(cp.other, p.other)
    MERGE (v)-[:AFFECTS]->(p)
    """
    graph.run(query_cpe, cves=batch)


def import_year(graph: Graph, year: int, batch_size: int = 500):
    url = f"{NVD_BASE}/nvdcve-2.0-{year}.json.gz"
    print(f"[NVD] Год {year}: загрузка фида…")
    doc = download_feed(url)
    vulns = doc.get("vulnerabilities") or []
    total = len(vulns)
    print(f"[NVD] Год {year}: {total} CVE")

    batch: List[dict] = []
    batch_ids: List[str] = []
    processed = 0

    ensure_constraints(graph)

    pbar = tqdm(total=total, desc=f"NVD {year}", unit="cve", leave=True)
    for v in vulns:
        item = extract_from_vuln(v)
        if not item["id"]:
            pbar.update(1)
            continue
        batch.append(item)
        batch_ids.append(item["id"])
        if len(batch) >= batch_size:
            epss_map = get_epss_scores(batch_ids)
            upsert_batch(graph, batch, epss_map)
            processed += len(batch)
            pbar.update(len(batch))
            batch.clear()
            batch_ids.clear()
            time.sleep(0.2)

    if batch:
        epss_map = get_epss_scores(batch_ids)
        upsert_batch(graph, batch, epss_map)
        processed += len(batch)
        pbar.update(len(batch))
    if pbar.n < total:
        pbar.update(total - pbar.n)
    pbar.close()

    print(f"[OK] Год {year} импортирован")


def import_modified(graph: Graph, batch_size: int = 500):
    url = f"{NVD_BASE}/nvdcve-2.0-modified.json.gz"
    print("[NVD] Модифицированный фид: загрузка…")
    doc = download_feed(url)
    vulns = doc.get("vulnerabilities") or []
    total = len(vulns)
    print(f"[NVD] Модифицированный фид: {total} CVE")

    batch: List[dict] = []
    batch_ids: List[str] = []
    processed = 0

    ensure_constraints(graph)

    pbar = tqdm(total=total, desc="NVD modified", unit="cve", leave=True)
    for v in vulns:
        item = extract_from_vuln(v)
        if not item["id"]:
            pbar.update(1)
            continue
        batch.append(item)
        batch_ids.append(item["id"])
        if len(batch) >= batch_size:
            epss_map = get_epss_scores(batch_ids)
            upsert_batch(graph, batch, epss_map)
            processed += len(batch)
            pbar.update(len(batch))
            batch.clear()
            batch_ids.clear()
            time.sleep(0.2)

    if batch:
        epss_map = get_epss_scores(batch_ids)
        upsert_batch(graph, batch, epss_map)
        processed += len(batch)
        pbar.update(len(batch))
    if pbar.n < total:
        pbar.update(total - pbar.n)
    pbar.close()

    print("[OK] Модифицированный фид импортирован")


def update_cisa_kev(graph: Graph):
    """Обогащает CVE флагом присутствия в CISA KEV и сроком устранения.

    Использует CISA_KEV_URL из .env (или дефолтный URL). Безопасно к повторным запускам.
    """
    kev_url = os.getenv("CISA_KEV_URL", DEFAULT_CISA_KEV_URL)
    try:
        resp = requests.get(kev_url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[KEV] Ошибка загрузки KEV: {e}")
        return

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        print("[KEV] Пустой список уязвимостей")
        return

    # Собираем список CVE и dueDate
    items: List[Tuple[str, Optional[str]]] = []
    kev_ids: List[str] = []
    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        kev_ids.append(cve_id)
        items.append((cve_id, v.get("dueDate")))

    print(f"[KEV] Обновление флагов для {len(items)} CVE…")

    # Обновляем пачками
    batch_size = 500
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        graph.run(
            """
            UNWIND $rows AS r
            MATCH (v:CVE {identifier: r[0]})
            SET v.in_cisa_kev = true,
                v.cisa_kev_due_date = r[1]
            """,
            rows=batch,
        )

    # Снимаем флаг у CVE, которые ранее были помечены, но больше не в KEV
    graph.run(
        """
        MATCH (v:CVE)
        WHERE coalesce(v.in_cisa_kev,false) = true AND NOT v.identifier IN $ids
        REMOVE v.cisa_kev_due_date
        SET v.in_cisa_kev = false
        """,
        ids=kev_ids,
    )
    print("[KEV] Обновление завершено")


def load():
    try:
        # Подключение к Neo4j
        neo4j_uri = os.getenv("NEO4J_URI")
        neo4j_user = os.getenv("NEO4J_USER")
        neo4j_password = os.getenv("NEO4J_PASSWORD")
        neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
        
        if not all([neo4j_uri, neo4j_user, neo4j_password]):
            raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
        print(f"Запись в базу: {neo4j_db}")
        graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)

        # Диапазон лет
        current_year = dt.datetime.now(dt.UTC).year
        # Аккуратно парсим годы: пустые/некорректные значения игнорируем
        raw_from = (os.getenv("NVD_FROM_YEAR") or "").strip()
        raw_to = (os.getenv("NVD_TO_YEAR") or "").strip()
        try:
            from_year = int(raw_from) if raw_from else 1999
        except Exception:
            from_year = 1999
        try:
            to_year = int(raw_to) if raw_to else current_year
        except Exception:
            to_year = current_year
        batch_size = int(os.getenv("NVD_BATCH", 500))
        also_modified = os.getenv("NVD_ALSO_MODIFIED", "false").lower() in {"1", "true", "yes"}

        t0 = time.time()
        for y in range(from_year, to_year + 1):
            import_year(graph, y, batch_size=batch_size)
            time.sleep(0.3)

        if also_modified:
            import_modified(graph, batch_size=batch_size)

        # Обогащение из CISA KEV
        try:
            update_cisa_kev(graph)
        except Exception as e:
            print(f"[KEV] Ошибка обновления: {e}")

        print(f"Импорт CVE завершён за {time.time() - t0:.1f}с")
    except Exception as e:
        print(f"[CRITICAL]: {str(e)}")
        sys.exit(1)
