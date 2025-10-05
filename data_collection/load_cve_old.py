import re
import os
import time
from itertools import permutations
from threading import Lock
from py2neo import Graph
from datetime import timedelta
import queue
import threading

from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

# Конфигурация (переопределяется через .env)
CACHE_FILE = os.getenv("NVD_CACHE_FILE", "nvd_cache.json")
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
API_KEY = os.getenv("NVD_API_KEY")

import requests
from requests.exceptions import RequestException
from typing import List, Dict, Optional


def get_epss_scores(cve_list: List[str]) -> Dict[str, Dict[str, Optional[float]]]:
    """
    Запрашивает EPSS-оценки для списка CVE.

    :param cve_list: Список CVE-идентификаторов
    :return: Словарь вида {'CVE-XXXX': {'epss': 0.95, 'percentile': 0.99}, ...}
    """
    base_url = "https://api.first.org/data/v1/epss"
    results = {}

    # Разбиваем CVE на пакеты по 2000 символов (учитывая запятые)
    batch = []
    batch_chars = 0
    for cve in cve_list:
        cve_len = len(cve) + 1  # +1 для запятой
        if batch_chars + cve_len > 2000:
            results.update(_fetch_epss_batch(base_url, batch))
            batch = []
            batch_chars = 0
        batch.append(cve)
        batch_chars += cve_len
    if batch:
        results.update(_fetch_epss_batch(base_url, batch))

    return results


def _fetch_epss_batch(base_url: str, cve_batch: List[str]) -> Dict[str, Dict[str, Optional[float]]]:
    """
    Вспомогательная функция для запроса одного пакета CVE.
    """
    params = {"cve": ",".join(cve_batch)}
    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", [])
        return {
            item["cve"]: {
                "epss": float(item["epss"]) if item.get("epss") else None
            }
            for item in data
        }
    except (RequestException, ValueError) as e:
        print(f"EPSS API error: {e}")
        return {cve: {"epss": None, "percentile": None} for cve in cve_batch}



def calculate_separate_scores(version, vector_string, base_score):
    """
    Разделяет CVSS Base Score на три компонента: confidentiality, integrity, availability.

    Parameters:
    - version (str): Версия CVSS (например, '2.0', '3.1', '4.0').
    - vector_string (str): Вектор CVSS (например, 'AV:L/AC:L/Au:N/C:C/I:C/A:C').

    Returns:
    - dict: {'confidentiality': float, 'integrity': float, 'availability': float}
    """

    def calculate_cvss2_scores(vector):
        # Mapping CVSS levels to numeric values
        CVSS_LEVEL_MAP = {
            'N': 0,  # None
            'P': 0.276,  # Partial
            'C': 0.684  # Complete
        }

        # Exploitability mappings
        AV_MAP = {'N': 1.0, 'A': 0.7, 'L': 0.3}  # Attack Vector
        AC_MAP = {'L': 0.7, 'M': 0.6, 'H': 0.5}  # Attack Complexity
        AU_MAP = {'N': 0.75, 'S': 0.45, 'M': 0.35}  # Authentication Required

        def calculate_impact(C, I, A):
            """Calculate Impact metric"""
            return 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))

        def calculate_exploitability(AV, AC, AU):
            """Calculate Exploitability metric"""
            return 20 * AV * AC * AU

        def calculate_base_score(impact, exploitability):
            """Calculate final Base Score (CVSS v2 compatible)"""
            if impact == 0:
                return 0.0
            return min((0.6 * impact + 0.4 * exploitability) * 1.176 - 1.5, 10.0)

        def shapley_impact_contribution(C, I, A):
            """
            Calculate Shapley values for impact contributions using permutations
            Returns dictionary with contributions of C, I, A
            """
            metrics = ['C', 'I', 'A']
            perms = list(permutations(metrics))
            contributions = {'C': 0, 'I': 0, 'A': 0}

            for perm in perms:
                # Initialize coalition with all metrics set to 0
                coalition = {'C': 0, 'I': 0, 'A': 0}

                for metric in perm:
                    # Calculate impact without current metric
                    impact_no = calculate_impact(**coalition)

                    # Calculate impact with current metric
                    coalition_with_metric = coalition.copy()
                    coalition_with_metric[metric] = locals()[metric]
                    impact_with = calculate_impact(**coalition_with_metric)

                    # Add marginal contribution
                    contributions[metric] += (impact_with - impact_no)

                    # Update coalition for next steps
                    coalition = coalition_with_metric

            # Average across all permutations
            for metric in contributions:
                contributions[metric] /= len(perms)

            return contributions

        def analyze_cvss_vector_shapley(vector):
            """
            Analyze CVSS vector using Shapley values
            Returns dictionary with Base Score and metric contributions
            """
            try:
                # Parse vector
                parts = vector.split('/')
                metric_dict = {}
                for part in parts:
                    if ':' in part:
                        key, val = part.split(':')
                        metric_dict[key] = val

                # Get metric values
                C = CVSS_LEVEL_MAP[metric_dict.get('C', 'N')]
                I = CVSS_LEVEL_MAP[metric_dict.get('I', 'N')]
                A = CVSS_LEVEL_MAP[metric_dict.get('A', 'N')]

                # Get Exploitability values
                AV = AV_MAP[metric_dict.get('AV', 'L')]
                AC = AC_MAP[metric_dict.get('AC', 'M')]
                AU = AU_MAP[metric_dict.get('Au', 'N')]

                # Calculate contributions
                contrib = shapley_impact_contribution(C, I, A)

                # Calculate base components
                impact = calculate_impact(C, I, A)
                exploitability = calculate_exploitability(AV, AC, AU)
                base_score = calculate_base_score(impact, exploitability)

                # Calculate normalized contributions
                total_impact_contrib = contrib['C'] + contrib['I'] + contrib['A']

                if total_impact_contrib == 0:
                    c_weight = i_weight = a_weight = 0.0
                else:
                    c_weight = contrib['C'] / total_impact_contrib
                    i_weight = contrib['I'] / total_impact_contrib
                    a_weight = contrib['A'] / total_impact_contrib

                # Distribute base score by contributions
                base_contrib_c = base_score * c_weight
                base_contrib_i = base_score * i_weight
                base_contrib_a = base_score * a_weight

                return {
                    'BaseScore': round(base_score, 2),
                    'Contribution_C': round(base_contrib_c, 2),
                    'Contribution_I': round(base_contrib_i, 2),
                    'Contribution_A': round(base_contrib_a, 2)
                }

            except Exception as e:
                return {
                    'error': str(e),
                    'message': 'Invalid CVSS vector format. Expected format: AV:L/AC:M/Au:N/C:N/I:P/A:C'
                }

        return analyze_cvss_vector_shapley(vector)

    def calculate_cvss3_scores(vector):

        # Mapping CVSS 3.x уровней к числовым значениям
        CVSS_LEVEL_MAP = {
            'N': 0,  # None
            'L': 0.22,  # Low
            'H': 0.56  # High
        }

        # Mapping для новых метрик CVSS 3.x
        AV_MAP = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}  # Attack Vector
        AC_MAP = {'L': 0.77, 'H': 0.44}  # Attack Complexity
        PR_MAP = {  # Privileges Required
            'N': 0.85,  # None
            'L': {'U': 0.62, 'C': 0.27},  # Low (Scope Unchanged / Changed)
            'H': {'U': 0.27, 'C': 0.20}  # High (Scope Unchanged / Changed)
        }
        UI_MAP = {'N': 0.85, 'R': 0.62}  # User Interaction
        SCOPE_MAP = {'U': 6.42, 'C': 7.52}  # Scope modifier

        def calculate_impact(C, I, A, scope='U'):
            """Рассчет Impact Score с учетом Scope"""
            impact_score = 1 - (1 - C) * (1 - I) * (1 - A)

            if scope == 'U':
                return 6.42 * impact_score
            else:  # Scope: Changed
                return 7.52 * (impact_score - 0.029) - 3.25 * (impact_score - 0.02) ** 15

        def calculate_exploitability(AV, AC, PR, UI):
            """Рассчет Exploitability Score"""
            return 8.22 * AV * AC * PR * UI

        def calculate_base_score(impact, exploitability):
            """Рассчет финального Base Score (CVSS 3.x)"""
            if impact == 0:
                return 0.0
            return min(impact + exploitability, 10.0)

        def shapley_impact_contribution(C, I, A, scope='U'):
            """
            Рассчет Shapley values для C, I, A с учетом Scope
            """
            metrics = ['C', 'I', 'A']
            perms = list(permutations(metrics))
            contributions = {'C': 0, 'I': 0, 'A': 0}

            for perm in perms:
                coalition = {'C': 0, 'I': 0, 'A': 0}

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

        def analyze_cvss_vector_shapley(vector):
            """
            Анализ CVSS вектора с учетом CVSS 3.x
            """
            try:
                # Парсинг вектора
                parts = vector.split('/')
                metric_dict = {}

                for part in parts:
                    if ':' in part:
                        key, val = part.split(':')
                        metric_dict[key] = val

                # Получение значений метрик
                C = CVSS_LEVEL_MAP[metric_dict.get('C', 'N')]
                I = CVSS_LEVEL_MAP[metric_dict.get('I', 'N')]
                A = CVSS_LEVEL_MAP[metric_dict.get('A', 'N')]
                scope = metric_dict.get('S', 'U')

                # Получение новых метрик
                AV = AV_MAP[metric_dict.get('AV', 'L')]
                AC = AC_MAP[metric_dict.get('AC', 'L')]
                UI = UI_MAP[metric_dict.get('UI', 'N')]

                # Privileges Required требует учета Scope
                PR_value = metric_dict.get('PR', 'N')
                if PR_value == 'N':
                    PR = PR_MAP['N']
                else:
                    PR = PR_MAP[PR_value][scope]

                # Расчет вклада C, I, A
                contrib = shapley_impact_contribution(C, I, A, scope=scope)

                # Расчет компонентов
                impact = calculate_impact(C, I, A, scope=scope)
                exploitability = calculate_exploitability(AV, AC, PR, UI)
                base_score = calculate_base_score(impact, exploitability)

                # Нормализация вкладов
                total_impact_contrib = contrib['C'] + contrib['I'] + contrib['A']

                if total_impact_contrib == 0:
                    c_weight = i_weight = a_weight = 0.0
                else:
                    c_weight = contrib['C'] / total_impact_contrib
                    i_weight = contrib['I'] / total_impact_contrib
                    a_weight = contrib['A'] / total_impact_contrib

                base_contrib_c = base_score * c_weight
                base_contrib_i = base_score * i_weight
                base_contrib_a = base_score * a_weight

                return {
                    'BaseScore': round(base_score, 1),
                    'Contribution_C': round(base_contrib_c, 1),
                    'Contribution_I': round(base_contrib_i, 1),
                    'Contribution_A': round(base_contrib_a, 1)
                }

            except Exception as e:
                return {
                    'error': str(e),
                    'message': 'Неверный формат CVSS вектора. Пример: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H'
                }

        return analyze_cvss_vector_shapley(vector)

    def calculate_cvss4_scores(vector, base_score):
        CVSS_LEVEL_MAP = {'N': 0, 'L': 1, 'H': 2}

        def calculate_impact(C, I, A):
            return C + I + A

        def analyze_cvss_vector_simple(vector):
            try:
                # Parse vector
                if not vector.startswith("CVSS:4.0/"):
                    return {'error': 'Invalid CVSS version', 'message': 'Expected CVSS:4.0 vector'}

                parts = vector.split('/')
                metric_dict = {}
                for part in parts[1:]:
                    if ':' in part:
                        key, val = part.split(':')
                        metric_dict[key] = val

                # Get metric values
                C = CVSS_LEVEL_MAP[metric_dict.get('VC', 'N')]
                I = CVSS_LEVEL_MAP[metric_dict.get('VI', 'N')]
                A = CVSS_LEVEL_MAP[metric_dict.get('VA', 'N')]

                # Calculate Impact Score
                impact_score = calculate_impact(C, I, A)

                # Calculate contributions
                if impact_score == 0:
                    c_weight = i_weight = a_weight = 0.0
                else:
                    c_weight = C / impact_score
                    i_weight = I / impact_score
                    a_weight = A / impact_score

                contrib_c = base_score * c_weight
                contrib_i = base_score * i_weight
                contrib_a = base_score * a_weight

                return {
                    'BaseScore': round(base_score, 1),
                    'Contribution_C': round(contrib_c, 2),
                    'Contribution_I': round(contrib_i, 2),
                    'Contribution_A': round(contrib_a, 2)
                }

            except Exception as e:
                return {
                    'error': str(e),
                    'message': 'Invalid CVSS vector format. Expected format: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/C:N/I:N/A:N'
                }

        return analyze_cvss_vector_simple(vector)

    # Основная логика
    if version.startswith('2.'):
        return calculate_cvss2_scores(vector_string)
    elif version in ['3.0', '3.1']:
        return calculate_cvss3_scores(vector_string)
    elif version == '4.0':
        return calculate_cvss4_scores(vector_string, base_score)
    else:
        raise ValueError(f"Unsupported CVSS version: {version}")



def enrich_cve_data(cve_list):
    """Обогащает данные."""

    # Получаем EPSS-оценки
    cve_ids = [cve['cve']['id'] for cve in cve_list]
    epss_data = get_epss_scores(cve_ids)

    enriched = []
    for cve in cve_list:
        cve_data = cve['cve']
        cve_id = cve_data['id']

        # Извлечение ссылок на патчи
        patch_vendor = None
        patch_third_party = None
        for reference in cve_data['references']:
            if "tags" in reference and "Patch" in reference['tags']:
                if "Vendor Advisory" in reference['tags']:
                    patch_vendor = reference['url']
                elif "Third Party Advisory" in reference['tags']:
                    patch_third_party = reference['url']

        published = cve_data['published']

        epss_info = epss_data.get(cve_id, {"epss": None})

        if epss_info['epss'] == None:
            continue

        # Извлечение CVSS BaseScore, C, I, A
        cvss_cia_scores = None

        metrics = cve_data.get('metrics', {})
        cvss_versions = []
        # Находим все ключи, соответствующие шаблону cvssMetricV*
        for key in metrics.keys():
            match = re.match(r'cvssMetricV(\d+)', key)
            if match:
                version = float(match.group(1))  # преобразуем "31" → 3.1
                cvss_versions.append((version, key))

        if len(cvss_versions) == 0:
            continue

        # Сортируем версии по убыванию (новые версии имеют приоритет)
        cvss_versions.sort(reverse=True, key=lambda x: x[0])

        # Ищем baseScore и парсим C, I, A в порядке приоритета версий
        for version, key in cvss_versions:
            metric_list = metrics.get(key, [])
            if metric_list:

                cvss_data = metric_list[0].get('cvssData', {})

                base_score = cvss_data.get('baseScore')
                vector = cvss_data.get('vectorString', '')
                if vector and base_score is not None:
                    cvss_cia_scores = calculate_separate_scores(cvss_data['version'], vector, base_score)
                    break

        # Извлечение CWE
        weaknesses = []
        for weakness in cve_data.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc['lang'] == 'en':
                    match = re.search(r'CWE-\d+', desc['value'])
                    if match:
                        weaknesses.append(match.group(0))

        enriched_cve = {
            'id': cve_id,
            'description': next(
                (d['value'] for d in cve_data['descriptions'] if d['lang'] == 'en'),
                ''
            ),
            'cvss_C_score': cvss_cia_scores['Contribution_C'],
            'cvss_I_score': cvss_cia_scores['Contribution_I'],
            'cvss_A_score': cvss_cia_scores['Contribution_A'],
            'epss': epss_info['epss'],
            'published': published,
            'weaknesses': weaknesses,
            'patch_vendor': patch_vendor,
            'patch_third_party': patch_third_party
        }
        enriched.append(enriched_cve)

    return enriched

def sync_cve_nodes(graph, cve_list, max_retries=3):
    retries = 0
    while retries <= max_retries:
        try:
            # Создаем узлы CVE
            query1 = """
                UNWIND $cves AS cve
                MERGE (c:CVE {identifier: cve.id})
                ON CREATE SET
                    c.description = cve.description,
                    c.cvss_C_score = cve.cvss_C_score,
                    c.cvss_I_score = cve.cvss_I_score,
                    c.cvss_A_score = cve.cvss_A_score,
                    c.epss = cve.epss,
                    c.published = cve.published,
                    c.patch_vendor = cve.patch_vendor,
                    c.patch_third_party = cve.patch_third_party
                ON MATCH SET
                    c.description = cve.description,
                    c.cvss_C_score = cve.cvss_C_score,
                    c.cvss_I_score = cve.cvss_I_score,
                    c.cvss_A_score = cve.cvss_A_score,
                    c.epss = cve.epss,
                    c.published = cve.published,
                    c.patch_vendor = cve.patch_vendor,
                    c.patch_third_party = cve.patch_third_party
                """
            graph.run(query1, cves=cve_list)

            # Создаем связи с CWE
            query2 = """
                UNWIND $cves AS cve
                MATCH (c:CVE {identifier: cve.id})
                UNWIND cve.weaknesses AS cwe_id
                MERGE (w:CWE {identifier: cwe_id})
                MERGE (w)-[:CWE_TO_CVE]->(c)
                """
            graph.run(query2, cves=cve_list)
            break
        except Exception as e:
            if "DeadlockDetected" in str(e) and retries < max_retries:
                retries += 1
                time.sleep(0.1 * (2 ** retries))  # Экспоненциальная задержка
            else:
                raise e


def processor(q, lock, total_processed, uri, auth):
    user, password = auth
    while True:
        current_cves = q.get()
        if current_cves is None:
            q.task_done()
            break
        try:
            neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
            graph = Graph(uri, auth=(user, password), name=neo4j_db)
            cves_enriched = enrich_cve_data(current_cves)
            sync_cve_nodes(graph, cves_enriched)

            # Обновляем счетчик под блокировкой
            with lock:
                total_processed[0] += len(cves_enriched)
        except Exception as e:
            print(f"Ошибка в потоке: {e}")
        finally:
            q.task_done()


def load_cve(neo4j_uri: str, neo4j_auth: tuple, api_key: str = None) -> None:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"startIndex": 0, "resultsPerPage": 2000}
    total_processed = [0]  # Используем список для хранения значения
    total_results = None
    start_time = time.time()

    q = queue.Queue(maxsize=10)
    lock = Lock()

    num_threads = 2  # Количество потоков
    workers = []
    for _ in range(num_threads):
        worker = threading.Thread(target=processor,
                                  args=(q, lock, total_processed, neo4j_uri, neo4j_auth),
                                  daemon=True)
        worker.start()
        workers.append(worker)

    try:
        while True:

            min_pause = 2 if api_key else 15
            response = requests.get(
                NVD_API_URL,
                headers=headers,
                params=params,
                timeout=30
            )
            print(response.status_code)


            response.raise_for_status()
            data = response.json()
            last_request_time = time.time()

            if total_results is None:
                total_results = data.get('totalResults', 0)
                print(f"Всего CVE для загрузки: {total_results}")

            current_cves = data.get('vulnerabilities', [])
            if not current_cves:
                print("Нет данных для обработки. Завершение.")
                break

            q.put(current_cves)
            params['startIndex'] += params['resultsPerPage']

            # Вывод прогресса
            with lock:
                current_total = total_processed[0]
            elapsed = time.time() - start_time
            percent = (current_total / total_results) * 100 if total_results else 0
            remaining = total_results - current_total
            if current_total == 0:
                eta = "Идет инициализация..."
            else:
                eta_seconds = (elapsed / current_total) * remaining
                eta = str(timedelta(seconds=int(eta_seconds)))

            if params['startIndex'] % (5 * params['resultsPerPage']) == 0:
                print(f"Прогресс: {current_total}/{total_results} ({percent:.1f}%) | "
                      f"Осталось: {eta}")

            time.sleep(max(0, min_pause - (time.time() - last_request_time)))

    except Exception as e:
        print(f"Произошла ошибка: {e}")
    finally:
        # Завершаем потоки
        for _ in range(num_threads):
            q.put(None)
        for worker in workers:
            worker.join()
        q.join()

    # Удаление всех CVE без c.cvss_I, c.cvss_A, c.cvss_score или c.epss
    query = """
    MATCH (c:CVE)
    WHERE c.cvss_C_score IS NULL OR
      c.cvss_I_score IS NULL OR
      c.cvss_A_score IS NULL OR
      c.epss IS NULL OR
      c.published IS NULL
    DETACH DELETE c;
    """
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)
    graph.run(query)

    print(f"Обновлено всего {total_processed[0]} CVE.")


    kev_url = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    response = requests.get(kev_url)
    kev_data = response.json()

    # Обновление узлов CVE
    for vuln in tqdm(kev_data["vulnerabilities"], desc="Обновление информации CISA KEV"):
        cve_id = vuln["cveID"]
        due_date = vuln.get("dueDate", None)

        query = """
        MATCH (cve:CVE {identifier: $cve_id})
        SET 
          cve.in_cisa_kev = true,
          cve.cisa_kev_due_date = $dueDate
        """
        graph.run(query, cve_id=cve_id, dueDate=due_date)

def load():
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    load_cve(neo4j_uri, (neo4j_user, neo4j_password), api_key=API_KEY)
