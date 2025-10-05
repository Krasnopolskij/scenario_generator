import re
import os
import requests
import zipfile
import io
import csv
from py2neo import Graph
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()


def load_cwe(graph, csv_url):
    response = requests.get(csv_url)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as the_zip:
        with the_zip.open(the_zip.namelist()[0]) as csv_file:
            csv_reader = csv.DictReader(
                io.TextIOWrapper(csv_file, encoding='utf-8')
            )
            rows = list(csv_reader)
            pbar = tqdm(total=len(rows), desc="CWE", unit="зап.", leave=True)
            # Порог года для создания заглушек CVE (берём из NVD_FROM_YEAR, если задан)
            year_limit_env = os.getenv("NVD_FROM_YEAR")
            try:
                year_limit = int(year_limit_env) if year_limit_env else None
            except Exception:
                year_limit = None

            for row in rows:
                current_cwe_id = row["CWE-ID"].strip()
                current_name = row['Name'].strip()
                current_description = row['Description'].strip()
                abstraction = row.get('Weakness Abstraction', '')
                status = row.get('Status', '')

                # Создаем/обновляем текущий CWE узел
                graph.run(
                    """
                    MERGE (w:CWE {identifier: $id})
                    ON CREATE SET 
                        w.name = $name,
                        w.description = $description,
                        w.abstraction = $abstraction,
                        w.status = $status
                    ON MATCH SET 
                        w.name = $name,
                        w.description = $description,
                        w.abstraction = $abstraction,
                        w.status = $status
                    """,
                    {
                        "id": f"CWE-{current_cwe_id}",
                        "name": current_name,
                        "description": current_description,
                        "abstraction": abstraction,
                        "status": status
                    }
                )

                # # Обработка связей с другими CWE
                # related_weaknesses = row.get('Related Weaknesses', '')
                # for rel_part in [p for p in related_weaknesses.split("::") if p]:
                #     parts = rel_part.split(':')
                #     if len(parts) >= 4 and parts[0] == 'NATURE':
                #         nature = parts[1]
                #         target_cwe_id = parts[3].strip()  # CWE ID:XXX
                #         if nature in ["ChildOf", "ParentOf"]:
                #             if nature == "ChildOf":
                #                 parent_id = f"CWE-{target_cwe_id}"
                #                 child_id = f"CWE-{current_cwe_id}"
                #             else:
                #                 parent_id = f"CWE-{current_cwe_id}"
                #                 child_id = f"CWE-{target_cwe_id}"
                #             graph.run(
                #                 """
                #                 MATCH (parent:CWE {identifier: $parent_id}), (child:CWE {identifier: $child_id})
                #                 MERGE (parent)-[r:CWE_PARENT_TO_CWE_CHILD]->(child)
                #                 """,
                #                 {"parent_id": parent_id, "child_id": child_id}
                #             )

                # Связи с Taxonomy Mappings (например, ATT&CK)
                taxonomy_mappings = row.get('Taxonomy Mappings', '')
                for mapping in taxonomy_mappings.split("::"):
                    if "TAXONOMY NAME:ATTACK" in mapping:
                        entry_id = re.search(r'ENTRY ID:(T\d+)', mapping)
                        if entry_id:
                            mitre_id = entry_id.group(1)
                            graph.run(
                                """
                                MERGE (t:Technique {identifier: $mitre_id})
                                """,
                                {"mitre_id": mitre_id}
                            )
                            graph.run(
                                """
                                MATCH (w:CWE {identifier: $cwe_id}), (t:Technique {identifier: $mitre_id})
                                MERGE (t)-[r:TECHNIQUE_TO_CWE]->(w)
                                """,
                                {
                                    "cwe_id": f"CWE-{current_cwe_id}",
                                    "mitre_id": mitre_id
                                }
                            )

                # Обработка CVE из Observed Examples
                observed_examples = row.get('Observed Examples', '')
                for example_part in observed_examples.split("::"):
                    # Убираем лишние пробелы
                    example_part = example_part.strip()
                    if not example_part:
                        continue  # Пропускаем пустые части

                    # Проверяем наличие CVE в формате REFERENCE:CVE-XXXX-XXXX
                    if example_part.startswith("REFERENCE:CVE-"):
                        # Извлекаем часть после "CVE-"
                        cve_part = example_part.split("CVE-")[1]
                        # Находим первые цифры в формате XXXX-XXXX
                        cve_id = re.search(r'^(\d+-\d+)', cve_part)
                        if cve_id:
                            cve_id_full = f"CVE-{cve_id.group(1)}"
                            year_match = re.match(r'^CVE-(\d{4})-', cve_id_full)
                            cve_year = int(year_match.group(1)) if year_match else None
                            if year_limit and cve_year is not None and cve_year < year_limit:
                                # Только связываем с уже существующим CVE, не создавая заглушку
                                graph.run(
                                    """
                                    MATCH (w:CWE {identifier: $cwe_id})
                                    MATCH (cve:CVE {identifier: $cve_id})
                                    MERGE (w)-[:CWE_TO_CVE]->(cve)
                                    """,
                                    {"cwe_id": f"CWE-{current_cwe_id}", "cve_id": cve_id_full}
                                )
                            else:
                                # Создаём (или обновляем) узел CVE и связь
                                graph.run(
                                    """
                                    MERGE (cve:CVE {identifier: $cve_id})
                                    """,
                                    {"cve_id": cve_id_full}
                                )
                                graph.run(
                                    """
                                    MATCH (w:CWE {identifier: $cwe_id}), (cve:CVE {identifier: $cve_id})
                                    MERGE (w)-[:CWE_TO_CVE]->(cve)
                                    """,
                                    {"cwe_id": f"CWE-{current_cwe_id}", "cve_id": cve_id_full}
                                )
                    else:
                        # Если формат не REFERENCE:CVE..., используем базовое регулярное выражение
                        cve_matches = re.findall(r'CVE-\d+-\d+', example_part)
                        for cve_id in cve_matches:
                            year_match = re.match(r'^CVE-(\d{4})-', cve_id)
                            cve_year = int(year_match.group(1)) if year_match else None
                            if year_limit and cve_year is not None and cve_year < year_limit:
                                graph.run(
                                    """
                                    MATCH (w:CWE {identifier: $cwe_id})
                                    MATCH (cve:CVE {identifier: $cve_id})
                                    MERGE (w)-[:CWE_TO_CVE]->(cve)
                                    """,
                                    {"cwe_id": f"CWE-{current_cwe_id}", "cve_id": cve_id}
                                )
                            else:
                                graph.run(
                                    """
                                    MERGE (cve:CVE {identifier: $cve_id})
                                    """,
                                    {"cve_id": cve_id}
                                )
                                graph.run(
                                    """
                                    MATCH (w:CWE {identifier: $cwe_id}), (cve:CVE {identifier: $cve_id})
                                    MERGE (w)-[:CWE_TO_CVE]->(cve)
                                    """,
                                    {"cwe_id": f"CWE-{current_cwe_id}", "cve_id": cve_id}
                                )

                pbar.update(1)
            pbar.close()


def load():
    neo4j_uri = os.getenv("NEO4J_URI")
    neo4j_user = os.getenv("NEO4J_USER")
    neo4j_password = os.getenv("NEO4J_PASSWORD")
    if not all([neo4j_uri, neo4j_user, neo4j_password]):
        raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
    neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
    print(f"Запись в базу: {neo4j_db}")
    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)

    # Список URL для разных категорий CWE (можно переопределить через env CWE_CSV_URLS)
    urls_env = os.getenv("CWE_CSV_URLS")
    if urls_env:
        urls = [u.strip() for u in urls_env.split(',') if u.strip()]
    else:
        urls = [
            "https://cwe.mitre.org/data/csv/699.csv.zip",  # Software Development
            "https://cwe.mitre.org/data/csv/1194.csv.zip",  # Hardware Design
            "https://cwe.mitre.org/data/csv/1000.csv.zip"  # Research Concepts
        ]

    for url in urls:
        load_cwe(graph, url)
