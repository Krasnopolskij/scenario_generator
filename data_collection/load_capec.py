import re
import os
import sys
import requests
import zipfile
import io
import csv
from py2neo import Graph
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

def load():
    try:
        neo4j_uri = os.getenv("NEO4J_URI")
        neo4j_user = os.getenv("NEO4J_USER")
        neo4j_password = os.getenv("NEO4J_PASSWORD")
        neo4j_db = os.getenv("NEO4J_DATABASE", "neo4j")
        if not all([neo4j_uri, neo4j_user, neo4j_password]):
            raise RuntimeError("Отсутствуют NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD. Укажите их в .env")
        print(f"Запись в базу: {neo4j_db}")
        graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password), name=neo4j_db)

        zip_url = os.getenv("CAPEC_CSV_ZIP_URL", "https://capec.mitre.org/data/csv/1000.csv.zip")
        response = requests.get(zip_url)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as the_zip:
            with the_zip.open('1000.csv') as csv_file:
                csv_reader = csv.DictReader(
                    io.TextIOWrapper(csv_file, encoding='utf-8')
                )
                rows = list(csv_reader)
                pbar = tqdm(total=len(rows), desc="CAPEC", unit="зап.", leave=True)
                for row in rows:
                    current_capec_id = row["'ID"].strip()
                    current_name = row['Name'].strip()
                    current_description = row['Description'].strip()

                    # Создаём/обновляем текущий узел CAPEC
                    graph.run(
                        """
                        MERGE (c:CAPEC {identifier: $id})
                        ON CREATE SET 
                            c.name = $name,
                            c.description = $description
                        ON MATCH SET 
                            c.name = $name,
                            c.description = $description
                        """,
                        {
                            "id": f"CAPEC-{current_capec_id}",
                            "name": current_name,
                            "description": current_description
                        }
                    )

                    # Обработка связей с другими узлами CAPEC
                    related_attack_patterns = row.get('Related Attack Patterns', '')
                    for pattern in related_attack_patterns.split("::"):
                        if pattern.strip():
                            match = re.search(r'CAPEC ID:(\d+)', pattern)
                            if match:
                                target_capec_id = match.group(1)
                            parts = pattern.split(":")
                            if len(parts) >= 4 and "CAPEC ID" in parts:
                                nature = parts[1]

                                if nature in ["ChildOf", "ParentOf"]:
                                    if nature == "ChildOf":
                                        parent_id = f"CAPEC-{target_capec_id}"
                                        child_id = f"CAPEC-{current_capec_id}"
                                    else:
                                        parent_id = f"CAPEC-{current_capec_id}"
                                        child_id = f"CAPEC-{target_capec_id}"

                                    # Создаём связь (parent)-[:CAPEC_PARENT_TO_CAPEC_CHILD]->(child)
                                    graph.run(
                                        """
                                        MATCH (parent:CAPEC {identifier: $parent_id}), (child:CAPEC {identifier: $child_id})
                                        MERGE (parent)-[r:CAPEC_PARENT_TO_CAPEC_CHILD]->(child)
                                        """,
                                        {
                                            "parent_id": parent_id,
                                            "child_id": child_id,
                                        }
                                    )

                    # Обработка связей с MITRE ATT&CK
                    taxonomy_mappings = row.get('Taxonomy Mappings', '')
                    for mapping in taxonomy_mappings.split("::"):
                        if "TAXONOMY NAME:ATTACK" in mapping:
                            mitre_id = re.search(r'ENTRY ID:T?(\d+)', mapping)
                            if mitre_id:
                                mitre_id = "T" + mitre_id.group(1)
                            if mitre_id:
                                graph.run(
                                    """
                                    MERGE (t:Technique {identifier: $mitre_id})
                                    """,
                                    {
                                        "mitre_id": mitre_id,
                                    }
                                )

                                graph.run(
                                    """
                                    MATCH (c:CAPEC {identifier: $capec_id}), (t:Technique {identifier: $mitre_id})
                                    MERGE (c)-[r:CAPEC_TO_TECHNIQUE]->(t)
                                    """,
                                    {
                                        "capec_id": f"CAPEC-{current_capec_id}",
                                        "mitre_id": mitre_id
                                    }
                                )
                    pbar.update(1)
                pbar.close()
    except Exception as e:
        print(f"[CRITICAL]: {str(e)}")
        sys.exit(1)


def mapping(graph):
    zip_url = os.getenv("CAPEC_MAPPING_CSV_ZIP_URL", "https://capec.mitre.org/data/csv/658.csv.zip")
    response = requests.get(zip_url)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as the_zip:
        with the_zip.open('658.csv') as csv_file:
            csv_reader = csv.DictReader(
                io.TextIOWrapper(csv_file, encoding='utf-8')
            )

            rows = list(csv_reader)
            pbar = tqdm(total=len(rows), desc="CAPEC mapping", unit="зап.", leave=True)
            for row in rows:
                current_capec_id = row["'ID"].strip()

                # Создаем/обновляем CAPEC узел
                graph.run(
                    """
                    MERGE (c:CAPEC {identifier: $id})
                    """,
                    {"id": f"CAPEC-{current_capec_id}"}
                )

                # Связи между CAPEC
                related_attack_patterns = row.get('Related Attack Patterns', '')
                for pattern in related_attack_patterns.split("::"):
                    if pattern.strip():
                        match = re.search(r'CAPEC ID:(\d+)', pattern)
                        if match:
                            target_capec_id = match.group(1)
                        parts = pattern.split(":")
                        if len(parts) >= 4 and "CAPEC ID" in parts:
                            nature = parts[1]

                            if nature in ["ChildOf", "ParentOf"]:
                                if nature == "ChildOf":
                                    parent_id = f"CAPEC-{target_capec_id}"
                                    child_id = f"CAPEC-{current_capec_id}"
                                else:
                                    parent_id = f"CAPEC-{current_capec_id}"
                                    child_id = f"CAPEC-{target_capec_id}"

                                graph.run(
                                    """
                                    MATCH (parent:CAPEC {identifier: $parent_id}), 
                                          (child:CAPEC {identifier: $child_id})
                                    MERGE (parent)-[r:CAPEC_PARENT_TO_CAPEC_CHILD]->(child)
                                    """,
                                    {"parent_id": parent_id, "child_id": child_id}
                                )

                # Связи с MITRE Techniques
                taxonomy_mappings = row.get('Taxonomy Mappings', '')
                for mapping_str in taxonomy_mappings.split("::"):
                    if "TAXONOMY NAME:ATTACK" in mapping_str:
                        mitre_id = re.search(r'ENTRY ID:T?(\d+)', mapping_str)
                        if mitre_id:
                            mitre_id = "T" + mitre_id.group(1)
                            graph.run(
                                """
                                MERGE (t:Technique {identifier: $mitre_id})
                                """,
                                {"mitre_id": mitre_id}
                            )
                            graph.run(
                                """
                                MATCH (c:CAPEC {identifier: $capec_id}), 
                                      (t:Technique {identifier: $mitre_id})
                                MERGE (c)-[:CAPEC_TO_TECHNIQUE]->(t)
                                """
                                ,
                                {
                                    "capec_id": f"CAPEC-{current_capec_id}",
                                    "mitre_id": mitre_id
                                }
                            )
                pbar.update(1)
