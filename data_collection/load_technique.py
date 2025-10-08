import re
import os
import requests
from py2neo import Graph
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

# Порядок тактик MITRE ATT&CK (enterprise) для хронологии сценариев
ORDERED_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
TACTIC_ORDER = {name: idx for idx, name in enumerate(ORDERED_TACTICS, start=1)}

def get_attack_techniques():
    """Загружает данные MITRE ATT&CK напрямую из GitHub в память"""
    all_objects = []
    urls_env = os.getenv("ATTACK_JSON_URLS")
    if urls_env:
        URLS = [u.strip() for u in urls_env.split(',') if u.strip()]
    else:
        URLS = [
            "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/enterprise-attack/enterprise-attack.json"
        ]
    for url in URLS:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            stix_objects = data.get("objects", [])
            all_objects.extend(stix_objects)
        except Exception as e:
            print(f"Ошибка загрузки коллекции: {str(e)}")
    return all_objects

def process_techniques(objects, graph):
    stix_to_mitre = {}
    CAPEC_PATTERN = re.compile(r'^CAPEC-?\d+$', re.IGNORECASE)
    CWE_PATTERN = re.compile(r'^CWE-?\d+$', re.IGNORECASE)

    total = 0
    for _obj in objects:
        if _obj.get('type') == 'attack-pattern':
            for _ref in _obj.get('external_references', []):
                if _ref.get('source_name') == 'mitre-attack':
                    total += 1
                    break
    pbar = tqdm(total=total, desc="ATT&CK техники", unit="техн.", leave=True)

    for obj in objects:
        if obj.get('type') != "attack-pattern":
            continue

        mitre_id = None
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                pbar.update(1)
                break
        if not mitre_id:
            continue

        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase['phase_name'])

        # Вычисляем основную тактику и её порядковый номер (минимальный по хронологии)
        tactic_order_values = []
        for tname in tactics:
            tnorm = (tname or "").strip().lower()
            if tnorm in TACTIC_ORDER:
                tactic_order_values.append((TACTIC_ORDER[tnorm], tnorm))
        tactic_order = None
        primary_tactic = None
        if tactic_order_values:
            tactic_order_values.sort(key=lambda x: x[0])
            tactic_order, primary_tactic = tactic_order_values[0]

        try:
            graph.run(
                """
                MERGE (t:Technique {identifier: $id})
                SET t.name = $name, 
                    t.description = $desc, 
                    t.tactics = $tactics,
                    t.primary_tactic = $primary_tactic,
                    t.tactic_order = $tactic_order
                """,
                id=mitre_id,
                name=obj.get('name', ''),
                desc=obj.get('description', ''),
                tactics=tactics,
                primary_tactic=primary_tactic,
                tactic_order=tactic_order
            )
        except Exception as e:
            print(f"Ошибка при обработке {mitre_id}: {str(e)}")
            continue

        stix_to_mitre[obj.get('id')] = mitre_id

        for ref in external_refs:
            ext_id = ref.get('external_id', '')
            link_type = None
            if CAPEC_PATTERN.match(ext_id):
                link_type = 'CAPEC'
            elif CWE_PATTERN.match(ext_id):
                link_type = 'CWE'

            if link_type:
                ext_id = ext_id.upper().replace('_', '-')
                try:
                    if link_type == 'CAPEC':
                        graph.run(
                            f"""
                            MATCH (t {{identifier: $tech}})
                            MERGE (n:{link_type} {{identifier: $ext_id}})
                            MERGE (n)-[:{link_type}_TO_TECHNIQUE]->(t)
                            """,
                            tech=mitre_id,
                            ext_id=ext_id
                        )
                    else:
                        graph.run(
                            f"""
                            MATCH (t {{identifier: $tech}})
                            MERGE (n:{link_type} {{identifier: $ext_id}})
                            MERGE (t)-[:TECHNIQUE_TO_{link_type}]->(n)
                            """,
                            tech=mitre_id,
                            ext_id=ext_id
                        )
                except Exception as e:
                    print(f"Ошибка связи {link_type} {ext_id}: {str(e)}")
    pbar.close()


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
        attack_objects = get_attack_techniques()
        process_techniques(attack_objects, graph)
    except Exception as e:
        print(f"Критическая ошибка: {str(e)}")
    finally:
        pass
