import os
import json
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # sobe de legacy_cli/ pra raiz do projeto
load_dotenv(os.path.join(BASE_DIR, ".env"))

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
USER = os.getenv("WAZUH_USER")
PASSWORD = os.getenv("WAZUH_PASSWORD")

requests.packages.urllib3.disable_warnings()



QUERY = {
    "size": 30,
    "sort": [
        {"timestamp": {"order": "desc"}}
    ],
    "_source": [
        "timestamp",
        "agent.name",
        "agent.ip",
        "manager.name",
        "rule.id",
        "rule.level",
        "rule.description",
        "rule.groups",
        "data.event_type",
        "data.src_ip",
        "data.dest_ip",
        "data.srcip",
        "data.dstip",
        "data.proto",
        "data.alert.signature",
        "data.alert.category",
        "data.alert.severity",
        "syscheck.path",
        "syscheck.event",
        "location"
    ],
    "query": {
        "bool": {
            "should": [
                {"match": {"rule.groups": "suricata"}},
                {"match": {"rule.groups": "sshd"}},
                {"match": {"rule.groups": "syscheck"}},
                {"match": {"rule.id": "5712"}},
                {"match": {"rule.id": "5710"}}
            ],
            "minimum_should_match": 1
        }
    }
}


def main():
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"

    response = requests.get(
        url,
        auth=HTTPBasicAuth(USER, PASSWORD),
        headers={"Content-Type": "application/json"},
        data=json.dumps(QUERY),
        verify=False,
        timeout=20
    )

    if response.status_code != 200:
        print("[ERRO] Falha ao consultar Wazuh Indexer")
        print("Status:", response.status_code)
        print(response.text)
        return

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    eventos = []

    for hit in hits:
        src = hit.get("_source", {})
        evento = {
            "timestamp": src.get("timestamp"),
            "agent": src.get("agent", {}).get("name"),
            "agent_ip": src.get("agent", {}).get("ip"),
            "rule_id": src.get("rule", {}).get("id"),
            "level": src.get("rule", {}).get("level"),
            "description": src.get("rule", {}).get("description"),
            "groups": src.get("rule", {}).get("groups"),
            "src_ip": src.get("data", {}).get("src_ip") or src.get("data", {}).get("srcip"),
            "dest_ip": src.get("data", {}).get("dest_ip") or src.get("data", {}).get("dstip"),
            "proto": src.get("data", {}).get("proto"),
            "signature": src.get("data", {}).get("alert", {}).get("signature"),
            "category": src.get("data", {}).get("alert", {}).get("category"),
            "suricata_severity": src.get("data", {}).get("alert", {}).get("severity"),
            "fim_path": src.get("syscheck", {}).get("path"),
            "fim_event": src.get("syscheck", {}).get("event"),
            "location": src.get("location")
        }
        eventos.append(evento)

    with open("alertas_wazuh.json", "w", encoding="utf-8") as f:
        json.dump(eventos, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(eventos)} alertas coletados.")
    print("[OK] Arquivo gerado: alertas_wazuh.json")

    for e in eventos[:5]:
        print("-" * 80)
        print(f"Data: {e['timestamp']}")
        print(f"Agente: {e['agent']}")
        print(f"Regra: {e['rule_id']} | Level: {e['level']}")
        print(f"Descrição: {e['description']}")
        print(f"Origem: {e['src_ip']} -> Destino: {e['dest_ip']}")


if __name__ == "__main__":
    main()
   
