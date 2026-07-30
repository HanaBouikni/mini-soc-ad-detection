"""
Client pour l'API du Wazuh Indexer (OpenSearch), qui stocke les alertes.

Contrairement à une hypothèse initiale, les alertes Wazuh ne sont PAS accessibles
via l'API du manager (port 55000) sur les versions récentes -- elles sont stockées
et interrogeables uniquement via l'indexer (OpenSearch, port 9200, index wazuh-alerts-*).
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhIndexerClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_ssl = verify_ssl

    def get_alerts(self, rule_group: str = "ad_kerberos", size: int = 200, index_pattern: str = "wazuh-alerts-*") -> list[dict]:
        """
        Récupère les alertes correspondant à un groupe de règles donné, triées
        par timestamp décroissant (les plus récentes d'abord).
        """
        url = f"{self.base_url}/{index_pattern}/_search"
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "match": {"rule.groups": rule_group}
            }
        }

        response = requests.post(
            url,
            auth=self.auth,
            json=query,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_alerts_by_rule_id(self, rule_id: str, size: int = 200, index_pattern: str = "wazuh-alerts-*") -> list[dict]:
        """Récupère les alertes pour un rule.id précis (ex: '100011')."""
        url = f"{self.base_url}/{index_pattern}/_search"
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "term": {"rule.id": rule_id}
            }
        }

        response = requests.post(url, auth=self.auth, json=query, verify=self.verify_ssl)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]


if __name__ == "__main__":
    # Exemple d'usage -- adapte l'IP, le user et le mot de passe indexer (wazuh-passwords.txt)
    client = WazuhIndexerClient(
        base_url="https://192.168.202.128:9200",
        username="admin",
        password="<TON_MOT_DE_PASSE_INDEXER>",
    )
    alerts = client.get_alerts(rule_group="ad_kerberos")
    print(f"{len(alerts)} alertes récupérées")
