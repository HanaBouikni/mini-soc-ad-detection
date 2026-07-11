"""
Client minimal pour interroger l'API Wazuh (authentification + récupération des alertes).
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None

    def authenticate(self) -> str:
        """Récupère un token JWT depuis l'API Wazuh."""
        url = f"{self.base_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        self.token = response.json()["data"]["token"]
        return self.token

    def _headers(self) -> dict:
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get_alerts(self, limit: int = 100, rule_group: str | None = None) -> list[dict]:
        """
        Récupère les alertes récentes. À adapter selon la version de l'API Wazuh
        utilisée (indexer API vs manager API) — cette version cible l'API manager.
        """
        url = f"{self.base_url}/alerts"
        params = {"limit": limit}
        if rule_group:
            params["rule.groups"] = rule_group

        response = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json().get("data", {}).get("affected_items", [])


if __name__ == "__main__":
    # Exemple d'usage — à adapter avec tes identifiants de lab
    client = WazuhClient(
        base_url="https://<IP_MANAGER>:55000",
        username="wazuh-wui",
        password="<TON_MOT_DE_PASSE>",
    )
    alerts = client.get_alerts(rule_group="ad_kerberos")
    print(f"{len(alerts)} alertes récupérées")
