"""
Moteur de corrélation : récupère les alertes Wazuh, les enrichit avec MITRE ATT&CK,
détecte les chaînes d'attaque, et génère un rapport.

Squelette de départ — la logique de corrélation temporelle est à implémenter.
"""

import json
from datetime import datetime

from wazuh_client import WazuhClient
from mitre_mapper import enrich_alert

CHAIN_WINDOW_MINUTES = 10


def parse_timestamp(alert: dict) -> datetime:
    # À adapter selon le format de timestamp retourné par l'API Wazuh utilisée
    raw = alert.get("timestamp")
    return datetime.fromisoformat(raw)


def detect_attack_chains(alerts: list[dict]) -> list[dict]:
    """
    Détecte les chaînes d'attaque : ex. AS-REP Roasting suivi d'un Kerberoasting
    sur le même host dans une fenêtre de CHAIN_WINDOW_MINUTES.

    TODO: implémenter la logique de corrélation temporelle + host.
    """
    chains = []
    # squelette : à compléter avec le tri par host + timestamp
    return chains


def compute_risk_score(alert: dict, chains: list[dict]) -> int:
    """
    Calcule un score de risque simple. À affiner :
    - alerte isolée : score de base (ex. niveau Wazuh natif)
    - alerte faisant partie d'une chaîne détectée : score majoré
    """
    base_score = alert.get("rule", {}).get("level", 0)
    # TODO: majorer le score si l'alerte appartient à une chaîne
    return base_score


def generate_report(alerts: list[dict], chains: list[dict], output_path: str = "report.json"):
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": len(alerts),
        "attack_chains": chains,
        "alerts": alerts,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Rapport généré : {output_path}")


def main():
    client = WazuhClient(
        base_url="https://<IP_MANAGER>:55000",
        username="wazuh-wui",
        password="<TON_MOT_DE_PASSE>",
    )
    raw_alerts = client.get_alerts(rule_group="ad_kerberos")
    enriched_alerts = [enrich_alert(a) for a in raw_alerts]

    chains = detect_attack_chains(enriched_alerts)

    for alert in enriched_alerts:
        alert["risk_score"] = compute_risk_score(alert, chains)

    generate_report(enriched_alerts, chains)


if __name__ == "__main__":
    main()
