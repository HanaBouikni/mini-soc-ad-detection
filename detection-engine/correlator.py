"""
Moteur de corrélation : récupère les alertes Wazuh (via l'indexer), les enrichit
avec MITRE ATT&CK, détecte les chaînes d'attaque, calcule un score de risque,
et génère un rapport JSON + HTML.
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

from wazuh_client import WazuhIndexerClient
from mitre_mapper import enrich_alert

# Fenêtre de corrélation pour considérer deux alertes comme faisant partie
# de la même chaîne d'attaque (ex: AS-REP Roasting suivi d'un Kerberoasting)
CHAIN_WINDOW_MINUTES = 10

# Règles qui, enchaînées dans la fenêtre CHAIN_WINDOW_MINUTES sur le même agent,
# constituent une chaîne d'attaque à signaler
CHAIN_PATTERNS = [
    {
        "name": "Reconnaissance puis exploitation Kerberos",
        "sequence": ["100010", "100011"],  # AS-REP Roasting -> Kerberoasting
        "description": "AS-REP Roasting suivi d'un Kerberoasting sur le même host : "
                        "probable reconnaissance de comptes vulnérables puis exploitation ciblée.",
    },
    {
        "name": "Brute-force suivi de compromission",
        "sequence": ["100012", "100013"],  # brute-force -> logon réussi post rafale
        "description": "Rafale d'échecs d'authentification suivie d'un logon réussi : "
                        "compromission de compte probable par brute-force.",
    },
]


def parse_timestamp(alert: dict) -> datetime:
    """
    Parse le timestamp d'une alerte Wazuh (format ex: '2026-07-28T17:35:50.454+0100').
    """
    raw = alert.get("timestamp")
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")


def get_agent_name(alert: dict) -> str:
    return alert.get("agent", {}).get("name", "unknown")


def get_rule_id(alert: dict) -> str:
    return str(alert.get("rule", {}).get("id", ""))


def detect_attack_chains(alerts: list[dict]) -> list[dict]:
    """
    Détecte les chaînes d'attaque définies dans CHAIN_PATTERNS : deux alertes
    liées par une séquence connue, sur le même agent, dans une fenêtre de
    CHAIN_WINDOW_MINUTES.
    """
    # Regrouper les alertes par agent, triées par timestamp croissant
    by_agent = defaultdict(list)
    for alert in alerts:
        by_agent[get_agent_name(alert)].append(alert)

    for agent_alerts in by_agent.values():
        agent_alerts.sort(key=parse_timestamp)

    chains = []

    for agent_name, agent_alerts in by_agent.items():
        for pattern in CHAIN_PATTERNS:
            first_id, second_id = pattern["sequence"]
            first_alerts = [a for a in agent_alerts if get_rule_id(a) == first_id]
            second_alerts = [a for a in agent_alerts if get_rule_id(a) == second_id]

            for first in first_alerts:
                first_time = parse_timestamp(first)
                for second in second_alerts:
                    second_time = parse_timestamp(second)
                    delta = second_time - first_time
                    if timedelta(0) <= delta <= timedelta(minutes=CHAIN_WINDOW_MINUTES):
                        chains.append({
                            "chain_name": pattern["name"],
                            "description": pattern["description"],
                            "agent": agent_name,
                            "first_alert_rule_id": first_id,
                            "first_alert_time": first_time.isoformat(),
                            "second_alert_rule_id": second_id,
                            "second_alert_time": second_time.isoformat(),
                            "gap_seconds": delta.total_seconds(),
                        })
                        break  # une seule chaîne par occurrence du premier event, évite les doublons

    return chains


def compute_risk_score(alert: dict, chains: list[dict]) -> int:
    """
    Score de risque = niveau Wazuh natif, majoré de +5 si l'alerte fait partie
    d'une chaîne d'attaque détectée (les deux extrémités de la chaîne sont majorées).
    """
    base_score = alert.get("rule", {}).get("level", 0)
    rule_id = get_rule_id(alert)
    agent_name = get_agent_name(alert)
    alert_time = parse_timestamp(alert)

    for chain in chains:
        if chain["agent"] != agent_name:
            continue
        is_first = rule_id == chain["first_alert_rule_id"] and alert_time.isoformat() == chain["first_alert_time"]
        is_second = rule_id == chain["second_alert_rule_id"] and alert_time.isoformat() == chain["second_alert_time"]
        if is_first or is_second:
            return base_score + 5

    return base_score


def generate_html_report(report: dict, output_path: str = "report.html"):
    rows = ""
    for alert in report["alerts"]:
        mitre = alert.get("mitre_attack", {})
        rows += f"""
        <tr>
          <td>{alert.get('timestamp', '')}</td>
          <td>{alert.get('agent', {}).get('name', '')}</td>
          <td>{alert.get('rule', {}).get('id', '')}</td>
          <td>{alert.get('rule', {}).get('description', '')}</td>
          <td>{alert.get('risk_score', '')}</td>
          <td>{mitre.get('technique_id', '')}</td>
        </tr>"""

    chains_html = ""
    for chain in report["attack_chains"]:
        chains_html += f"""
        <li><strong>{chain['chain_name']}</strong> sur {chain['agent']} — 
        {chain['description']} (écart : {chain['gap_seconds']:.0f}s)</li>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport de détection — Mini-SOC AD</title>
<style>
  body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #222; color: white; }}
  tr:nth-child(even) {{ background: #f5f5f5; }}
  .summary {{ background: #eef; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }}
</style>
</head>
<body>
  <h1>Rapport de détection — Mini-SOC AD</h1>
  <div class="summary">
    <p><strong>Généré le :</strong> {report['generated_at']}</p>
    <p><strong>Total d'alertes :</strong> {report['total_alerts']}</p>
    <p><strong>Chaînes d'attaque détectées :</strong> {len(report['attack_chains'])}</p>
  </div>
  <h2>Chaînes d'attaque</h2>
  <ul>{chains_html if chains_html else "<li>Aucune chaîne détectée</li>"}</ul>
  <h2>Alertes</h2>
  <table>
    <tr><th>Timestamp</th><th>Agent</th><th>Rule ID</th><th>Description</th><th>Score de risque</th><th>MITRE</th></tr>
    {rows}
  </table>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Rapport HTML généré : {output_path}")


def generate_report(alerts: list[dict], chains: list[dict], output_path: str = "report.json"):
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": len(alerts),
        "attack_chains": chains,
        "alerts": alerts,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Rapport JSON généré : {output_path}")
    generate_html_report(report, output_path.replace(".json", ".html"))


def main():
    password = os.environ.get("WAZUH_INDEXER_PASSWORD")
    if not password:
        raise SystemExit("Définissez la variable d'environnement WAZUH_INDEXER_PASSWORD.")
    client = WazuhIndexerClient(
        base_url=os.environ.get("WAZUH_INDEXER_URL", "https://192.168.202.128:9200"),
        username=os.environ.get("WAZUH_INDEXER_USER", "admin"),
        password=password,
    )
    raw_alerts = client.get_alerts(rule_group="ad_kerberos", size=500)
    enriched_alerts = [enrich_alert(a) for a in raw_alerts]

    chains = detect_attack_chains(enriched_alerts)

    for alert in enriched_alerts:
        alert["risk_score"] = compute_risk_score(alert, chains)

    generate_report(enriched_alerts, chains)


if __name__ == "__main__":
    main()
