"""
Mapping des règles de détection custom vers les techniques MITRE ATT&CK.

Note : les alertes Wazuh contiennent déjà un bloc rule.mitre nativement
(visible dans les résultats de l'API indexer), donc ce module sert surtout
de fallback/normalisation et de source de vérité indépendante du format
exact retourné par Wazuh.
"""

MITRE_MAPPING = {
    "100010": {
        "technique_id": "T1558.004",
        "technique_name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "tactic": "Credential Access",
    },
    "100011": {
        "technique_id": "T1558.003",
        "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
    },
    "100012": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "100013": {
        "technique_id": "T1110",
        "technique_name": "Brute Force (compromission probable)",
        "tactic": "Credential Access",
    },
    "100014": {
        "technique_id": "T1110",
        "technique_name": "Brute Force (échec individuel)",
        "tactic": "Credential Access",
    },
}


def enrich_alert(alert: dict) -> dict:
    """Ajoute/normalise les métadonnées MITRE ATT&CK sur une alerte Wazuh brute."""
    rule_id = str(alert.get("rule", {}).get("id", ""))
    mitre_info = MITRE_MAPPING.get(rule_id)

    enriched = dict(alert)
    if mitre_info:
        enriched["mitre_attack"] = mitre_info
    return enriched
