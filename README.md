# Mini-SOC — Détection d'attaques Active Directory

Projet de détection d'attaques Kerberos (AS-REP Roasting, Kerberoasting, brute-force) sur un lab Active Directory, combinant Wazuh (SIEM) et un moteur de corrélation Python custom avec mapping MITRE ATT&CK.

## Contexte

Ce projet simule un environnement Active Directory ciblé par des techniques d'attaque courantes contre Kerberos, et met en place une chaîne de détection complète : collecte des logs, règles de détection SIEM, corrélation applicative, et reporting.

## Architecture

```
Kali Linux (attaquant)
        |
        v
AD lab.local (DC cible) --agent Wazuh--> Wazuh manager (SIEM)
                                                |
                                                v
                                    Module Python (corrélation + MITRE ATT&CK)
                                                |
                                                v
                                    Dashboard & rapport d'alertes
```

Voir [docs/architecture.md](docs/architecture.md) pour le détail.

## Stack technique

- **SIEM** : Wazuh (manager, indexer, dashboard)
- **Cible** : Windows Server (Active Directory Domain Services)
- **Attaquant** : Kali Linux (Rubeus, Impacket, Hydra)
- **Moteur de corrélation** : Python 3
- **Reporting** : JSON + HTML

## Techniques d'attaque simulées

| Technique | MITRE ATT&CK | Détection |
|---|---|---|
| AS-REP Roasting | T1558.004 | Event ID 4768, chiffrement RC4, compte DONT_REQUIRE_PREAUTH |
| Kerberoasting | T1558.003 | Event ID 4769, chiffrement RC4 en volume anormal |
| Brute-force | T1110 | Rafales d'Event ID 4625 sur fenêtre courte |

Détails complets dans [docs/attack-scenarios.md](docs/attack-scenarios.md).

## Installation

### 1. Wazuh manager

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

### 2. Agent Wazuh sur le DC Windows

Voir les instructions détaillées dans [docs/architecture.md](docs/architecture.md).

### 3. Règles de détection custom

```bash
sudo cp wazuh-config/rules/ad_kerberos_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

### 4. Module de corrélation Python

```bash
cd detection-engine
pip install -r requirements.txt

# Identifiants de l'indexer Wazuh (ne jamais les écrire dans le code)
export WAZUH_INDEXER_PASSWORD='<mot de passe indexer>'
export WAZUH_INDEXER_URL='https://<ip-wazuh>:9200'   # optionnel
export WAZUH_INDEXER_USER='admin'                     # optionnel

python correlator.py
```

## Structure du repo

```
mini-soc-ad-detection/
├── README.md
├── docs/
│   ├── architecture.md
│   └── attack-scenarios.md
├── wazuh-config/
│   ├── rules/
│   │   └── ad_kerberos_rules.xml
│   └── decoders/
├── detection-engine/
│   ├── correlator.py
│   ├── mitre_mapper.py
│   ├── wazuh_client.py
│   └── requirements.txt
└── LICENSE
```

## Résultats

Les trois techniques d'attaque simulées (AS-REP Roasting, Kerberoasting, brute-force) ont été détectées avec succès par les règles Wazuh custom (`100011`, `100012`, `100013`). Le module Python de corrélation enrichit ces alertes avec un mapping MITRE ATT&CK et détecte les chaînes d'attaque multi-étapes. Voir [docs/attack-scenarios.md](docs/attack-scenarios.md) pour le détail complet, captures d'écran à l'appui.

## Limitations connues

- Environnement de lab isolé, non représentatif d'un AD de production à grande échelle
- L'indexer Wazuh a été exposé sur toutes les interfaces réseau (`network.host: 0.0.0.0`) pour permettre l'accès au module Python depuis l'hôte — à restreindre en production (authentification mutuelle TLS, réseau dédié)
- Les règles de détection sont calibrées sur ce lab et nécessiteraient un tuning pour un environnement réel
- Pas de gestion des faux positifs à grande échelle (hors périmètre du projet)
- Pas de capture d'écran de la commande Kali pour le scénario brute-force (détection validée côté dashboard uniquement)

## Auteure

Hana Bouikni — Étudiante en ingénierie de la cybersécurité, USTHB
