# Architecture

## Vue d'ensemble

Le lab est composé de trois machines virtuelles :

| VM | Rôle | OS |
|---|---|---|
| DC | Contrôleur de domaine cible, domaine `lab.local` | Windows Server 2012 |
| Attaquant | Machine offensive | Kali Linux |
| SIEM | Wazuh manager, indexer, dashboard | Ubuntu 22.04 |

## Flux de données

1. L'attaquant (Kali) exécute des techniques Kerberos contre le DC.
2. Le DC journalise les événements de sécurité (Event ID 4768, 4769, 4625, 4624) dans le journal Windows Security.
3. L'agent Wazuh installé sur le DC transmet ces logs au manager Wazuh.
4. Le manager applique les règles de détection custom et génère des alertes.
5. Le module Python interroge l'API Wazuh, corrèle les alertes entre elles, et les enrichit avec un mapping MITRE ATT&CK.
6. Un rapport final (JSON/HTML) est généré avec la timeline de l'attaque et un score de risque.

## Configuration de l'audit Kerberos sur le DC

Sur le contrôleur de domaine, activer via `gpedit.msc` ou une GPO :

- Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon
  - Audit Kerberos Authentication Service : Success + Failure
  - Audit Kerberos Service Ticket Operations : Success + Failure

## Installation de l'agent Wazuh sur le DC

1. Télécharger le package Wazuh agent pour Windows depuis le manager
2. Installer avec l'adresse du manager :
   ```
   msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="<IP_DU_MANAGER>"
   ```
3. Démarrer le service `WazuhSvc`
4. Vérifier l'enregistrement côté manager : `/var/ossec/bin/agent_control -l`

## Points d'attention

- S'assurer que le fuseau horaire est synchronisé entre le DC et le manager Wazuh (sinon la corrélation temporelle du module Python sera faussée)
- Vérifier que le canal `WinEventLog:Security` est bien inclus dans `ossec.conf` côté agent
