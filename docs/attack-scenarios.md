# Scénarios d'attaque simulés

## 1. AS-REP Roasting (T1558.004)

**Principe** : extraction de hashs pour les comptes n'exigeant pas la pré-authentification Kerberos (`DONT_REQUIRE_PREAUTH`).

**Détection** : Event ID 4768 (demande de TGT) avec type de chiffrement faible (RC4, 0x17) pour un compte vulnérable — règle Wazuh custom `100011`.

**Statut** : ✅ Validé.

Compte ciblé : `user_asrep` (attribut `DoesNotRequirePreAuth` activé au préalable).

Attaque lancée depuis Kali avec `impacket-GetNPUsers` :

```bash
impacket-GetNPUsers lab.local/user_asrep -no-pass -dc-ip 192.168.202.167
```

Un premier essai a échoué avec `KDC_ERR_KEY_EXPIRED` (mot de passe du compte expiré côté AD) — corrigé via `Set-ADAccountPassword` + `PasswordNeverExpires`. Une fois le compte réinitialisé, le hash `$krb5asrep$23$user_asrep@LAB.LOCAL:...` a été extrait avec succès, confirmant la vulnérabilité du compte.

L'alerte a été déclenchée côté Wazuh dans la minute suivant l'attaque, visible dans Threat Hunting avec la règle `100011` (niveau 10).

Captures : `screenshots/attack-asrep-kali.jpg` (commande réussie), `screenshots/alert-asrep-roasting.png` (alerte dashboard).

## 2. Kerberoasting (T1558.003)

**Principe** : demande de tickets de service (TGS) pour des comptes de service, puis cassage hors-ligne du hash.

**Détection** : Event ID 4769 (demande de TGS) avec chiffrement RC4 en volume anormal sur un compte de service — règle Wazuh custom `100011` (fréquence ≥5 requêtes en 120s).

**Statut** : ✅ Validé.

Compte ciblé : `svc_http`, SPN enregistré `HTTP/webserver.lab.local`.

Attaque lancée depuis Kali avec `impacket-GetUserSPNs` en ciblant le domaine `lab.local`. Le hash TGS a été extrait avec succès, confirmant que le compte de service est exposé au Kerberoasting.

L'alerte correspondante est visible dans Threat Hunting, associée à l'agent WS-AD.

Captures : `screenshots/attack-kerberoasting-kali.jpg` (commande réussie), `screenshots/alert-kerberoasting.png` (alerte dashboard).

## 3. Brute-force (T1110)

**Principe** : tentatives répétées d'authentification sur un ou plusieurs comptes.

**Détection** : rafales d'Event ID 4625 (échec de logon) sur une fenêtre temporelle courte (règle `100012`, fréquence ≥8 échecs en 60s), potentiellement suivies d'un 4624 (succès) signalant une compromission (règle `100013`, `if_matched_sid` sur `100012`).

**Statut** : ✅ Validé côté détection.

Une rafale d'échecs d'authentification a été générée contre un compte AD, déclenchant la règle `100012`. La chaîne de détection compromission (`100013`) est en place et prête à se déclencher en cas de succès après échecs répétés.

Capture : `screenshots/alert-bruteforce.png` (alerte dashboard). *Pas de capture de la commande côté Kali pour cette attaque.*

## Chaîne d'attaque corrélée

Le module Python détecte les enchaînements suivants comme des chaînes d'attaque à risque élevé :

- AS-REP Roasting suivi d'un Kerberoasting sur le même host dans une fenêtre de 10 minutes → probable reconnaissance puis exploitation ciblée
- Brute-force suivi d'un logon réussi (4624) → compromission de compte probable

**Statut** : ✅ Module validé — le rapport de corrélation (`report.html`) enrichit les alertes brutes avec le mapping MITRE ATT&CK correspondant à chaque technique détectée.

Capture : `screenshots/python-correlation-report.png`.