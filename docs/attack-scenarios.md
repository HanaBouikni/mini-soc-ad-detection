# Scénarios d'attaque simulés

## 1. AS-REP Roasting (T1558.004)

**Principe** : extraction de hashs pour les comptes n'exigeant pas la pré-authentification Kerberos (`DONT_REQUIRE_PREAUTH`).

**Détection** : Event ID 4768 (demande de TGT) avec type de chiffrement faible (RC4, 0x17) pour un compte vulnérable.

**Statut** : à compléter avec captures d'écran et résultats une fois le lab rejoué.

## 2. Kerberoasting (T1558.003)

**Principe** : demande de tickets de service (TGS) pour des comptes de service, puis cassage hors-ligne du hash.

**Détection** : Event ID 4769 (demande de TGS) avec chiffrement RC4 en volume anormal sur un compte de service, hors des heures habituelles ou en rafale.

**Statut** : à compléter.

## 3. Brute-force (T1110)

**Principe** : tentatives répétées d'authentification sur un ou plusieurs comptes.

**Détection** : rafales d'Event ID 4625 (échec de logon) sur une fenêtre temporelle courte, potentiellement suivies d'un 4624 (succès) signalant une compromission.

**Statut** : à compléter.

## Chaîne d'attaque corrélée

Le module Python détecte les enchaînements suivants comme des chaînes d'attaque à risque élevé :

- AS-REP Roasting suivi d'un Kerberoasting sur le même host dans une fenêtre de 10 minutes → probable reconnaissance puis exploitation ciblée
- Brute-force suivi d'un logon réussi (4624) → compromission de compte probable

Cette section sera complétée avec les résultats réels, timelines et scores de risque obtenus lors des tests.
