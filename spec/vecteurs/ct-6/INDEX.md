# Vecteurs CT-6 — vérificateur

Produit par `scripts/vecteurs/generer-ct6.mjs` (`npm run vecteurs:ct6`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-6-verificateur.md`](../../CT-6-verificateur.md), annexe A.

Le générateur rejoue tout à l'identique, sauf trois entrées qu'il lit et ne réécrit jamais : `registre/capture/` (capture unique du réseau de développement, procédure dans `registre/capture/CAPTURE.md`), `rfc3161/cles/*.cle.pem` (clés RSA de test, publiques, dérivées de graines publiées, pour les tests seulement) et `confrontation/` (implémentations tierces).

Données de base : le journal `journal-sinistres` de CT-1, ses trois manifestes (`spec/vecteurs/ct-1/manifestes/periode-{1,2,3}.json`) et le dossier `spec/vecteurs/ct-1/dossiers/valide-seq-7/` (période 1). Les heures des blocs du registre sont celles de la capture (octobre 2026), antérieures aux dates fictives des manifestes (novembre 2026) : aucune vérification ne les compare (EX-A.9).

## Vérifier un dossier

```bash
node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet \
  --ancres spec/vecteurs/ct-6/ancres/ancres-test.json \
  --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json            # code 0
node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet --json   # sans ancres : 4, 5, 8 non exécutés
```

Chaque dossier porte un `attendu.json` (EX-A.3) : `anchors` et `bitcoin_headers` donnent, relativement au répertoire du dossier, le fichier d'ancres et le fichier d'en-têtes à passer au vérificateur (`null` : option omise).

Révision 0.2 : les dossiers `valide-point-de-controle-*`, `invalide-k*` et `invalide-r11-*` portent la treizième partie `points-de-controle.json` (CT-1 révision 0.3) bâtie sur le point de contrôle couvrant seq 7 de `spec/vecteurs/ct-1/points-de-controle/periode-1.json` (09:32:00.000Z, `tree_size` 8) ; ils se vérifient avec `ots/entetes/chaine-points.json` (EX-A.14) et, quand la référence au registre est non nulle, les parties de `registre/periode-1-point/` (EX-A.15). Exceptions : `valide-point-de-controle-point-contresigne` (point de 09:35:00.000Z, contresigné à D_7) et `valide-point-de-controle-point-de-cloture` (point de clôture, `tree_size` 9) portent un point plus tardif de la série avec un jeton construit par le générateur sur son `checkpoint_hash` (TSA de test, numéros de série 1002 et 1003, absent de `rfc3161/jetons`), `registry` et `ots` nuls : ils illustrent le choix du point couvrant d'EX-10.2 de CT-5 (AN-51), qui retient le point porteur d'un jeton plutôt que le point de 09:32, ancré au registre seul. Les cinquante dossiers antérieurs ne changent pas (EX-6.18).

## dossiers/

| Dossier | Ancres | En-têtes | Visée | En échec | Contrôles non exécutés | Avertissements | Code |
|---|---|---|---|---|---|---|---|
| `valide-seq-7-complet/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `valide-seq-7-complet-sans-ancres/` | aucune | chaine.json | — | aucune | 4, 5, 8 | — | 0 |
| `valide-seq-7-complet-sans-entetes/` | ancres-test.json | aucun | — | aucune | 5 | — | 0 |
| `valide-t11-qualification-declaree/` | ancres-qualification-declaree.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `valide-t7-deux-autorites/` | ancres-deux-autorites.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `valide-unite-sans-cn/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `invalide-t1-octet-en-trop/` | ancres-test.json | chaine.json | T-1 | T-1 | — | AV-O-3 | 1 |
| `invalide-t1-default-explicite/` | ancres-test.json | chaine.json | T-1 | T-1 | — | AV-O-3 | 1 |
| `invalide-t1-cn-utf8-invalide/` | ancres-test.json | chaine.json | T-1 | T-1 | — | AV-O-3 | 1 |
| `invalide-t2-jeton-autre-manifeste/` | ancres-test.json | chaine.json | T-2 | T-2 | — | AV-O-3 | 1 |
| `invalide-t3-message-digest/` | ancres-test.json | chaine.json | T-3 | T-3 | — | AV-O-3 | 1 |
| `invalide-t4-ess-autre-certificat/` | ancres-test.json | chaine.json | T-4 | T-4 | — | AV-O-3 | 1 |
| `invalide-t5-sha1/` | ancres-test.json | chaine.json | T-5 | T-5 | — | AV-O-3 | 1 |
| `invalide-t6-signature/` | ancres-test.json | chaine.json | T-6 | T-6 | — | AV-O-3 | 1 |
| `invalide-t7-tsa-expiree/` | ancres-test.json | chaine.json | T-7 | T-7 | — | AV-O-3 | 1 |
| `invalide-t8-eku-non-critique/` | ancres-test.json | chaine.json | T-8 | T-8 | — | AV-O-3 | 1 |
| `invalide-t9-extension-critique/` | ancres-test.json | chaine.json | T-9 | T-9 | — | AV-O-3 | 1 |
| `invalide-t10-tsa-revoquee/` | ancres-tsa-revoquee.json | chaine.json | T-10 | T-10 | — | AV-O-3 | 1 |
| `invalide-t10-unite-epinglee-revoquee/` | ancres-unite-epinglee-revoquee.json | chaine.json | T-10 | T-10 | — | AV-O-3 | 1 |
| `invalide-o1-octet-en-trop/` | ancres-test.json | chaine.json | O-1 | O-1 | — | — | 1 |
| `invalide-o2-preuve-autre-manifeste/` | ancres-test.json | chaine.json | O-2 | O-2 | — | AV-O-3 | 1 |
| `invalide-o3-resultat-trop-long/` | ancres-test.json | chaine.json | O-3 | O-3 | — | AV-O-3, AV-O-2 | 1 |
| `invalide-o4-mauvaise-hauteur/` | ancres-test.json | chaine.json | O-4 | O-4 | — | AV-O-3 | 1 |
| `invalide-o5-chaine-sans-travail/` | ancres-test.json | chaine-sans-travail.json | O-5 | O-5 | — | AV-O-3 | 1 |
| `non-execute-o5-point-de-controle-hors-entetes/` | ancres-test.json | chaine-depuis-1001.json | — | aucune | 5 | — | 0 |
| `non-execute-o6-profondeur/` | ancres-test.json | chaine-courte.json | — | aucune | 5 | AV-O-3 | 0 |
| `non-execute-o7-en-attente/` | ancres-test.json | chaine.json | — | aucune | 5 | AV-O-2 | 0 |
| `valide-deux-attestations/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-1, AV-O-3 | 0 |
| `valide-attente-uri-vide/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-3, AV-O-2 | 0 |
| `valide-o3-branche-hors-profil/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-2, AV-O-3 | 0 |
| `invalide-r1-sans-ancre/` | ancres-test.json | chaine.json | R-1 | R-1 | — | AV-O-3 | 1 |
| `invalide-r2-jeu-substitue/` | ancres-test.json | chaine.json | R-2 | R-2 | — | AV-O-3 | 1 |
| `invalide-r3-validateurs-declares/` | ancres-test.json | chaine.json | R-3 | R-3 | — | AV-O-3 | 1 |
| `invalide-r4-autre-chaine/` | ancres-autre-chaine.json | chaine.json | R-4 | R-4 | — | AV-O-3 | 1 |
| `invalide-r5-quorum/` | ancres-test.json | chaine.json | R-5 | R-5 | — | AV-O-3 | 1 |
| `invalide-r6-entete-modifie/` | ancres-test.json | chaine.json | R-6 | R-6 | — | AV-O-3 | 1 |
| `invalide-r7-recu-falsifie/` | ancres-test.json | chaine.json | R-7 | R-7 | — | AV-O-3 | 1 |
| `invalide-r8-autre-contrat/` | ancres-autre-registre.json | chaine.json | R-8 | R-8 | — | AV-O-3 | 1 |
| `invalide-r9-cloture-autre-periode/` | ancres-test.json | chaine.json | R-9 | R-9 | — | AV-O-3 | 1 |
| `invalide-r10-inscription-cle-inconnue/` | ancres-test.json | chaine.json | R-10 | R-10 | — | AV-O-3 | 1 |
| `invalide-n3-cle-enregistreur/` | ancres-cle-enregistreur-autre.json | chaine.json | N-3 | N-3 | — | AV-O-3 | 1 |
| `invalide-n4-cle-chaine/` | ancres-cle-chaine-autre.json | chaine.json | N-4 | N-4 | — | AV-O-3 | 1 |
| `valide-sans-inscription/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-3, AV-R-1 | 0 |
| `valide-ligne-non-canonique/` | ancres-test.json | chaine.json | — | aucune | — | AV-O-3, AV-R-2 | 0 |
| `valide-provenance-registre/` | ancres-sans-enregistreurs.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `valide-provenance-mixte/` | ancres-enregistreur-01-seul.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `valide-deux-jeux-validateurs/` | ancres-deux-jeux.json | chaine.json | — | aucune | — | AV-O-3 | 0 |
| `invalide-p1-manifeste-membre-en-trop/` | ancres-test.json | chaine.json | P-1 | P-1, P-5 | 4, 5, 8 | AV-O-3 | 1 |
| `valide-decision-refusee/` | aucune | aucun | — | aucune | 4, 5, 8 | — | 0 |
| `valide-decision-expiree/` | aucune | aucun | — | aucune | 4, 5, 8 | — | 0 |
| `valide-point-de-controle-complet/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3, AV-O-3 | 0 |
| `valide-point-de-controle-jeton-seul/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3 | 0 |
| `valide-point-de-controle-sans-ancre/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3 | 0 |
| `valide-point-de-controle-declare-absent/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3 | 0 |
| `valide-point-de-controle-sans-ancres-reviseur/` | aucune | chaine-points.json | — | aucune | 4, 5, 8 | — | 0 |
| `valide-point-de-controle-reference-declarative/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-K-1, AV-O-3, AV-O-3 | 0 |
| `valide-point-de-controle-point-contresigne/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3 | 0 |
| `valide-point-de-controle-point-de-cloture/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-3 | 0 |
| `valide-point-de-controle-ots-en-attente/` | ancres-test.json | chaine-points.json | — | aucune | — | AV-O-2, AV-O-3 | 0 |
| `invalide-k1-partie-inexploitable/` | ancres-test.json | chaine-points.json | K-1 | K-1 | — | AV-O-3 | 1 |
| `invalide-k1-double-defaut/` | ancres-test.json | chaine-points.json | K-1 | K-1 | — | AV-O-3 | 1 |
| `invalide-k7-jeton-autre-empreinte/` | ancres-test.json | chaine-points.json | K-7 | K-7 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-k7-jeton-signature/` | ancres-test.json | chaine-points.json | K-7 | K-7 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-k7-base64-non-canonique/` | ancres-test.json | chaine-points.json | K-7 | K-7 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-k8-empreinte/` | ancres-test.json | chaine-points.json | K-8 | K-8 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-k8-contrat/` | ancres-test.json | chaine-points.json | K-8 | K-8 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-k9-preuve-autre-empreinte/` | ancres-test.json | chaine-points.json | K-9 | K-9 | — | AV-O-3, AV-O-3 | 1 |
| `invalide-r11-ancre-de-periode/` | ancres-test.json | chaine-points.json | R-11 | R-11 | — | AV-O-3, AV-O-3 | 1 |

- `valide-seq-7-complet/` : Dossier valide-seq-7 de CT-1, ses sept parties inchangées, complété du jeton de la période 1 (rfc3161/jetons/periode-1.der), de sa preuve OpenTimestamps (ots/preuves/periode-1.ots) et des trois parties du registre de la période 1 (registre/periode-1/ : inscriptions de rec-test-01 et rec-test-02, ancre et clôture). Les huit contrôles réussissent ; T-11 n'est pas exécutée (aucun statut qualifié déclaré), l'énoncé ne dit pas « qualifié ».
- `valide-seq-7-complet-sans-ancres/` : Le même dossier, vérifié sans fichier d'ancres (avec chaine.json) : les contrôles 4, 5 et 8 ne sont pas exécutés (ancre_absente) ; N-3 et N-4 ne figurent pas au rapport ; aucun avertissement (AV-O-3 exige O-5 exécutée).
- `valide-seq-7-complet-sans-entetes/` : Le même dossier, vérifié avec ancres-test.json et sans fichier d'en-têtes : contrôle 5 non exécuté (partie_absente, EX-4.5).
- `valide-t11-qualification-declaree/` : Le même dossier, vérifié avec ancres-qualification-declaree.json : T-11 réussie ; l'énoncé dit « horodatage qualifié eIDAS selon le réviseur (déclaration de test, sans valeur) ».
- `valide-t7-deux-autorites/` : Le même dossier, vérifié avec ancres-deux-autorites.json (l'unité tsa-test.pem épinglée, statut qualifié déclaré, puis ac-test.pem) : T-7 retient la première autorité du fichier pour laquelle un chemin existe, par l'identité (EX-9.13) ; T-10 n'a rien à prouver ; T-11 réussie ; l'énoncé nomme « Unité TSA épinglée de test CT-6 ».
- `valide-unite-sans-cn/` : jeton-rfc3161.der = rfc3161/jetons/periode-1-unite-sans-cn.der : le sujet de l'unité tsa-sans-cn.pem n'a pas de commonName ; tsu_subject_cn est nul, et l'énoncé nomme l'unité par le SHA-256 de son certificat (EX-9.19, EX-9.20).
- `invalide-t1-octet-en-trop/` : jeton-rfc3161.der = rfc3161/jetons/t1-octet-en-trop.der : un octet 00 après le ContentInfo.
- `invalide-t1-default-explicite/` : jeton-rfc3161.der = rfc3161/jetons/t1-default-explicite.der : certificat de l'unité dont une extension encode critical à FALSE, valeur DEFAULT (EX-9.21).
- `invalide-t1-cn-utf8-invalide/` : jeton-rfc3161.der = rfc3161/jetons/t1-cn-utf8-invalide.der : certificat de l'unité dont le CN est une UTF8String d'octets ff fe, UTF-8 invalide (EX-9.4).
- `invalide-t2-jeton-autre-manifeste/` : jeton-rfc3161.der = rfc3161/jetons/periode-2.der : jeton de la période 2 dans un dossier de la période 1 (rejeu sur un autre manifeste).
- `invalide-t3-message-digest/` : jeton-rfc3161.der = rfc3161/jetons/t3-message-digest.der : genTime avancé d'une seconde dans TSTInfo, message-digest inchangé.
- `invalide-t4-ess-autre-certificat/` : jeton-rfc3161.der = rfc3161/jetons/t4-ess-autre-certificat.der : certHash de ESSCertIDv2 = SHA-256 de ac-test.pem.
- `invalide-t5-sha1/` : jeton-rfc3161.der = rfc3161/jetons/t5-sha1.der : digestAlgorithm et signature en SHA-1.
- `invalide-t6-signature/` : jeton-rfc3161.der = rfc3161/jetons/t6-signature.der : dernier octet de la signature inversé.
- `invalide-t7-tsa-expiree/` : jeton-rfc3161.der = rfc3161/jetons/t7-tsa-expiree.der : certificat de la TSA expiré à genTime.
- `invalide-t8-eku-non-critique/` : jeton-rfc3161.der = rfc3161/jetons/t8-eku-non-critique.der : extKeyUsage non critique.
- `invalide-t9-extension-critique/` : jeton-rfc3161.der = rfc3161/jetons/t9-extension-critique.der : extension critique inconnue dans TSTInfo.
- `invalide-t10-tsa-revoquee/` : Le dossier complet, vérifié avec ancres-tsa-revoquee.json : le certificat de la TSA est révoqué pour keyCompromise ; T-10 échoue.
- `invalide-t10-unite-epinglee-revoquee/` : Le dossier complet, vérifié avec ancres-unite-epinglee-revoquee.json : le réviseur épingle l'unité elle-même, et la CRL de son fichier d'ancres la révoque pour keyCompromise avant genTime ; T-10 échoue sur le certificat de l'autorité (EX-9.16).
- `invalide-o1-octet-en-trop/` : preuve.ots = ots/preuves/o1-octet-en-trop.ots : un octet après l'arbre. O-5 n'est pas exécutée : pas d'AV-O-3.
- `invalide-o2-preuve-autre-manifeste/` : preuve.ots = ots/preuves/periode-2.ots : preuve de la période 2 dans un dossier de la période 1.
- `invalide-o3-resultat-trop-long/` : preuve.ots = ots/preuves/o3-resultat-trop-long.ots : branche f0 d'un argument de 4096 octets, message de plus de 4096 octets.
- `invalide-o4-mauvaise-hauteur/` : preuve.ots = ots/preuves/o4-mauvaise-hauteur.ots : attestation à la hauteur 1002.
- `invalide-o5-chaine-sans-travail/` : Le dossier complet, vérifié avec ots/entetes/chaine-sans-travail.json : l'en-tête 1010 n'a pas de preuve de travail.
- `non-execute-o5-point-de-controle-hors-entetes/` : Le dossier complet, vérifié avec ots/entetes/chaine-depuis-1001.json (1001 à 1020) : le point de contrôle 1000 du réviseur n'est pas dans le fichier ; O-5 non exécutée (ancre_absente, EX-10.9), contrôle 5 non exécuté ; dossier valide. O-5 n'est pas exécutée : pas d'AV-O-3.
- `non-execute-o6-profondeur/` : Le dossier complet, vérifié avec ots/entetes/chaine-courte.json (990 à 1003) : 3 confirmations pour 6 exigées ; contrôle 5 non exécuté (ancre_absente) ; dossier valide.
- `non-execute-o7-en-attente/` : preuve.ots = ots/preuves/o7-en-attente.ots : une seule attestation en attente ; contrôle 5 non exécuté (partie_absente) ; dossier valide. O-5 n'est pas exécutée : pas d'AV-O-3.
- `valide-deux-attestations/` : preuve.ots = ots/preuves/deux-attestations.ots : attestations à 1001 (concordante) et 1002 (discordante) ; AV-O-1.
- `valide-attente-uri-vide/` : preuve.ots = ots/preuves/attente-uri-vide.ots : à côté de la branche Bitcoin attestée à 1001, une attestation en attente d'URI vide, que la bibliothèque de référence admet (EX-10.2) ; O-1 réussie ; AV-O-2.
- `valide-o3-branche-hors-profil/` : preuve.ots = ots/preuves/branche-hors-profil.ots : une seconde branche 03 (ripemd160, hors profil) finie par une attestation Bitcoin, non exécutée ; O-3 réussie, les opérations hors profil ne changeant pas son statut (EX-10.7) ; AV-O-2.
- `invalide-r1-sans-ancre/` : parties du registre de registre/variantes/invalide-r1-sans-ancre/ : entrée ancre retirée de registre.json.
- `invalide-r2-jeu-substitue/` : parties du registre de registre/variantes/invalide-r2-jeu-substitue/ : certificats re-signés par un jeu substitué, déclaré par validateurs.json.
- `invalide-r3-validateurs-declares/` : parties du registre de registre/variantes/invalide-r3-validateurs-declares/ : validateurs.json déclare un autre jeu que celui qui a signé.
- `invalide-r4-autre-chaine/` : le dossier complet, vérifié avec ancres-autre-chaine.json : chain_id noortrace-9999-test dans l'ancre.
- `invalide-r5-quorum/` : parties du registre de registre/variantes/invalide-r5-quorum/ : une ligne de precommit retirée du certificat de la clôture, qui portait le quorum exact.
- `invalide-r6-entete-modifie/` : parties du registre de registre/variantes/invalide-r6-entete-modifie/ : timestamp + 1 dans block de l'entrée cloture.
- `invalide-r7-recu-falsifie/` : parties du registre de registre/variantes/invalide-r7-recu-falsifie/ : topics[2] du journal de la clôture remplacé par 0x11…11.
- `invalide-r8-autre-contrat/` : le dossier complet, vérifié avec ancres-autre-registre.json : period_registry = adresse d'AttestationRegistry dans l'ancre.
- `invalide-r9-cloture-autre-periode/` : parties du registre de registre/variantes/invalide-r9-cloture-autre-periode/ : entrées cloture et ancre et leurs certificats pris dans registre/periode-2/.
- `invalide-r10-inscription-cle-inconnue/` : parties du registre de registre/variantes/invalide-r10-inscription-cle-inconnue/ : inscription de rec-test-03, clé absente de cles.json, et certificat de son bloc ajoutés.
- `invalide-n3-cle-enregistreur/` : Le dossier complet, vérifié avec ancres-cle-enregistreur-autre.json : la clé publique de rec-test-01 dans l'ancre est celle de rec-test-02 ; N-3 échoue, contrôle 6 en échec.
- `invalide-n4-cle-chaine/` : Le dossier complet, vérifié avec ancres-cle-chaine-autre.json : la chain_key de rec-test-02 dans l'ancre est celle de rec-test-01 ; N-4 échoue, contrôle 8 en échec.
- `valide-sans-inscription/` : parties du registre de registre/variantes/valide-sans-inscription/ : inscriptions retirées ; R-10 non exécutée (partie_absente), sans effet sur le contrôle 8 ; AV-R-1.
- `valide-ligne-non-canonique/` : parties du registre de registre/variantes/valide-ligne-non-canonique/ : membre « Domain » dans une ligne de precommit, accepté par le décodeur du nœud ; AV-R-2.
- `valide-provenance-registre/` : Le dossier complet, vérifié avec ancres-sans-enregistreurs.json : N-3 et N-4 ne figurent pas ; les deux clés de l'énoncé sont confirmées par les inscriptions que R-10 prouve, provenance « registre » (EX-6.8).
- `valide-provenance-mixte/` : parties du registre de registre/variantes/valide-provenance-mixte/ (inscription de rec-test-01 retirée), vérifiées avec ancres-enregistreur-01-seul.json : rec-test-01 est confirmée par N-3 seulement, rec-test-02 par l'inscription que R-10 prouve ; l'énoncé écrit la provenance clé par clé (EX-6.8) ; N-4 ne figure pas.
- `valide-deux-jeux-validateurs/` : Le dossier complet, vérifié avec ancres-deux-jeux.json : les blocs des inscriptions et de l'ancre relèvent du premier jeu, celui de la clôture du second ; la proposition de l'énoncé nomme les deux groupes (EX-11.22).
- `invalide-p1-manifeste-membre-en-trop/` : manifeste.json porte un membre « extra » de plus (dossier.json réindexé) : P-1 échoue, et P-5 aussi, la forme canonique du manifeste modifié n'étant plus celle que manifeste.sig signe ; periodHash n'est pas recalculé pour les ancres ; T-2, O-2, R-9 et R-10 sont non exécutées (prerequis_en_echec), toutes les autres vérifications T-, O- et R- s'exécutent (EX-5.4) ; le contrôle 5 n'est pas réussi sans O-2 (EX-10.12).
- `valide-decision-refusee/` : Dossier de la décision (seq 6) d'une variante du journal de CT-1 produite par scripts/vecteurs/ct6/decisions.mjs : décision du ticket apr-2201 refusée (decision = refuse), signée par les comptes Hardhat 1 et 2 ; l'énoncé dit « porte un refus signé par » (EX-6.8, F3). Les cinq parties réservées sont absentes (hors périmètre CT-1) ; vérifié sans ancres.
- `valide-decision-expiree/` : Dossier de la décision (seq 6) d'une variante du journal de CT-1 produite par scripts/vecteurs/ct6/decisions.mjs : décision du ticket apr-2201 expirée (decision = expire), sans approbateur ni signature ; l'énoncé dit « porte une demande d'approbation expirée sans signature » et facts.approval.approvers est vide (EX-6.8, F3). Les cinq parties réservées sont absentes (hors périmètre CT-1) ; vérifié sans ancres.
- `valide-point-de-controle-complet/` : valide-seq-7-complet dont l'index passe à treize parties : points-de-controle.json porte le point de contrôle couvrant seq 7 (série de CT-1, 09:32:00.000Z, tree_size 8, signé par rec-test-01), la preuve de cohérence de huit feuilles vers neuf, le jeton rfc3161/jetons/point-periode-1.der, la preuve ots/preuves/point-periode-1.ots (attestation à 1004, en-têtes chaine-points.json) et la référence à l'ancre du point au registre ; parties du registre de registre/periode-1-point/ (entrée ancre_point_de_controle). K-1 à K-9 et R-11 réussies ; FK avec ses trois clauses ; facts.checkpoint complet (inclusion prouvee) ; AV-O-3 deux fois (K-9 et O-5).
- `valide-point-de-controle-jeton-seul/` : Même partie avec le seul jeton du point (registry et ots nuls), parties du registre de periode-1/ : K-8 et K-9 non exécutées (partie_absente), R-11 non exécutée (partie_absente, aucune entrée) ; FK avec la seule clause jeton ; F7 absent (les huit contrôles réussissent).
- `valide-point-de-controle-sans-ancre/` : Même partie avec les trois ancres nulles : K-7 à K-9 non exécutées (partie_absente) ; pas de FK ; facts.checkpoint non nul à timestamp, bitcoin et registry nuls ; énoncé égal à celui de valide-seq-7-complet.
- `valide-point-de-controle-declare-absent/` : Treize parties déclarées, la treizième absente avec la raison « aucun point de contrôle » : aucune vérification K- au rapport, absent_parts la porte ; énoncé, statuts et borne égaux à ceux de valide-seq-7-complet (EX-6.18).
- `valide-point-de-controle-sans-ancres-reviseur/` : Comme valide-point-de-controle-complet, vérifié sans fichier d'ancres (avec chaine-points.json) : K-7, K-8 et K-9 non exécutées (ancre_absente) comme les contrôles 4, 5 et 8 ; pas de FK ; les K- ne changent aucun statut (EX-5.8) ; aucun avertissement (O-5 non exécutée).
- `valide-point-de-controle-reference-declarative/` : Comme valide-point-de-controle-complet, parties du registre de periode-1/ (sans l'entrée ancre_point_de_controle) : K-8 réussie, inclusion declarative, AV-K-1 ; R-11 non exécutée (partie_absente) ; FK sans clause registre.
- `valide-point-de-controle-point-contresigne/` : Partie bâtie sur le point de 09:35:00.000Z (tree_size 8), celui que le planificateur de CT-5 contresigne à l'échéance D_7 (c_T = 300 s), porteur d'un jeton de la TSA de test sur son checkpoint_hash (genTime 09:35:02Z, numéro de série 1002) ; registry et ots nuls : le point de 09:32 de même tree_size est ancré au registre seul, et la règle d'EX-10.2 (CT-5), de CT-1 §11.2 et d'EX-13.18 (CT-6) retient le point qui porte un jeton promu. K-1 à K-7 réussies ; K-8 et K-9 non exécutées (partie_absente) ; FK avec la seule clause jeton. Le jeton est construit par le générateur et ne figure pas dans rfc3161/jetons.
- `valide-point-de-controle-point-de-cloture/` : Partie bâtie sur le point de clôture de la période 1 (10:00:00.300Z, tree_size 9 = count), porteur d'un jeton de la TSA de test sur son checkpoint_hash (genTime 10:00:02Z, numéro de série 1003) ; preuve de cohérence de neuf feuilles vers neuf, chemin vide (CT-1 §10.7) ; K-6 non exécutée pour une raison admise (l'événement last_seq, seq 9, est hors du dossier) ; K-8 et K-9 non exécutées (partie_absente) ; FK avec la seule clause jeton. Le jeton est construit par le générateur et ne figure pas dans rfc3161/jetons.
- `valide-point-de-controle-ots-en-attente/` : Comme valide-point-de-controle-complet avec ots/preuves/point-periode-1-en-attente.ots (une attestation en attente) : K-9 non exécutée (partie_absente, O-7), AV-O-2 (K-9) ; FK sans clause Bitcoin.
- `invalide-k1-partie-inexploitable/` : points-de-controle.json réduit au littéral JSON null (index recalculé) : K-1 échoue, K-2 à K-9 non exécutées (prerequis_en_echec, dans blocking_unexecuted), contrôle 3 en échec ; R-11 non exécutée (partie_absente) ; les contrôles 4, 5 et 8 réussissent sur le manifeste (EX-5.8).
- `invalide-k1-double-defaut/` : Partie de valide-point-de-controle-complet portant un membre « extra » hors du schéma et un chemin de cohérence tronqué (dernier nœud retiré), index recalculé : K-1 échoue sur le schéma ; K-2 à K-9 non exécutées (prerequis_en_echec, dans blocking_unexecuted), si bien que le chemin tronqué n'est pas examiné et K-5 n'est pas en échec (CT-6 EX-5.9, CT-1 §11.4) ; failed_checks = [K-1] ; contrôle 3 en échec.
- `invalide-k7-jeton-autre-empreinte/` : Le jeton de la clôture (rfc3161/jetons/periode-1.der) embarqué comme jeton du point : T-2 du point en échec, K-7 échoue, contrôle 4 en échec ; les T- de la clôture restent réussies.
- `invalide-k7-jeton-signature/` : Jeton du point rfc3161/jetons/k7-point-signature.der (dernier octet de la signature inversé) : T-6 du point en échec, K-7 échoue, contrôle 4 en échec.
- `invalide-k7-base64-non-canonique/` : token dont le dernier caractère utile porte des bits de bourrage non nuls (même longueur, même remplissage : le motif du schéma passe, K-1 réussie) : le décodage n'est pas canonique, K-7 échoue (jeton inexploitable, EX-4.14), contrôle 4 en échec.
- `invalide-k8-empreinte/` : anchors.registry.fingerprint remplacée par 0x11…11 : K-8 échoue, contrôle 8 en échec ; R-11 réussie (l'entrée est authentique et son topics[1] égale le recalcul : seule la référence de la partie est fausse).
- `invalide-k8-contrat/` : anchors.registry.contract = adresse de PeriodRegistry : K-8 échoue, contrôle 8 en échec ; R-11 réussie (l'entrée, elle, est émise par AttestationRegistry).
- `invalide-k9-preuve-autre-empreinte/` : La preuve de la clôture (ots/preuves/periode-1.ots) embarquée comme preuve du point : O-2 du point en échec, K-9 échoue, contrôle 5 en échec.
- `invalide-r11-ancre-de-periode/` : Parties du registre de registre/variantes/invalide-r11-ancre-de-periode/ (entrée ancre de la période 1, bloc 16660, dupliquée sous le rôle ancre_point_de_controle) ; anchors.registry de la partie porte l'empreinte et le docType du point mais désigne ce bloc et cette transaction : R-11 échoue (règle 1 : docType de période), R-6 et R-7 réussies (bloc authentique), K-8 réussie, contrôle 8 en échec.

## ancres/

| Fichier | Contenu |
|---|---|
| `ancres-test.json` | autorité ac-test.pem (politique d'essai admise, qualified = null), crl-vide.pem ; bitcoin regtest, point de contrôle 1000, profondeur 6 ; registry de capture.json et validators.json ; recorders rec-test-01 et rec-test-02 avec leurs clés de chaîne |
| `ancres-qualification-declaree.json` | idem, qualified = {eidas, 2026-01-01, sans fin, « déclaration de test, sans valeur »} |
| `ancres-tsa-revoquee.json` | idem, crl-tsa-revoquee.pem à la place de crl-vide.pem (tsa-test.pem révoqué le 2026-11-05T12:00:00Z, keyCompromise) |
| `ancres-autre-chaine.json` | idem, registry.chain_id = noortrace-9999-test |
| `ancres-autre-registre.json` | idem, period_registry = adresse d'AttestationRegistry |
| `ancres-cle-enregistreur-autre.json` | idem, public_key de rec-test-01 remplacée par celle de rec-test-02 |
| `ancres-cle-chaine-autre.json` | idem, chain_key de rec-test-02 remplacée par celle de rec-test-01 |
| `ancres-sans-enregistreurs.json` | idem, recorders vide : aucune clé d'enregistreur ne vient du fichier d'ancres (N-3 et N-4 absentes) ; les clés sont confirmées par les inscriptions que R-10 prouve |
| `ancres-enregistreur-01-seul.json` | idem, recorders réduit à rec-test-01 (provenance mixte des clés, EX-6.8 ; N-4 absente) |
| `ancres-deux-jeux.json` | idem, registry.validator_sets coupé en deux jeux de mêmes clés, l'un jusqu'au bloc de l'ancre de la période 1, l'autre au-delà (EX-11.22) |
| `ancres-unite-epinglee-revoquee.json` | idem, autorité = l'unité tsa-test.pem elle-même (« Unité TSA épinglée de test CT-6 ») et crl-tsa-revoquee.pem, qui la révoque pour keyCompromise : T-10 échoue (EX-9.16) |
| `ancres-deux-autorites.json` | idem, deux autorités : l'unité tsa-test.pem épinglée (qualified eidas déclaré), puis ac-test.pem ; crl-vide.pem. T-7 retient la première (EX-9.13) |

## rfc3161/ (contrôle 4)

Autorité de test et TSA de test à clés RSA 3072 publiques (`rfc3161/cles/`), CRL de test (`rfc3161/crl/`), jetons (`rfc3161/jetons/`). Attendus : `rfc3161/attendu.json`.

| Jeton | periodHash (checkpoint_hash pour le jeton du point) | genTime | Visée | SHA-256 |
|---|---|---|---|---|
| `jetons/periode-1.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | — | `0xdbfb99a9cd7a6b022614b62957cd4f9e17a168a43efa7dee729503937af58d13` |
| `jetons/periode-2.der` | `0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19` | 2026-11-05T11:00:05Z | — | `0x79ae36a3821fdfe4d65bcb2a1781ee8667356a99d0f5e6c384ac92ea0545ec03` |
| `jetons/periode-3.der` | `0x5852e3c7f403875b9b634f5e5d7074ea197fc34ecf80e092b9686d8c2dc80594` | 2026-11-05T12:00:05Z | — | `0x79ccf23495b5356dff57577e77d9e8fdf5ecdad48e99bbcdb9bb2163b1ffc6f0` |
| `jetons/t1-octet-en-trop.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-1 | `0x77a0e9496ccd1e967c868cc5a6232b5ba9cebe4ea97e382fa6914f135fdf7239` |
| `jetons/t3-message-digest.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:06Z | T-3 | `0x9dba5465d44dda53ead1722a24fcafb4811a814f0a49b2b24e3549df9dd31c89` |
| `jetons/t4-ess-autre-certificat.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-4 | `0xa2fe0c8f5591523b6b53a046d5ccb061467fd19cfc6b12cb2bef7be6dd4ff044` |
| `jetons/t5-sha1.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-5 | `0xfff90cf64db42bc9d6139dfe37ac1aa0e99ac28cc1de8d79c01125a8201e0494` |
| `jetons/t6-signature.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-6 | `0xa36be096a4faacfe5cdaaf7f2687a013d72221763434aad926ee95debbf20eec` |
| `jetons/t7-tsa-expiree.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-7 | `0x185b86e2785130a030e72a9cf1c7f03373770e6bce946212e175ec30c5023a7d` |
| `jetons/t8-eku-non-critique.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-8 | `0xa9bc9d1ed5b566627fa936be88fa199f367f47f9c78fa156205459bfe3643b3a` |
| `jetons/t9-extension-critique.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-9 | `0xa34eb4fc9cdb6b323c29c5d2b531583641e10dcb5c9199f6d09f7d23d3c1914d` |
| `jetons/t1-default-explicite.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-1 | `0xd17544c5512de273fe4152d14502760b68f54447d23b88aa551a906dc7b11067` |
| `jetons/t1-cn-utf8-invalide.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | T-1 | `0xc5d96c9f3c0e7bc354cd23cfa98ff0e5c026343b264220d3c4d84588489a790a` |
| `jetons/periode-1-unite-sans-cn.der` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | 2026-11-05T10:00:05Z | — | `0x9fbb5ea0074cb8d0d2ff3fea8c53d9df80ae57b4c82b18eca9f44d0f4cfe2551` |
| `jetons/point-periode-1.der` | `0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4` | 2026-11-05T09:32:02Z | — | `0x00734a31b38e888bebe7af85a63144779e68be09e6424e2213c6e0f97abf09cf` |
| `jetons/k7-point-signature.der` | `0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4` | 2026-11-05T09:32:02Z | T-6 | `0x8bb6b5ede744f6ef4162523c5f6e1436f237205b70a74baa31d496bfe279e428` |

## ots/ (contrôle 5)

Chaîne regtest synthétique (`ots/entetes/`), point de contrôle 1000 (`0x30f16c707dbc79c93c3d9d5279170f623d3f0d691735c0670ea90bb16087b3a0`), profondeur minimale 6. Attendus : `ots/attendu.json`. `chaine-points.json` (révision 0.2) : mêmes en-têtes 990 à 1003 que `chaine.json`, racine 1004 égale au résultat de `preuves/point-periode-1.ots`, en-têtes 1004 à 1020 recalculés.

| Preuve | Empreinte de fichier | Visée | SHA-256 |
|---|---|---|---|
| `preuves/periode-1.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | — | `0xf70b77c15a5226d537f34d7288a5b296cad3c0dbd5b0d2fc79d679e5dc3cff1f` |
| `preuves/periode-2.ots` | `0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19` | — | `0xeb16dead539d000f78234d1cedda4a9168800e013a3e78e1a97ea6081bb710e0` |
| `preuves/periode-3.ots` | `0x5852e3c7f403875b9b634f5e5d7074ea197fc34ecf80e092b9686d8c2dc80594` | — | `0x4a061d21b2305142a9a8be8592b0eed9aa2d24a001a7a97b54ab8b534f387c6d` |
| `preuves/o1-octet-en-trop.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | O-1 | `0xad4512c241e146db792f6002543947fae9133fce32e2cc30bcf4d315f1dd7850` |
| `preuves/o3-resultat-trop-long.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | O-3 | `0x781ea6b317e9abe6a6f70f4a007caf1a888d9906529eb10163e158f90f8cd6b3` |
| `preuves/o4-mauvaise-hauteur.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | O-4 | `0x305dc8022c1a34354b7ad6a1e8a1ec799a6af7fb75f92285e8ff0439d8bc4e44` |
| `preuves/o7-en-attente.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | O-7 | `0xa928d3f5bdb6a2eaa7173eae9bb6bfe2fd57513983369c953b263ddcfba39b26` |
| `preuves/deux-attestations.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | — | `0xd3a21c0afb5e8d4d8e1df7ca90c6720b630bc917819c6dd890e0cc293cae7a32` |
| `preuves/attente-uri-vide.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | — | `0x7d872b32550ab04bc69a8f01c013a26880654f54a3f506c19a1889dff5468252` |
| `preuves/branche-hors-profil.ots` | `0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914` | — | `0x63c1ff77939ab1a9ecc659d356eb598d576e730f811a57997d033fd4892a0062` |
| `preuves/point-periode-1.ots` | `0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4` | — | `0x559c12fd7a8b11d11cc2f804be2b23ee5d97b797ad3209901d2d9590156d3961` |
| `preuves/point-periode-1-en-attente.ots` | `0x93acd0fc36f93d7a267367e22367154e875d38c6368c527649d298619c90a4f4` | — | `0x5c69f4a86b49d23f5a5fc655d787b50d14941e4a80aba235c4fb0ce22e021246` |

## registre/ (contrôle 8)

Capture unique du 2026-10-22T22:21:03.442Z sur le réseau de développement `noortrace-2124-dev` (noorcore `618fcef` et correctif `0001-noor_getCommitCertificate.patch`), complétée de l'ancre du point de contrôle couvrant seq 7 (bloc 18928, rôle `ancre_point_de_controle`, EX-A.15), procédure dans `registre/capture/CAPTURE.md`. Jeu de validateurs de hachage `0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751`. `periode-1-point/` est `periode-1/` plus cette entrée et son certificat.

| Bloc | Rôle | Hachage BFT | Racine des reçus |
|---|---|---|---|
| 16648 | inscription (rec-test-01) | `0x73f5b9980d64ce2b8c63d20d3590281cf09eec86a980fe4293eca4157fcc2da2` | `0xb3c82c3469e6e3a68d778f93f268c0377668012108f4bae1936e2804f161f8ef` |
| 16652 | inscription (rec-test-02) | `0x73483f231f12206f373d70201b0be12ec5610f14ebf7745a64e2e19c18f7f27d` | `0x6f928b897911ec2d1317f55e0d9ec60f81b355b98acad2885b278f7f3f9ddcc1` |
| 16656 | inscription (rec-test-03) | `0x6e907c1f5304e76ab5a4542959cc12fa94e589474830f8719e4e880b39468da8` | `0xda74d270a7274ccb6826937b9b43c9e376a918730b712622b08e55a66c61455e` |
| 16660 | ancre (période 1) | `0x1e371008e09681b8a3d5a1b5515f1271bafbd418950488692608f2c500b861ee` | `0x3e8c30f8511077b2a5388f6f551c496dd5e5b9f22634d440aa58be73c6fb5638` |
| 16664 | ancre (période 2) | `0x593377aa5a1e891d7c3d5aabaeb0915a52826eedd85b846e7570cef354538323` | `0xa30e3a290a5dc7b5745674908f0156acd491adf73511c09fbe451dd9d9d3b0a8` |
| 16668 | cloture (période 1) | `0xe59edea93690470f375dc54ef19cb6c69d1ed5e916bdd7a5f810e10f4e375d3e` | `0x50fb8e0b920bd3ba439d52978a8488884a223593c1a778715a1eec5a99b5059c` |
| 16672 | cloture (période 2) | `0xc27d3fee203a5361fc5d5ef200a4326b9742288b108cd038ae5889012107058f` | `0xfd2d267fcddcc3d09951eb9fd3a70397311a1f811f9b155ffff6f57ac1041128` |
| 18928 | ancre_point_de_controle (rec-test-01) (période 1) | `0x3bbf473dc07a2b10039d0064472ea7205e412b6d038dbb4d7e9219e09e70612b` | `0xd6aa475698d5f2e0424d99c2c3b8de6ff984799ae3a67ce2cd590bfa20f3b9d7` |

| Jeu de parties | Ancres | Contrôle 8 | Non exécutées |
|---|---|---|---|
| periode-1, ancres-test.json | ancres-test.json | reussi | — |
| periode-2, ancres-test.json | ancres-test.json | reussi | — |
| periode-1, sans fichier d'ancres | aucune | non_execute (ancre_absente) | R-2 (ancre_absente), R-4 (ancre_absente), R-5 (ancre_absente), R-8 (ancre_absente) |
| periode-1, ancres-sans-enregistreurs.json | ancres-sans-enregistreurs.json | reussi | — |
| periode-1, validateurs.json absent | ancres-test.json | reussi | R-3 (partie_absente) |
| periode-1-point, ancres-test.json, partie points-de-controle.json rattachée | ancres-test.json | reussi | — |
| periode-1-point, ancres-test.json, sans partie points-de-controle.json | ancres-test.json | reussi | R-11 (partie_absente) |

R-11 (ancre d'un point de contrôle du journal, révision 0.2) ne figure au rapport qu'avec la partie `points-de-controle.json` déclarée présente ou une entrée `ancre_point_de_controle` ; les jeux sans l'un ni l'autre gardent les vérifications de la version 0.1.

| Variante | Vérification visée | Ancres | En échec | Non exécutées | Avertissements |
|---|---|---|---|---|---|
| `invalide-r1-sans-ancre` | R-1 | ancres-test.json | R-1 | R-2 (prerequis_en_echec), R-3 (prerequis_en_echec), R-4 (prerequis_en_echec), R-5 (prerequis_en_echec), R-6 (prerequis_en_echec), R-7 (prerequis_en_echec), R-8 (prerequis_en_echec), R-9 (prerequis_en_echec), R-10 (prerequis_en_echec), N-4 (prerequis_en_echec) | — |
| `invalide-r2-jeu-substitue` | R-2 | ancres-test.json | R-2 | R-5 (prerequis_en_echec), N-4 (prerequis_en_echec) | — |
| `invalide-r3-validateurs-declares` | R-3 | ancres-test.json | R-3 | — | — |
| `invalide-r4-autre-chaine` | R-4 | ancres-autre-chaine.json | R-4 | — | — |
| `invalide-r5-quorum` | R-5 | ancres-test.json | R-5 | — | — |
| `invalide-r6-entete-modifie` | R-6 | ancres-test.json | R-6 | R-8 (prerequis_en_echec), R-9 (prerequis_en_echec) | — |
| `invalide-r7-recu-falsifie` | R-7 | ancres-test.json | R-7 | R-8 (prerequis_en_echec), R-9 (prerequis_en_echec) | — |
| `invalide-r8-autre-contrat` | R-8 | ancres-autre-registre.json | R-8 | — | — |
| `invalide-r9-cloture-autre-periode` | R-9 | ancres-test.json | R-9 | — | — |
| `invalide-r10-inscription-cle-inconnue` | R-10 | ancres-test.json | R-10 | — | — |
| `invalide-n4-cle-chaine` | N-4 | ancres-cle-chaine-autre.json | N-4 | — | — |
| `invalide-r11-ancre-de-periode` | R-11 | ancres-test.json | R-11 | — | — |
| `valide-sans-inscription` | — | ancres-test.json | aucune | R-10 (partie_absente) | AV-R-1 |
| `valide-provenance-mixte` | — | ancres-enregistreur-01-seul.json | aucune | — | — |
| `valide-deux-jeux` | — | ancres-deux-jeux.json | aucune | — | — |
| `valide-ligne-non-canonique` | — | ancres-test.json | aucune | — | AV-R-2 |

Les racines des reçus synthétiques et des couples génériques sont dans `registre/trie.json` ; go-ethereum et noorcore les recalculent dans `confrontation/registre/` (sortie : `confrontation/sorties/registre.txt`).

