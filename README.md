# Polymarkets

Outils pour mesurer, collecter et simuler les écarts de cotation sur Polymarket.
Tout passe par les API publiques, sans compte ni clé. Le dépôt ne contient aucun
outil de passage d'ordres : il lit des données publiques et rejoue des stratégies
en paper trading.

Trois commandes :

| Commande | Rôle |
|---|---|
| `polyscan scan` | mesure instantanée des écarts sur tout le catalogue |
| `polyscan watch` | collecte continue des carnets et transactions de marchés sélectionnés |
| `polyscan simulate` | rejoue les données collectées avec une stratégie de market making |

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Sans installation : `PYTHONPATH=src python3 -m polyscan ...`

## 1. `scan` : les écarts en direct

Polymarket cote chaque issue entre 0 et 1 $. Le scan parcourt le catalogue
complet par pagination keyset et mesure :

1. **Somme des issues d'un événement à plusieurs issues.** Sur un événement
   « negative risk », une seule issue paie 1 $. Si la somme des meilleurs prix
   vendeurs est inférieure à 1 $, acheter une part de chaque issue rapporte la
   différence, moins les frais taker. Le scan donne l'écart brut, les frais,
   l'écart net, le rendement annualisé, puis signale ce qui empêche de parler
   d'arbitrage :
   - `liste_extensible` : Polymarket peut ajouter des issues, la liste n'est pas close ;
   - `echeance_passee` : la date de fin est dépassée, les cotations sont figées ;
   - `sans_autre` : pas d'issue « Autre » explicite, l'exhaustivité n'est pas garantie ;
   - `illiquide` : moins de 100 $ de volume sur 24 h ;
   - `issues_indisponibles` : certaines issues ne sont pas achetables, le lot ne peut pas être complété.
   Les cas durs, échéance passée ou issues indisponibles, sont exclus du tableau
   par défaut (`--all` pour les voir). Avec `--validate N`, les N meilleurs
   candidats sont revérifiés sur les carnets CLOB en direct, avec l'écart net
   réel pour 5, 20, 100 et 500 lots.
2. **Spread achat-vente des marchés binaires**, par tranche de liquidité.
3. **OUI + NON d'un même marché** : rien à mesurer, les deux carnets sont le
   miroir exact l'un de l'autre. Cet écart n'existe pas par construction.

```bash
polyscan scan --top 25 --validate 10 --json data/scan.json
polyscan collect --books-top 20            # instantané horodaté du catalogue dans data/snapshots
polyscan scan --source data/snapshots/events_20261019T120000Z.json.gz
```

Lecture du tableau : `net ¢` est le gain net par lot d'une part de chaque issue
après frais taker ; `net@N` le même gain si l'on achète N parts de chaque issue
en consommant la profondeur réelle (`--` : profondeur insuffisante) ; un écart
avec une réserve n'est pas un arbitrage, c'est un pari.

## 2. `watch` : la collecte continue

Sélectionne des marchés rémunérés par les liquidity rewards, liquides, à
échéance ni trop proche ni trop lointaine et au prix non extrême, puis, à chaque
passage, lit le carnet du jeton OUI sur le CLOB et les dernières transactions
publiques sur la Data API.

```bash
polyscan watch --top 30 --interval 60 --keep-days 90        # tourne sans fin, Ctrl-C pour arrêter
polyscan watch --watchlist data/watch/watchlist.json         # reprend la même liste de marchés
```

Fichiers produits dans `data/watch/` :

- `watchlist.json` : les marchés suivis avec jetons, tick, taux de frais, taux
  journalier de rewards, taille minimale et spread maximal des rewards ;
- `books_AAAA-MM-JJ.jsonl` : un carnet par ligne, écrit seulement s'il a changé,
  20 niveaux par côté ;
- `trades_AAAA-MM-JJ.jsonl` : une transaction par ligne, dédoublonnée, côté
  preneur tel que publié par la Data API.

Les fichiers des jours précédents sont compressés en gzip au démarrage de
chaque passage. Ordre de grandeur : 30 marchés à un passage par minute donnent
quelques dizaines de Mo par jour avant compression.

### Faire tourner la collecte chez soi

La collecte doit tourner en permanence pendant des semaines pour que la
simulation ait un sens. Sur Linux, `deploy/polyscan-watch.service` est une
unité systemd prête à adapter. Sur macOS ou Windows, lancer la commande dans un
terminal qui reste ouvert, ou via `nohup` / le planificateur de tâches. Un petit
serveur suffit : la charge est de quelques requêtes par seconde.

## 3. `simulate` : le market making en paper trading

Rejoue, dans l'ordre, carnets et transactions. À chaque carnet la stratégie
place une cote achat et une cote vente virtuelles ; chaque transaction réelle
d'un preneur est confrontée à ces cotes.

```bash
polyscan simulate                                               # taille auto = minimum des rewards de chaque marché
polyscan simulate --quote improve --improve-ticks 1 --size 100 --skew-ticks 1 --flatten --json data/sim.json
polyscan simulate --market 0x12aa13b3 --csv data/equity.csv      # un marché, courbe d'équité
```

Paramètres :

- `--quote join` : se placer au meilleur prix affiché, en queue de file ;
  `--quote improve` : resserrer le spread de k ticks de chaque côté tant qu'il le permet ;
- `--size` : taille de chaque cote en parts ; `auto` prend la taille minimale des
  rewards du marché, entre 20 et 200 parts selon les marchés. Coter des deux côtés
  immobilise environ « taille » dollars par marché, plus l'inventaire accumulé ;
- `--max-inventory` : au-delà, la cote qui accroîtrait l'inventaire est retirée ;
- `--skew-ticks` : décale les deux cotes contre l'inventaire, en ticks par multiple de la taille ;
- `--fill prudent` : à prix égal, on est derrière la taille déjà affichée au niveau ;
  seul l'excédent de la transaction nous revient. `optimiste` : on est servi en premier ;
- `--flatten` : aplatit l'inventaire final en preneur, frais compris.

Ce que mesure le rapport :

- **P&L** : réalisé par coût moyen, latent au dernier prix médian, total ;
- **rewards estimés** : la méthode officielle, échantillonnée une fois par
  minute : score quadratique de chaque ordre dans le spread maximal, combinaison
  des deux côtés, part du pool journalier. Le carnet affiché est traité comme un
  seul concurrent, ce qui majore son score et minore notre part : l'estimation est prudente ;
- **markout** : écart entre le prix médian 1, 5 et 30 minutes après chaque
  exécution et notre prix, signé dans notre sens. Négatif signifie que le marché
  part contre nous après nous avoir servis : c'est la sélection adverse ;
- **DD max** : perte maximale depuis un plus haut de la courbe d'équité.

Limites à garder en tête : nos cotes virtuelles ne modifient pas le comportement
des autres participants ; les carnets ne sont observés qu'une fois par minute ;
quelques heures de données ne prouvent rien, il faut des semaines et des
centaines d'exécutions pour conclure.

## Cadre légal

Polymarket figure sur la liste de blocage de la Gespa, l'autorité intercantonale
suisse de surveillance des jeux d'argent, depuis le 26 novembre 2024, et le site
est bloqué en France par l'ANJ depuis le 16 juillet 2026. Vérifier la situation
légale et fiscale de son pays avant tout engagement de fonds.
