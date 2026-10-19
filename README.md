# Polymarkets

Outils pour mesurer, collecter et simuler les écarts de cotation sur Polymarket.
Première brique : `polyscan`, un scanner d'écarts en direct et un collecteur
d'instantanés horodatés. Tout passe par les API publiques, sans compte ni clé,
et le catalogue complet est parcouru par pagination keyset.

## Ce que mesure le scanner

Polymarket cote chaque issue entre 0 et 1 $. Trois écarts sont surveillés :

1. **Somme des issues d'un événement à plusieurs issues.** Sur un événement
   « negative risk », une seule issue paie 1 $. Si la somme des meilleurs prix
   vendeurs est inférieure à 1 $, acheter une part de chaque issue rapporte la
   différence, moins les frais taker. Le scanner calcule l'écart brut, les frais,
   l'écart net, le rendement annualisé, puis signale ce qui empêche de parler
   d'arbitrage :
   - `liste_extensible` : Polymarket peut ajouter des issues, la liste n'est pas close ;
   - `echeance_passee` : la date de fin est dépassée, les cotations sont figées ;
   - `sans_autre` : pas d'issue « Autre » explicite, l'exhaustivité n'est pas garantie ;
   - `illiquide` : moins de 100 $ de volume sur 24 h ;
   - `issues_indisponibles` : certaines issues ne sont pas achetables (marché clos,
     suspendu ou sans carnet), le lot ne peut pas être complété.
   Les cas durs, échéance passée ou issues indisponibles, sont exclus du tableau
   par défaut (`--all` pour les voir).
   Avec `--validate N`, les N meilleurs candidats sont revérifiés sur les carnets
   d'ordres CLOB en direct, avec l'écart net réel pour 5, 20, 100 et 500 lots.
2. **Spread achat-vente des marchés binaires**, par tranche de liquidité, avec
   la part des marchés déjà cotés à un tick.
3. **OUI + NON d'un même marché** : rien à mesurer. Le moteur apparie un achat
   OUI à p avec un achat NON à 1 − p, les deux carnets sont le miroir l'un de
   l'autre. Cet écart n'existe pas par construction.

Les frais suivent la formule officielle `parts × taux × p × (1 − p)`, avec le
taux publié par Gamma pour chaque marché. Seuls les ordres qui traversent le
spread paient ; les ordres au repos ne paient rien.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Utilisation

```bash
# Scan en direct, 25 candidats, les 10 meilleurs revérifiés sur les carnets CLOB
polyscan scan --top 25 --validate 10 --json data/scan.json

# Instantané horodaté du catalogue dans data/snapshots, avec les carnets des 20 meilleurs candidats
polyscan collect --books-top 20

# Même chose toutes les 5 minutes, en continu (--full pour garder tous les champs Gamma)
polyscan collect --books-top 20 --every 300

# Rejouer le scan sur un instantané enregistré
polyscan scan --source data/snapshots/events_20261019T120000Z.json.gz
```

Sans installation : `PYTHONPATH=src python3 -m polyscan ...`

Tests : `pytest`

## Lecture du rapport

```
 net ¢ brut ¢ frais ¢ iss. jours  ann. %  net@5     net@20    ...  réserves | événement
  2.27   2.40    0.13    2    16    54.2    2.27      2.27 ...  liste_extensible,sans_autre | IA-04 House Election Winner
```

- `net ¢` : gain net par lot d'une part de chaque issue, après frais taker ;
- `jours` et `ann. %` : capital immobilisé jusqu'à la résolution et rendement annualisé ;
- `net@N` : gain net par lot si l'on achète N parts de chaque issue en consommant
  la profondeur réelle des carnets (`--` : profondeur insuffisante) ;
- `réserves` : un écart avec une réserve n'est pas un arbitrage, c'est un pari.

## Cadre légal

Polymarket figure sur la liste de blocage de la Gespa, l'autorité intercantonale
suisse de surveillance des jeux d'argent, depuis le 26 novembre 2024, et le site
est bloqué en France par l'ANJ depuis le 16 juillet 2026. Ce dépôt ne contient
aucun outil de passage d'ordres : il lit des données publiques et ne contourne
aucune restriction. Vérifier la situation légale et fiscale de son pays avant
tout engagement de fonds.

## Suite prévue

- Simulateur de market making en paper trading sur les instantanés collectés,
  avec frais, spread, liquidity rewards et sélection adverse.
- Comparaison des cotations avec d'autres plateformes, avec contrôle des règles
  de résolution, qui diffèrent souvent d'un site à l'autre.
