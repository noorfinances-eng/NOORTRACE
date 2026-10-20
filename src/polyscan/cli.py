"""Interface en ligne de commande : ``polyscan scan`` et ``polyscan collect``."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
import time
from pathlib import Path

from polyscan.api import ClobClient, GammaClient
from polyscan.arbitrage import DEFAULT_SIZES, EventScan, depth_margins, scan_events, summarize
from polyscan.collector import load_events, snapshot
from polyscan.spreads import spread_stats
from polyscan.simulate import Params, load_market, resolve_size, simulate, write_equity_csv
from polyscan.watch import Watcher, build_watchlist, load_watchlist


def _cents(value: float | None) -> str:
    return "   --" if value is None else f"{value * 100:5.2f}"


def _print_scan_table(scans: list[EventScan], validate: dict[str, dict[int, float | None]] | None) -> None:
    sizes = DEFAULT_SIZES
    head = f"{'net ¢':>6} {'brut ¢':>6} {'frais ¢':>7} {'iss.':>4} {'jours':>5} {'ann. %':>7}  "
    if validate:
        head += "  ".join(f"net@{s:<4}" for s in sizes) + "  "
    head += "réserves | événement"
    print(head)
    print("-" * len(head))
    for scan in scans:
        line = (
            f"{_cents(scan.net_buy):>6} {_cents(scan.gross_buy):>6} {_cents(scan.fee_buy):>7} "
            f"{scan.outcomes:>4} {('%5.0f' % scan.days_to_end) if scan.days_to_end is not None else '   --':>5} "
            f"{('%7.1f' % (scan.annualized * 100)) if scan.annualized is not None else '     --':>7}  "
        )
        if validate:
            margins = validate.get(scan.event_id, {})
            line += "  ".join(f"{_cents(margins.get(s)):>8}" for s in sizes) + "  "
        line += (",".join(scan.flags) or "aucune") + " | " + scan.title[:60]
        print(line)


def cmd_scan(args: argparse.Namespace) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    if args.source:
        events = load_events(Path(args.source))
    else:
        events = GammaClient().active_events()
    scans = scan_events(events, now)
    counts = summarize(scans)
    print(f"Événements actifs : {len(events)} | événements à plusieurs issues analysés : {counts['analyses']}")
    print(f"  somme des vendeurs ≥ 1 $ (rien à prendre)        : {counts['somme_vendeurs_>=_1']}")
    print(f"  écart brut absorbé par les frais taker            : {counts['ecart_brut_absorbe_par_frais']}")
    print(f"  écart net positif                                 : {counts['ecart_net_positif']}")
    print(f"  dont sans aucune réserve (liste close, non échu…) : {counts['ecart_net_positif_sans_reserve']}")
    print()
    eligible = [s for s in scans if s.net_buy > 0 and (args.all or not s.disqualified)]
    top = sorted(eligible, key=lambda s: -s.net_buy)[: args.top]
    if not args.all:
        print(f"Candidats après exclusion des cas durs (échéance passée, issues indisponibles) : {len(eligible)}")
    validate = None
    if args.validate and top:
        clob = ClobClient()
        validate = {}
        for scan in top[: args.validate]:
            tokens = [q.token_id for q in scan.quotes if q.token_id]
            books = clob.books(tokens)
            scan.depth = depth_margins(scan, books)
            validate[scan.event_id] = scan.depth
    _print_scan_table(top, validate)
    print()
    print("Spread achat-vente des marchés binaires (jeton OUI) :")
    print(f"{'liquidité':>10} {'marchés':>8} {'médian ¢':>9} {'moyen ¢':>8} {'à 1 tick':>9}")
    for row in spread_stats(events):
        print(
            f"{row['liquidite']:>10} {row['marches']:>8} {row['spread_median'] * 100:>9.2f} "
            f"{row['spread_moyen'] * 100:>8.2f} {row['part_a_un_tick'] * 100:>8.1f}%"
        )
    if args.json:
        payload = {"taken_at": now.isoformat(), "summary": counts, "top": [s.to_dict() for s in top]}
        Path(args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\nDétail écrit dans {args.json}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    gamma, clob = GammaClient(), ClobClient()
    out_dir = Path(args.out)
    while True:
        result = snapshot(out_dir, gamma, clob, books_top=args.books_top, full=args.full)
        print(json.dumps(result, ensure_ascii=False))
        if not args.every:
            return 0
        time.sleep(args.every)


def cmd_watch(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    if args.watchlist:
        watchlist = load_watchlist(Path(args.watchlist))
    else:
        watchlist = build_watchlist(
            top=args.top, min_liquidity=args.min_liquidity, min_days=args.min_days, max_days=args.max_days
        )
    if not watchlist:
        print("Aucun marché ne satisfait les critères de sélection.", file=sys.stderr)
        return 1
    print(f"{len(watchlist)} marchés surveillés, intervalle {args.interval}s, sortie {out_dir}")
    for m in watchlist:
        print(f"  {m['reward_daily_rate']:7.2f} $/j  vol24h {m['volume_24h']:10.0f}  mid {m['mid_at_selection']:.3f}  {m['question'][:60]}")
    Watcher(out_dir, watchlist, interval=args.interval, levels=args.levels, keep_days=args.keep_days).run(args.iterations)
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    data_dir = Path(args.data)
    watchlist = load_watchlist(data_dir / "watchlist.json")
    if args.market:
        watchlist = [m for m in watchlist if m["condition_id"].startswith(args.market) or m.get("slug") == args.market]
        if not watchlist:
            print("marché introuvable dans watchlist.json", file=sys.stderr)
            return 1
    results = []
    for m in watchlist:
        books, trades = load_market(data_dir, m["condition_id"], m.get("yes_token"))
        if len(books) < 2:
            continue
        size = resolve_size(args.size, m)
        params = Params(
            quote=args.quote, improve_ticks=args.improve_ticks, size=size, max_inventory=max(args.max_inventory, size),
            skew_ticks=args.skew_ticks, fill=args.fill, tick=float(m.get("tick") or 0.01),
            reward_daily_rate=float(m.get("reward_daily_rate") or 0.0), reward_min_size=float(m.get("reward_min_size") or 0.0),
            reward_max_spread=float(m.get("reward_max_spread_cents") or 0.0) / 100.0, fee_rate=float(m.get("fee_rate") or 0.0),
            flatten_at_end=args.flatten,
        )
        result = simulate(books, trades, params, market=m["condition_id"], question=str(m.get("question") or ""))
        results.append(result)
        if args.csv and len(watchlist) == 1:
            write_equity_csv(Path(args.csv), books, trades, params)
    if not results:
        print("aucun marché avec au moins deux carnets dans ce dossier", file=sys.stderr)
        return 1
    head = (f"{'heures':>6} {'carnets':>7} {'trades':>6} {'exéc.':>5} {'vol. exéc.':>10} {'inv. fin':>8} "
            f"{'taille':>6} {'P&L $':>8} {'rewards $':>9} {'rew. $/j':>8} {'total $':>8} {'DD max $':>8} {'markout 5 min ¢':>15} | marché")
    print(f"Paramètres : cotes={args.quote} amélioration={args.improve_ticks} tick(s) taille={args.size} "
          f"inventaire max={args.max_inventory:g} skew={args.skew_ticks:g} remplissage={args.fill}")
    print("Coter des deux côtés immobilise environ « taille » dollars par marché, plus l'inventaire accumulé.")
    print(head)
    print("-" * len(head))
    tot = {"pnl": 0.0, "rew": 0.0, "fills": 0, "vol": 0.0, "rew_day": 0.0}
    for r in results:
        mk = r.markouts_cents.get("300s")
        note = " ! " + "; ".join(r.warnings) if r.warnings else ""
        print(f"{r.hours:6.1f} {r.books:7d} {r.trades:6d} {r.fills:5d} {r.filled_volume:10.0f} {r.end_inventory:8.0f} "
              f"{r.size:6.0f} {r.pnl_total:8.2f} {r.rewards_estimate:9.2f} {(f'{r.rewards_per_day:8.2f}' if r.rewards_per_day is not None else '      --')} {r.pnl_with_rewards:8.2f} {r.max_drawdown:8.2f} "
              f"{(f'{mk:+.2f}' if mk is not None else '--'):>15} | {r.question[:50]}{note}")
        tot["pnl"] += r.pnl_total; tot["rew"] += r.rewards_estimate; tot["fills"] += r.fills; tot["vol"] += r.filled_volume
        tot["rew_day"] += r.rewards_per_day or 0.0
    print("-" * len(head))
    print(f"TOTAL : {len(results)} marchés, {tot['fills']} exécutions, {tot['vol']:.0f} parts, "
          f"P&L {tot['pnl']:+.2f} $, rewards estimés {tot['rew']:+.2f} $ soit {tot['rew_day']:.2f} $/jour extrapolés, "
          f"total {tot['pnl'] + tot['rew']:+.2f} $")
    if args.json:
        Path(args.json).write_text(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Détail écrit dans {args.json}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="polyscan", description="Scanner d'écarts de cotation Polymarket")
    parser.add_argument("-v", "--verbose", action="store_true", help="journal détaillé")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="mesure les écarts sur le catalogue en direct ou un instantané")
    scan.add_argument("--source", help="fichier events_*.json.gz au lieu de l'API")
    scan.add_argument("--top", type=int, default=25, help="nombre de candidats affichés")
    scan.add_argument("--validate", type=int, default=0, help="vérifie N candidats sur les carnets CLOB en direct")
    scan.add_argument("--all", action="store_true", help="inclut les cas durs (échéance passée, issues indisponibles)")
    scan.add_argument("--json", help="écrit le détail des candidats dans ce fichier")
    scan.set_defaults(func=cmd_scan)

    collect = sub.add_parser("collect", help="enregistre un instantané horodaté du catalogue")
    collect.add_argument("--out", default="data/snapshots", help="dossier de sortie")
    collect.add_argument("--books-top", type=int, default=0, help="carnets des N meilleurs candidats")
    collect.add_argument("--every", type=int, default=0, help="répète toutes les N secondes (0 = une fois)")
    collect.add_argument("--full", action="store_true", help="conserve tous les champs Gamma au lieu du sous-ensemble utile")
    collect.set_defaults(func=cmd_collect)

    watch = sub.add_parser("watch", help="collecte continue des carnets et transactions de marchés sélectionnés")
    watch.add_argument("--out", default="data/watch", help="dossier de sortie")
    watch.add_argument("--watchlist", help="réutilise un watchlist.json existant au lieu de sélectionner")
    watch.add_argument("--top", type=int, default=30, help="nombre de marchés surveillés")
    watch.add_argument("--min-liquidity", type=float, default=10_000, help="liquidité minimale en $")
    watch.add_argument("--min-days", type=float, default=7, help="jours minimum avant l'échéance")
    watch.add_argument("--max-days", type=float, default=400, help="jours maximum avant l'échéance")
    watch.add_argument("--interval", type=float, default=60, help="secondes entre deux passages")
    watch.add_argument("--levels", type=int, default=20, help="niveaux de carnet conservés par côté")
    watch.add_argument("--keep-days", type=int, default=0, help="rétention en jours (0 = illimitée)")
    watch.add_argument("--iterations", type=int, default=0, help="nombre de passages (0 = sans fin)")
    watch.set_defaults(func=cmd_watch)

    sim = sub.add_parser("simulate", help="rejoue les données collectées avec une stratégie de market making")
    sim.add_argument("--data", default="data/watch", help="dossier produit par polyscan watch")
    sim.add_argument("--market", help="préfixe du condition id ou slug ; tous les marchés par défaut")
    sim.add_argument("--quote", choices=["join", "improve"], default="join", help="join : au meilleur prix affiché ; improve : k ticks à l'intérieur")
    sim.add_argument("--improve-ticks", type=int, default=1, help="ticks d'amélioration de chaque côté pour --quote improve")
    sim.add_argument("--size", default="auto", help="taille de chaque cote en parts, ou auto = taille minimale des rewards du marché")
    sim.add_argument("--max-inventory", type=float, default=500, help="inventaire maximal en parts, en valeur absolue (au moins la taille)")
    sim.add_argument("--skew-ticks", type=float, default=0, help="décalage des cotes contre l'inventaire, en ticks par multiple de la taille")
    sim.add_argument("--fill", choices=["prudent", "optimiste"], default="prudent", help="modèle de remplissage à prix égal")
    sim.add_argument("--flatten", action="store_true", help="aplatit l'inventaire final en preneur, frais compris")
    sim.add_argument("--csv", help="courbe d'équité (un seul marché)")
    sim.add_argument("--json", help="résultats détaillés")
    sim.set_defaults(func=cmd_simulate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
