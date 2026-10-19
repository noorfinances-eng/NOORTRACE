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
