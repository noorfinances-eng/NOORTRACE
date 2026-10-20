"""Collecte horodatée du catalogue et des carnets d'ordres.

Chaque instantané est un fichier ``events_<UTC>.json.gz`` ; avec ``books_top``,
un fichier ``books_<UTC>.json.gz`` contient les carnets des meilleurs candidats.
Ces fichiers sont la matière première des backtests et du paper trading.

Par défaut, seuls les champs utiles au scan sont conservés (``slim``), ce qui
divise la taille des fichiers par dix environ. ``full=True`` garde tout.
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
import logging
from pathlib import Path
from typing import Any

from polyscan.api import ClobClient, GammaClient
from polyscan.arbitrage import scan_events

log = logging.getLogger(__name__)

EVENT_FIELDS = (
    "id", "title", "slug", "negRisk", "negRiskAugmented", "endDate", "startDate",
    "volume24hr", "volume", "liquidity", "active", "closed", "tags",
)
MARKET_FIELDS = (
    "id", "question", "groupItemTitle", "conditionId", "active", "closed", "acceptingOrders",
    "enableOrderBook", "bestBid", "bestAsk", "spread", "lastTradePrice", "outcomePrices", "outcomes",
    "clobTokenIds", "feeSchedule", "feeType", "feesEnabled", "liquidityNum", "volume24hr",
    "orderPriceMinTickSize", "orderMinSize", "rewardsMinSize", "rewardsMaxSpread", "negRiskOther", "endDate",
)


def slim_event(event: dict[str, Any]) -> dict[str, Any]:
    out = {key: event.get(key) for key in EVENT_FIELDS if key in event}
    if isinstance(out.get("tags"), list):
        out["tags"] = [t.get("label") for t in out["tags"] if isinstance(t, dict)]
    out["markets"] = [{key: m.get(key) for key in MARKET_FIELDS if key in m} for m in event.get("markets", [])]
    return out


def _stamp(now: dt.datetime) -> str:
    return now.strftime("%Y%m%dT%H%M%SZ")


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)


def snapshot(
    out_dir: Path, gamma: GammaClient, clob: ClobClient, books_top: int = 0, full: bool = False
) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    events = gamma.active_events()
    stored = events if full else [slim_event(e) for e in events]
    events_path = out_dir / f"events_{_stamp(now)}.json.gz"
    _write(events_path, {"taken_at": now.isoformat(), "events": stored})
    result: dict[str, Any] = {"taken_at": now.isoformat(), "events": len(events), "events_path": str(events_path)}
    if books_top > 0:
        scans = sorted((s for s in scan_events(events, now) if s.net_buy > 0), key=lambda s: -s.net_buy)[:books_top]
        tokens = [q.token_id for s in scans for q in s.quotes if q.token_id]
        books = clob.books(tokens)
        books_path = out_dir / f"books_{_stamp(now)}.json.gz"
        _write(books_path, {"taken_at": now.isoformat(), "books": books})
        result.update({"books": len(books), "books_path": str(books_path)})
    log.info("instantané écrit : %s", result)
    return result


def load_events(path: Path) -> list[dict[str, Any]]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:  # type: ignore[operator]
        payload = json.load(fh)
    return payload["events"] if isinstance(payload, dict) else payload
