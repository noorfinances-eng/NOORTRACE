"""Statistiques de spread achat-vente sur les marchés binaires."""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any

from polyscan.api import active_markets, is_tradable

BUCKETS = ("<1k", "1k-10k", "10k-100k", ">100k")


def liquidity_bucket(liquidity: float | None) -> str:
    if liquidity is None:
        return "<1k"
    if liquidity < 1_000:
        return "<1k"
    if liquidity < 10_000:
        return "1k-10k"
    if liquidity < 100_000:
        return "10k-100k"
    return ">100k"


def _float(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


def binary_markets(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Marchés binaires isolés : événements sans « negative risk » ou à un seul marché."""
    out: list[dict[str, Any]] = []
    for event in events:
        markets = active_markets(event)
        if event.get("negRisk") and len(markets) >= 2:
            continue
        out.extend(m for m in markets if is_tradable(m))
    return out


def spread_stats(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[str, list[tuple[float, float | None]]] = defaultdict(list)
    for market in binary_markets(events):
        spread = _float(market.get("spread"))
        if spread is None:
            continue
        tick = _float(market.get("orderPriceMinTickSize"))
        rows[liquidity_bucket(_float(market.get("liquidityNum")))].append((spread, tick))
    out: list[dict[str, Any]] = []
    for bucket in BUCKETS:
        values = rows.get(bucket, [])
        if not values:
            continue
        spreads = [s for s, _ in values]
        one_tick = sum(1 for s, t in values if t is not None and s <= t + 1e-9)
        out.append(
            {
                "liquidite": bucket,
                "marches": len(values),
                "spread_median": statistics.median(spreads),
                "spread_moyen": statistics.fmean(spreads),
                "part_a_un_tick": one_tick / len(values),
            }
        )
    return out
