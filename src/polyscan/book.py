"""Lecture et parcours des carnets d'ordres CLOB."""

from __future__ import annotations

from typing import Any, Iterable

Level = tuple[float, float]  # (prix, taille en parts)


def parse_levels(levels: Iterable[dict[str, Any]]) -> list[Level]:
    out: list[Level] = []
    for lvl in levels or []:
        try:
            price = float(lvl["price"])
            size = float(lvl["size"])
        except (KeyError, TypeError, ValueError):
            continue
        if size > 0:
            out.append((price, size))
    return out


def asks(book: dict[str, Any]) -> list[Level]:
    """Vendeurs, du moins cher au plus cher."""
    return sorted(parse_levels(book.get("asks", [])), key=lambda lvl: lvl[0])


def bids(book: dict[str, Any]) -> list[Level]:
    """Acheteurs, du plus cher au moins cher."""
    return sorted(parse_levels(book.get("bids", [])), key=lambda lvl: -lvl[0])


def best(levels: list[Level]) -> float | None:
    return levels[0][0] if levels else None


def walk(levels: list[Level], size: float) -> tuple[float, float]:
    """Coût pour exécuter ``size`` parts en consommant les niveaux dans l'ordre.

    Retourne (coût total, quantité réellement servie). Si la profondeur est
    insuffisante, la quantité servie est inférieure à ``size``.
    """
    cost = 0.0
    remaining = size
    for price, available in levels:
        take = min(remaining, available)
        cost += take * price
        remaining -= take
        if remaining <= 1e-9:
            break
    return cost, size - remaining
