"""Liquidity rewards : score d'un carnet selon la méthode publiée par Polymarket.

Source : docs.polymarket.com, « Liquidity Rewards ». Pour un ordre à distance
``s`` du prix médian, dans la limite ``v`` du marché : ``S(v, s) = ((v − s) / v)² × taille``.
``Q_one`` somme les achats, ``Q_two`` les ventes. Si le prix médian est dans
[0,10 ; 0,90] : ``Q_min = max(min(Q_one, Q_two), max(Q_one / c, Q_two / c))``
avec ``c = 3`` ; sinon la liquidité doit être des deux côtés :
``Q_min = min(Q_one, Q_two)``. Le carnet est échantillonné une fois par minute,
et la part d'un teneur de marché est son ``Q_min`` divisé par la somme de tous
les ``Q_min``. Seuls les ordres d'au moins la taille minimale du marché comptent.
"""

from __future__ import annotations

from typing import Iterable

C_FACTOR = 3.0
Level = tuple[float, float]


def order_score(distance: float, max_spread: float, size: float) -> float:
    """Score d'un ordre à ``distance`` du médian, en prix ; nul au-delà de ``max_spread``."""
    if max_spread <= 0 or size <= 0 or distance < 0 or distance > max_spread + 1e-12:
        return 0.0
    return ((max_spread - distance) / max_spread) ** 2 * size


def side_score(levels: Iterable[Level], mid: float, max_spread: float, min_size: float) -> float:
    total = 0.0
    for price, size in levels:
        if size + 1e-9 < min_size:
            continue
        total += order_score(abs(mid - price), max_spread, size)
    return total


def combine(q_one: float, q_two: float, mid: float, c: float = C_FACTOR) -> float:
    if 0.10 <= mid <= 0.90:
        return max(min(q_one, q_two), max(q_one / c, q_two / c))
    return min(q_one, q_two)


def book_score(bids: Iterable[Level], asks: Iterable[Level], mid: float, max_spread: float, min_size: float) -> float:
    """Score du carnet affiché, traité comme un seul concurrent (borne haute, donc estimation prudente de notre part)."""
    return combine(side_score(bids, mid, max_spread, min_size), side_score(asks, mid, max_spread, min_size), mid)


def share(ours: float, others: float) -> float:
    total = ours + others
    return ours / total if total > 0 else 0.0
