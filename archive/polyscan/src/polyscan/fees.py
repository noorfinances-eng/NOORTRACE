"""Frais de transaction Polymarket.

Formule officielle (docs.polymarket.com/trading/fees) :
    frais = parts × taux × p × (1 − p)
Seuls les ordres qui traversent le spread (takers) paient. Les ordres au repos
(makers) ne paient rien. Le taux dépend de la catégorie du marché et est publié
par Gamma dans ``feeSchedule.rate``.
"""

from __future__ import annotations

from typing import Any

DEFAULT_RATE_IF_UNKNOWN = 0.05  # taux le plus courant hors crypto, utilisé si Gamma ne le publie pas


def taker_fee(shares: float, price: float, rate: float) -> float:
    """Frais en USDC payés par un taker pour ``shares`` parts au prix ``price``."""
    if shares <= 0 or rate <= 0:
        return 0.0
    return shares * rate * price * (1.0 - price)


def market_rate(market: dict[str, Any]) -> float:
    """Taux taker du marché d'après Gamma (0 si les frais sont désactivés)."""
    schedule = market.get("feeSchedule") or {}
    rate = schedule.get("rate")
    if rate is not None:
        return float(rate)
    if not market.get("feesEnabled"):
        return 0.0
    return DEFAULT_RATE_IF_UNKNOWN
