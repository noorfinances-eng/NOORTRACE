"""Détection des écarts sur les événements à plusieurs issues.

Sur un événement « negative risk », les issues sont mutuellement exclusives et
une seule paie 1 $. Acheter toutes les issues pour moins de 1 $ est un gain
certain **uniquement** si la liste est exhaustive et si l'événement résout bien
vers une issue listée. Ce module calcule l'écart brut, les frais taker, l'écart
net, puis signale tout ce qui empêche de parler d'arbitrage :

- ``liste_extensible`` : Polymarket peut ajouter des issues (``negRiskAugmented``) ;
- ``echeance_passee`` : la date de fin est dépassée, les cotations sont probablement figées ;
- ``sans_autre`` : aucune issue « Autre » explicite, l'exhaustivité n'est pas garantie ;
- ``illiquide`` : volume sur 24 h inférieur à 100 $ ;
- ``issues_indisponibles`` : certaines issues de l'événement ne sont pas achetables
  (marché clos, suspendu ou sans carnet), le lot ne peut pas être complété.

Les deux derniers cas, avec ``echeance_passee``, sont « durs » : ils excluent
l'événement du tableau par défaut, les autres sont des réserves à juger.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Any

from polyscan import book as bk
from polyscan.api import active_markets, best_prices, yes_token
from polyscan.fees import market_rate, taker_fee

DEFAULT_SIZES = (5, 20, 100, 500)
HARD_FLAGS = frozenset({"echeance_passee", "issues_indisponibles"})


@dataclass
class OutcomeQuote:
    label: str
    token_id: str | None
    ask: float
    bid: float | None
    rate: float


@dataclass
class EventScan:
    event_id: str
    title: str
    slug: str
    outcomes: int
    sum_ask: float
    sum_bid: float | None
    gross_buy: float
    fee_buy: float
    net_buy: float
    days_to_end: float | None
    annualized: float | None
    augmented: bool
    ended: bool
    other_present: bool
    volume_24h: float
    markets_total: int = 0
    flags: list[str] = field(default_factory=list)
    quotes: list[OutcomeQuote] = field(default_factory=list)
    depth: dict[int, float | None] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        """Vrai si aucun indicateur ne disqualifie l'écart."""
        return not self.flags

    @property
    def disqualified(self) -> bool:
        """Vrai si un indicateur dur rend l'achat du lot impossible ou sans objet."""
        return any(flag in HARD_FLAGS for flag in self.flags)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["clean"] = self.clean
        return data


def _parse_date(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def is_multi_outcome(event: dict[str, Any]) -> bool:
    return bool(event.get("negRisk")) and len(active_markets(event)) >= 2


def classify(scan: EventScan) -> list[str]:
    flags: list[str] = []
    if scan.augmented:
        flags.append("liste_extensible")
    if scan.ended:
        flags.append("echeance_passee")
    if not scan.other_present:
        flags.append("sans_autre")
    if scan.volume_24h < 100:
        flags.append("illiquide")
    if scan.markets_total > scan.outcomes:
        flags.append("issues_indisponibles")
    return flags


def scan_event(event: dict[str, Any], now: dt.datetime | None = None) -> EventScan | None:
    """Évalue l'achat d'une part de chaque issue. ``None`` si une issue n'a pas de vendeur."""
    now = now or dt.datetime.now(dt.timezone.utc)
    markets = active_markets(event)
    if len(markets) < 2:
        return None
    quotes: list[OutcomeQuote] = []
    fee_total = 0.0
    other_present = False
    for market in markets:
        bid, ask = best_prices(market)
        if ask is None:
            return None
        rate = market_rate(market)
        fee_total += taker_fee(1.0, ask, rate)
        other_present = other_present or bool(market.get("negRiskOther"))
        quotes.append(
            OutcomeQuote(
                label=str(market.get("groupItemTitle") or market.get("question") or ""),
                token_id=yes_token(market),
                ask=ask,
                bid=bid,
                rate=rate,
            )
        )
    sum_ask = sum(q.ask for q in quotes)
    sum_bid = sum(q.bid for q in quotes) if all(q.bid is not None for q in quotes) else None  # type: ignore[misc]
    gross = 1.0 - sum_ask
    net = gross - fee_total
    end = _parse_date(event.get("endDate"))
    days = None
    ended = False
    if end is not None:
        seconds = (end - now).total_seconds()
        ended = seconds <= 0
        days = max(seconds / 86400.0, 0.0)
    annualized = None
    if days and days > 0 and sum_ask > 0:
        annualized = net / sum_ask * 365.0 / days
    scan = EventScan(
        event_id=str(event.get("id")),
        title=str(event.get("title") or ""),
        slug=str(event.get("slug") or ""),
        outcomes=len(quotes),
        sum_ask=sum_ask,
        sum_bid=sum_bid,
        gross_buy=gross,
        fee_buy=fee_total,
        net_buy=net,
        days_to_end=days,
        annualized=annualized,
        augmented=bool(event.get("negRiskAugmented")),
        ended=ended,
        other_present=other_present,
        volume_24h=_float(event.get("volume24hr")),
        markets_total=len(event.get("markets", [])),
        quotes=quotes,
    )
    scan.flags = classify(scan)
    return scan


def scan_events(events: list[dict[str, Any]], now: dt.datetime | None = None) -> list[EventScan]:
    out: list[EventScan] = []
    for event in events:
        if not is_multi_outcome(event):
            continue
        scan = scan_event(event, now)
        if scan is not None:
            out.append(scan)
    return out


def depth_margins(
    scan: EventScan, books: dict[str, dict[str, Any]], sizes: tuple[int, ...] = DEFAULT_SIZES
) -> dict[int, float | None]:
    """Écart net par lot complet quand on achète ``size`` parts de chaque issue.

    Parcourt les carnets en direct. ``None`` quand une issue n'a pas assez de
    profondeur pour servir ``size`` parts.
    """
    out: dict[int, float | None] = {}
    for size in sizes:
        total_price = 0.0
        total_fee = 0.0
        complete = True
        for quote in scan.quotes:
            book = books.get(quote.token_id or "")
            if book is None:
                complete = False
                break
            cost, filled = bk.walk(bk.asks(book), float(size))
            if filled + 1e-9 < size:
                complete = False
                break
            avg = cost / size
            total_price += avg
            total_fee += taker_fee(1.0, avg, quote.rate)
        out[size] = (1.0 - total_price - total_fee) if complete else None
    return out


def summarize(scans: list[EventScan]) -> dict[str, int]:
    """Compte les événements par situation, pour le résumé en tête de rapport."""
    counts = {
        "analyses": len(scans),
        "somme_vendeurs_>=_1": 0,
        "ecart_brut_absorbe_par_frais": 0,
        "ecart_net_positif": 0,
        "ecart_net_positif_sans_reserve": 0,
    }
    for scan in scans:
        if scan.gross_buy <= 0:
            counts["somme_vendeurs_>=_1"] += 1
        elif scan.net_buy <= 0:
            counts["ecart_brut_absorbe_par_frais"] += 1
        else:
            counts["ecart_net_positif"] += 1
            if scan.clean:
                counts["ecart_net_positif_sans_reserve"] += 1
    return counts
