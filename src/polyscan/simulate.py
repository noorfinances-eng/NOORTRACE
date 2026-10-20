"""Simulateur de market making en paper trading sur les données de ``polyscan watch``.

Principe : on rejoue, dans l'ordre, les carnets et les transactions publiques
d'un marché. À chaque carnet, la stratégie place une cote achat et une cote
vente virtuelles. Chaque transaction réelle d'un preneur est confrontée à ces
cotes : un vendeur qui frappe à un prix inférieur ou égal à notre achat nous
remplit, un acheteur qui frappe à un prix supérieur ou égal à notre vente aussi.

Deux modèles de remplissage :
- ``prudent`` (défaut) : à prix égal, on est derrière la taille déjà affichée à
  ce niveau au moment de la cote ; seul l'excédent de la transaction nous revient.
- ``optimiste`` : à prix égal, on est servi en premier.

La sélection adverse est mesurée par les *markouts* : écart entre le prix
médian 1, 5 et 30 minutes après chaque exécution et notre prix, signé dans
notre sens. Négatif signifie que le marché part contre nous après nous avoir
servis. Les rewards sont estimés une fois par minute avec la méthode officielle,
le carnet affiché étant traité comme un unique concurrent, ce qui minore notre
part. Les ordres au repos ne paient pas de frais ; seul l'aplatissement final
optionnel, exécuté en preneur, en paie.
"""

from __future__ import annotations

import bisect
import csv
import datetime as dt
import gzip
import json
import math
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from polyscan import rewards as rw
from polyscan.fees import taker_fee

Level = tuple[float, float]


@dataclass
class Book:
    t: float
    bids: list[Level]
    asks: list[Level]

    @property
    def best_bid(self) -> float | None:
        return self.bids[0][0] if self.bids else None

    @property
    def best_ask(self) -> float | None:
        return self.asks[0][0] if self.asks else None

    @property
    def mid(self) -> float | None:
        if self.best_bid is None or self.best_ask is None:
            return None
        return (self.best_bid + self.best_ask) / 2

    def size_at(self, side: str, price: float) -> float:
        levels = self.bids if side == "bid" else self.asks
        return sum(size for p, size in levels if abs(p - price) < 1e-9)


@dataclass
class Trade:
    t: float
    side: str  # côté preneur, exprimé sur le jeton OUI : BUY frappe les ventes, SELL frappe les achats
    price: float
    size: float


@dataclass
class Params:
    quote: str = "join"  # join : se placer au meilleur prix affiché ; improve : améliorer le meilleur prix de k ticks
    improve_ticks: int = 1
    size: float = 50.0
    max_inventory: float = 500.0
    skew_ticks: float = 0.0  # décalage des cotes en ticks par multiple de ``size`` d'inventaire
    fill: str = "prudent"
    tick: float = 0.01
    reward_daily_rate: float = 0.0
    reward_min_size: float = 0.0
    reward_max_spread: float = 0.0  # en prix, ex. 0.035 pour 3,5 ¢
    fee_rate: float = 0.0
    flatten_at_end: bool = False
    markout_horizons: tuple[int, ...] = (60, 300, 1800)


@dataclass
class Fill:
    t: float
    side: str  # notre côté : BUY ou SELL
    price: float
    size: float
    mid: float | None


@dataclass
class Quote:
    price: float
    remaining: float
    queue_ahead: float


@dataclass
class Result:
    market: str
    question: str
    start: str
    end: str
    hours: float
    books: int
    trades: int
    taker_volume: float
    fills: int
    filled_volume: float
    buys: float
    sells: float
    end_inventory: float
    size: float
    pnl_realized: float
    pnl_unrealized: float
    pnl_total: float
    rewards_estimate: float
    pnl_with_rewards: float
    max_drawdown: float
    flatten_pnl_total: float | None
    markouts_cents: dict[str, float | None]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----- Chargement ---------------------------------------------------------------------------------


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:  # type: ignore[operator]
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def _iso_to_epoch(value: str) -> float:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def normalize_trade(raw: dict[str, Any], yes_token: str | None) -> Trade:
    """Exprime une transaction sur le jeton OUI. Acheter NON à p revient à vendre OUI à 1 − p."""
    side = str(raw.get("side", "")).upper()
    price = float(raw["price"])
    is_yes = (yes_token is not None and str(raw.get("asset")) == str(yes_token)) or (
        yes_token is None and str(raw.get("outcome", "")).lower() == "yes"
    )
    if not is_yes:
        price = 1.0 - price
        side = "SELL" if side == "BUY" else "BUY"
    return Trade(t=float(raw["t"]), side=side, price=round(price, 6), size=float(raw["size"]))


def load_market(data_dir: Path, condition_id: str, yes_token: str | None) -> tuple[list[Book], list[Trade]]:
    books: list[Book] = []
    trades: list[Trade] = []
    seen: set[str] = set()
    for path in sorted(data_dir.glob("books_*.jsonl*")):
        for rec in iter_jsonl(path):
            if rec.get("cid") != condition_id:
                continue
            books.append(Book(_iso_to_epoch(rec["t"]), [tuple(x) for x in rec["bids"]], [tuple(x) for x in rec["asks"]]))
    for path in sorted(data_dir.glob("trades_*.jsonl*")):
        for rec in iter_jsonl(path):
            if rec.get("cid") != condition_id:
                continue
            key = f"{rec.get('tx')}|{rec.get('asset')}|{rec.get('price')}|{rec.get('size')}|{rec.get('t')}"
            if key in seen:
                continue
            seen.add(key)
            trades.append(normalize_trade(rec, yes_token))
    books.sort(key=lambda b: b.t)
    trades.sort(key=lambda t: t.t)
    return books, trades


# ----- Stratégie ------------------------------------------------------------------------------------


def resolve_size(size: str | float, market: dict[str, Any]) -> float:
    """Taille des cotes : un nombre, ou ``auto`` = taille minimale des rewards du marché (au moins la taille minimale d'ordre)."""
    if isinstance(size, str) and size.strip().lower() == "auto":
        return max(float(market.get("reward_min_size") or 0.0), float(market.get("min_order_size") or 0.0), 1.0)
    return float(size)



def _round_tick(price: float, tick: float) -> float:
    return round(round(price / tick) * tick, 6)


def compute_quotes(book: Book, params: Params, inventory: float) -> tuple[float | None, float | None]:
    best_bid, best_ask = book.best_bid, book.best_ask
    if best_bid is None or best_ask is None:
        return None, None
    tick = params.tick
    bid, ask = best_bid, best_ask
    if params.quote == "improve":
        # on resserre le spread de k ticks de chaque côté, sans jamais le fermer ni croiser le carnet
        step = params.improve_ticks * tick
        if best_ask - best_bid - 2 * step >= tick - 1e-9:
            bid, ask = best_bid + step, best_ask - step
    if params.skew_ticks and params.size > 0 and inventory:
        shift = params.skew_ticks * tick * (inventory / params.size)
        bid -= shift
        ask -= shift
    bid = min(max(_round_tick(bid, tick), tick), 1.0 - tick)
    ask = min(max(_round_tick(ask, tick), tick), 1.0 - tick)
    if bid >= ask:
        bid = _round_tick(ask - tick, tick)
    bid_q = None if inventory >= params.max_inventory else bid
    ask_q = None if inventory <= -params.max_inventory else ask
    return bid_q, ask_q


class Position:
    """Inventaire, trésorerie et P&L réalisé par coût moyen."""

    def __init__(self) -> None:
        self.qty = 0.0
        self.avg = 0.0
        self.cash = 0.0
        self.realized = 0.0

    def apply(self, side: str, price: float, qty: float) -> None:
        signed = qty if side == "BUY" else -qty
        self.cash -= signed * price
        if self.qty == 0 or (self.qty > 0) == (signed > 0):
            total = abs(self.qty) + qty
            self.avg = (self.avg * abs(self.qty) + price * qty) / total if total else price
            self.qty += signed
            return
        closing = min(abs(self.qty), qty)
        direction = 1.0 if self.qty > 0 else -1.0
        self.realized += (price - self.avg) * closing * direction
        self.qty += signed
        if abs(self.qty) < 1e-9:
            self.qty = 0.0
            self.avg = 0.0
        elif (self.qty > 0) == (signed > 0):  # retournement : le reste ouvre une position au prix courant
            self.avg = price

    def unrealized(self, mid: float | None) -> float:
        return 0.0 if mid is None or self.qty == 0 else (mid - self.avg) * self.qty

    def equity(self, mid: float | None) -> float:
        return self.cash + (self.qty * mid if mid is not None else self.qty * self.avg)


def _fill_quantity(trade_price: float, trade_size: float, quote: Quote, better: bool, params: Params) -> float:
    if better:
        return min(quote.remaining, trade_size)
    if params.fill == "optimiste":
        return min(quote.remaining, trade_size)
    ahead = min(quote.queue_ahead, trade_size)
    quote.queue_ahead -= ahead
    return min(quote.remaining, trade_size - ahead)


def simulate(books: list[Book], trades: list[Trade], params: Params, market: str = "", question: str = "") -> Result:
    warnings: list[str] = []
    if len(books) < 2:
        raise ValueError("au moins deux carnets sont nécessaires pour simuler")
    if params.reward_daily_rate > 0 and params.size < params.reward_min_size:
        warnings.append(
            f"taille {params.size:g} inférieure à la taille minimale des rewards {params.reward_min_size:g} : aucun reward"
        )
    position = Position()
    fills: list[Fill] = []
    equity_curve: list[tuple[float, float]] = []
    bid: Quote | None = None
    ask: Quote | None = None
    current: Book | None = None
    rewards_total = 0.0
    next_sample = books[0].t
    taker_volume = 0.0
    trades_in_window = 0

    events: list[tuple[float, int, Any]] = [(b.t, 0, b) for b in books] + [(t.t, 1, t) for t in trades]
    events.sort(key=lambda e: (e[0], e[1]))
    last_t = events[-1][0]

    def sample_rewards(until: float) -> None:
        nonlocal next_sample, rewards_total
        if current is None or current.mid is None or params.reward_daily_rate <= 0:
            next_sample = max(next_sample, until)
            return
        mid = current.mid
        while next_sample <= until:
            ours_one = ours_two = 0.0
            if bid is not None and bid.remaining >= params.reward_min_size:
                ours_one = rw.order_score(abs(mid - bid.price), params.reward_max_spread, bid.remaining)
            if ask is not None and ask.remaining >= params.reward_min_size:
                ours_two = rw.order_score(abs(mid - ask.price), params.reward_max_spread, ask.remaining)
            ours = rw.combine(ours_one, ours_two, mid)
            others = rw.book_score(current.bids, current.asks, mid, params.reward_max_spread, params.reward_min_size)
            rewards_total += params.reward_daily_rate / 1440.0 * rw.share(ours, others)
            next_sample += 60.0

    for t, kind, payload in events:
        if kind == 0:
            sample_rewards(t)
            current = payload
            bid_price, ask_price = compute_quotes(current, params, position.qty)
            bid = Quote(bid_price, params.size, current.size_at("bid", bid_price)) if bid_price is not None else None
            ask = Quote(ask_price, params.size, current.size_at("ask", ask_price)) if ask_price is not None else None
            equity_curve.append((t, position.equity(current.mid)))
            continue
        if current is None:
            continue  # transaction antérieure au premier carnet observé
        trade: Trade = payload
        trades_in_window += 1
        taker_volume += trade.size
        if trade.side == "SELL" and bid is not None and trade.price <= bid.price + 1e-9:
            qty = _fill_quantity(trade.price, trade.size, bid, trade.price < bid.price - 1e-9, params)
            qty = min(qty, params.max_inventory - position.qty)
            if qty > 1e-9:
                position.apply("BUY", bid.price, qty)
                bid.remaining -= qty
                fills.append(Fill(t, "BUY", bid.price, qty, current.mid))
        elif trade.side == "BUY" and ask is not None and trade.price >= ask.price - 1e-9:
            qty = _fill_quantity(trade.price, trade.size, ask, trade.price > ask.price + 1e-9, params)
            qty = min(qty, params.max_inventory + position.qty)
            if qty > 1e-9:
                position.apply("SELL", ask.price, qty)
                ask.remaining -= qty
                fills.append(Fill(t, "SELL", ask.price, qty, current.mid))
    sample_rewards(last_t)

    final = books[-1]
    final_mid = final.mid
    pnl_total = position.equity(final_mid)
    peak = -math.inf
    max_dd = 0.0
    for _, equity in equity_curve:
        peak = max(peak, equity)
        max_dd = max(max_dd, peak - equity)

    flatten_total: float | None = None
    if params.flatten_at_end and position.qty and final.best_bid is not None and final.best_ask is not None:
        exec_price = final.best_bid if position.qty > 0 else final.best_ask
        fee = taker_fee(abs(position.qty), exec_price, params.fee_rate)
        flatten_total = position.cash + position.qty * exec_price - fee

    book_times = [b.t for b in books]
    markouts: dict[str, float | None] = {}
    for horizon in params.markout_horizons:
        values = []
        for f in fills:
            if f.t + horizon > books[-1].t:
                continue  # la fenêtre observée ne couvre pas cet horizon
            idx = bisect.bisect_right(book_times, f.t + horizon) - 1
            if idx < 0 or books[idx].mid is None:
                continue
            direction = 1.0 if f.side == "BUY" else -1.0
            values.append((books[idx].mid - f.price) * direction * 100.0)
        markouts[f"{horizon}s"] = statistics.fmean(values) if values else None

    buys = sum(f.size for f in fills if f.side == "BUY")
    sells = sum(f.size for f in fills if f.side == "SELL")
    return Result(
        market=market,
        question=question,
        start=dt.datetime.fromtimestamp(books[0].t, dt.timezone.utc).isoformat(timespec="seconds"),
        end=dt.datetime.fromtimestamp(last_t, dt.timezone.utc).isoformat(timespec="seconds"),
        hours=(last_t - books[0].t) / 3600.0,
        books=len(books),
        trades=trades_in_window,
        taker_volume=taker_volume,
        fills=len(fills),
        filled_volume=buys + sells,
        buys=buys,
        sells=sells,
        end_inventory=position.qty,
        size=params.size,
        pnl_realized=position.realized,
        pnl_unrealized=position.unrealized(final_mid),
        pnl_total=pnl_total,
        rewards_estimate=rewards_total,
        pnl_with_rewards=pnl_total + rewards_total,
        max_drawdown=max_dd,
        flatten_pnl_total=flatten_total,
        markouts_cents=markouts,
        warnings=warnings,
    )


def write_equity_csv(path: Path, books: list[Book], trades: list[Trade], params: Params) -> None:
    """Courbe d'équité à chaque carnet, utile pour tracer le résultat (rejoue la simulation)."""
    position = Position()
    rows = []
    bid = ask = None
    current = None
    events = sorted([(b.t, 0, b) for b in books] + [(t.t, 1, t) for t in trades], key=lambda e: (e[0], e[1]))
    for t, kind, payload in events:
        if kind == 0:
            current = payload
            bid_price, ask_price = compute_quotes(current, params, position.qty)
            bid = Quote(bid_price, params.size, current.size_at("bid", bid_price)) if bid_price is not None else None
            ask = Quote(ask_price, params.size, current.size_at("ask", ask_price)) if ask_price is not None else None
            rows.append((t, current.mid, position.qty, position.cash, position.equity(current.mid)))
            continue
        if current is None:
            continue
        trade = payload
        if trade.side == "SELL" and bid is not None and trade.price <= bid.price + 1e-9:
            qty = min(_fill_quantity(trade.price, trade.size, bid, trade.price < bid.price - 1e-9, params), params.max_inventory - position.qty)
            if qty > 1e-9:
                position.apply("BUY", bid.price, qty)
                bid.remaining -= qty
        elif trade.side == "BUY" and ask is not None and trade.price >= ask.price - 1e-9:
            qty = min(_fill_quantity(trade.price, trade.size, ask, trade.price > ask.price + 1e-9, params), params.max_inventory + position.qty)
            if qty > 1e-9:
                position.apply("SELL", ask.price, qty)
                ask.remaining -= qty
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["t_utc", "mid", "inventory", "cash", "equity"])
        for t, mid, qty, cash, equity in rows:
            writer.writerow([dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds"), mid, qty, cash, equity])
