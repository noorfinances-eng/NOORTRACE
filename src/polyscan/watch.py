"""Collecte continue des carnets d'ordres et des transactions d'une liste de marchés.

Conçu pour tourner en permanence sur une machine personnelle ou un petit
serveur. Toutes les ``interval`` secondes, pour chaque marché surveillé :

- le carnet du jeton OUI est lu sur le CLOB et enregistré s'il a changé
  (le carnet NON est son miroir exact, inutile de le stocker) ;
- les dernières transactions publiques sont lues sur la Data API et les
  nouvelles sont ajoutées, dédoublonnées.

Les fichiers sont des JSON Lines par jour UTC (``books_AAAA-MM-JJ.jsonl``,
``trades_AAAA-MM-JJ.jsonl``), compressés en gzip à la rotation. La liste des
marchés et leurs paramètres (jetons, tick, frais, rewards) est écrite dans
``watchlist.json`` au démarrage.
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
import logging
import shutil
import signal
import time
from pathlib import Path
from typing import Any

from polyscan.api import ClobClient, GammaClient, HttpClient, active_markets, best_prices, token_ids
from polyscan.fees import market_rate

DATA_URL = "https://data-api.polymarket.com"
log = logging.getLogger(__name__)


class DataClient:
    """Transactions publiques (Data API). Par défaut l'API ne renvoie que le côté preneur."""

    def __init__(self, http: HttpClient | None = None, base_url: str = DATA_URL):
        self.http = http or HttpClient()
        self.base_url = base_url

    def trades(self, condition_id: str, limit: int = 500) -> list[dict[str, Any]]:
        data = self.http.get_json(f"{self.base_url}/trades", params={"market": condition_id, "limit": limit})
        return data if isinstance(data, list) else []


# ----- Sélection des marchés ----------------------------------------------------------------------


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        return default


def _parse_date(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def daily_reward_rate(market: dict[str, Any], today: dt.date) -> float:
    """Somme des taux journaliers (USDC/jour) des fenêtres de rewards actives aujourd'hui."""
    total = 0.0
    for window in market.get("clobRewards") or []:
        start = _parse_date(window.get("startDate"))
        end = _parse_date(window.get("endDate"))
        if start and start.date() > today:
            continue
        if end and end.date() < today:
            continue
        total += _float(window.get("rewardsDailyRate"))
    return total


def select_watchlist(
    events: list[dict[str, Any]],
    top: int = 30,
    min_liquidity: float = 10_000.0,
    min_days: float = 7.0,
    max_days: float = 400.0,
    price_band: tuple[float, float] = (0.10, 0.90),
    now: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    """Marchés rémunérés, liquides, à échéance ni trop proche ni trop lointaine, au prix non extrême.

    Triés par volume sur 24 h décroissant : sans flux, un market maker n'est jamais servi.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    rows: list[dict[str, Any]] = []
    for event in events:
        for market in active_markets(event):
            rate = daily_reward_rate(market, now.date())
            if rate <= 0:
                continue
            bid, ask = best_prices(market)
            if bid is None or ask is None:
                continue
            mid = (bid + ask) / 2
            if not price_band[0] <= mid <= price_band[1]:
                continue
            liquidity = _float(market.get("liquidityNum"))
            if liquidity < min_liquidity:
                continue
            end = _parse_date(market.get("endDate") or event.get("endDate"))
            if end is None:
                continue
            days = (end - now).total_seconds() / 86400
            if days < min_days or days > max_days:
                continue
            tokens = token_ids(market)
            if len(tokens) < 2:
                continue
            rows.append(
                {
                    "condition_id": market.get("conditionId"),
                    "question": market.get("question"),
                    "event": event.get("title"),
                    "slug": market.get("slug"),
                    "yes_token": tokens[0],
                    "no_token": tokens[1],
                    "tick": _float(market.get("orderPriceMinTickSize"), 0.01),
                    "min_order_size": _float(market.get("orderMinSize"), 5.0),
                    "fee_rate": market_rate(market),
                    "reward_daily_rate": rate,
                    "reward_min_size": _float(market.get("rewardsMinSize")),
                    "reward_max_spread_cents": _float(market.get("rewardsMaxSpread")),
                    "liquidity": liquidity,
                    "volume_24h": _float(market.get("volume24hr")),
                    "end_date": end.isoformat(),
                    "mid_at_selection": mid,
                }
            )
    rows.sort(key=lambda r: -r["volume_24h"])
    return rows[:top]


# ----- Boucle de collecte --------------------------------------------------------------------------


def trade_key(trade: dict[str, Any]) -> str:
    return f"{trade.get('transactionHash')}|{trade.get('asset')}|{trade.get('price')}|{trade.get('size')}|{trade.get('timestamp')}"


def trim_book(book: dict[str, Any], levels: int) -> dict[str, Any]:
    bids = sorted(((float(x["price"]), float(x["size"])) for x in book.get("bids", [])), key=lambda l: -l[0])[:levels]
    asks = sorted(((float(x["price"]), float(x["size"])) for x in book.get("asks", [])), key=lambda l: l[0])[:levels]
    return {"bids": bids, "asks": asks, "hash": book.get("hash"), "ts": book.get("timestamp")}


class Watcher:
    def __init__(self, out_dir: Path, watchlist: list[dict[str, Any]], interval: float = 60.0, levels: int = 20,
                 keep_days: int = 0, clob: ClobClient | None = None, data: DataClient | None = None):
        self.out_dir = out_dir
        self.watchlist = watchlist
        self.interval = interval
        self.levels = levels
        self.keep_days = keep_days
        self.clob = clob or ClobClient()
        self.data = data or DataClient()
        self.last_hash: dict[str, str | None] = {}
        self.seen: dict[str, set[str]] = {m["condition_id"]: set() for m in watchlist}
        self.stop = False
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def request_stop(self, *_: Any) -> None:
        self.stop = True

    def _append(self, name: str, day: dt.date, record: dict[str, Any]) -> None:
        with open(self.out_dir / f"{name}_{day.isoformat()}.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def rotate(self, today: dt.date) -> None:
        """Compresse les fichiers des jours précédents et applique la rétention."""
        for path in sorted(self.out_dir.glob("*_????-??-??.jsonl")):
            day = dt.date.fromisoformat(path.stem[-10:])
            if day >= today:
                continue
            with open(path, "rb") as src, gzip.open(path.with_suffix(".jsonl.gz"), "wb") as dst:
                shutil.copyfileobj(src, dst)
            path.unlink()
        if self.keep_days > 0:
            for path in self.out_dir.glob("*_????-??-??.jsonl.gz"):
                day = dt.date.fromisoformat(path.name.split("_")[1][:10])
                if (today - day).days > self.keep_days:
                    path.unlink()

    def poll_once(self) -> tuple[int, int]:
        now = dt.datetime.now(dt.timezone.utc)
        day = now.date()
        books_written = trades_written = 0
        for market in self.watchlist:
            cid = market["condition_id"]
            try:
                book = self.clob.book(market["yes_token"])
                trimmed = trim_book(book, self.levels)
                if trimmed["hash"] != self.last_hash.get(cid):
                    self.last_hash[cid] = trimmed["hash"]
                    self._append("books", day, {"t": now.isoformat(timespec="seconds"), "cid": cid, **trimmed})
                    books_written += 1
            except Exception as exc:  # noqa: BLE001 - un marché en erreur ne doit pas arrêter la collecte
                log.warning("carnet %s : %s", cid[:10], exc)
            try:
                seen = self.seen[cid]
                fresh = []
                for trade in self.data.trades(cid):
                    key = trade_key(trade)
                    if key in seen:
                        continue
                    seen.add(key)
                    fresh.append(trade)
                for trade in sorted(fresh, key=lambda t: _float(t.get("timestamp"))):
                    self._append(
                        "trades", day,
                        {"cid": cid, "t": int(_float(trade.get("timestamp"))), "side": trade.get("side"),
                         "price": _float(trade.get("price")), "size": _float(trade.get("size")),
                         "asset": trade.get("asset"), "outcome": trade.get("outcome"), "tx": trade.get("transactionHash")},
                    )
                    trades_written += 1
                if len(seen) > 5000:
                    # borne mémoire : on ne garde que les clés les plus récentes
                    self.seen[cid] = set(list(seen)[-2500:])
            except Exception as exc:  # noqa: BLE001
                log.warning("transactions %s : %s", cid[:10], exc)
        return books_written, trades_written

    def run(self, iterations: int = 0) -> None:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        (self.out_dir / "watchlist.json").write_text(
            json.dumps({"selected_at": dt.datetime.now(dt.timezone.utc).isoformat(), "markets": self.watchlist},
                       ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        done = 0
        while not self.stop:
            started = time.monotonic()
            self.rotate(dt.datetime.now(dt.timezone.utc).date())
            books, trades = self.poll_once()
            done += 1
            log.info("itération %d : %d carnets modifiés, %d transactions nouvelles, %.1fs", done, books, trades,
                     time.monotonic() - started)
            if iterations and done >= iterations:
                break
            remaining = self.interval - (time.monotonic() - started)
            while remaining > 0 and not self.stop:
                time.sleep(min(remaining, 1.0))
                remaining -= 1.0


def load_watchlist(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["markets"] if isinstance(payload, dict) else payload


def build_watchlist(gamma: GammaClient | None = None, **kwargs: Any) -> list[dict[str, Any]]:
    gamma = gamma or GammaClient()
    return select_watchlist(gamma.active_events(), **kwargs)
