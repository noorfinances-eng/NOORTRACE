"""Clients HTTP minimalistes pour les API publiques de Polymarket.

Deux services sont utilisés, tous deux accessibles sans compte ni clé :
- Gamma (``gamma-api.polymarket.com``) : catalogue des événements et marchés,
  avec meilleur prix vendeur, spread, paramètres de frais et de rewards.
- CLOB (``clob.polymarket.com``) : carnets d'ordres en direct par jeton.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterator

import requests

GAMMA_URL = "https://gamma-api.polymarket.com"
CLOB_URL = "https://clob.polymarket.com"
USER_AGENT = "polyscan/0.1"
PAGE_SIZE = 100  # Gamma plafonne ``limit`` à 100 par page.

log = logging.getLogger(__name__)


class HttpError(RuntimeError):
    def __init__(self, status: int, url: str, body: str = ""):
        super().__init__(f"HTTP {status} sur {url}: {body[:200]}")
        self.status = status


class HttpClient:
    """Session ``requests`` avec User-Agent, délai d'attente et reprises sur erreurs transitoires."""

    def __init__(self, timeout: float = 30.0, retries: int = 3, backoff: float = 1.0, pause: float = 0.05):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.pause = pause

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise HttpError(resp.status_code, resp.url, resp.text)
                if resp.status_code >= 400:
                    # Erreur non transitoire (404, 422...) : on ne réessaie pas.
                    raise HttpError(resp.status_code, resp.url, resp.text)
                if self.pause:
                    time.sleep(self.pause)
                return resp.json()
            except HttpError as exc:
                if exc.status != 429 and exc.status < 500:
                    raise
                last = exc
            except (requests.RequestException, ValueError) as exc:
                last = exc
            if attempt < self.retries:
                time.sleep(self.backoff * (2**attempt))
        assert last is not None
        raise last


class GammaClient:
    def __init__(self, http: HttpClient | None = None, base_url: str = GAMMA_URL):
        self.http = http or HttpClient()
        self.base_url = base_url

    def iter_active_events(self, page_size: int = PAGE_SIZE) -> Iterator[dict[str, Any]]:
        """Parcourt tout le catalogue des événements actifs, non clos, avec leurs marchés.

        Utilise ``/events/keyset`` : la pagination par ``offset`` de ``/events`` est
        refusée au-delà de quelques milliers d'événements, alors que le curseur
        ``next_cursor`` permet de tout lire.
        """
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"active": "true", "closed": "false", "limit": page_size}
            if cursor:
                params["after_cursor"] = cursor
            page = self.http.get_json(f"{self.base_url}/events/keyset", params=params)
            events = page.get("events") if isinstance(page, dict) else page
            if not events:
                return
            yield from events
            cursor = page.get("next_cursor") if isinstance(page, dict) else None
            if not cursor or len(events) < page_size:
                return

    def active_events(self) -> list[dict[str, Any]]:
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for event in self.iter_active_events():
            if event["id"] in seen:
                continue
            seen.add(event["id"])
            out.append(event)
        return out


class ClobClient:
    def __init__(self, http: HttpClient | None = None, base_url: str = CLOB_URL):
        self.http = http or HttpClient()
        self.base_url = base_url

    def book(self, token_id: str) -> dict[str, Any]:
        return self.http.get_json(f"{self.base_url}/book", params={"token_id": token_id})

    def market(self, condition_id: str) -> dict[str, Any]:
        """Fiche d'un marché côté moteur d'appariement : tick, taille minimale, paramètres de rewards."""
        return self.http.get_json(f"{self.base_url}/markets/{condition_id}")

    def books(self, token_ids: list[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for token_id in token_ids:
            try:
                out[token_id] = self.book(token_id)
            except Exception as exc:  # noqa: BLE001 - on continue avec les autres jetons
                log.warning("carnet indisponible pour %s : %s", token_id[:12], exc)
        return out


# ----- Aides de lecture des objets Gamma ---------------------------------------------------------


def _float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def is_tradable(market: dict[str, Any]) -> bool:
    return bool(
        market.get("active")
        and not market.get("closed")
        and market.get("acceptingOrders")
        and market.get("enableOrderBook")
    )


def active_markets(event: dict[str, Any]) -> list[dict[str, Any]]:
    return [m for m in event.get("markets", []) if is_tradable(m)]


def token_ids(market: dict[str, Any]) -> list[str]:
    raw = market.get("clobTokenIds")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    return [str(t) for t in (raw or [])]


def yes_token(market: dict[str, Any]) -> str | None:
    ids = token_ids(market)
    return ids[0] if ids else None


def best_prices(market: dict[str, Any]) -> tuple[float | None, float | None]:
    """Retourne (meilleur acheteur, meilleur vendeur) du jeton OUI.

    Les marchés imbriqués dans ``/events`` n'exposent pas ``bestBid`` : on le
    reconstruit comme ``bestAsk - spread``. Quand aucun acheteur n'existe, Gamma
    publie un spread égal au meilleur vendeur, ce qui donne bien un bid nul.
    """
    ask = _float(market.get("bestAsk"))
    bid = _float(market.get("bestBid"))
    if bid is None and ask is not None:
        spread = _float(market.get("spread"))
        if spread is not None:
            bid = max(ask - spread, 0.0)
    if bid is not None and bid <= 0:
        bid = None
    return bid, ask
