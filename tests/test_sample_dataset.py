"""Test d'intégration sur l'extrait réel livré dans samples/ : format des fichiers et chaîne complète sans réseau."""

from pathlib import Path

from polyscan.simulate import Params, load_market, resolve_size, simulate
from polyscan.watch import load_watchlist

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "watch_2026-10-20"


def test_extrait_reel_se_rejoue_de_bout_en_bout():
    markets = load_watchlist(SAMPLE / "watchlist.json")
    assert len(markets) == 3
    simulated = 0
    for m in markets:
        books, trades = load_market(SAMPLE, m["condition_id"], m["yes_token"])
        assert len(books) >= 2
        assert all(b.mid is not None for b in books)
        assert all(t.side in ("BUY", "SELL") and 0 < t.price < 1 for t in trades)
        size = resolve_size("auto", m)
        params = Params(size=size, max_inventory=max(500.0, size), reward_daily_rate=m["reward_daily_rate"],
                        reward_min_size=m["reward_min_size"], reward_max_spread=m["reward_max_spread_cents"] / 100,
                        tick=m["tick"], fee_rate=m["fee_rate"])
        result = simulate(books, trades, params, market=m["condition_id"], question=m["question"])
        assert result.hours > 0 and result.rewards_estimate >= 0
        assert abs(result.pnl_total - (result.pnl_realized + result.pnl_unrealized)) < 1e-6
        simulated += 1
    assert simulated == 3
