import datetime as dt

from polyscan.watch import daily_reward_rate, enrich_from_clob, select_watchlist, trim_book

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.timezone.utc)


def market(**extra):
    base = {
        "conditionId": "0xabc", "question": "Q ?", "slug": "q", "active": True, "closed": False, "acceptingOrders": True,
        "enableOrderBook": True, "bestAsk": "0.31", "spread": "0.01", "liquidityNum": 50_000, "volume24hr": 1000,
        "endDate": "2026-12-31T00:00:00Z", "clobTokenIds": '["y", "n"]', "orderPriceMinTickSize": 0.01, "orderMinSize": 5,
        "feeSchedule": {"rate": 0.04}, "feesEnabled": True, "rewardsMinSize": 200, "rewardsMaxSpread": 4.5,
        "clobRewards": [{"rewardsDailyRate": 200, "startDate": "2026-10-01", "endDate": "2500-12-31"}],
    }
    base.update(extra)
    return base


def test_taux_journalier_fenetres_actives_seulement():
    m = market(clobRewards=[
        {"rewardsDailyRate": 100, "startDate": "2026-10-01", "endDate": "2026-10-19"},   # terminée
        {"rewardsDailyRate": 50, "startDate": "2026-10-21", "endDate": "2026-12-31"},    # pas encore commencée
        {"rewardsDailyRate": 25, "startDate": "2026-10-10", "endDate": "2026-12-31"},    # active
    ])
    assert daily_reward_rate(m, NOW.date()) == 25


def test_selection_filtres_et_tri():
    events = [
        {"title": "E1", "markets": [market(volume24hr=10)]},
        {"title": "E2", "markets": [market(conditionId="0xdef", volume24hr=500)]},
        {"title": "E3", "markets": [market(conditionId="0xlow", liquidityNum=100)]},               # trop peu liquide
        {"title": "E4", "markets": [market(conditionId="0xext", bestAsk="0.96", spread="0.01")]},   # prix extrême
        {"title": "E5", "markets": [market(conditionId="0xsoon", endDate="2026-10-22T00:00:00Z")]}, # échéance trop proche
        {"title": "E6", "markets": [market(conditionId="0xnorw", clobRewards=[])]},                 # pas de rewards
    ]
    rows = select_watchlist(events, top=10, now=NOW)
    assert [r["condition_id"] for r in rows] == ["0xdef", "0xabc"]
    assert rows[0]["reward_daily_rate"] == 200 and rows[0]["reward_min_size"] == 200 and rows[0]["fee_rate"] == 0.04
    assert rows[0]["yes_token"] == "y" and rows[0]["no_token"] == "n"


class FakeClob:
    def __init__(self, info):
        self.info = info

    def market(self, condition_id):
        if condition_id == "0xfail":
            raise RuntimeError("indisponible")
        return self.info


def test_alignement_sur_le_clob():
    rows = [{"condition_id": "0xabc", "reward_daily_rate": 200.0, "reward_min_size": 200.0, "reward_max_spread_cents": 4.5,
             "tick": 0.01, "min_order_size": 5.0},
            {"condition_id": "0xfail", "reward_daily_rate": 7.0, "reward_min_size": 1.0, "reward_max_spread_cents": 1.0,
             "tick": 0.01, "min_order_size": 5.0}]
    info = {"rewards": {"rates": [{"rewards_daily_rate": 100}], "min_size": 100, "max_spread": 6.5},
            "minimum_tick_size": 0.001, "minimum_order_size": 15}
    out = enrich_from_clob(rows, FakeClob(info))
    assert out[0]["reward_daily_rate"] == 100 and out[0]["reward_min_size"] == 100 and out[0]["reward_max_spread_cents"] == 6.5
    assert out[0]["tick"] == 0.001 and out[0]["min_order_size"] == 15
    assert out[1]["reward_daily_rate"] == 7.0  # fiche indisponible : valeurs Gamma conservées


def test_carnet_tronque_et_trie():
    book = {"bids": [{"price": "0.40", "size": "1"}, {"price": "0.45", "size": "2"}],
            "asks": [{"price": "0.60", "size": "1"}, {"price": "0.50", "size": "2"}], "hash": "h", "timestamp": "1"}
    out = trim_book(book, levels=1)
    assert out["bids"] == [(0.45, 2.0)] and out["asks"] == [(0.5, 2.0)] and out["hash"] == "h"
