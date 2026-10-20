import math

from polyscan.simulate import Book, Params, Position, Trade, compute_quotes, normalize_trade, resolve_size, simulate

T0 = 1_800_000_000.0


def book(t, bid, ask, bid_size=100.0, ask_size=100.0):
    return Book(t, [(bid, bid_size), (round(bid - 0.01, 2), 500.0)], [(ask, ask_size), (round(ask + 0.01, 2), 500.0)])


def test_normalisation_des_transactions_sur_le_jeton_non():
    yes = normalize_trade({"t": 1, "side": "BUY", "price": 0.3, "size": 10, "asset": "Y"}, "Y")
    assert (yes.side, yes.price) == ("BUY", 0.3)
    no = normalize_trade({"t": 1, "side": "BUY", "price": 0.3, "size": 10, "asset": "N"}, "Y")
    assert (no.side, no.price) == ("SELL", 0.7)


def test_cotes_join_mid_et_plafond_d_inventaire():
    b = book(T0, 0.49, 0.52)
    assert compute_quotes(b, Params(quote="join"), 0) == (0.49, 0.52)
    # improve : un tick à l'intérieur de chaque côté tant que le spread le permet
    assert compute_quotes(b, Params(quote="improve", improve_ticks=1), 0) == (0.5, 0.51)
    # spread de 1 tick : impossible d'améliorer sans fermer le spread, on se place au meilleur prix
    assert compute_quotes(book(T0, 0.49, 0.50), Params(quote="improve", improve_ticks=1), 0) == (0.49, 0.5)
    assert compute_quotes(b, Params(quote="join", max_inventory=100), 100) == (None, 0.52)
    assert compute_quotes(b, Params(quote="join", max_inventory=100), -100) == (0.49, None)
    # skew : long de 2 × taille, cotes abaissées de 2 ticks
    assert compute_quotes(b, Params(quote="join", size=50, skew_ticks=1), 100) == (0.47, 0.5)


def test_position_cout_moyen_et_retournement():
    p = Position()
    p.apply("BUY", 0.40, 10)
    p.apply("BUY", 0.50, 10)
    assert abs(p.avg - 0.45) < 1e-12 and p.qty == 20
    p.apply("SELL", 0.55, 5)
    assert abs(p.realized - 0.5) < 1e-12 and p.qty == 15
    p.apply("SELL", 0.60, 20)  # ferme 15 (+2,25) puis ouvre 5 à découvert à 0,60
    assert abs(p.realized - 2.75) < 1e-12 and p.qty == -5 and p.avg == 0.60
    assert abs(p.unrealized(0.50) - 0.5) < 1e-12


def test_remplissage_prudent_contre_optimiste_et_capture_du_spread():
    books = [book(T0, 0.49, 0.51, bid_size=5.0, ask_size=0.0), book(T0 + 600, 0.49, 0.51), book(T0 + 1200, 0.49, 0.51)]
    trades = [Trade(T0 + 10, "SELL", 0.49, 15), Trade(T0 + 20, "BUY", 0.51, 10)]
    prudent = simulate(books, trades, Params(quote="join", size=10, fill="prudent"))
    # vendeur de 15 à 0,49 : 5 affichées devant nous → 10 pour nous ; acheteur de 10 à 0,51 : rien devant → 10
    assert prudent.fills == 2 and prudent.buys == 10 and prudent.sells == 10
    assert abs(prudent.pnl_realized - 0.20) < 1e-9 and abs(prudent.pnl_total - 0.20) < 1e-9
    assert prudent.end_inventory == 0
    assert prudent.markouts_cents["300s"] is not None and abs(prudent.markouts_cents["300s"] - 1.0) < 1e-9
    # transaction à prix égal avec toute la taille devant nous : rien en prudent, tout en optimiste
    trades2 = [Trade(T0 + 10, "SELL", 0.49, 5)]
    assert simulate(books, trades2, Params(quote="join", size=10, fill="prudent")).fills == 0
    assert simulate(books, trades2, Params(quote="join", size=10, fill="optimiste")).fills == 1


def test_plafond_d_inventaire_et_selection_adverse():
    books = [book(T0, 0.49, 0.51, bid_size=0.0), book(T0 + 300, 0.39, 0.41), book(T0 + 600, 0.39, 0.41)]
    trades = [Trade(T0 + 10, "SELL", 0.48, 100), Trade(T0 + 20, "SELL", 0.48, 100)]
    r = simulate(books, trades, Params(quote="join", size=200, max_inventory=120, fill="prudent"))
    assert r.buys == 120 and r.end_inventory == 120
    # achetés à 0,49, le médian tombe à 0,40 : −0,09 × 120 = −10,80, et un markout de −9 ¢
    assert abs(r.pnl_total + 10.80) < 1e-9
    assert abs(r.markouts_cents["300s"] + 9.0) < 1e-9
    assert abs(r.max_drawdown - 10.80) < 1e-9
    flat = simulate(books, trades, Params(quote="join", size=200, max_inventory=120, flatten_at_end=True, fee_rate=0.04))
    # aplatissement en vendant 120 à 0,39 : trésorerie −58,8 + 46,8 = −12 moins frais 120 × 0,04 × 0,39 × 0,61
    assert flat.flatten_pnl_total is not None
    assert abs(flat.flatten_pnl_total - (-12.0 - 120 * 0.04 * 0.39 * 0.61)) < 1e-9


def test_rewards_echantillonnes_une_fois_par_minute():
    books = [book(T0, 0.49, 0.51), book(T0 + 180, 0.49, 0.51)]
    params = Params(quote="join", size=100, reward_daily_rate=1440.0, reward_min_size=50, reward_max_spread=0.03)
    r = simulate(books, [], params)
    # 4 échantillons (t0, +60, +120, +180) à 1 $ chacun. Notre score : ((3 − 1)/3)² × 100 = 44,44 par côté.
    # Carnet : 44,44 au premier niveau + ((3 − 2)/3)² × 500 = 55,56 au second, soit 100 par côté.
    assert abs(r.rewards_estimate - 4 * (44.444444444 / 144.444444444)) < 1e-6
    small = simulate(books, [], Params(quote="join", size=10, reward_daily_rate=1440.0, reward_min_size=50, reward_max_spread=0.03))
    assert small.rewards_estimate == 0.0 and small.warnings


def test_taille_auto():
    assert resolve_size("auto", {"reward_min_size": 100, "min_order_size": 5}) == 100
    assert resolve_size("auto", {"reward_min_size": 0, "min_order_size": 5}) == 5
    assert resolve_size("auto", {}) == 1.0
    assert resolve_size("40", {"reward_min_size": 100}) == 40.0
    assert resolve_size(25, {"reward_min_size": 100}) == 25.0
