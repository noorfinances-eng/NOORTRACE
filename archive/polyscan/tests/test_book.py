from polyscan.book import asks, best, bids, walk

BOOK = {
    "asks": [{"price": "0.30", "size": "10"}, {"price": "0.25", "size": "5"}, {"price": "0.40", "size": "100"}],
    "bids": [{"price": "0.20", "size": "7"}, {"price": "0.24", "size": "3"}],
}


def test_tri_des_niveaux():
    assert [p for p, _ in asks(BOOK)] == [0.25, 0.30, 0.40]
    assert [p for p, _ in bids(BOOK)] == [0.24, 0.20]
    assert best(asks(BOOK)) == 0.25
    assert best([]) is None


def test_parcours_avec_profondeur_suffisante():
    cost, filled = walk(asks(BOOK), 12)
    # 5 parts à 0,25 puis 7 parts à 0,30
    assert filled == 12
    assert abs(cost - (5 * 0.25 + 7 * 0.30)) < 1e-12


def test_parcours_avec_profondeur_insuffisante():
    cost, filled = walk(asks(BOOK), 1000)
    assert filled == 115
    assert abs(cost - (5 * 0.25 + 10 * 0.30 + 100 * 0.40)) < 1e-9


def test_niveaux_invalides_ignores():
    assert asks({"asks": [{"price": "x", "size": "1"}, {"price": "0.5", "size": "0"}]}) == []
