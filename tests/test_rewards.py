from polyscan.rewards import book_score, combine, order_score, share, side_score


def test_exemple_de_la_documentation():
    # spread max 3 ¢, ordre à 1 ¢ du médian, 100 parts : ((3 − 1) / 3)² × 100 = 44,44
    assert abs(order_score(0.01, 0.03, 100) - 44.444444) < 1e-4
    assert order_score(0.03, 0.03, 100) == 0.0      # à la limite : zéro
    assert order_score(0.04, 0.03, 100) == 0.0      # au-delà : zéro
    assert order_score(0.0, 0.03, 100) == 100.0     # au médian : taille entière


def test_taille_minimale_et_cotes_des_deux_cotes():
    bids = [(0.49, 100), (0.48, 5)]
    asks = [(0.51, 100)]
    assert side_score(bids, 0.50, 0.03, min_size=20) == side_score([(0.49, 100)], 0.50, 0.03, 0)
    q_one = side_score(bids, 0.50, 0.03, 20)
    q_two = side_score(asks, 0.50, 0.03, 20)
    assert abs(combine(q_one, q_two, 0.50) - q_one) < 1e-9  # symétrique : min = max
    # un seul côté dans la zone normale : divisé par c = 3
    assert abs(combine(q_one, 0.0, 0.50) - q_one / 3) < 1e-9
    # zone extrême : un seul côté ne vaut rien
    assert combine(q_one, 0.0, 0.95) == 0.0
    assert abs(book_score(bids, asks, 0.50, 0.03, 20) - q_one) < 1e-9


def test_part_du_pool():
    assert share(0, 0) == 0.0
    assert abs(share(10, 30) - 0.25) < 1e-12
