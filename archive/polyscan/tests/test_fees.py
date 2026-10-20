from polyscan.fees import DEFAULT_RATE_IF_UNKNOWN, market_rate, taker_fee


def test_formule_officielle_au_prix_median():
    # 100 parts à 50 ¢ avec un taux de 0,04 : 100 × 0,04 × 0,5 × 0,5 = 1,00 USDC
    assert abs(taker_fee(100, 0.5, 0.04) - 1.0) < 1e-12


def test_frais_nuls_aux_extremes_et_sans_taux():
    assert taker_fee(100, 0.0, 0.04) == 0.0
    assert taker_fee(100, 1.0, 0.04) == 0.0
    assert taker_fee(100, 0.5, 0.0) == 0.0
    assert taker_fee(0, 0.5, 0.04) == 0.0


def test_taux_lu_depuis_gamma():
    assert market_rate({"feeSchedule": {"rate": 0.07}, "feesEnabled": True}) == 0.07
    assert market_rate({"feesEnabled": False}) == 0.0
    assert market_rate({"feesEnabled": True}) == DEFAULT_RATE_IF_UNKNOWN
