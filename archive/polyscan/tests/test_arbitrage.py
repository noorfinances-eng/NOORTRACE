import datetime as dt

from polyscan.arbitrage import depth_margins, scan_event, scan_events, summarize

NOW = dt.datetime(2026, 10, 19, 12, 0, tzinfo=dt.timezone.utc)


def market(label, ask, spread, rate=0.04, token="t", other=False, **extra):
    base = {
        "active": True,
        "closed": False,
        "acceptingOrders": True,
        "enableOrderBook": True,
        "groupItemTitle": label,
        "bestAsk": str(ask),
        "spread": str(spread),
        "feeSchedule": {"rate": rate},
        "feesEnabled": rate > 0,
        "clobTokenIds": f'["{token}", "{token}-no"]',
        "negRiskOther": other,
    }
    base.update(extra)
    return base


def event(markets, **extra):
    base = {
        "id": "e1",
        "title": "Test",
        "slug": "test",
        "negRisk": True,
        "negRiskAugmented": False,
        "endDate": "2026-11-18T12:00:00Z",
        "volume24hr": 1000,
        "markets": markets,
    }
    base.update(extra)
    return base


def test_ecart_brut_frais_et_net():
    ev = event([market("A", 0.30, 0.01, token="a"), market("B", 0.30, 0.01, token="b"), market("C", 0.30, 0.01, token="c")])
    scan = scan_event(ev, NOW)
    assert scan is not None
    assert abs(scan.sum_ask - 0.90) < 1e-12
    assert abs(scan.gross_buy - 0.10) < 1e-12
    # frais par issue : 0,04 × 0,3 × 0,7 = 0,0084, soit 0,0252 pour le lot
    assert abs(scan.fee_buy - 0.0252) < 1e-12
    assert abs(scan.net_buy - 0.0748) < 1e-12
    assert abs(scan.days_to_end - 30) < 1e-9
    assert scan.sum_bid is not None and abs(scan.sum_bid - 0.87) < 1e-12
    assert scan.flags == ["sans_autre"]


def test_reserves_liste_extensible_echeance_et_illiquidite():
    ev = event(
        [market("A", 0.5, 0.01, token="a"), market("B", 0.4, 0.01, token="b", other=True)],
        negRiskAugmented=True,
        endDate="2026-10-01T00:00:00Z",
        volume24hr=5,
    )
    scan = scan_event(ev, NOW)
    assert scan is not None
    assert scan.ended and scan.days_to_end == 0
    assert scan.annualized is None
    assert scan.flags == ["liste_extensible", "echeance_passee", "illiquide"]
    assert not scan.clean


def test_issue_sans_vendeur_ou_evenement_binaire_ignores():
    assert scan_event(event([market("A", 0.5, 0.01), market("B", None, None)]), NOW) is None
    assert scan_events([event([market("A", 0.5, 0.01)])], NOW) == []
    assert scan_events([event([market("A", 0.4, 0.01), market("B", 0.4, 0.01)], negRisk=False)], NOW) == []


def test_profondeur_reelle_sur_les_carnets():
    ev = event([market("A", 0.30, 0.01, token="a"), market("B", 0.30, 0.01, token="b")], volume24hr=1000)
    scan = scan_event(ev, NOW)
    books = {
        "a": {"asks": [{"price": "0.30", "size": "10"}, {"price": "0.60", "size": "100"}]},
        "b": {"asks": [{"price": "0.30", "size": "10"}, {"price": "0.60", "size": "100"}]},
    }
    margins = depth_margins(scan, books, sizes=(5, 20, 1000))
    # 5 parts : 0,30 + 0,30 = 0,60, frais 2 × 0,04 × 0,3 × 0,7 = 0,0168 → net 0,3832
    assert abs(margins[5] - 0.3832) < 1e-12
    # 20 parts : prix moyen (10×0,30 + 10×0,60)/20 = 0,45 par issue → 0,90, frais 2 × 0,04 × 0,45 × 0,55 = 0,0198
    assert abs(margins[20] - (1 - 0.90 - 0.0198)) < 1e-12
    assert margins[1000] is None


def test_resume():
    scans = scan_events(
        [
            event([market("A", 0.6, 0.01, token="a"), market("B", 0.5, 0.01, token="b")], id="e1"),
            event([market("A", 0.3, 0.01, token="a"), market("B", 0.3, 0.01, token="b", other=True)], id="e2"),
            event([market("A", 0.499, 0.001, token="a"), market("B", 0.499, 0.001, token="b")], id="e3"),
        ],
        NOW,
    )
    counts = summarize(scans)
    assert counts == {
        "analyses": 3,
        "somme_vendeurs_>=_1": 1,
        "ecart_brut_absorbe_par_frais": 1,
        "ecart_net_positif": 1,
        "ecart_net_positif_sans_reserve": 1,
    }


def test_instantane_allege_conserve_les_champs_du_scan():
    from polyscan.collector import slim_event

    ev = event([market("A", 0.3, 0.01, token="a", description="long texte"), market("B", 0.3, 0.01, token="b")],
               description="long texte", tags=[{"id": 1, "label": "Politics"}])
    slim = slim_event(ev)
    assert "description" not in slim and "description" not in slim["markets"][0]
    assert slim["tags"] == ["Politics"]
    before = scan_event(ev, NOW)
    after = scan_event(slim, NOW)
    assert after is not None and before is not None
    assert after.net_buy == before.net_buy and after.flags == before.flags


def test_issues_indisponibles_disqualifient():
    closed = market("C", 0.001, 0.001, token="c", closed=True)
    ev = event([market("A", 0.3, 0.01, token="a"), market("B", 0.3, 0.01, token="b"), closed])
    scan = scan_event(ev, NOW)
    assert scan is not None
    assert scan.outcomes == 2 and scan.markets_total == 3
    assert "issues_indisponibles" in scan.flags
    assert scan.disqualified and not scan.clean
    complete = scan_event(event([market("A", 0.3, 0.01, token="a"), market("B", 0.3, 0.01, token="b")]), NOW)
    assert complete is not None and not complete.disqualified
