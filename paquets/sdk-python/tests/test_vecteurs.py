"""Vecteurs de l'annexe B rejoués par le SDK Python (CT-2 EX-6.5 : « Les deux SDK
partagent les vecteurs de l'annexe B (`pieces-mcp`, `redaction`,
`pieces-modele`) : le SDK ne calcule rien, mais ses tests vérifient que le
démon rend les références attendues »), contre le démon réel muni de la
politique de rédaction des vecteurs (`pii-v1`, `pii-pseudo-test`) :

- ``redaction/cas.json`` : portées ``arguments`` (``debut_appel``),
  ``resultat`` (``fin_appel``), ``contexte`` (``declarer_contexte``),
  ``requete``, ``reponse`` et ``prompt_systeme`` (``echange_modele``) ; les
  cas de ``pii-regles-test`` ne sont pas rejoués : leurs règles visent par
  sélecteur des outils du frontal MCP (``demo__…``, ``mail__send``), qu'un nom
  du SDK (``<alias>__<tool>``, EX-6.6) ne peut pas porter ;
- ``pieces-modele/gemini-sdk-*`` : ``echange_modele`` au format ``gemini`` ;
- ``pieces-mcp/appels`` : la pièce « arguments » de chaque cas non refusé
  (arguments de la requête de ``hote.jsonl``) et la pièce « résultat » d'un
  cas dont le résultat est celui du serveur (relue depuis ses octets
  attendus : la rédaction est idempotente, EX-10.14)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from conftest import RACINE, Banc

from noortrace_sdk import ClientNoortrace

VECTEURS = RACINE / "spec" / "vecteurs" / "ct-2"
CAS = json.loads((VECTEURS / "redaction" / "cas.json").read_text(encoding="utf-8"))


def references(evenement: Any) -> Dict[str, dict]:
    """Toutes les références CT-1 d'un événement, par ``sha256``."""
    vues: Dict[str, dict] = {}

    def parcourir(v: Any) -> None:
        if isinstance(v, dict):
            if isinstance(v.get("sha256"), str) and "length" in v and "redacted" in v:
                vues[v["sha256"]] = v
            for x in v.values():
                parcourir(x)
        elif isinstance(v, list):
            for x in v:
                parcourir(x)

    parcourir(evenement)
    return vues


def piece_stockee(banc: Banc, sha: str) -> bytes:
    h = sha[2:]
    return Path(banc.info["journal"], "pieces", h[:2], h).read_bytes()


@pytest.fixture(scope="module")
def banc_pii():
    b = Banc(politique="pii-v1")
    b.politique = "pii-v1"
    yield b
    b.fermer()


@pytest.fixture(scope="module")
def banc_pseudo():
    b = Banc(politique="pii-pseudo-test")
    b.politique = "pii-pseudo-test"
    yield b
    b.fermer()


def test_redaction_cas_pii_v1(banc_pii):
    rejouer_redaction(banc_pii)


def test_redaction_cas_pii_pseudo_test(banc_pseudo):
    rejouer_redaction(banc_pseudo)


def rejouer_redaction(b):
    cas = [c for c in CAS if c["policy"] == b.politique]
    assert cas, b.politique
    rejoues: List[str] = []
    with ClientNoortrace(socket=b.socket, delai_s=20).ouvrir(run_id=f"run-vecteurs-{b.politique}") as s:
        for k, c in enumerate(cas):
            e = c["expected"]
            if c["scope"] == "arguments":
                d = s.debut_appel(f"lire_vecteur_{k}", c["input"], classe="lecture")
                s.fin_appel(d, None, False, 0)
                ref = [x for x in b.evenements() if x["execution"]["tool"] == f"agent-py__lire_vecteur_{k}"][-1]["execution"]["arguments"]
            elif c["scope"] == "resultat":
                d = s.debut_appel(f"lire_vecteur_{k}", {}, classe="lecture")
                sc = s.fin_appel(d, c["input"], False, 0)
                ref = [x for x in b.evenements() if x["seq"] == sc.seq][0]["execution"]["result"]
            elif c["scope"] == "contexte":
                texte = isinstance(c["input"], str)
                octets = c["input"].encode("utf-8") if texte else json.dumps(c["input"], ensure_ascii=False).encode("utf-8")
                r = s.declarer_contexte("document", octets, media_type="text/plain" if texte else "application/json")
                ref = {"sha256": r.sha256, "length": r.length, "redacted": r.redacted}
            elif c["scope"] in ("requete", "reponse", "prompt_systeme"):
                if c["scope"] == "requete":
                    requete, reponse = c["input"], {"id": "msg_v", "type": "message", "role": "assistant", "model": "modele-demo-1", "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}
                elif c["scope"] == "reponse":
                    requete, reponse = {"model": "modele-demo-1", "max_tokens": 16, "messages": [{"role": "user", "content": "x"}]}, c["input"]
                else:
                    requete = {"model": "modele-demo-1", "max_tokens": 16, "system": c["input"], "messages": [{"role": "user", "content": "x"}]}
                    reponse = {"id": "msg_v", "type": "message", "role": "assistant", "model": "modele-demo-1", "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}
                sc = s.echange_modele("anthropic-messages", "anthropic", requete, reponse, 200, 1, False)
                evt = [x for x in b.evenements() if x["seq"] == sc.seq][0]
                if c["scope"] == "prompt_systeme":
                    # La pièce « prompt système » est citée par son sha256 dans code.prompt_version (7.2).
                    assert evt["code"]["prompt_version"] == e["sha256"], (c["name"], evt["code"])
                    stockee = piece_stockee(b, e["sha256"])
                    ref = {"sha256": e["sha256"], "length": len(stockee), "redacted": stockee.decode("utf-8") != c["input"]}
                else:
                    refs = references(evt)
                    assert e["sha256"] in refs, (c["name"], e, list(refs))
                    ref = refs[e["sha256"]]
            else:
                continue
            assert (ref["sha256"], ref["length"], ref["redacted"]) == (e["sha256"], e["length"], e["redacted"]), (c["name"], ref, e)
            assert piece_stockee(b, e["sha256"]).decode("utf-8") == e["piece"], c["name"]
            rejoues.append(c["name"])
    print(f"\nnoortrace-vecteurs redaction {b.politique} : {len(rejoues)} cas rejoues")
    assert len(rejoues) == len(cas)


def test_pieces_modele_gemini_sdk(banc_pii):
    b = banc_pii
    noms = sorted(p.name for p in (VECTEURS / "pieces-modele").iterdir() if p.name.startswith("gemini-sdk-"))
    assert noms == ["gemini-sdk-erreur-declaree", "gemini-sdk-morceaux"]
    with ClientNoortrace(socket=b.socket, delai_s=20).ouvrir(run_id="run-vecteurs-gemini") as s:
        for nom in noms:
            d = VECTEURS / "pieces-modele" / nom
            attendu = json.loads((d / "attendu.json").read_text(encoding="utf-8"))
            echange = json.loads((d / "echange-sdk.json").read_text(encoding="utf-8"))
            requete = json.loads((d / "requete.json").read_text(encoding="utf-8"))
            reponse = json.loads((d / "reponse-morceaux.json").read_text(encoding="utf-8"))
            sc = s.echange_modele(echange["format"], echange["provider_label"], requete, reponse, echange["status"], echange["duration_ms"], echange["is_error"])
            evt = [x for x in b.evenements() if x["seq"] == sc.seq][0]
            refs = references(evt)
            for cle, p in attendu["pieces"].items():
                if p is None:
                    continue
                if cle == "system_prompt":
                    assert evt["code"]["prompt_version"] == p["sha256"], (nom, evt["code"])
                else:
                    assert p["sha256"] in refs, (nom, cle)
                assert piece_stockee(b, p["sha256"]).decode("utf-8") == p["bytes"], (nom, cle)
            assert evt["execution"]["is_error"] is attendu["is_error"], nom
            assert evt["code"]["model"] == attendu["code_model"], nom
            assert evt["code"]["prompt_version"] == attendu["prompt_version"], nom
            # EX-6.8 point 3 : membre ajouté par le SDK Python retiré et consigné (sdk_member_removed).
            if attendu["removed_members"]:
                retires = [l["data"].get("member") or l["data"].get("name") for l in b.exploitation("sdk_member_removed")]
                assert set(attendu["removed_members"]) <= set(retires), (nom, retires)


def test_pieces_mcp_arguments_et_resultats(banc_pii):
    b = banc_pii
    rejoues = []
    with ClientNoortrace(socket=b.socket, delai_s=20).ouvrir(run_id="run-vecteurs-mcp") as s:
        for d in sorted((VECTEURS / "pieces-mcp" / "appels").iterdir()):
            attendu = json.loads((d / "attendu.json").read_text(encoding="utf-8"))
            if attendu["rejected"]:
                continue
            requete = None
            for l in (d / "hote.jsonl").read_text(encoding="utf-8").splitlines():
                env = json.loads(l)
                if env.get("dir") != "in":
                    continue
                corps = env["line"]
                try:
                    m = json.loads(corps)
                except ValueError:
                    m = json.loads(corps.replace("\r", ""))
                if isinstance(m, dict) and m.get("method") == "tools/call":
                    requete = m
            assert requete is not None, d.name
            pa = attendu["pieces"]["arguments"]
            debut = s.debut_appel(f"vecteur_{d.name.replace('-', '_')}", requete["params"].get("arguments", {}), classe="lecture")
            pr = attendu["pieces"].get("result")
            resultat = json.loads(pr["bytes"]) if pr and pr.get("bytes") and not pr["bytes"].startswith('{"noortrace_') else None
            sc = s.fin_appel(debut, resultat, False, 0)
            evt = [x for x in b.evenements() if x["seq"] == sc.seq][0]
            a = evt["execution"]["arguments"]
            assert (a["sha256"], a["length"], a["redacted"]) == (pa["sha256"], pa["length"], pa["redacted"]), (d.name, a, pa)
            if resultat is not None:
                r = evt["execution"]["result"]
                assert (r["sha256"], r["length"]) == (pr["sha256"], pr["length"]), (d.name, r, pr)
            rejoues.append(d.name)
    print(f"\nnoortrace-vecteurs pieces-mcp : {len(rejoues)} cas rejoues ({', '.join(rejoues)})")
    assert len(rejoues) >= 15
