"""LiteLLM en mandataire, disposition (a) d'EX-6.22, la disposition recommandée :
agent → passerelle de l'enregistreur → mandataire LiteLLM (``litellm[proxy]``
1.106.4) → fournisseur simulé. La route de la passerelle a pour amont l'URL du
mandataire et pour format celui de l'agent (``openai-chat``) ; l'enregistreur
voit la requête de l'agent, sous la délégation de l'agent (sa connexion
d'hôte), et la réponse que LiteLLM rend. Aucun code d'adaptateur ne sert ici ;
les crochets ``async_pre_call_hook`` du mandataire ne sont pas employés. La
disposition (b) (mandataire devant la passerelle) n'est pas essayée : le texte
ne l'admet que si la documentation d'intégration le dit."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from conftest import Banc, evenements_outil, exiger

exiger("litellm.proxy.proxy_server")


@pytest.fixture(scope="module")
def banc_mandataire():
    litellm_bin = Path(sys.prefix) / "bin" / "litellm"
    assert litellm_bin.exists(), "executable litellm de l'environnement du mandataire absent"
    b = Banc(mandataire=str(litellm_bin))
    yield b
    b.fermer()


def chat(contenu: str) -> dict:
    return {"id": "chatcmpl-mandataire-1", "object": "chat.completion", "created": 1794306000, "model": "modele-chat",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": contenu}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}


def test_disposition_a_passerelle_devant_le_mandataire(banc_mandataire):
    import httpx

    b = banc_mandataire
    assert b.info["mandataire_url"].startswith("http://127.0.0.1:")
    b.commande(cmd="scenario", reponses=[chat("Le sinistre 2026-77812 est ouvert.")])
    avant = b.evenements()
    n = len(b.commande(cmd="requetes_fournisseur")["requetes"])
    requete = {"model": "modele-chat", "messages": [{"role": "system", "content": "Tu es l'agent sinistres."},
                                                    {"role": "user", "content": "Ou en est le sinistre 2026-77812 ?"}]}
    r = httpx.post(b.info["passerelle_url"] + "/v1/chat/completions", json=requete, timeout=60,
                   headers={"Authorization": f"Bearer {b.info['passerelle_jeton']}", "X-Noortrace-Run-Id": "run-mandataire-0001"})
    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == "Le sinistre 2026-77812 est ouvert."
    # Le fournisseur a reçu la requête émise par LiteLLM (pas par la passerelle).
    recues = b.commande(cmd="requetes_fournisseur")["requetes"][n:]
    assert len(recues) == 1 and recues[0]["cible"].endswith("/chat/completions")
    fin = time.monotonic() + 10
    while True:
        echanges = evenements_outil(b.evenements()[len(avant):], "noortrace.modele.echange")
        if echanges or time.monotonic() > fin:
            break
        time.sleep(0.05)
    assert len(echanges) == 1
    e = echanges[0]
    # Délégation de l'agent (connexion d'hôte de la passerelle), pas celle du mandataire.
    assert e["delegation"]["launched_by"] == "agent-sinistres" and e["delegation"]["run_id"] == "run-mandataire-0001"
    assert e["code"]["model"] == "openai/modele-chat" and e["context"] == []
    # La pièce « requête » est la requête de l'agent (rédigée), la pièce « réponse » ce que LiteLLM a rendu.
    h = e["execution"]["arguments"]["sha256"][2:]
    piece = json.loads(Path(b.info["journal"], "pieces", h[:2], h).read_bytes())
    assert piece["messages"][-1]["content"] == "Ou en est le sinistre 2026-77812 ?"
    h = e["execution"]["result"]["sha256"][2:]
    reponse = json.loads(Path(b.info["journal"], "pieces", h[:2], h).read_bytes())
    assert "Le sinistre 2026-77812 est ouvert." in json.dumps(reponse, ensure_ascii=False)
    print(f"\nnoortrace-mandataire : agent -> passerelle -> LiteLLM {b.info['mandataire_url']} -> fournisseur simule ; 1 echange, delegation de l'agent")
