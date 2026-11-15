"""Partie commune des agents des scénarios d'intégration (CT-9 TI-4 à TI-11,
test/integrations.test.js) : lecture des adresses et jetons dans
l'environnement, client MCP sans état de l'ère moderne (CT-2 §0.3, les mêmes
requêtes que ``conteneurs/agent-demo/agent-demo.mjs``) pour les SDK qui n'ont
pas de client MCP, attente d'une approbation (CT-3 EX-11.9 : l'appel soumis à
approbation est redemandé tel quel, jamais après ``refuse`` ni ``expire``),
assainissement des noms d'outils (CT-2 EX-4.12) et trace de ce que l'agent a
vu, écrite sur la sortie standard en une ligne ``noortrace-agent {…}`` que
l'essai compare au journal et aux dossiers (« pièces égales aux octets vus par
l'hôte »). Aucune dépendance hors de la bibliothèque standard.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# SDK Python `noortrace-sdk` du dépôt (paquets/sdk-python/src), pour les adaptateurs de CT-2 6.6.
RACINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
_SDK = os.path.join(RACINE, "paquets", "sdk-python", "src")
if _SDK not in sys.path:
    sys.path.insert(0, _SDK)

VERSION_PROTOCOLE = "2026-07-28"
SYSTEME = "Tu es l'agent sinistres de l'assureur de démonstration. Contact interne : support@assureur-demo.example (jamais communiqué)."
DEMANDE = "Traite le sinistre 2026-81044."
MODELE = "modele-demo-1"


@dataclass
class Configuration:
    mcp_url: str
    mcp_jeton: str
    passerelle_url: str
    passerelle_jeton: str
    run_id: str
    sdk_socket: Optional[str]
    otel_url: Optional[str]
    otel_jeton: Optional[str]
    mandataire_url: Optional[str]
    mandataire_cle: Optional[str]
    pause_s: float
    attente_max_s: float


def configuration() -> Configuration:
    e = os.environ
    return Configuration(
        mcp_url=e["NOORTRACE_MCP_URL"],
        mcp_jeton=e["NOORTRACE_MCP_TOKEN"],
        passerelle_url=e.get("NOORTRACE_GATEWAY_URL", "").rstrip("/"),
        passerelle_jeton=e.get("NOORTRACE_GATEWAY_TOKEN", ""),
        run_id=e.get("NOORTRACE_RUN_ID", "run-integration-0001"),
        sdk_socket=e.get("NOORTRACE_SDK_SOCKET"),
        otel_url=e.get("NOORTRACE_OTEL_URL"),
        otel_jeton=e.get("NOORTRACE_OTEL_TOKEN"),
        mandataire_url=e.get("NOORTRACE_MANDATAIRE_URL"),
        mandataire_cle=e.get("NOORTRACE_MANDATAIRE_CLE"),
        pause_s=float(e.get("AGENT_PAUSE_S", "0.5")),
        attente_max_s=float(e.get("AGENT_ATTENTE_MAX_S", "60")),
    )


def assainir(nom: str) -> str:
    """Nom d'outil vu par le modèle : tout caractère hors ``[A-Za-z0-9_-]`` remplacé par ``_`` (CT-2 EX-4.12)."""
    return "".join(c if c.isalnum() or c in "_-" else "_" for c in nom)


def texte_resultat(contenu: Any) -> str:
    """Texte d'un résultat MCP (blocs ``text``), que le résultat soit un dict ou un objet du client ``mcp``."""
    blocs = contenu if isinstance(contenu, list) else getattr(contenu, "content", None) or (contenu.get("content") if isinstance(contenu, dict) else []) or []
    textes = []
    for b in blocs:
        t = b.get("type") if isinstance(b, dict) else getattr(b, "type", None)
        if t == "text":
            textes.append(b.get("text") if isinstance(b, dict) else getattr(b, "text", ""))
    return "\n".join(textes)


def signal_approbation(resultat: Any) -> Optional[dict]:
    """Signal d'approbation ``_meta["noortrace/approval"]`` d'un résultat (CT-2 EX-4.49), ou None."""
    meta = resultat.get("_meta") if isinstance(resultat, dict) else getattr(resultat, "meta", None)
    if meta is None and not isinstance(resultat, dict):
        meta = getattr(resultat, "_meta", None)
    if isinstance(meta, dict):
        return meta.get("noortrace/approval")
    return None


def est_erreur(resultat: Any) -> bool:
    if isinstance(resultat, dict):
        return bool(resultat.get("isError"))
    return bool(getattr(resultat, "is_error", None) if getattr(resultat, "is_error", None) is not None else getattr(resultat, "isError", False))


def contenu_structure(resultat: Any) -> Any:
    if isinstance(resultat, dict):
        return resultat.get("structuredContent")
    v = getattr(resultat, "structured_content", None)
    return v if v is not None else getattr(resultat, "structuredContent", None)


@dataclass
class Appel:
    outil: str
    nom_modele: str
    arguments: Any
    resultat: str = ""
    is_error: bool = False
    emissions: int = 0
    tickets: List[str] = field(default_factory=list)
    structured: Any = None


@dataclass
class Trace:
    sdk: str
    echanges: List[dict] = field(default_factory=list)
    appels: List[Appel] = field(default_factory=list)
    fin: Optional[str] = None
    notes: Dict[str, Any] = field(default_factory=dict)

    def echange(self, **k: Any) -> None:
        self.echanges.append(k)

    def imprimer(self) -> None:
        d = {"sdk": self.sdk, "echanges": self.echanges, "appels": [a.__dict__ for a in self.appels], "fin": self.fin, "notes": self.notes}
        sys.stdout.write("noortrace-agent " + json.dumps(d, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def rapporter_echec(e: BaseException) -> None:
    """Écrit l'exception (et chaque sous-exception d'un ``ExceptionGroup``) sur la sortie d'erreur, avec sa trace."""
    import traceback

    def _une(x: BaseException, prefixe: str) -> None:
        sys.stderr.write(f"agent : échec : {prefixe}{type(x).__name__}: {x}\n")
        sys.stderr.write("".join(traceback.format_exception(type(x), x, x.__traceback__))[-3000:] + "\n")
        for s in getattr(x, "exceptions", []) or []:
            _une(s, prefixe + "  ")

    _une(e, "")


def dire(texte: str) -> None:
    sys.stdout.write(f"agent : {texte}\n")
    sys.stdout.flush()


def appeler_avec_approbation(appel: Callable[[], Any], trace_appel: Appel, pause_s: float, attente_max_s: float) -> Any:
    """Appelle l'outil ; soumis à approbation (``state`` ``en_attente``), le redemande
    tel quel après ``pause_s`` tant que le ticket attend ; ``refuse`` ou ``expire``
    arrête sans répéter (CT-3 EX-11.9). Rend le résultat final."""
    debut = time.monotonic()
    while True:
        trace_appel.emissions += 1
        r = appel()
        signal = signal_approbation(r)
        if not signal:
            trace_appel.resultat = texte_resultat(r)
            trace_appel.is_error = est_erreur(r)
            trace_appel.structured = contenu_structure(r)
            return r
        trace_appel.tickets.append(signal.get("ticket"))
        if signal.get("state") != "en_attente":
            raise RuntimeError(f"{trace_appel.outil} : ticket {signal.get('ticket')} {signal.get('state')}, l'appel n'est pas répété")
        if time.monotonic() - debut > attente_max_s:
            raise RuntimeError(f"{trace_appel.outil} : toujours en attente d'approbation après {attente_max_s} s")
        dire(f"{trace_appel.outil} : en attente d'approbation (ticket {signal.get('ticket')})")
        time.sleep(pause_s)


async def appeler_avec_approbation_async(appel: Callable[[], Any], trace_appel: Appel, pause_s: float, attente_max_s: float) -> Any:
    """Variante asynchrone de ``appeler_avec_approbation`` (``appel`` rend une coroutine)."""
    import asyncio

    debut = time.monotonic()
    while True:
        trace_appel.emissions += 1
        r = await appel()
        signal = signal_approbation(r)
        if not signal:
            trace_appel.resultat = texte_resultat(r)
            trace_appel.is_error = est_erreur(r)
            trace_appel.structured = contenu_structure(r)
            return r
        trace_appel.tickets.append(signal.get("ticket"))
        if signal.get("state") != "en_attente":
            raise RuntimeError(f"{trace_appel.outil} : ticket {signal.get('ticket')} {signal.get('state')}, l'appel n'est pas répété")
        if time.monotonic() - debut > attente_max_s:
            raise RuntimeError(f"{trace_appel.outil} : toujours en attente d'approbation après {attente_max_s} s")
        dire(f"{trace_appel.outil} : en attente d'approbation (ticket {signal.get('ticket')})")
        await asyncio.sleep(pause_s)


def session_mcp(cfg: Configuration, nom_client: str = "agent-integration"):
    """Contexte asynchrone : session du client MCP de référence (``mcp`` 2.x,
    Streamable HTTP) vers le frontal, jeton statique de l'hôte en ``Authorization:
    Bearer`` ; rend la ``ClientSession`` initialisée."""
    from contextlib import asynccontextmanager

    import httpx2
    from mcp import ClientSession, types as mcp_types
    from mcp.client.streamable_http import streamable_http_client

    @asynccontextmanager
    async def _ctx():
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {cfg.mcp_jeton}"}, timeout=httpx2.Timeout(120, read=300)) as http:
            async with streamable_http_client(cfg.mcp_url, http_client=http) as flux:
                async with ClientSession(flux[0], flux[1], client_info=mcp_types.Implementation(name=nom_client, version="0.1.0")) as session:
                    await session.initialize()
                    yield session

    return _ctx()


class ClientMcpSansEtat:
    """Client MCP Streamable HTTP de l'ère moderne (métadonnées par requête,
    aucune session) : ``tools/list`` et ``tools/call`` par ``urllib``, en-têtes
    ``MCP-Protocol-Version``, ``Mcp-Method``, ``Mcp-Name``, ``run_id`` déclaré
    dans ``_meta`` (CT-2 §4, EX-4.4)."""

    def __init__(self, url: str, jeton: str, run_id: str, nom_client: str = "agent-integration") -> None:
        self.url, self.jeton, self.run_id, self.nom_client = url, jeton, run_id, nom_client
        self.compteur = 0

    def _requete(self, methode: str, params: dict) -> Any:
        self.compteur += 1
        corps = {
            "jsonrpc": "2.0", "id": f"{self.nom_client}-{self.compteur:02d}", "method": methode,
            "params": {**params, "_meta": {
                "io.modelcontextprotocol/protocolVersion": VERSION_PROTOCOLE,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": self.nom_client, "version": "0.1.0"},
                "noortrace/delegation": {"run_id": self.run_id},
            }},
        }
        entetes = {"content-type": "application/json", "accept": "application/json, text/event-stream", "authorization": f"Bearer {self.jeton}",
                   "mcp-protocol-version": VERSION_PROTOCOLE, "mcp-method": methode}
        if methode == "tools/call":
            entetes["mcp-name"] = params["name"]
        req = urllib.request.Request(self.url, data=json.dumps(corps).encode("utf-8"), headers=entetes, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as rep:
                texte = rep.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            texte = e.read().decode("utf-8", "replace")
        if texte.startswith("event:") or texte.startswith("data:"):
            donnees = [l[5:].lstrip() for l in texte.split("\n") if l.startswith("data:")]
            texte = donnees[-1] if donnees else texte
        reponse = json.loads(texte)
        if "error" in reponse:
            err = reponse["error"]
            raise RuntimeError(f"{methode} : erreur {err.get('code')} {err.get('message')}")
        return reponse["result"]

    def lister(self) -> List[dict]:
        return self._requete("tools/list", {})["tools"]

    def appeler(self, nom: str, arguments: Any) -> dict:
        return self._requete("tools/call", {"name": nom, "arguments": arguments})


def schema_entree(outil: Any) -> dict:
    """Schéma d'entrée d'un outil annoncé (dict ou objet ``mcp.types.Tool``), réduit à type, properties, required."""
    s = outil.get("inputSchema") if isinstance(outil, dict) else getattr(outil, "inputSchema", None)
    s = s or {"type": "object", "properties": {}}
    r = {"type": s.get("type", "object"), "properties": s.get("properties", {})}
    if s.get("required"):
        r["required"] = s["required"]
    return r
