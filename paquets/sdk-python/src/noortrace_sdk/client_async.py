"""Client asynchrone du SDK Python de NOORTRACE (CT-2 6.5, EX-6.9 à EX-6.15).

``ClientNoortraceAsync`` porte les mêmes noms que le client synchrone, avec
des méthodes ``async``. Il appartient à la boucle d'événements qui l'a créé
(connexion par ``asyncio.open_unix_connection``, R12-F51) et lève
``NoortraceConfiguration`` s'il est employé depuis une autre boucle
(EX-6.14) ; créé hors de toute boucle (au niveau d'un module, comme dans
l'exemple de 6.6), il appartient à la boucle de son premier appel (LISEZMOI,
lecture 144). Les adaptateurs l'emploient sur les chemins asynchrones
(``awrap_tool_call``, ``acall``, ``on_invoke_tool``).
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import math
import os
import time
import weakref
from typing import Any, Callable, Dict, Iterable, Optional

from ._commun import (
    Adresse,
    creer_preuve,
    defi_valide,
    delai_reprise,
    journal,
    ligne_jsonrpc,
    nom_de_classe,
    octets_de,
    params_debut,
    params_echange,
    resoudre_adresse,
    resultat_declare,
    verifier_reglages,
)
from .erreurs import (
    AppelNonAutorise,
    NoortraceConfiguration,
    NoortraceEntreeInvalide,
    NoortraceIndisponible,
    erreur_depuis_reponse,
)
from .objets import Debut, Reference, Scelle

#: Borne d'une ligne lue (``limits.line_max_bytes`` de l'exemple de 15.3 : 16 842 752 octets).
_LIGNE_MAX = 16842752

_LIENS: "weakref.WeakKeyDictionary[Debut, tuple]" = weakref.WeakKeyDictionary()


def _duree_ms(t0: float) -> int:
    return max(0, math.floor((time.monotonic() - t0) * 1000))


class ConnexionAsync:
    """Une connexion asynchrone au démon ; perdue, elle n'est jamais réutilisée (EX-6.13)."""

    def __init__(self, adresse: Adresse) -> None:
        self.adresse = adresse
        self.prochain_id = 1
        self.attentes: Dict[int, asyncio.Future] = {}
        self.perdue = False
        self._lecteur: Optional[asyncio.StreamReader] = None
        self._ecrivain: Optional[asyncio.StreamWriter] = None
        self._tache: Optional[asyncio.Task] = None

    async def ouvrir(self, delai_s: float) -> None:
        """Établit la connexion et la preuve d'identité, au plus ``delai_s`` (EX-6.10)."""
        try:
            await asyncio.wait_for(self._ouvrir(), delai_s)
        except asyncio.TimeoutError as e:
            self._detruire()
            raise NoortraceIndisponible("noortrace: enregistreur injoignable (delai)", False) from e
        except NoortraceIndisponible:
            self._detruire()
            raise
        except (OSError, ValueError, asyncio.IncompleteReadError) as e:
            self._detruire()
            raise NoortraceIndisponible(f"noortrace: enregistreur injoignable ({type(e).__name__})", False) from e
        self._tache = asyncio.get_running_loop().create_task(self._lire())

    async def _ouvrir(self) -> None:
        a = self.adresse
        if a.socket:
            r, w = await asyncio.open_unix_connection(a.socket, limit=_LIGNE_MAX)
        elif a.tls is not None:
            r, w = await asyncio.open_connection(a.hote, a.port, ssl=a.tls, server_hostname=a.hote, limit=_LIGNE_MAX)
        else:
            r, w = await asyncio.open_connection(a.hote, a.port, limit=_LIGNE_MAX)
        self._lecteur, self._ecrivain = r, w
        if not a.socket and a.tls is None:
            # Prise TCP : première ligne {"noortrace_token": …}, sauf en mTLS (EX-6.10, EX-4.39).
            w.write((json.dumps({"noortrace_token": a.jeton or ""}) + "\n").encode("utf-8"))
            await w.drain()
        while True:
            ligne = await r.readline()
            if not ligne.endswith(b"\n"):
                raise NoortraceIndisponible("noortrace: enregistreur injoignable (fermee)", False)
            try:
                m = json.loads(ligne.decode("utf-8"))
            except ValueError:
                m = None
            defi = defi_valide(m)
            if defi is not None and a.socket:
                try:
                    creer_preuve(a.socket, defi)
                except OSError as e:
                    raise NoortraceIndisponible(f"noortrace: enregistreur injoignable (preuve_{type(e).__name__})", False) from e
                w.write((json.dumps({"noortrace_preuve": defi}) + "\n").encode("utf-8"))
                await w.drain()
                continue
            if isinstance(m, dict) and m.get("noortrace_identite") == "acceptee":
                return
            raise NoortraceIndisponible("noortrace: enregistreur injoignable (reponse_inattendue)", False)

    async def _lire(self) -> None:
        r = self._lecteur
        try:
            while r is not None:
                ligne = await r.readline()
                if not ligne.endswith(b"\n"):
                    break
                self._ligne(ligne[:-1])
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except asyncio.CancelledError:
            pass
        self._perdre()

    def _ligne(self, ligne: bytes) -> None:
        try:
            m = json.loads(ligne.decode("utf-8"))
        except ValueError:
            return
        if not isinstance(m, dict):
            return
        id_ = m.get("id")
        if not isinstance(id_, int) or isinstance(id_, bool):
            return
        f = self.attentes.pop(id_, None)
        if f is not None and not f.done():
            f.set_result(m)

    def _perdre(self) -> None:
        if self.perdue:
            return
        self.perdue = True
        attentes = list(self.attentes.values())
        self.attentes.clear()
        for f in attentes:
            if not f.done():
                f.set_exception(NoortraceIndisponible("noortrace: connexion perdue", True))
        self._detruire()

    def _detruire(self) -> None:
        w = self._ecrivain
        if w is not None:
            try:
                w.close()
            except (OSError, RuntimeError):
                pass

    async def appeler(self, nom: str, params: dict, delai_s: float) -> Any:
        """Envoie une requête et attend sa réponse, au plus ``delai_s`` (EX-6.11 (1))."""
        if self.perdue or self._ecrivain is None:
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        id_ = self.prochain_id
        ligne = ligne_jsonrpc(id_, nom, params)
        self.prochain_id += 1
        f: asyncio.Future = asyncio.get_running_loop().create_future()
        self.attentes[id_] = f
        try:
            self._ecrivain.write(ligne)
        except (OSError, RuntimeError) as e:
            self.attentes.pop(id_, None)
            self._perdre()
            raise NoortraceIndisponible("noortrace: connexion perdue", False) from e
        # La requête est écrite : elle ne sera jamais renvoyée (EX-6.13).
        try:
            m = await asyncio.wait_for(asyncio.shield(f), delai_s)
        except asyncio.TimeoutError as e:
            self.attentes.pop(id_, None)
            raise NoortraceIndisponible("noortrace: delai ecoule", True) from e
        if "error" in m and m["error"] is not None:
            raise erreur_depuis_reponse(m["error"])
        return m.get("result")

    def fermer(self) -> None:
        if self._tache is not None and not self._tache.done():
            self._tache.cancel()
        self._perdre()

    def abandonner(self) -> None:
        """Après ``os.fork()`` : la prise du parent n'est jamais réutilisée (EX-6.14)."""
        self.perdue = True
        self.attentes = {}
        w = self._ecrivain
        self._ecrivain = None
        if w is not None:
            try:
                w.transport.abort()
            except (OSError, RuntimeError, AttributeError):
                pass


class ClientNoortraceAsync:
    """Client asynchrone du démon (EX-6.9, EX-6.14) ; la connexion est ouverte au premier appel."""

    def __init__(self, socket: Optional[str] = None, tcp: Optional[str] = None, jeton: Optional[str] = None,
                 delai_s: float = 30.0, reprises: int = 2, sur_indisponibilite_lecture: str = "bloquer") -> None:
        verifier_reglages(delai_s, reprises, sur_indisponibilite_lecture)
        self._adresse = resoudre_adresse(socket, tcp, jeton)
        self.delai_s = float(delai_s)
        self.reprises = reprises
        self.sur_indisponibilite_lecture = sur_indisponibilite_lecture
        self._connexion: Optional[ConnexionAsync] = None
        self._generation = 0
        self._pid = os.getpid()
        try:
            self._boucle: Optional[asyncio.AbstractEventLoop] = asyncio.get_running_loop()
        except RuntimeError:
            self._boucle = None
        self._etablissement: Optional[asyncio.Lock] = None

    @classmethod
    def depuis_environnement(cls) -> "ClientNoortraceAsync":
        """Client configuré par l'environnement seul (EX-6.10)."""
        return cls()

    def _verifier_boucle(self) -> None:
        """EX-6.14 : le client appartient à la boucle qui l'a créé ; ailleurs, ``NoortraceConfiguration``."""
        try:
            boucle = asyncio.get_running_loop()
        except RuntimeError as e:
            raise NoortraceConfiguration("noortrace: client asynchrone employe hors d'une boucle d'evenements") from e
        if self._boucle is None:
            self._boucle = boucle
        elif self._boucle is not boucle:
            raise NoortraceConfiguration("noortrace: client asynchrone employe depuis une autre boucle d'evenements")
        if self._pid != os.getpid():
            # EX-6.14 : après os.fork(), une connexion et une session nouvelles.
            self._pid = os.getpid()
            if self._connexion is not None:
                self._connexion.abandonner()
            self._connexion = None
            self._generation += 1
            self._etablissement = None

    def _vivante(self, generation: int) -> bool:
        c = self._connexion
        return c is not None and not c.perdue and self._generation == generation and self._pid == os.getpid()

    async def _connexion_une_tentative(self) -> tuple:
        if self._etablissement is None:
            self._etablissement = asyncio.Lock()
        async with self._etablissement:
            c = self._connexion
            if c is not None and not c.perdue:
                return c, self._generation
            c = ConnexionAsync(self._adresse)
            await c.ouvrir(self.delai_s)
            self._connexion = c
            self._generation += 1
            return c, self._generation

    async def _ouvrir_session(self, run_id: Optional[str], on_behalf_of: Optional[str]) -> tuple:
        """``ouvrir`` de 6.2, retenté avec l'établissement de la connexion (EX-6.13) :
        au plus ``1 + reprises`` tentatives."""
        self._verifier_boucle()
        derniere: Optional[BaseException] = None
        for n in range(self.reprises + 1):
            if n > 0:
                await asyncio.sleep(delai_reprise(n - 1))
            try:
                c, generation = await self._connexion_une_tentative()
                r = await c.appeler("ouvrir", {"run_id": run_id, "on_behalf_of": on_behalf_of}, self.delai_s)
                return r, generation
            except NoortraceIndisponible as e:
                derniere = e
        assert derniere is not None
        raise derniere

    def ouvrir(self, run_id: Optional[str] = None, on_behalf_of: Optional[str] = None) -> "_Ouverture":
        """``noortrace/sdk/ouvrir`` (EX-6.9) : un objet qui s'attend (``await``) ou
        s'emploie par ``async with``."""
        return _Ouverture(self, run_id, on_behalf_of)


class _Ouverture:
    """Résultat de ``ClientNoortraceAsync.ouvrir`` : attendu, il rend la session ;
    employé par ``async with``, il la ferme à la sortie du bloc."""

    def __init__(self, client: ClientNoortraceAsync, run_id: Optional[str], on_behalf_of: Optional[str]) -> None:
        self._client = client
        self._run_id = run_id
        self._on_behalf_of = on_behalf_of
        self._session: Optional[SessionAsync] = None

    async def _ouvrir(self) -> "SessionAsync":
        s = SessionAsync(self._client, self._run_id, self._on_behalf_of)
        await s._ouvrir()
        self._session = s
        return s

    def __await__(self):
        return self._ouvrir().__await__()

    async def __aenter__(self) -> "SessionAsync":
        return await self._ouvrir()

    async def __aexit__(self, type_, valeur, trace) -> None:
        if self._session is not None:
            await self._session.__aexit__(type_, valeur, trace)


class SessionAsync:
    """Session SDK du client asynchrone (mêmes méthodes que ``Session``, ``async``)."""

    def __init__(self, client: ClientNoortraceAsync, run_id: Optional[str], on_behalf_of: Optional[str]) -> None:
        self._client = client
        self._run_id = run_id
        self._on_behalf_of = on_behalf_of
        self._id: Optional[str] = None
        self._generation = 0
        self._contextes: set = set()
        self._contextes_perdus: set = set()
        self._close = False
        self._verrou: Optional[asyncio.Lock] = None
        self.reponse_ouvrir: Optional[Dict[str, Any]] = None

    async def _ouvrir(self) -> None:
        r, generation = await self._client._ouvrir_session(self._run_id, self._on_behalf_of)
        self._id = r["session"]
        self._generation = generation
        self.reponse_ouvrir = r

    async def _assurer(self) -> None:
        if self._close:
            raise NoortraceEntreeInvalide("noortrace: session fermee", {"reason": "session_inconnue"})
        self._client._verifier_boucle()
        if self._verrou is None:
            self._verrou = asyncio.Lock()
        async with self._verrou:
            if self._client._vivante(self._generation):
                return
            self._contextes_perdus.update(self._contextes)
            self._contextes.clear()
            await self._ouvrir()

    async def _appeler(self, nom: str, construire: Callable[[str], dict]) -> Any:
        await self._assurer()
        if not self._client._vivante(self._generation):
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        c = self._client._connexion
        assert c is not None and self._id is not None
        return await c.appeler(nom, construire(self._id), self._client.delai_s)

    async def declarer_contexte(self, kind: str, octets: Any, media_type: Optional[str] = None) -> Reference:
        """``noortrace/sdk/declarerContexte`` (EX-6.9)."""
        donnees = base64.b64encode(octets_de(octets)).decode("ascii")
        r = await self._appeler("declarerContexte", lambda s: {"session": s, "kind": kind, "media_type": media_type, "bytes_base64": donnees})
        self._contextes.add(r["sha256"])
        return Reference(sha256=r["sha256"], length=r["length"], redacted=r["redacted"])

    async def debut_appel(self, tool: str, arguments: Any, classe: Optional[str] = None, contexte: Iterable[str] = (),
                          intent: Optional[str] = None, effects: Optional[list] = None) -> Debut:
        """``noortrace/sdk/debutAppel`` (EX-6.9)."""
        await self._assurer()
        contexte = list(contexte or ())
        for s in contexte:
            if s in self._contextes_perdus and s not in self._contextes:
                raise NoortraceEntreeInvalide("noortrace: reference de contexte d'une session perdue",
                                              {"reason": "context_session_perdue"})
        generation = self._generation
        r = await self._appeler("debutAppel", lambda s: params_debut(s, tool, arguments, classe, contexte, intent, effects))
        debut = Debut(call=r.get("call"), decision=r.get("decision"), ticket=r.get("ticket"), ticket_state=r.get("ticket_state"))
        _LIENS[debut] = (weakref.ref(self), generation)
        return debut

    async def fin_appel(self, debut: Debut, resultat: Any, is_error: bool, duration_ms: int) -> Scelle:
        """``noortrace/sdk/finAppel`` (EX-6.9)."""
        self._client._verifier_boucle()
        lien = _LIENS.get(debut)
        if lien is not None:
            session, generation = lien[0](), lien[1]
            if session is not self or not self._client._vivante(generation) or self._generation != generation:
                raise NoortraceIndisponible("noortrace: session perdue avant finAppel", False)
        if not self._client._vivante(self._generation):
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        c = self._client._connexion
        assert c is not None
        r = await c.appeler("finAppel", {"call": getattr(debut, "call", None), "result": resultat, "is_error": is_error,
                                         "duration_ms": duration_ms}, self._client.delai_s)
        return Scelle(seq=r.get("seq"), hash=r.get("hash"))

    async def appel_outil(self, tool: str, arguments: Any, fonction: Callable[..., Any], classe: Optional[str] = None,
                          contexte: Iterable[str] = (), intent: Optional[str] = None, effects: Optional[list] = None) -> Any:
        """``debut_appel``, ``fonction(**arguments)`` (attendue si elle rend un objet
        attendable), ``fin_appel`` (EX-6.9)."""
        try:
            debut = await self.debut_appel(tool, arguments, classe=classe, contexte=contexte, intent=intent, effects=effects)
        except Exception as e:
            if (classe or "ecriture") == "lecture" and self._client.sur_indisponibilite_lecture == "executer":
                journal.warning("noortrace-sdk: debutAppel en echec (%s) ; outil de lecture %s execute sans evenement",
                                nom_de_classe(e), tool)
                v = fonction(**arguments)
                return (await v) if inspect.isawaitable(v) else v
            raise
        if debut.decision != "autorise":
            raise AppelNonAutorise(debut.decision, debut.ticket, debut.ticket_state)
        t0 = time.monotonic()
        try:
            valeur = fonction(**arguments)
            if inspect.isawaitable(valeur):
                valeur = await valeur
        except Exception as e:
            await self.fin_appel(debut, {"noortrace_sdk_exception": nom_de_classe(e)}, True, _duree_ms(t0))
            raise
        duree = _duree_ms(t0)
        await self.fin_appel(debut, resultat_declare(valeur), False, duree)
        return valeur

    async def echange_modele(self, format: str, provider_label: str, request: Any, response: Any, status: Optional[int],
                             duration_ms: int, is_error: bool) -> Scelle:
        """``noortrace/sdk/echangeModele`` (EX-6.9)."""
        r = await self._appeler("echangeModele", lambda s: params_echange(s, format, provider_label, request, response,
                                                                           status, duration_ms, is_error))
        return Scelle(seq=r.get("seq"), hash=r.get("hash"))

    async def fermer(self) -> Dict[str, Any]:
        """``noortrace/sdk/fermer`` (EX-6.9)."""
        if self._close:
            return {}
        self._client._verifier_boucle()
        if not self._client._vivante(self._generation):
            self._close = True
            return {}
        c = self._client._connexion
        assert c is not None
        r = await c.appeler("fermer", {"session": self._id}, self._client.delai_s)
        self._close = True
        return r if isinstance(r, dict) else {}

    async def __aenter__(self) -> "SessionAsync":
        return self

    async def __aexit__(self, type_, valeur, trace) -> None:
        try:
            await self.fermer()
        except Exception:
            if valeur is None:
                raise
            journal.warning("noortrace-sdk: fermer en echec apres une exception du bloc")
