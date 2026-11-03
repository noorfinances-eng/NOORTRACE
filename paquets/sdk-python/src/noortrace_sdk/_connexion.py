"""Connexion synchrone du SDK au démon (CT-2 EX-6.1, EX-6.10, EX-6.14).

Prise de domaine Unix ou prise TCP locale (jeton statique en première ligne,
ou mTLS), cadrage de 4.7.1 (une ligne JSON-RPC 2.0 par message, ``\\n``
final), ``id`` entiers croissants à partir de 1 sur chaque connexion. Le SDK
n'y reçoit jamais de requête du démon : il lit les réponses à ses requêtes,
et, à l'ouverture, les lignes de la preuve d'identité (prise Unix : défi du
démon, fichier créé en exclusion dans le répertoire de la prise, puis
l'acceptation ; prise TCP : acceptation après le jeton ou la poignée de main
mTLS).

EX-6.14 : une connexion partagée entre fils, écritures sérialisées par un
verrou, un fil lecteur qui remet chaque réponse au fil qui attend son ``id``.
"""

from __future__ import annotations

import json
import socket as _socket
import threading
import time
from typing import Any, Dict, Optional

from ._commun import Adresse, creer_preuve, defi_valide, ligne_jsonrpc
from .erreurs import NoortraceIndisponible, erreur_depuis_reponse


class _Attente:
    __slots__ = ("evenement", "reponse")

    def __init__(self) -> None:
        self.evenement = threading.Event()
        self.reponse: Optional[dict] = None


class Connexion:
    """Une connexion au démon ; perdue, elle n'est jamais réutilisée (EX-6.13)."""

    def __init__(self, adresse: Adresse) -> None:
        self.adresse = adresse
        self.prochain_id = 1
        self.attentes: Dict[int, _Attente] = {}
        self.perdue = False
        self._verrou_ecriture = threading.Lock()
        self._verrou_etat = threading.Lock()
        self._prise: Optional[_socket.socket] = None
        self._tampon = b""
        self._lecteur: Optional[threading.Thread] = None

    # ------------------------------------------------------------ ouverture

    def ouvrir(self, delai_s: float) -> None:
        """Établit la connexion et la preuve d'identité, au plus ``delai_s`` (EX-6.10)."""
        fin = time.monotonic() + delai_s
        a = self.adresse
        try:
            if a.socket:
                p = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
                p.settimeout(max(0.001, fin - time.monotonic()))
                p.connect(a.socket)
            else:
                p = _socket.create_connection((a.hote, a.port), timeout=max(0.001, fin - time.monotonic()))
                if a.tls is not None:
                    p = a.tls.wrap_socket(p, server_hostname=a.hote)
                else:
                    # Prise TCP : première ligne {"noortrace_token": …}, sauf en mTLS (EX-6.10, EX-4.39).
                    p.sendall((json.dumps({"noortrace_token": a.jeton or ""}) + "\n").encode("utf-8"))
        except (OSError, ValueError) as e:
            raise NoortraceIndisponible(f"noortrace: enregistreur injoignable ({type(e).__name__})", False) from e
        self._prise = p
        try:
            while True:
                reste = fin - time.monotonic()
                if reste <= 0:
                    raise NoortraceIndisponible("noortrace: enregistreur injoignable (delai)", False)
                p.settimeout(reste)
                ligne = self._lire_ligne()
                if ligne is None:
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
                    p.sendall((json.dumps({"noortrace_preuve": defi}) + "\n").encode("utf-8"))
                    continue
                if isinstance(m, dict) and m.get("noortrace_identite") == "acceptee":
                    break
                raise NoortraceIndisponible("noortrace: enregistreur injoignable (reponse_inattendue)", False)
        except NoortraceIndisponible:
            self._detruire()
            raise
        except OSError as e:
            self._detruire()
            raise NoortraceIndisponible(f"noortrace: enregistreur injoignable ({type(e).__name__})", False) from e
        p.settimeout(None)
        self._lecteur = threading.Thread(target=self._lire, name="noortrace-sdk-lecteur", daemon=True)
        self._lecteur.start()

    def _lire_ligne(self) -> Optional[bytes]:
        """Lit une ligne pendant l'ouverture (le fil lecteur n'existe pas encore)."""
        assert self._prise is not None
        while b"\n" not in self._tampon:
            x = self._prise.recv(65536)
            if not x:
                return None
            self._tampon += x
        ligne, _, self._tampon = self._tampon.partition(b"\n")
        return ligne

    # ------------------------------------------------------------ lecture

    def _lire(self) -> None:
        """Fil lecteur : remet chaque réponse au fil qui attend son ``id``."""
        p = self._prise
        try:
            while True:
                while b"\n" in self._tampon:
                    ligne, _, self._tampon = self._tampon.partition(b"\n")
                    self._ligne(ligne)
                x = p.recv(65536) if p is not None else b""
                if not x:
                    break
                self._tampon += x
        except (OSError, ValueError):
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
        with self._verrou_etat:
            a = self.attentes.pop(id_, None)
        if a is None:
            return
        a.reponse = m
        a.evenement.set()

    def _perdre(self) -> None:
        with self._verrou_etat:
            if self.perdue:
                return
            self.perdue = True
            attentes = list(self.attentes.values())
            self.attentes.clear()
        for a in attentes:
            a.evenement.set()
        self._detruire()

    def _detruire(self) -> None:
        p = self._prise
        if p is None:
            return
        try:
            p.shutdown(_socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            p.close()
        except OSError:
            pass

    # ------------------------------------------------------------ requêtes

    def appeler(self, nom: str, params: dict, delai_s: float) -> Any:
        """Envoie une requête et attend sa réponse, au plus ``delai_s`` (EX-6.11 (1))."""
        if self.perdue:
            raise NoortraceIndisponible("noortrace: connexion perdue", False)
        attente = _Attente()
        with self._verrou_ecriture:
            id_ = self.prochain_id
            # Une valeur non JSON lève ici, avant l'écriture et sans consommer d'id.
            ligne = ligne_jsonrpc(id_, nom, params)
            self.prochain_id += 1
            with self._verrou_etat:
                if self.perdue:
                    raise NoortraceIndisponible("noortrace: connexion perdue", False)
                self.attentes[id_] = attente
            try:
                assert self._prise is not None
                self._prise.sendall(ligne)
            except OSError as e:
                # La ligne n'a pas été écrite en entier : sans LF, le démon ne la traite pas.
                with self._verrou_etat:
                    self.attentes.pop(id_, None)
                self._perdre()
                raise NoortraceIndisponible("noortrace: connexion perdue", False) from e
        # La requête est écrite : elle ne sera jamais renvoyée (EX-6.13).
        if not attente.evenement.wait(delai_s):
            with self._verrou_etat:
                self.attentes.pop(id_, None)
            if attente.reponse is None:
                raise NoortraceIndisponible("noortrace: delai ecoule", True)
        if attente.reponse is None:
            raise NoortraceIndisponible("noortrace: connexion perdue", True)
        m = attente.reponse
        if "error" in m and m["error"] is not None:
            raise erreur_depuis_reponse(m["error"])
        return m.get("result")

    def fermer(self) -> None:
        """Ferme la connexion sans attendre (les attentes en cours échouent)."""
        self._perdre()

    def abandonner(self) -> None:
        """Après ``os.fork()``, dans l'enfant : la prise du parent n'est jamais
        réutilisée (EX-6.14) ; son descripteur est fermé sans ``shutdown``, qui
        couperait aussi la connexion du parent."""
        self.perdue = True
        self.attentes = {}
        p = self._prise
        self._prise = None
        if p is not None:
            try:
                p.close()
            except OSError:
                pass
