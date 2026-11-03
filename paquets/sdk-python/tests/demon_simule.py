"""Démon simulé pour les essais du protocole côté client (cadrage, ``id``, erreurs,
délais, requête jamais renvoyée, jeton TCP, sortie du processus) : il parle la
preuve d'identité du démon réel (défi, fichier créé en exclusion,
acceptation ; ou jeton en première ligne sur TCP) puis répond selon une
fonction de l'essai. Il ne remplace pas le démon réel, contre lequel le reste
des essais s'exécute."""

from __future__ import annotations

import json
import os
import secrets
import socket
import threading
from typing import Any, Callable, Dict, List, Optional


class DemonSimule:
    """``repondre(methode, params, id)`` rend un dict ``{"result": …}`` ou ``{"error": …}``, ou ``None`` (aucune réponse)."""

    def __init__(self, dossier: str, repondre: Callable[[str, Any, int], Optional[dict]], tcp: bool = False,
                 jeton: Optional[str] = None) -> None:
        self.repondre = repondre
        self.recues: List[dict] = []
        self.connexions = 0
        self.lignes_brutes: List[bytes] = []
        self.jeton = jeton
        self._prises: List[socket.socket] = []
        if tcp:
            self.serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.serveur.bind(("127.0.0.1", 0))
            self.adresse = f"127.0.0.1:{self.serveur.getsockname()[1]}"
            self.socket_path = None
        else:
            self.socket_path = os.path.join(dossier, "s.sock")
            self.serveur = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.serveur.bind(self.socket_path)
            self.adresse = None
        self.serveur.listen(16)
        self._fil = threading.Thread(target=self._accepter, daemon=True)
        self._fil.start()

    def _accepter(self) -> None:
        while True:
            try:
                c, _ = self.serveur.accept()
            except OSError:
                return
            self.connexions += 1
            self._prises.append(c)
            threading.Thread(target=self._servir, args=(c,), daemon=True).start()

    def _servir(self, c: socket.socket) -> None:
        f = c.makefile("rb")
        try:
            if self.socket_path:
                defi = secrets.token_hex(16)
                c.sendall((json.dumps({"noortrace_defi": defi}) + "\n").encode())
                preuve = json.loads(f.readline())
                fichier = os.path.join(os.path.dirname(self.socket_path), ".noortrace-defi-" + defi)
                if preuve.get("noortrace_preuve") != defi or not os.path.exists(fichier):
                    c.close()
                    return
                os.unlink(fichier)
            else:
                premiere = f.readline()
                self.lignes_brutes.append(premiere)
                if json.loads(premiere).get("noortrace_token") != self.jeton:
                    c.close()
                    return
            c.sendall(b'{"noortrace_identite":"acceptee"}\n')
            while True:
                ligne = f.readline()
                if not ligne:
                    return
                self.lignes_brutes.append(ligne)
                m = json.loads(ligne)
                self.recues.append(m)
                r = self.repondre(m["method"].split("/")[-1], m.get("params"), m["id"])
                if r is None:
                    continue
                if r.get("couper"):
                    c.shutdown(socket.SHUT_RDWR)
                    c.close()
                    return
                c.sendall((json.dumps({"jsonrpc": "2.0", "id": m["id"], **r}) + "\n").encode())
        except (OSError, ValueError):
            return

    def methodes(self) -> List[str]:
        return [m["method"].split("/")[-1] for m in self.recues]

    def couper_tout(self) -> None:
        for c in self._prises:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass

    def fermer(self) -> None:
        self.couper_tout()
        try:
            self.serveur.close()
        except OSError:
            pass


def reponses_nominales(session: str = "s-simule-1") -> Callable[[str, Any, int], Optional[dict]]:
    """Réponses de forme normale pour chaque méthode de 6.2."""
    compteur = {"n": 0}

    def repondre(methode: str, params: Any, id_: int) -> Optional[dict]:
        compteur["n"] += 1
        if methode == "ouvrir":
            return {"result": {"session": f"{session}-{compteur['n']}", "org_id": "0x00", "journal_id": "0x00", "policy_version": "v"}}
        if methode == "debutAppel":
            return {"result": {"call": f"c-{compteur['n']}", "decision": "autorise", "ticket": None, "ticket_state": None}}
        if methode in ("finAppel", "echangeModele"):
            return {"result": {"seq": compteur["n"], "hash": "0x" + "00" * 32}}
        if methode == "declarerContexte":
            return {"result": {"sha256": "0x" + "11" * 32, "length": 1, "redacted": False}}
        if methode == "fermer":
            return {"result": {}}
        return {"error": {"code": -32601, "message": "Method not found"}}

    return repondre
