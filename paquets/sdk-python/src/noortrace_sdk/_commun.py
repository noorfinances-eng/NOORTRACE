"""Éléments communs aux clients synchrone et asynchrone (CT-2 EX-6.9 à EX-6.15).

Adresse du démon (EX-6.10), délai de reprise (EX-6.13), valeurs JSON et noms
de types (EX-6.9), sérialisation d'une ligne JSON-RPC (cadrage de 4.7.1).
Le SDK ne calcule rien d'autre : ni hachage, ni signature, ni écriture de
journal (EX-6.1).
"""

from __future__ import annotations

import json
import logging
import math
import os
import random
import re
import ssl
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .erreurs import NoortraceConfiguration, NoortraceEntreeInvalide

#: Prise par défaut (EX-6.10).
PRISE_DEFAUT = "/run/noortrace/sdk.sock"
#: Longueur maximale du chemin d'une prise Unix, en octets (EX-6.10).
CHEMIN_PRISE_MAX = 103
#: Borne de la tentative de ``fermer`` à la sortie du processus, en secondes (EX-6.11 (4)).
FERMER_A_LA_SORTIE_S = 2.0
#: Préfixe du fichier de preuve d'identité sur la prise Unix (celui du connecteur stdio du démon).
PREFIXE_DEFI = ".noortrace-defi-"

#: Journaliseur du SDK (EX-6.11 (3), EX-6.15).
journal = logging.getLogger("noortrace_sdk")

_MOTIF_TCP = re.compile(r"^(\[[0-9A-Fa-f:]+\]|[^:\s]+):([0-9]{1,5})$")
_MOTIF_DEFI = re.compile(r"^[0-9a-f]{32}$")


def methode(nom: str) -> str:
    """Nom complet d'une méthode de 6.2."""
    return f"noortrace/sdk/{nom}"


def delai_reprise(n: int, u: Optional[float] = None) -> float:
    """Délai avant la tentative n + 1 de la reprise de connexion (EX-6.13), en secondes.

    ``min(0,5 × 2^n, 8) × (1 − 0,25 × u)``, u uniforme dans [0, 1[.
    """
    if u is None:
        u = random.random()
    return min(0.5 * 2 ** n, 8.0) * (1 - 0.25 * u)


def est_valeur_json(v: Any, _vus: Optional[set] = None) -> bool:
    """Valeur JSON au sens d'EX-6.9 : ``dict`` à clés chaînes, ``list``, ``str``,
    ``int``, ``float`` fini, ``bool``, ``None``, récursivement (sans cycle)."""
    if v is None or isinstance(v, (str, bool)):
        return True
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    if not isinstance(v, (dict, list)):
        return False
    vus = _vus if _vus is not None else set()
    if id(v) in vus:
        return False
    vus.add(id(v))
    try:
        if isinstance(v, list):
            return all(est_valeur_json(x, vus) for x in v)
        return all(isinstance(k, str) and est_valeur_json(x, vus) for k, x in v.items())
    finally:
        vus.discard(id(v))


def nom_du_type(v: Any) -> str:
    """Nom du type d'une valeur (EX-6.9 : ``noortrace_sdk_non_json``)."""
    return type(v).__name__


def nom_de_classe(e: BaseException) -> str:
    """Nom de la classe d'une exception (EX-6.9 : ``noortrace_sdk_exception``), jamais son message."""
    return type(e).__name__


def ligne_jsonrpc(id_: int, nom: str, params: Mapping[str, Any]) -> bytes:
    """Ligne JSON-RPC 2.0 d'une requête, ``\\n`` final (4.7.1).

    Une valeur que JSON ne représente pas (objet quelconque, nombre non fini)
    n'est jamais envoyée : ``NoortraceEntreeInvalide`` (raison
    ``valeur_non_json``), levée avant l'écriture (LISEZMOI, lecture 145).
    """
    try:
        texte = json.dumps(
            {"jsonrpc": "2.0", "id": id_, "method": methode(nom), "params": params},
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise NoortraceEntreeInvalide(
            "noortrace: valeur non JSON dans les parametres", {"reason": "valeur_non_json"}
        ) from e
    return (texte + "\n").encode("utf-8")


@dataclass(frozen=True)
class Adresse:
    """Adresse résolue du démon : prise Unix, ou TCP (jeton, ou mTLS)."""

    socket: Optional[str]
    hote: Optional[str]
    port: Optional[int]
    jeton: Optional[str]
    tls: Optional[ssl.SSLContext]


def _analyser_tcp(tcp: str) -> tuple:
    r = _MOTIF_TCP.match(tcp or "")
    if not r or not (1 <= int(r.group(2)) <= 65535):
        raise NoortraceConfiguration("noortrace: adresse TCP invalide (hote:port attendu)")
    return r.group(1).strip("[]"), int(r.group(2))


def resoudre_adresse(socket: Optional[str], tcp: Optional[str], jeton: Optional[str],
                     env: Optional[Mapping[str, str]] = None) -> Adresse:
    """Adresse du démon (EX-6.10), dans cet ordre : paramètres du constructeur,
    environnement (``NOORTRACE_SDK_SOCKET``, ``NOORTRACE_SDK_TCP``,
    ``NOORTRACE_SDK_TOKEN``, ``NOORTRACE_SDK_TLS_CA``, ``NOORTRACE_SDK_TLS_CERT``,
    ``NOORTRACE_SDK_TLS_KEY``), à défaut la prise ``/run/noortrace/sdk.sock``."""
    env = os.environ if env is None else env
    if socket and tcp:
        raise NoortraceConfiguration("noortrace: socket et tcp exclusifs")
    if not socket and not tcp:
        if env.get("NOORTRACE_SDK_SOCKET"):
            socket = env["NOORTRACE_SDK_SOCKET"]
        elif env.get("NOORTRACE_SDK_TCP"):
            tcp = env["NOORTRACE_SDK_TCP"]
        else:
            socket = PRISE_DEFAUT
    if jeton is None and env.get("NOORTRACE_SDK_TOKEN"):
        jeton = env["NOORTRACE_SDK_TOKEN"]
    if tcp:
        hote, port = _analyser_tcp(tcp)
        ca, cert, cle = env.get("NOORTRACE_SDK_TLS_CA"), env.get("NOORTRACE_SDK_TLS_CERT"), env.get("NOORTRACE_SDK_TLS_KEY")
        if ca or cert or cle:
            if not cert or not cle:
                raise NoortraceConfiguration("noortrace: mTLS exige NOORTRACE_SDK_TLS_CERT et NOORTRACE_SDK_TLS_KEY")
            try:
                contexte = ssl.create_default_context(cafile=ca or None)
                contexte.load_cert_chain(cert, cle)
            except (OSError, ssl.SSLError) as e:
                raise NoortraceConfiguration("noortrace: fichier mTLS illisible") from e
            return Adresse(None, hote, port, None, contexte)
        if not jeton:
            raise NoortraceConfiguration("noortrace: une prise TCP exige un jeton ou mTLS (EX-4.39)")
        return Adresse(None, hote, port, jeton, None)
    if not isinstance(socket, str) or len(socket) == 0:
        raise NoortraceConfiguration("noortrace: chemin de prise invalide")
    # EX-6.10 : au plus 103 octets ; un chemin plus long joindrait une autre prise.
    if len(os.fsencode(socket)) > CHEMIN_PRISE_MAX:
        raise NoortraceConfiguration("noortrace: chemin de prise de plus de 103 octets")
    return Adresse(socket, None, None, None, None)


def verifier_reglages(delai_s: Any, reprises: Any, sur: Any) -> None:
    """Réglages du constructeur (EX-6.9)."""
    if isinstance(delai_s, bool) or not isinstance(delai_s, (int, float)) or not math.isfinite(delai_s) or delai_s <= 0:
        raise NoortraceConfiguration("noortrace: delai_s invalide")
    if isinstance(reprises, bool) or not isinstance(reprises, int) or reprises < 0:
        raise NoortraceConfiguration("noortrace: reprises invalide")
    if sur not in ("bloquer", "executer"):
        raise NoortraceConfiguration("noortrace: sur_indisponibilite_lecture invalide")


def defi_valide(m: Any) -> Optional[str]:
    """Défi de la preuve d'identité sur la prise Unix, s'il est bien formé."""
    if isinstance(m, dict) and isinstance(m.get("noortrace_defi"), str) and _MOTIF_DEFI.match(m["noortrace_defi"]):
        return m["noortrace_defi"]
    return None


def creer_preuve(socket: str, defi: str) -> None:
    """Crée en exclusion le fichier de preuve d'identité dans le répertoire de la prise (lecture 112 du démon)."""
    f = os.path.join(os.path.dirname(socket), PREFIXE_DEFI + defi)
    fd = os.open(f, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)


def params_debut(session: str, tool: Any, arguments: Any, classe: Any, contexte: Any,
                 intent: Any, effects: Any) -> dict:
    """Paramètres de ``debutAppel`` (6.2), noms de 6.2."""
    return {
        "session": session,
        "tool": tool,
        "arguments": arguments,
        "class": classe,
        "context": list(contexte or ()),
        "intent": intent,
        "effects": effects,
    }


def params_echange(session: str, format_: Any, provider_label: Any, request: Any, response: Any,
                   status: Any, duration_ms: Any, is_error: Any) -> dict:
    """Paramètres de ``echangeModele`` (6.2)."""
    return {
        "session": session,
        "format": format_,
        "provider_label": provider_label,
        "request": request,
        "response": response,
        "status": status,
        "duration_ms": duration_ms,
        "is_error": is_error,
    }


def octets_de(octets: Any) -> bytes:
    """Octets d'un document de contexte : ``bytes``, ``bytearray``, ``memoryview`` ou ``str`` (UTF-8)."""
    if isinstance(octets, str):
        return octets.encode("utf-8")
    if isinstance(octets, (bytes, bytearray, memoryview)):
        return bytes(octets)
    raise NoortraceEntreeInvalide("noortrace: octets attendus", {"reason": "octets_invalides"})


def resultat_declare(valeur: Any) -> Any:
    """Résultat transmis par ``appel_outil`` (EX-6.9) : la valeur si elle est JSON, sinon la forme non JSON."""
    return valeur if est_valeur_json(valeur) else {"noortrace_sdk_non_json": nom_du_type(valeur)}
