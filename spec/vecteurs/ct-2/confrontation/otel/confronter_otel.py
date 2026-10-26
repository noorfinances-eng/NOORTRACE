#!/usr/bin/env python3
# Confrontation de la famille otel/ des vecteurs CT-2 par opentelemetry-proto
# et protobuf (CT-2, section 6.8 et annexe B.8, révision 0.5).
#
# Ce programme n'emploie aucun code du dépôt : chaque requête OTLP des
# vecteurs est analysée par les messages générés d'opentelemetry-proto
# (ExportTraceServiceRequest), en JSON par google.protobuf.json_format.Parse
# et en protobuf par FromString ; la forme normalisée de chaque span
# (CT-2 EX-6.31) est recalculée ici, en Python, depuis le message rendu par la
# bibliothèque, puis comparée à `normalized` d'attendu.json. Les identifiants
# hexadécimaux sont convertis en base64 avant Parse : la bibliothèque lit
# l'hexadécimal comme du base64 sans erreur (CT-2 R11-F44), ce que la
# section 3 montre.
#
# Usage : python -I confronter_otel.py <répertoire spec/vecteurs/ct-2>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import base64
import gzip
import hashlib
import json
import math
import os
import re
import sys
import zlib
from importlib import metadata

if len(sys.argv) != 2:
    print("usage : confronter_otel.py <spec/vecteurs/ct-2>", file=sys.stderr)
    sys.exit(2)

from google.protobuf import json_format  # noqa: E402
from google.protobuf.message import DecodeError  # noqa: E402
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: E402
    ExportTracePartialSuccess,
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

RACINE = os.path.abspath(sys.argv[1])
OTEL = os.path.join(RACINE, "otel")
SORTIE, DISCORDANCES, DIVERGENCES, AVANT_DECODAGE, REPONSES, STATUS = [], [], [], [], [], []

# Divergences voulues : NOORTRACE refuse ce que la bibliothèque accepte, avec la règle qui le fonde.
VOULUES = {
    "json-enum-en-chaine": "EX-6.29 : une énumération en chaîne (\"SPAN_KIND_CLIENT\") est refusée, « the enum name strings MUST NOT be used » (R11-F39)",
    "json-identifiant-non-hexadecimal": "EX-6.29 : un identifiant est une chaîne hexadécimale, jamais du base64 ; json_format.Parse lit le base64 (R11-F44)",
    "pb-champ-double": "EX-6.30 : un champ non répété présent deux fois est refusé, là où une bibliothèque garde le dernier ou fusionne",
    "json-entier-fractionnaire": "EX-6.29 : un entier 32 bits a un texte sans fraction ni exposant ; json_format.Parse lit 1.0 comme 1",
}
# Paires de cas qui portent le même lot en JSON et en protobuf (annexe B.8).
PAIRES = [("json-exemple-6-8-16", "pb-exemple-6-8-16"), ("json-identifiants-invalides", "pb-identifiants-invalides")]
# Les six attributs de contenu d'EX-6.31, analysés en JSON strict quand ils sont des chaînes.
CONTENU = {"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions", "gen_ai.tool.definitions", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}
MAX_SUR = 2 ** 53 - 1


def dire(*m):
    SORTIE.append(" ".join(str(x) for x in m))


def jc(v):
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fmt(v):
    return jc(v) if isinstance(v, (dict, list)) else str(v)


def comparer(libelle, vecteur, outil):
    ok = vecteur == outil
    dire("  %s : vecteur %s ; outil %s : %s" % (libelle, fmt(vecteur), fmt(outil), "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, outil %s" % (libelle, fmt(vecteur), fmt(outil)))
    return ok


def divergence(libelle, regle, texte):
    dire("  %s : divergence voulue (%s) : %s" % (libelle, regle, texte))
    DIVERGENCES.append("%s : %s" % (libelle, texte))


def sha256(octets):
    return "0x" + hashlib.sha256(octets).hexdigest()


# --- JSON des vecteurs relu sans perte (ordre des membres, doublons, texte des nombres) -------------

class Paires(list):
    """Objet JSON gardé comme liste de paires : ordre et doublons conservés."""


class Nombre(str):
    """Nombre JSON gardé sur son texte."""


def charger(texte):
    return json.loads(texte, object_pairs_hook=Paires, parse_int=Nombre, parse_float=Nombre, parse_constant=Nombre)


def ecrire(v):
    if isinstance(v, Paires):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + ecrire(x) for k, x in v) + "}"
    if isinstance(v, list):
        return "[" + ",".join(ecrire(x) for x in v) + "]"
    if isinstance(v, Nombre):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})*$")


def hex_vers_base64(v, compte):
    """Conversion des identifiants hexadécimaux d'OTLP/JSON (R11-F39) en base64, forme que lit json_format."""
    if isinstance(v, Paires):
        for i, (k, x) in enumerate(v):
            if k in ("traceId", "spanId", "parentSpanId") and isinstance(x, str) and HEX.match(x):
                v[i] = (k, base64.b64encode(bytes.fromhex(x)).decode("ascii"))
                compte[0] += 1
            else:
                hex_vers_base64(x, compte)
    elif isinstance(v, list):
        for x in v:
            hex_vers_base64(x, compte)
    return v


# --- Forme normalisée d'EX-6.31, recalculée depuis le message de la bibliothèque --------------------

def json_strict(texte):
    """JSON strict (EX-5.7 point 2) : clé en double, substitut isolé, constantes NaN/Infinity, marque d'ordre d'octets refusés."""
    if texte.startswith("﻿"):
        raise ValueError("marque d'ordre d'octets")

    def paires(p):
        cles = [k for k, _ in p]
        if len(cles) != len(set(cles)):
            raise ValueError("clé en double")
        return dict(p)

    def constante(c):
        raise ValueError("constante " + c)

    v = json.loads(texte, object_pairs_hook=paires, parse_constant=constante)

    def surrogats(x):
        if isinstance(x, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in x):
            raise ValueError("substitut isolé")
        if isinstance(x, dict):
            for k, y in x.items():
                surrogats(k)
                surrogats(y)
        if isinstance(x, list):
            for y in x:
                surrogats(y)

    surrogats(v)
    return v


def V(av):
    quoi = av.WhichOneof("value")
    if quoi is None or quoi == "string_value_strindex":
        return None
    if quoi == "string_value":
        return av.string_value
    if quoi == "bool_value":
        return av.bool_value
    if quoi == "int_value":
        return av.int_value if abs(av.int_value) <= MAX_SUR else str(av.int_value)
    if quoi == "double_value":
        d = av.double_value
        if math.isnan(d):
            return "NaN"
        if math.isinf(d):
            return "Infinity" if d > 0 else "-Infinity"
        return 0.0 if d == 0 else d
    if quoi == "array_value":
        return [V(x) for x in av.array_value.values]
    if quoi == "kvlist_value":
        return A(av.kvlist_value.values)
    if quoi == "bytes_value":
        return base64.b64encode(av.bytes_value).decode("ascii")
    raise AssertionError(quoi)


def A(liste, contenu=False):
    """Attributs : première occurrence d'une clé gardée ; un keyStrindex sans key fait ignorer l'attribut (EX-6.29)."""
    out = {}
    for kv in liste:
        if kv.key == "" and kv.key_strindex != 0:
            continue
        if kv.key in out:
            continue
        v = V(kv.value) if kv.HasField("value") else None
        if contenu and kv.key in CONTENU and isinstance(v, str):
            try:
                v = json_strict(v)
            except ValueError:
                pass
        out[kv.key] = v
    return out


def hexa(b):
    return b.hex()


def normaliser(rs, ss, sp):
    return {
        "trace_id": hexa(sp.trace_id),
        "span_id": hexa(sp.span_id),
        "parent_span_id": hexa(sp.parent_span_id) if sp.parent_span_id else None,
        "trace_state": sp.trace_state,
        "name": sp.name,
        "flags": sp.flags,
        "kind": sp.kind,
        "start_time_unix_nano": str(sp.start_time_unix_nano),
        "end_time_unix_nano": str(sp.end_time_unix_nano),
        "attributes": A(sp.attributes, contenu=True),
        "dropped_attributes_count": sp.dropped_attributes_count,
        "dropped_events_count": sp.dropped_events_count,
        "dropped_links_count": sp.dropped_links_count,
        "events": [{"name": e.name, "time_unix_nano": str(e.time_unix_nano), "attributes": A(e.attributes), "dropped_attributes_count": e.dropped_attributes_count} for e in sp.events],
        "links_count": len(sp.links),
        "status": {"code": sp.status.code, "message": sp.status.message},
        "resource": {"attributes": A(rs.resource.attributes), "dropped_attributes_count": rs.resource.dropped_attributes_count},
        "scope": {"name": ss.scope.name, "version": ss.scope.version, "attributes": A(ss.scope.attributes)},
        "schema_url": ss.schema_url or rs.schema_url or None,
    }


def canon(v):
    """Forme de comparaison : un nombre est sa valeur double (JCS intégral, CT-2 8.1), un booléen reste un booléen."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        f = float(v)
        return ("nombre", repr(0.0 if f == 0 else f))
    if isinstance(v, list):
        return [canon(x) for x in v]
    if isinstance(v, dict):
        return {k: canon(x) for k, x in v.items()}
    raise AssertionError(type(v))


def affichage(v):
    """Valeur pour la sortie : un nombre entier écrit en double s'écrit sans partie décimale, comme en JCS (CT-2 8.1)."""
    if isinstance(v, float) and v.is_integer() and abs(v) <= MAX_SUR:
        return int(v)
    if isinstance(v, list):
        return [affichage(x) for x in v]
    if isinstance(v, dict):
        return {k: affichage(x) for k, x in v.items()}
    return v


def comparer_valeurs(libelle, vecteur, outil):
    """Comparaison sur les valeurs (canon) ; sortie en JSON compact des deux côtés."""
    ok = canon(vecteur) == canon(outil)
    a, b = jc(affichage(vecteur)), jc(affichage(outil))
    dire("  %s : vecteur %s ; outil %s : %s" % (libelle, a, b, "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, outil %s" % (libelle, a, b))


def spans(msg):
    for r, rs in enumerate(msg.resource_spans):
        for s, ss in enumerate(rs.scope_spans):
            for p, sp in enumerate(ss.spans):
                yield [r, s, p], rs, ss, sp


def confronter_spans(msg, attendu):
    lus = list(spans(msg))
    comparer("nombre de spans lus par la bibliothèque", len(attendu["spans"]), len(lus))
    for (chemin, rs, ss, sp), at in zip(lus, attendu["spans"]):
        n = normaliser(rs, ss, sp)
        dire("  span %s (issue %s%s)" % (chemin, at["issue"], ", raison " + at["reason"] if at["reason"] else ""))
        comparer("    path", at["path"], chemin)
        comparer("    trace_id", at["trace_id"], n["trace_id"])
        comparer("    span_id", at["span_id"], n["span_id"])
        nn = at["normalized"]
        if nn is None:
            dire("    forme normalisée : aucune dans le vecteur (span ignoré, EX-6.32)")
            continue
        for cle in ("parent_span_id", "name", "kind", "start_time_unix_nano", "end_time_unix_nano", "status"):
            comparer("    " + cle, nn[cle], n[cle])
        for cle in ("attributes", "resource", "scope", "events"):
            comparer_valeurs("    %s (valeurs V d'EX-6.31%s)" % (cle, ", attributs de contenu analysés" if cle == "attributes" else ""), nn[cle], n[cle])
        reste = sorted(k for k in nn if k not in ("trace_id", "span_id", "parent_span_id", "name", "kind", "start_time_unix_nano", "end_time_unix_nano", "status", "attributes", "resource", "scope", "events"))
        comparer("    autres membres (%s)" % ", ".join(reste), [nn[k] for k in reste], [n[k] for k in reste])
        comparer("    forme normalisée complète = normalized", True, canon(nn) == canon(n))


def entetes(cas):
    return json.load(open(os.path.join(OTEL, cas, "requete-entetes.json"), encoding="utf-8"))


def corps(cas):
    for nom in ("requete.json", "requete.pb", "requete.brut"):
        f = os.path.join(OTEL, cas, nom)
        if os.path.exists(f):
            return nom, open(f, "rb").read()
    raise AssertionError(cas)


def analyser_json(octets):
    """json_format.Parse après conversion des identifiants. Rend (message ou None, erreur, nombre d'identifiants convertis)."""
    compte = [0]
    try:
        texte = ecrire(hex_vers_base64(charger(octets.decode("utf-8")), compte))
    except (ValueError, UnicodeDecodeError):
        texte = None
    if texte is None:
        # Le corps n'est pas du JSON pour la bibliothèque standard : json_format.Parse le reçoit tel quel.
        texte = octets.decode("utf-8", "replace")
    msg = ExportTraceServiceRequest()
    try:
        json_format.Parse(texte, msg, ignore_unknown_fields=True)
    except json_format.ParseError as e:
        return None, "ParseError : %s" % str(e).splitlines()[0], compte[0]
    return msg, None, compte[0]


def analyser_pb(octets):
    try:
        return ExportTraceServiceRequest.FromString(octets), None
    except DecodeError as e:
        return None, "DecodeError : %s" % str(e).splitlines()[0]


def confronter_reponse(cas, attendu, type_contenu):
    r = attendu["response"]
    if attendu["status"] != 200:
        STATUS.append(cas)
        dire("  corps de réponse %s du refus (message Status de google.rpc, absent d'opentelemetry-proto) : non confronté" % ("JSON" if "body_json" in r else "protobuf"))
        return
    REPONSES.append(cas)
    n = attendu["counts"]["rejete"]
    if "body_json" in r:
        rep = ExportTraceServiceResponse()
        json_format.Parse(json.dumps(r["body_json"]), rep)
        comparer("réponse JSON : partial_success.rejected_spans lu par la bibliothèque", n, rep.partial_success.rejected_spans)
        comparer("réponse JSON réécrite par la bibliothèque (MessageToDict) = body_json", r["body_json"], json_format.MessageToDict(rep))
    else:
        octets = bytes.fromhex(r["body_hex"])
        rep = ExportTraceServiceResponse.FromString(octets)
        comparer("réponse protobuf : partial_success.rejected_spans lu par la bibliothèque", n, rep.partial_success.rejected_spans)
        attendue = ExportTraceServiceResponse()
        if n:
            attendue.partial_success.CopyFrom(ExportTracePartialSuccess(rejected_spans=n, error_message=rep.partial_success.error_message))
        comparer("réponse protobuf = SerializeToString(deterministic=True) de la bibliothèque", r["body_hex"], attendue.SerializeToString(deterministic=True).hex())


VERSIONS = {p: metadata.version(p) for p in ["opentelemetry-proto", "protobuf"]}
dire("Confrontation des vecteurs CT-2 otel/ par opentelemetry-proto %s et protobuf %s" % (VERSIONS["opentelemetry-proto"], VERSIONS["protobuf"]))
dire("Entrées : otel/*/{requete.json, requete.pb, requete.brut, requete-entetes.json, attendu.json}")
dire("Analyse : json_format.Parse(…, ExportTraceServiceRequest(), ignore_unknown_fields=True) après conversion hexadécimal -> base64 de traceId, spanId, parentSpanId ; ExportTraceServiceRequest.FromString ; forme normalisée d'EX-6.31 recalculée depuis le message")
dire("")

CAS = sorted(os.listdir(OTEL))
ATTENDUS = {c: json.load(open(os.path.join(OTEL, c, "attendu.json"), encoding="utf-8")) for c in CAS}
MESSAGES = {}

# ---------------------------------------------------------------------------
dire("== 1. Requêtes analysées par la bibliothèque, span par span, contre normalized d'attendu.json")
for cas in CAS:
    a = ATTENDUS[cas]
    h = entetes(cas)
    nom, octets = corps(cas)
    dire("-- %s (%s, SHA-256 %s, %s%s, statut attendu %d)" % (cas, nom, sha256(octets), h["content-type"], ", " + h["content-encoding"] if h.get("content-encoding") else "", a["status"]))
    codage = h.get("content-encoding")
    if codage == "gzip":
        try:
            octets = gzip.decompress(octets)
            dire("  corps décomprimé (gzip de la bibliothèque standard) : %d octets" % len(octets))
        except (OSError, EOFError) as e:
            dire("  corps non décomprimable : %s" % e)
    elif codage == "deflate":
        try:
            octets = zlib.decompress(octets)
            dire("  corps décomprimé (zlib de la bibliothèque standard) : %d octets" % len(octets))
        except zlib.error as e:
            dire("  corps non décomprimable par zlib : %s" % e)
    if a["status"] in (401, 404, 405, 413, 415):
        # Refus décidé avant tout décodage (EX-6.26 à EX-6.28, EX-6.37 ; ordre des décisions d'EX-6.27) : la bibliothèque n'a pas d'avis sur le statut.
        if nom == "requete.pb" or h["content-type"] == "application/x-protobuf":
            msg, err = analyser_pb(octets)
        else:
            msg, err, _ = analyser_json(octets)
        etat = "analysable, %d span(s)" % len(list(spans(msg))) if msg is not None else "non analysable (%s)" % err
        dire("  statut %d décidé avant le décodage (en-têtes, taille ou authentification) : sans objet pour la bibliothèque ; corps : %s" % (a["status"], etat))
        AVANT_DECODAGE.append(cas)
        confronter_reponse(cas, a, h["content-type"])
        continue
    if nom == "requete.pb":
        msg, err = analyser_pb(octets)
        lecture = "ExportTraceServiceRequest.FromString"
    else:
        msg, err, convertis = analyser_json(octets)
        lecture = "json_format.Parse (%d identifiant(s) converti(s))" % convertis
    accepte = "accepte" if msg is not None else "refuse"
    attendu_lib = "accepte" if a["status"] == 200 else "refuse"
    if cas in VOULUES:
        dire("  vecteur : statut %d, %s" % (a["status"], a["response"].get("body_json", a["response"].get("body_hex"))))
        divergence(cas, VOULUES[cas], "la bibliothèque %s le corps%s" % ("accepte" if msg is not None else "refuse", "" if msg is None else " (%d span(s), %s)" % (len(list(spans(msg))), ", ".join("kind %d" % sp.kind for _, _, _, sp in spans(msg)))))
        if cas == "pb-champ-double" and msg is not None:
            dire("    valeur retenue par la bibliothèque : name %s" % json.dumps([sp.name for _, _, _, sp in spans(msg)], ensure_ascii=False))
        confronter_reponse(cas, a, h["content-type"])
        continue
    comparer("%s" % lecture, attendu_lib, accepte)
    if err:
        dire("    raison de la bibliothèque : %s" % err)
    if msg is None:
        confronter_reponse(cas, a, h["content-type"])
        continue
    MESSAGES[cas] = (msg, octets)
    confronter_spans(msg, a)
    confronter_reponse(cas, a, h["content-type"])
dire("")

# ---------------------------------------------------------------------------
dire("== 2. Requêtes protobuf : octets du générateur = SerializeToString(deterministic=True) ; paires JSON et protobuf (B.8) : même message")
for cas in CAS:
    if not cas.startswith("pb-") or cas not in MESSAGES:
        continue
    msg, octets = MESSAGES[cas]
    dire("-- %s" % cas)
    if cas == "pb-champ-inconnu":
        connus = ExportTraceServiceRequest()
        connus.CopyFrom(msg)
        connus.DiscardUnknownFields()
        dire("  champs de numéro inconnu sautés à l'analyse (EX-6.30) et gardés par la bibliothèque comme champs inconnus : %d octets dans requete.pb, %d après DiscardUnknownFields" % (len(octets), len(connus.SerializeToString(deterministic=True))))
        continue
    comparer("SerializeToString(deterministic=True) du message lu = octets de requete.pb (champs dans l'ordre de leur numéro, chacun une fois)", True, msg.SerializeToString(deterministic=True) == octets)
for cas_json, cas_pb in PAIRES:
    dire("-- paire %s / %s" % (cas_json, cas_pb))
    mj, mp = MESSAGES[cas_json][0], MESSAGES[cas_pb][0]
    comparer("Parse(%s) == FromString(%s)" % (cas_json, cas_pb), True, mj == mp)
    comparer("SerializeToString(deterministic=True) de Parse(%s) = octets de %s/requete.pb" % (cas_json, cas_pb), True, mj.SerializeToString(deterministic=True) == MESSAGES[cas_pb][1])
dire("")

# ---------------------------------------------------------------------------
dire("== 3. Piège de R11-F44 : json_format.Parse sans conversion des identifiants")
octets = open(os.path.join(OTEL, "json-exemple-6-8-16", "requete.json"), "rb").read()
brut = ExportTraceServiceRequest()
json_format.Parse(octets.decode("utf-8"), brut, ignore_unknown_fields=True)
premier = next(spans(brut))[3]
attendu_id = ATTENDUS["json-exemple-6-8-16"]["spans"][0]["trace_id"]
dire("-- json-exemple-6-8-16, premier span : traceId %s" % attendu_id.upper())
comparer("Parse sans conversion : longueur de trace_id en octets (R11-F44 : 24, au lieu des 16 de l'identifiant)", 24, len(premier.trace_id))
comparer("Parse sans conversion : trace_id différent de l'identifiant attendu", True, premier.trace_id.hex() != attendu_id)
dire("  trace_id lu sans conversion : %s" % premier.trace_id.hex())
dire("")

# ---------------------------------------------------------------------------
dire("== 4. Sonde : noms de champs d'origine (snake_case) dans le JSON")
# EX-6.29 : un nom de champ en snake_case est un champ inconnu, ignoré. Dans
# json-champ-inconnu, ces champs portent la valeur par défaut, de sorte que la
# forme ne dépend pas de leur lecture ; la sonde change trace_state en mémoire
# pour montrer ce que fait la bibliothèque.
sonde = open(os.path.join(OTEL, "json-champ-inconnu", "requete.json"), "rb").read().decode("utf-8")
dire("-- json-champ-inconnu, span [0, 0, 0] : \"trace_state\": \"\" remplacé en mémoire par \"trace_state\": \"sonde\"")
comparer("le corps du vecteur porte \"trace_state\": \"\"", 1, sonde.count('"trace_state": ""'))
msg, err, _ = analyser_json(sonde.replace('"trace_state": ""', '"trace_state": "sonde"').encode("utf-8"))
lu = next(spans(msg))[3].trace_state
LIMITES_SONDE = ["json_format.Parse lit le nom d'origine trace_state (valeur %s), qu'OTLP/JSON tient pour inconnu et que NOORTRACE ignore (EX-6.29)" % json.dumps(lu)] if lu == "sonde" else []
for t in LIMITES_SONDE:
    dire("  LIMITE DE L'OUTIL : " + t)
if not LIMITES_SONDE:
    dire("  la bibliothèque ignore le nom d'origine trace_state : %s" % json.dumps(lu))
dire("")

# ---------------------------------------------------------------------------
dire("Cas otel/ : %d ; requêtes analysées par la bibliothèque : %d ; statut décidé avant le décodage (sans objet) : %d ; corps de réponse confrontés : %d ; corps Status des refus non confrontés : %d ; divergences voulues : %d ; limites de l'outil : %d ; discordances : %d" % (len(CAS), len(CAS) - len(AVANT_DECODAGE), len(AVANT_DECODAGE), len(REPONSES), len(STATUS), len(DIVERGENCES), len(LIMITES_SONDE), len(DISCORDANCES)))
for d in DIVERGENCES:
    dire("  divergence voulue : " + d)
for d in LIMITES_SONDE:
    dire("  limite : " + d)
for d in DISCORDANCES:
    dire("  DISCORDANCE : " + d)
dire("Discordances au total : %d" % len(DISCORDANCES))
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
