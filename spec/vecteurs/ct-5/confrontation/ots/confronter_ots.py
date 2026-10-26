#!/usr/bin/env python3
# Confrontation des fichiers .ots de CT-5 (famille ots/, annexe A.6) par la
# bibliothèque officielle python-opentimestamps, hors ligne :
#
# - lecture stricte et fin de fichier exacte : DetachedTimestampFile.deserialize,
#   StreamDeserializationContext.assert_eof ;
# - réécriture octet pour octet : DetachedTimestampFile.serialize (l'ordre des
#   branches est celui de la bibliothèque : attestations puis opérations, triées) ;
# - empreinte, attestations en attente et leurs URI : arbre Timestamp
#   (ops, attestations, all_attestations) ;
# - mise à niveau d'EX-6.6 : le Timestamp servi par le calendrier est
#   désérialisé pour l'engagement, l'attestation en attente retirée, la
#   réponse fusionnée (Timestamp.merge), la preuve resérialisée et comparée à
#   la preuve complète de CT-6.
# Aucun code du dépôt n'est employé ; aucun accès réseau.
#
# Usage : python3 -I confronter_ots.py <répertoire spec/vecteurs/ct-5>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import hashlib
import io
import json
import os
import sys

import opentimestamps
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import BinaryOp, OpAppend, OpPrepend, OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext, StreamDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

if len(sys.argv) != 2:
    print("usage : confronter_ots.py <spec/vecteurs/ct-5>", file=sys.stderr)
    sys.exit(2)

RACINE = os.path.abspath(sys.argv[1])
os.chdir(os.path.join(RACINE, "ots"))
OTS = json.load(open("ots.json", encoding="utf-8"))
MISE_A_NIVEAU = json.load(open("mise-a-niveau.json", encoding="utf-8"))
SORTIE, DISCORDANCES = [], []


def dire(*m):
    SORTIE.append(" ".join(str(x) for x in m))


def comparer(libelle, vecteur, outil):
    ok = vecteur == outil
    dire("  %s : vecteur %s ; outil %s : %s" % (libelle, vecteur, outil, "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, outil %s" % (libelle, vecteur, outil))
    return ok


def hexa(b):
    return "0x" + b.hex()


def lire(octets):
    ctx = StreamDeserializationContext(io.BytesIO(octets))
    dtf = DetachedTimestampFile.deserialize(ctx)
    ctx.assert_eof()
    return dtf


def serialiser(dtf):
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def nom_op(op):
    return {OpAppend: "append", OpPrepend: "prepend", OpSHA256: "sha256"}.get(type(op), type(op).__name__)


def uri_de(a):
    """URI d'une attestation en attente (str dans la bibliothèque ; octets dans d'anciennes versions)."""
    return a.uri.decode() if isinstance(a.uri, bytes) else a.uri


def arg_de(op):
    """Argument d'une opération binaire (Op est un tuple : l'argument est op[0])."""
    return op[0] if isinstance(op, BinaryOp) else None


def branches(ts, chemin=()):
    """(chemin d'opérations, attestation) pour chaque attestation, dans l'ordre de la bibliothèque."""
    for a in sorted(ts.attestations):
        yield chemin, a, ts.msg
    for op, sous in sorted(ts.ops.items()):
        yield from branches(sous, chemin + ((nom_op(op), arg_de(op)),))


def nature(a):
    if isinstance(a, BitcoinBlockHeaderAttestation):
        return "bitcoin"
    if isinstance(a, PendingAttestation):
        return "en_attente"
    return "inconnue"


dire("Confrontation des fichiers .ots de CT-5 par opentimestamps %s (Python %s)" % (opentimestamps.__version__, sys.version.split()[0]))
dire("Entrées : ots/ots.json, ots/*.ots, ots/mise-a-niveau.json, ../ct-6/ots/preuves/{o7-en-attente,periode-1}.ots")
dire("")

dire("== 1. Fichiers .ots en attente (EX-6.4)")
for cas in OTS["cases"]:
    octets = open(cas["file"], "rb").read()
    dire("-- %s (%s)" % (cas["id"], cas["file"]))
    comparer("SHA-256 et taille", (cas["sha256"], cas["size"]), (hexa(hashlib.sha256(octets).digest()), len(octets)))
    try:
        dtf = lire(octets)
        lecture = "acceptee"
    except Exception as e:
        dtf = None
        lecture = "%s : %s" % (type(e).__name__, str(e)[:120])
    comparer("lecture stricte (DetachedTimestampFile.deserialize + assert_eof)", "acceptee", lecture)
    if dtf is None:
        continue
    comparer("réécriture par la bibliothèque identique aux octets du fichier", True, serialiser(dtf) == octets)
    comparer("opération de hachage du fichier = SHA-256 (08)", True, isinstance(dtf.file_hash_op, OpSHA256))
    comparer("empreinte du fichier", cas["digest"], hexa(dtf.file_digest))
    # première opération : append du nonce de 16 octets, puis sha256 → engagement
    racine = dtf.timestamp
    ops = list(racine.ops.items())
    comparer("une seule opération sous l'empreinte : append d'un argument de 16 octets (nonce)", ("append", 16), (nom_op(ops[0][0]), len(arg_de(ops[0][0]))) if len(ops) == 1 else (len(ops),))
    comparer("nonce", cas["nonce"], hexa(arg_de(ops[0][0])) if ops else None)
    apres_nonce = ops[0][1]
    ops2 = list(apres_nonce.ops.items())
    comparer("puis sha256 vers l'engagement", "sha256", nom_op(ops2[0][0]) if len(ops2) == 1 else None)
    engagement = ops2[0][1]
    comparer("engagement e = SHA-256(empreinte ‖ nonce)", cas["commitment"], hexa(engagement.msg))
    # branches sous l'engagement : une par calendrier, dans l'ordre de la bibliothèque
    lues = []
    for chemin, a, msg in branches(engagement):
        lues.append({"calendar_ops": [(n, hexa(arg) if arg is not None else None) for n, arg in chemin], "attestation": nature(a), "uri": uri_de(a) if isinstance(a, PendingAttestation) else None})
    attendues = []
    for b in cas["branches"]:
        attendues.append({"calendar_ops": [(o["op"], o.get("argument")) for o in b["ops"]], "attestation": b["attestation"], "uri": b["uri"]})
    # l'ordre d'écriture de la bibliothèque : attestations (triées par URI) puis opérations (triées par étiquette et argument)
    cle = lambda x: (0, x["uri"]) if not x["calendar_ops"] else (1, x["calendar_ops"][0][1] or "")
    comparer("branches de calendrier (opérations puis attestation en attente), dans l'ordre de la bibliothèque", sorted(attendues, key=cle), lues)
    comparer("toutes les attestations en attente (EX-6.7 : en_attente)", True, all(isinstance(a, PendingAttestation) for _, a in dtf.timestamp.all_attestations()))
    comparer("état", cas["state"], "en_attente" if not any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in dtf.timestamp.all_attestations()) else "complete")
dire("")

dire("== 2. Mise à niveau (EX-6.6, EX-8.11) : preuves de CT-6 lues, non copiées")
m = MISE_A_NIVEAU
avant = open(m["before"]["file"], "rb").read()
apres = open(m["after"]["file"], "rb").read()
reponse = bytes.fromhex(m["response"]["der"][2:])
comparer("avant : SHA-256 et taille", (m["before"]["sha256"], m["before"]["size"]), (hexa(hashlib.sha256(avant).digest()), len(avant)))
comparer("après : SHA-256 et taille", (m["after"]["sha256"], m["after"]["size"]), (hexa(hashlib.sha256(apres).digest()), len(apres)))
comparer("réponse du calendrier : SHA-256 et taille", (m["response"]["sha256"], m["response"]["size"]), (hexa(hashlib.sha256(reponse).digest()), len(reponse)))
d_avant = lire(avant)
d_apres = lire(apres)
comparer("avant : réécriture identique", True, serialiser(d_avant) == avant)
comparer("après : réécriture identique", True, serialiser(d_apres) == apres)
etat = lambda d: "complete" if any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in d.timestamp.all_attestations()) else "en_attente"
comparer("état avant", m["expected"]["state_before"], etat(d_avant))
comparer("état après", m["expected"]["state_after"], etat(d_apres))
# nœud qui porte l'attestation en attente du calendrier
uri = m["calendar"]
def noeuds(ts):
    yield ts
    for sous in ts.ops.values():
        yield from noeuds(sous)


cible = [ts for ts in noeuds(d_avant.timestamp) if any(isinstance(a, PendingAttestation) and uri_de(a) == uri for a in ts.attestations)]
comparer("une attestation en attente du calendrier %s dans la preuve avant" % m["calendar"], 1, len(cible))
ts = cible[0]
ctx = StreamDeserializationContext(io.BytesIO(reponse))
servi = Timestamp.deserialize(ctx, ts.msg)
ctx.assert_eof()
comparer("réponse du calendrier : attestation Bitcoin à la hauteur 1001 au bout des opérations", [("bitcoin", 1001)], [(nature(a), a.height) for _, a in servi.all_attestations()])
ts.attestations = {a for a in ts.attestations if not (isinstance(a, PendingAttestation) and uri_de(a) == uri)}
ts.merge(servi)
fusion = serialiser(d_avant)
comparer("preuve fusionnée : SHA-256", m["expected"]["merged_sha256"], hexa(hashlib.sha256(fusion).digest()))
comparer("preuve fusionnée = preuve complète de CT-6 (octets)", m["expected"]["merged_equals_after"], fusion == apres)
comparer("état de la preuve fusionnée", m["expected"]["state_after"], etat(lire(fusion)))
dire("")

dire("Discordances au total : %d" % len(DISCORDANCES))
for d in DISCORDANCES:
    dire("  - " + d)
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
