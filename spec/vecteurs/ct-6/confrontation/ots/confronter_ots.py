#!/usr/bin/env python3
# Confrontation des vecteurs CT-6 ots/ par la bibliothèque officielle
# python-opentimestamps (CT-6, annexe A.8).
#
# - lecture des .ots, exécution des opérations et comparaison à la racine de
#   Merkle de l'en-tête : opentimestamps.core (DetachedTimestampFile,
#   Timestamp, BitcoinBlockHeaderAttestation.verify_against_blockheader) ;
# - en-têtes Bitcoin : bitcoin.core de python-bitcoinlib (CBlockHeader,
#   GetHash, CheckProofOfWork avec les paramètres regtest,
#   uint256_from_compact) et, indépendamment, hashlib (double SHA-256) ;
# - règles O-1 à O-7 (CT-6 §10.4) refaites ici à partir de ces primitives,
#   pour comparer statut et raison à ots/attendu.json.
# Aucun code du dépôt n'est employé ; aucun accès réseau.
#
# Usage : python3 -I confronter_ots.py <répertoire spec/vecteurs/ct-6>
# Code de retour : 0 si aucune discordance, 1 sinon.

import hashlib
import io
import json
import os
import sys
from datetime import datetime, timezone

import bitcoin
import bitcoin.core
from bitcoin.core import CBlockHeader, CheckProofOfWork, CheckProofOfWorkError
from bitcoin.core.serialize import uint256_from_compact
import opentimestamps
from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation, PendingAttestation,
                                        UnknownAttestation, VerificationError)
from opentimestamps.core.op import Op, OpAppend, OpPrepend, OpSHA256
from opentimestamps.core.serialize import (BytesSerializationContext, DeserializationError,
                                           StreamDeserializationContext)
from opentimestamps.core.timestamp import DetachedTimestampFile

RACINE = os.path.abspath(sys.argv[1])
O = os.path.join(RACINE, "ots")
ATTENDU = json.load(open(os.path.join(O, "attendu.json"), encoding="utf-8"))
ANCRE = json.load(open(os.path.join(RACINE, "ancres", "ancres-test.json"), encoding="utf-8"))["bitcoin"]
SORTIE, DISCORDANCES = [], []


def dire(*m):
    SORTIE.append(" ".join(str(x) for x in m))


def comparer(libelle, vecteur, outil):
    ok = vecteur == outil
    dire("  %s : vecteur %s ; outil %s : %s" % (libelle, vecteur, outil, "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, outil %s" % (libelle, vecteur, outil))
    return ok


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hexa(b):
    return "0x" + b.hex()


dire("Confrontation des vecteurs CT-6 ots/ par opentimestamps %s et python-bitcoinlib %s (Python %s)"
     % (opentimestamps.__version__, bitcoin.__version__, sys.version.split()[0]))
dire("Entrées : ots/attendu.json, ots/preuves/*.ots, ots/entetes/*.json, ancres/ancres-test.json (partie bitcoin)")
dire("")

# ---------------------------------------------------------------------------
# 1. En-têtes : lecture par python-bitcoinlib, double SHA-256 par hashlib
bitcoin.SelectParams("regtest")
POW_LIMIT_REGTEST = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
comparer("powLimit regtest de python-bitcoinlib (CT-6 §10.4, table des réseaux)", POW_LIMIT_REGTEST,
         bitcoin.core.coreparams.PROOF_OF_WORK_LIMIT)

ENTETES = {}
dire("== 1. Chaînes d'en-têtes (EX-A.6)")
for nom, att in ATTENDU["headers"].items():
    chemin = os.path.join(O, nom)
    brut = open(chemin, "rb").read()
    d = json.loads(brut)
    dire("-- %s" % nom)
    comparer("SHA-256 du fichier", att["sha256"], hexa(hashlib.sha256(brut).digest()))
    comparer("réseau", "regtest", d["network"])
    s = d["start_height"]
    octets = [bytes.fromhex(h[2:]) for h in d["headers"]]
    t = s + len(octets) - 1
    comparer("hauteurs", (att["start_height"], att["end_height"]), (s, t))
    hdr = {s + i: CBlockHeader.deserialize(b) for i, b in enumerate(octets)}
    brut_h = {s + i: b for i, b in enumerate(octets)}
    ENTETES[nom] = (s, t, hdr, brut_h)
    # hachages : python-bitcoinlib (GetHash) et hashlib, ordre d'affichage
    affiches = {}
    for h in range(s, t + 1):
        a = hdr[h].GetHash()
        assert a == dsha(brut_h[h])
        affiches[str(h)] = hexa(a[::-1])
    comparer("hachages des %d en-têtes (GetHash de python-bitcoinlib = double SHA-256 de hashlib, ordre d'affichage)" % len(octets),
             att["hashes"], affiches)
    # champs fixés par EX-A.6
    comparer("nVersion = 0x20000000 partout", True, all(hdr[h].nVersion == 0x20000000 for h in hdr))
    comparer("nBits = 0x207fffff partout", True, all(hdr[h].nBits == 0x207fffff for h in hdr))
    comparer("nTime(990) = 1793880000 puis +600 s par bloc", True, all(hdr[h].nTime == 1793880000 + 600 * (h - 990) for h in hdr))
    if s == 990:
        comparer("prev(990) = 32 octets nuls", True, hdr[s].hashPrevBlock == b"\0" * 32)
    chainage = [h for h in range(s + 1, t + 1) if hdr[h].hashPrevBlock != hdr[h - 1].GetHash()]
    sans_travail = []
    for h in range(s, t + 1):
        try:
            CheckProofOfWork(hdr[h].GetHash(), hdr[h].nBits)
        except CheckProofOfWorkError:
            sans_travail.append(h)
    dire("  chaînage prev(i) = dSHA(H(i−1)) : %s ; CheckProofOfWork (paramètres regtest) en échec : %s"
         % ("rompu en " + str(chainage) if chainage else "intact", sans_travail or "aucun"))
    if "sans-travail" in nom:
        comparer("en-têtes sans preuve de travail (EX-A.6 : seul 1010)", [1010], sans_travail)
    else:
        comparer("en-têtes sans preuve de travail", [], sans_travail)
    comparer("chaînage", [], chainage)
    # nNonce minimal (EX-A.6) : aucun nNonce inférieur ne satisfait la cible
    non_minimaux = []
    for h in range(s, t + 1):
        if h in sans_travail:
            continue
        for n in range(hdr[h].nNonce):
            essai = brut_h[h][:76] + n.to_bytes(4, "little")
            if int.from_bytes(dsha(essai), "little") <= uint256_from_compact(hdr[h].nBits):
                non_minimaux.append(h)
                break
    comparer("nNonce minimal pour chaque en-tête avec travail", [], non_minimaux)
    # racines : celles des preuves en 1001 à 1003, dSHA(étiquette) ailleurs
    # racines réelles : 1001 à 1003 (preuves de période) ; 1004 dans chaine-points.json (preuve du point, EX-A.13)
    reelles = (1001, 1002, 1003, 1004) if nom.endswith("chaine-points.json") else (1001, 1002, 1003)
    autres = [h for h in range(s, t + 1) if h not in reelles
              and hdr[h].hashMerkleRoot != dsha(("noortrace/vecteurs/v0/ct-6/bitcoin/racine/%d" % h).encode())]
    comparer("racine(i) = dSHA(« noortrace/vecteurs/v0/ct-6/bitcoin/racine/<i> ») hors %s" % ("1001 à 1004" if len(reelles) == 4 else "1001 à 1003"), [], autres)

c_h = ANCRE["checkpoint"]["height"]
s, t, hdr, _ = ENTETES["entetes/chaine.json"]
comparer("point de contrôle de ancres-test.json (hauteur 1000, ordre d'affichage)", ANCRE["checkpoint"]["hash"],
         hexa(hdr[c_h].GetHash()[::-1]))
comparer("bitcoin_anchor de ots/attendu.json = partie bitcoin de ancres-test.json", ATTENDU["bitcoin_anchor"], ANCRE)
s2, t2, hdr2, _ = ENTETES["entetes/chaine-courte.json"]
comparer("chaine-courte.json = 14 premiers en-têtes de chaine.json", True,
         all(hdr2[h].serialize() == hdr[h].serialize() for h in range(s2, t2 + 1)))
s4, t4, hdr4, _ = ENTETES["entetes/chaine-depuis-1001.json"]
comparer("chaine-depuis-1001.json = en-têtes 1001 à 1020 de chaine.json (sans la hauteur 1000 du point de contrôle)", True,
         (s4, t4) == (1001, 1020) and all(hdr4[h].serialize() == hdr[h].serialize() for h in range(s4, t4 + 1)))
s3, t3, hdr3, _ = ENTETES["entetes/chaine-sans-travail.json"]
comparer("chaine-sans-travail.json = chaine.json jusqu'à 1009, nNonce de 1010 seul changé dans 1010",
         True, all(hdr3[h].serialize() == hdr[h].serialize() for h in range(990, 1010))
         and hdr3[1010].serialize()[:76] == hdr[1010].serialize()[:76] and hdr3[1010].nNonce != hdr[1010].nNonce)
dire("")


# ---------------------------------------------------------------------------
# 2. Preuves .ots : lecture stricte par la bibliothèque, puis lecture aux limites
#    relâchées pour séparer le format (O-1) des longueurs (O-3)
def lire_strict(octets):
    try:
        ctx = StreamDeserializationContext(io.BytesIO(octets))
        dtf = DetachedTimestampFile.deserialize(ctx)
        ctx.assert_eof()
        return dtf, None
    except Exception as e:  # la bibliothèque lève DeserializationError et ses sous-classes
        return None, "%s : %s" % (type(e).__name__, str(e)[:160])


def lire_relache(octets):
    anciens = (Op.MAX_RESULT_LENGTH, Op.MAX_MSG_LENGTH)
    Op.MAX_RESULT_LENGTH = Op.MAX_MSG_LENGTH = 1 << 20
    try:
        return lire_strict(octets)
    finally:
        Op.MAX_RESULT_LENGTH, Op.MAX_MSG_LENGTH = anciens


PROFIL = (OpAppend, OpPrepend, OpSHA256)


def parcourir(ts, chemin=()):
    """(message, attestation, opérations du chemin) pour chaque attestation de l'arbre."""
    for a in sorted(ts.attestations):
        yield ts.msg, a, chemin
    for op, sous in sorted(ts.ops.items()):
        yield from parcourir(sous, chemin + ((op, ts.msg, sous.msg),))


def nature(a):
    if isinstance(a, BitcoinBlockHeaderAttestation):
        return "bitcoin"
    if isinstance(a, PendingAttestation):
        return "en_attente"
    return "inconnue"


PREUVES = {}
dire("== 2. Preuves .ots (EX-A.7) : lecture par opentimestamps, opérations, attestations")
# URI d'une attestation en attente (CT-6 §10.2, table des étiquettes) : 0 à 1000 octets pris dans
# A-Z a-z 0-9 - . _ / : ; ce sont les constantes de PendingAttestation, que deserialize applique
comparer("URI en attente : longueur maximale de la bibliothèque (PendingAttestation.MAX_URI_LENGTH)", 1000, PendingAttestation.MAX_URI_LENGTH)
comparer("URI en attente : caractères admis par la bibliothèque (PendingAttestation.ALLOWED_URI_CHARS)",
         bytes(sorted(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")).decode(),
         bytes(sorted(PendingAttestation.ALLOWED_URI_CHARS)).decode())
for p in ATTENDU["proofs"]:
    f = p["file"]
    octets = open(os.path.join(O, f), "rb").read()
    dire("-- %s (cible : %s ; altération : %s)" % (f, p["target"] or "aucune", p["alteration"] or "aucune"))
    comparer("SHA-256 et taille", (p["sha256"], p["size"]), (hexa(hashlib.sha256(octets).digest()), len(octets)))
    dtf, err = lire_strict(octets)
    lecture = "acceptee" if dtf else "refusee"
    dire("  lecture stricte (DetachedTimestampFile.deserialize + assert_eof) : %s%s" % (lecture, "" if dtf else " (" + err + ")"))
    comparer("lecture par python-opentimestamps présumée par attendu.json (%s)" % p["python_opentimestamps"]["source"],
             p["python_opentimestamps"]["parsing"], lecture)
    if dtf:
        ctx = BytesSerializationContext()
        dtf.serialize(ctx)
        comparer("réécriture par la bibliothèque identique aux octets du fichier", True, ctx.getbytes() == octets)
    dtf_r, err_r = lire_relache(octets)
    if dtf_r is None:
        dire("  lecture aux limites de longueur relâchées : refusée (%s)" % err_r)
        PREUVES[f] = {"format": False, "erreur": err_r}
        comparer("attestations", p["attestations"], [])
        continue
    comparer("opération de hachage du fichier = SHA-256 (08)", True, isinstance(dtf_r.file_hash_op, OpSHA256))
    comparer("empreinte du fichier", p["file_digest"], hexa(dtf_r.file_digest))
    atts, longueurs_ko, hors_profil_ops, args_trop_longs = [], [], set(), []
    for msg, a, chemin in parcourir(dtf_r.timestamp):
        ops_hors = [type(op).__name__ for op, _, _ in chemin if not isinstance(op, PROFIL)]
        hors_profil_ops.update(ops_hors)
        for op, entree, sortie in chemin:
            if not (1 <= len(entree) <= 4096 and 1 <= len(sortie) <= 4096):
                longueurs_ko.append((type(op).__name__, len(entree), len(sortie)))
            if isinstance(op, (OpAppend, OpPrepend)) and not 1 <= len(op[0]) <= 4096:
                args_trop_longs.append(len(op[0]))
        atts.append({"kind": nature(a), "height": getattr(a, "height", None), "uri": getattr(a, "uri", None),
                     "result": hexa(msg), "_att": a, "_hors_profil": bool(ops_hors),
                     "_longueur_ko": any(not (1 <= len(e) <= 4096 and 1 <= len(s) <= 4096) for _, e, s in chemin),
                     "_ops": len(chemin)})
    # sous une opération dont l'entrée ou le résultat sort de 1 à 4096 octets, le résultat n'est pas
    # défini par le profil (EX-10.7) : il est noté null, comme les vecteurs le notent
    # De même sous une opération hors profil, qui n'est pas exécutée (EX-10.7) : la bibliothèque
    # calcule ce résultat (ripemd160 par exemple) ; il est relevé, puis noté null.
    for x in atts:
        if x["_hors_profil"] and not x["_longueur_ko"]:
            dire("  résultat calculé par la bibliothèque sous l'opération hors profil (attestation %s %s) : %s, noté null (EX-10.7)"
                 % (x["kind"], x["height"] if x["height"] is not None else x["uri"], x["result"]))
        if x["_longueur_ko"] or x["_hors_profil"]:
            x["result"] = None
    vus = [{k: v for k, v in x.items() if not k.startswith("_")} for x in atts]
    comparer("attestations (nature, hauteur, URI, résultat des opérations)", sorted(p["attestations"], key=str), sorted(vus, key=str))
    dire("  opérations hors profil {f0, f1, 08} : %s ; longueurs hors de 1 à 4096 : %s ; plus long chemin : %d opérations"
         % (sorted(hors_profil_ops) or "aucune", longueurs_ko or "aucune", max(x["_ops"] for x in atts)))
    PREUVES[f] = {"format": not args_trop_longs and max(x["_ops"] for x in atts) <= 255, "dtf": dtf_r, "atts": atts,
                  "longueurs_ko": bool(longueurs_ko), "strict": dtf is not None}
dire("")


# ---------------------------------------------------------------------------
# 3. Vérifications O-1 à O-7 refaites sur ces primitives (CT-6 §10.4), cas par cas
def chaine_o5(nom):
    """O-5 sur le fichier d'en-têtes ; rend (statut, raison, détail)."""
    s, t, hdr, brut = ENTETES[nom]
    c = ANCRE["checkpoint"]["height"]
    if ANCRE["network"] != "regtest":
        return "echoue", None, "réseau"
    if any(hdr[i].hashPrevBlock != hdr[i - 1].GetHash() for i in range(s + 1, t + 1)):
        return "echoue", None, "chaînage"
    if not (s <= c <= t):
        # EX-10.9, règle 3 : le fichier ne contient pas la hauteur du point de contrôle
        return "non_execute", "ancre_absente", "point de contrôle %d hors de %d à %d" % (c, s, t)
    if hexa(hdr[c].GetHash()[::-1]) != ANCRE["checkpoint"]["hash"]:
        return "echoue", None, "point de contrôle"
    for i in range(c + 1, t + 1):
        try:
            CheckProofOfWork(hdr[i].GetHash(), hdr[i].nBits)
        except CheckProofOfWorkError as e:
            return "echoue", None, "preuve de travail en %d (%s)" % (i, e)
        if hdr[i].nBits != 0x207fffff:
            return "echoue", None, "nBits regtest en %d" % i
        if i - 11 >= s and not hdr[i].nTime > sorted(hdr[j].nTime for j in range(i - 11, i))[5]:
            return "echoue", None, "médiane des onze en %d" % i
    return "reussi", None, "chaînage, point de contrôle %d, travail et médiane de %d à %d" % (c, c + 1, t)


def statuts(cas):
    pv = PREUVES[cas["proof"]]
    r, av = {}, []
    for a in pv.get("atts", []):
        a.pop("_statut", None)  # statut de la comparaison de ce cas seulement
    if not pv["format"]:
        r["O-1"] = ("echoue", None)
        for i in ("O-2", "O-3", "O-4", "O-5", "O-6", "O-7"):
            r[i] = ("non_execute", "prerequis_en_echec")
        return r, av
    r["O-1"] = ("reussi", None)
    r["O-2"] = ("reussi" if hexa(pv["dtf"].file_digest) == cas["dossier_period_hash"] else "echoue", None)
    r["O-3"] = ("echoue" if pv["longueurs_ko"] else "reussi", None)
    btc = [a for a in pv["atts"] if a["kind"] == "bitcoin"]
    # AV-O-2 : une par attestation en attente ou inconnue (O-7, EX-10.11), une par attestation
    # Bitcoin sous une opération hors profil (O-4, EX-10.7)
    for a in pv["atts"]:
        if a["kind"] != "bitcoin":
            av.append(("AV-O-2", "O-7"))
        elif a["_hors_profil"]:
            av.append(("AV-O-2", "O-4"))
    r["O-7"] = ("reussi", None) if btc else ("non_execute", "partie_absente")
    # O-5
    if not btc:
        r["O-5"] = r["O-7"]
    elif cas["headers"] is None:
        r["O-5"] = ("non_execute", "partie_absente")
    elif cas["anchors"] is None:
        r["O-5"] = ("non_execute", "ancre_absente")
    else:
        st, raison, det = chaine_o5(cas["headers"])
        r["O-5"] = (st, raison)
        if ANCRE["network"] == "regtest" and st != "non_execute":
            av.append(("AV-O-3", "O-5"))
    # O-4 : exécutée si O-3 et O-5 réussies (EX-5.5 sinon)
    def herite(*pre):
        for p in pre:
            if r[p][0] == "echoue" or r[p][1] == "prerequis_en_echec":
                return ("non_execute", "prerequis_en_echec")
        for p in pre:
            if r[p][0] == "non_execute":
                return r[p]
        return None
    h = herite("O-3", "O-5")
    concordantes, comparees = [], []
    if h:
        r["O-4"] = h
    else:
        s, t, hdr, _ = ENTETES[cas["headers"]]
        for a in btc:
            if a["_hors_profil"] or a["_longueur_ko"]:
                continue
            if not s <= a["height"] <= t:
                continue
            try:
                a["_att"].verify_against_blockheader(bytes.fromhex(a["result"][2:]), hdr[a["height"]])
                comparees.append(True)
                concordantes.append(a["height"])
                a["_statut"] = "reussi"
            except VerificationError:
                comparees.append(False)
                a["_statut"] = "echoue"
        if concordantes:
            r["O-4"] = ("reussi", None)
            for _ in range(comparees.count(False)):
                av.append(("AV-O-1", "O-4"))
        elif comparees:
            r["O-4"] = ("echoue", None)
        else:
            r["O-4"] = ("non_execute", "ancre_absente")
    # O-6
    h6 = herite("O-4")
    if h6:
        r["O-6"] = h6
    else:
        s, t, hdr, _ = ENTETES[cas["headers"]]
        k = t - min(concordantes) + 1
        r["O-6"] = ("reussi", None) if k >= ANCRE["min_confirmations"] else ("non_execute", "ancre_absente")
    r["_concordantes"] = concordantes
    r["_comparees"] = comparees if not h else []
    # ordre de EX-6.15 : vérification qui lève l'avertissement (O-1 à O-7), puis identifiant, puis émission
    num = lambda x: int(x.rsplit("-", 1)[1])
    ordre = sorted(range(len(av)), key=lambda i: (num(av[i][1]), num(av[i][0]), i))
    return r, [av[i][0] for i in ordre]


def statut_controle(r):
    if any(r[i][0] == "echoue" for i in ("O-1", "O-2", "O-3", "O-4", "O-5")):
        return "echoue", None
    if all(r[i][0] == "reussi" for i in ("O-2", "O-4", "O-6", "O-7")):
        return "reussi", None
    raisons = [r[i][1] for i in ("O-1", "O-2", "O-3", "O-4", "O-5", "O-6", "O-7") if r[i][0] == "non_execute"]
    for raison in ("prerequis_en_echec", "hors_perimetre_version", "partie_absente", "ancre_absente"):
        if raison in raisons:
            return "non_execute", raison


dire("== 3. Vérifications O-1 à O-7, cas de ots/attendu.json (statut/raison attendus et recalculés)")
BILAN = [0, 0]
for cas in ATTENDU["cases"]:
    dire("-- %s, en-têtes %s, ancres %s, periodHash du dossier %s…" % (cas["proof"], cas["headers"] or "absents", cas["anchors"] or "absentes", cas["dossier_period_hash"][:10]))
    r, av = statuts(cas)
    for chk in cas["checks"]:
        att = (chk["status"], chk["reason"])
        ok = att == r[chk["id"]]
        BILAN[0 if ok else 1] += 1
        dire("  %-4s attendu %-32s outil %-32s %s" % (chk["id"], "/".join(x for x in att if x), "/".join(x for x in r[chk["id"]] if x),
                                                     "concorde" if ok else "DISCORDANCE"))
        if not ok:
            DISCORDANCES.append("%s %s (en-têtes %s) : vecteur %s, outil %s" % (cas["proof"], chk["id"], cas["headers"], att, r[chk["id"]]))
    comparer("statut du contrôle 5", (cas["control_status"], cas["control_reason"]), statut_controle(r))
    comparer("avertissements (liste exacte, ordre de EX-6.15)", cas["warnings"], av)
    fa = cas.get("facts")
    if fa:
        s, t, hdr, _ = ENTETES[cas["headers"]]
        h = min(r["_concordantes"])
        c = ANCRE["checkpoint"]["height"]
        travail = sum((1 << 256) // (uint256_from_compact(hdr[i].nBits) + 1) for i in range(max(h, c + 1), t + 1))
        mediane = iso(sorted(hdr[j].nTime for j in range(h + 1, h + 12))[5]) if t >= h + 11 else None
        pv = PREUVES[cas["proof"]]
        faits = {
            "file_digest": hexa(pv["dtf"].file_digest), "network": ANCRE["network"],
            "checkpoint": ANCRE["checkpoint"],
            # non_execute : attestation en attente ou inconnue, sous une opération hors profil, ou de
            # hauteur absente du fichier d'en-têtes (EX-10.7, EX-10.8) ; sinon le résultat de la comparaison
            "attestations": [{"kind": a["kind"], "height": a["height"], "uri": a["uri"],
                              "tag": hexa(a["_att"].TAG) if a["kind"] == "inconnue" else None,
                              "status": a.get("_statut", "non_execute")} for a in pv["atts"]],
            "retained_height": h, "block_hash": hexa(hdr[h].GetHash()[::-1]),
            "block_time": iso(hdr[h].nTime), "median_bound": mediane, "confirmations": t - h + 1,
            "cumulative_work": str(travail),
        }
        for cle in fa:
            comparer("fait %s" % cle, fa[cle], faits.get(cle, "absent"))
dire("")
dire("Bilan des vérifications O- : %d concordances, %d discordances" % tuple(BILAN))
dire("Discordances au total : %d" % len(DISCORDANCES))
for d in DISCORDANCES:
    dire("  - " + d)
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
