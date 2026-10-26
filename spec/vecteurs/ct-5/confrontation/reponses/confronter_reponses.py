#!/usr/bin/env python3
# Confrontation des vecteurs CT-5 reponses/ par OpenSSL (CT-5, annexe A.6), et
# des jetons embarqués dans les dossiers de CT-6 révision 0.2 qui portent la
# partie points-de-controle.json (CT-6 EX-A.17).
#
# Tout ce qui touche au DER, aux jetons et aux signatures est fait par
# l'exécutable openssl (ts -reply, ts -verify, dgst) ; ce programme (Python,
# bibliothèque standard seulement) ne fait que le lancer, lire ses sorties
# texte et les comparer à reponses/reponses.json et aux attendu.json des
# dossiers. Il n'emploie aucun code du dépôt et n'accède pas au réseau.
#
# Usage : python3 -I confronter_reponses.py <répertoire spec/vecteurs/ct-5> <répertoire de travail vide>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import base64
import binascii
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

if len(sys.argv) != 3:
    print("usage : confronter_reponses.py <spec/vecteurs/ct-5> <répertoire de travail>", file=sys.stderr)
    sys.exit(2)

RACINE = os.path.abspath(sys.argv[1])
TRAVAIL = os.path.abspath(sys.argv[2])
os.makedirs(TRAVAIL, exist_ok=True)
os.chdir(RACINE)

REPONSES = json.load(open("reponses/reponses.json", encoding="utf-8"))
CA = ["-CAfile", "../ct-6/rfc3161/cles/ac-test.pem", "-untrusted", "../ct-6/rfc3161/cles/tsa-test.pem"]
STATUTS = {0: "Granted.", 1: "Granted with modifications.", 2: "Rejected.", 3: "Waiting.", 4: "Revocation warning.", 5: "Revoked."}
FAILURE_INFO = {"badAlg": "unrecognized or unsupported algorithm identifier", "badRequest": "transaction not permitted or supported",
                "badDataFormat": "the data submitted has the wrong format", "timeNotAvailable": "the TSA's time source is not available",
                "unacceptedPolicy": "the requested TSA policy is not supported by the TSA", "unacceptedExtension": "the requested extension is not supported by the TSA",
                "addInfoNotAvailable": "the additional information requested could not be understood or is not available", "systemFailure": "the request cannot be handled due to system failure"}
SORTIE, DISCORDANCES, LIMITES = [], [], []


def dire(*m):
    SORTIE.append(" ".join(str(x) for x in m))


def comparer(libelle, vecteur, outil):
    ok = vecteur == outil
    dire("  %s : vecteur %s ; openssl %s : %s" % (libelle, vecteur, outil, "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, openssl %s" % (libelle, vecteur, outil))
    return ok


def ossl(args, entree=None):
    r = subprocess.run(["openssl"] + args, input=entree, capture_output=True)
    texte = (r.stdout + r.stderr).decode("utf-8", "replace")
    lignes = []
    for l in texte.splitlines():
        if l.startswith("Using configuration from") or l.startswith("Warning: certificate from"):
            continue
        l = re.sub(r"^[0-9A-F]{8,}:error:", "error:", l)
        l = l.replace(TRAVAIL + os.sep, "<travail>/")
        lignes.append(l)
    return r.returncode, "\n".join(lignes)


def ossl_octets(args, entree=None):
    r = subprocess.run(["openssl"] + args, input=entree, capture_output=True)
    return r.returncode, r.stdout


def sha256_ossl(octets):
    code, s = ossl(["dgst", "-sha256", "-r"], entree=octets)
    assert code == 0, s
    return "0x" + s.split()[0].lower()


def erreurs(sortie):
    """Raisons d'échec d'openssl, dans son ordre, chacune une fois. Les erreurs
    de la bibliothèque système (« system library », par exemple un fichier de
    configuration ou un magasin de certificats par défaut absent, qu'OpenSSL
    3.5 empile à chaque échec) tiennent à l'environnement, pas au jeton : elles
    sont écartées."""
    out = []
    for l in sortie.splitlines():
        m = re.match(r"error:[0-9A-F]+:([^:]*):[^:]*:([^:]*):", l)
        if m and m.group(1) != "system library" and m.group(2) not in out:
            out.append(m.group(2))
    return out


def verdict(sortie):
    return "OK" if "Verification: OK" in sortie else "; ".join(erreurs(sortie)) or "FAILED"


def iso(texte):
    """« Nov  3 13:53:02 2026 GMT » → RFC 3339."""
    t = datetime.strptime(re.sub(r"\s+", " ", texte.strip()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def unix(texte):
    return int(datetime.strptime(texte, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def champs_reply(texte):
    c = {}
    m = re.search(r"^Status: (.+)$", texte, re.M)
    c["statut"] = m.group(1) if m else None
    m = re.search(r"^Failure info: (.+)$", texte, re.M)
    c["failure_info"] = None if not m or m.group(1) == "unspecified" else m.group(1)
    c["jeton"] = "TST info:\nNot included." not in texte and "TST info:" in texte
    if c["jeton"]:
        hexs = re.findall(r"^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]?)+)", texte, re.M)
        c["condense"] = "0x" + "".join(re.sub(r"[^0-9a-f]", "", h) for h in hexs)
        m = re.search(r"^Policy OID: (.+)$", texte, re.M)
        c["politique"] = m.group(1) if m else None
        m = re.search(r"^Serial number: 0x([0-9A-F]+)$", texte, re.M)
        c["serie"] = int(m.group(1), 16) if m else None
        m = re.search(r"^Time stamp: (.+)$", texte, re.M)
        c["gen_time"] = iso(m.group(1)) if m else None
        m = re.search(r"^Accuracy: (.+)$", texte, re.M)
        if m:
            parts = m.group(1).split(", ")
            val = 0.0
            for p, ech in zip(parts, (1, 1e-3, 1e-6)):
                v = p.split()[0]
                if v != "unspecified":
                    val += int(v, 16) * ech
            c["accuracy_s"] = val if m.group(1) != "unspecified seconds, unspecified millis, unspecified micros" else None
        m = re.search(r"^Nonce: (.+)$", texte, re.M)
        c["nonce"] = None if not m or m.group(1) == "unspecified" else "0x" + m.group(1)[2:].lower().rjust(16, "0")
    return c


code, version = ossl(["version"])
dire("Confrontation des vecteurs CT-5 reponses/ par %s" % version.strip())
dire("Entrées : reponses/reponses.json, reponses/*.tsr, reponses/*.der, requetes/*.tsq, ../ct-6/rfc3161/cles/{ac-test,tsa-test}.pem, ../ct-6/dossiers/*/points-de-controle.json et attendu.json")
dire("")

# ---------------------------------------------------------------------------
dire("== 1. Réponses TimeStampResp (EX-5.10 à EX-5.12) : openssl ts -reply -text, -token_out, ts -verify -queryfile")
for cas in REPONSES["cases"]:
    i, e = cas["input"], cas["expected"]
    dire("-- %s (requête %s)" % (cas["id"], i["request"].split("/")[-1]))
    if i["response"] is None:
        dire("  réponse HTTP représentée (statut %s, %s) : aucun octet de TimeStampResp, sans objet pour openssl" % (i["http"]["status"], i["http"]["content_type"]))
        continue
    fichier = "reponses/" + i["response"]
    octets = open(fichier, "rb").read()
    comparer("SHA-256 du fichier", i["response_sha256"], sha256_ossl(octets))
    comparer("taille du corps", i["http"]["body_size"], len(octets))
    code, s = ossl(["ts", "-reply", "-in", fichier, "-text"])
    comparer("openssl ts -reply -text : code de retour", 0, code)
    c = champs_reply(s)
    comparer("Status (PKIStatus %d)" % e["pki_status"], STATUTS[e["pki_status"]], c["statut"])
    comparer("Failure info (PKIFailureInfo %s)" % e["failure_info"], FAILURE_INFO.get(e["failure_info"]), c["failure_info"])
    comparer("TimeStampToken présent", e["token"] is not None, c["jeton"])
    if not c["jeton"]:
        code, s = ossl(["ts", "-verify", "-queryfile", "requetes/" + i["request"].split("/")[-1], "-in", fichier] + CA)
        dire("  openssl ts -verify -queryfile : %s (aucun jeton à vérifier)" % verdict(s))
        continue
    code, q = ossl(["ts", "-query", "-in", "requetes/" + i["request"].split("/")[-1], "-text"])
    hexs = re.findall(r"^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]?)+)", q, re.M)
    empreinte_requete = "0x" + "".join(re.sub(r"[^0-9a-f]", "", h) for h in hexs)
    comparer("messageImprint = empreinte de la requête (imprint_matches)", e["imprint_matches"], c["condense"] == empreinte_requete)
    comparer("nonce du TSTInfo", e["nonce_in_response"], c["nonce"])
    comparer("genTime", e["gen_time"], c["gen_time"])
    comparer("accuracy (secondes)", e["accuracy_s"], c["accuracy_s"])
    dire("  politique du jeton : %s ; numéro de série : %s" % (c["politique"], c["serie"]))
    code, jeton = ossl_octets(["ts", "-reply", "-in", fichier, "-token_out"])
    comparer("jeton extrait (openssl ts -reply -token_out) : SHA-256", e["token_sha256"], sha256_ossl(jeton))
    comparer("jeton extrait : taille", e["token_size"], len(jeton))
    comparer("jeton extrait = fichier reponses/%s" % e["token"], True, jeton == open("reponses/" + e["token"], "rb").read())
    code, s = ossl(["ts", "-verify", "-queryfile", "requetes/" + i["request"].split("/")[-1], "-in", fichier, "-attime", str(unix(c["gen_time"]))] + CA)
    v = verdict(s)
    if e["openssl_verify"] is not None:
        comparer("openssl ts -verify -queryfile (à genTime)", e["openssl_verify"], v)
    else:
        note = ""
        if e["error_code"] == "verification_T-6":
            note = " (T-6 : signature altérée relevée par openssl)"
        dire("  openssl ts -verify -queryfile (à genTime) : %s ; classement de CT-5 : %s%s" % (v, e["error_code"], note))
    # EX-5.10, étape 5 : openssl ne connaît pas accepted_policies ; la politique
    # qu'il lit dans le TSTInfo (« Policy OID ») est confrontée à la liste du
    # prestataire de reponses.json : hors liste <=> refus de l'étape 5
    # (politique_refusee, ou politique_differente quand reqPolicy a été envoyé,
    # cette comparaison passant en premier).
    admises = REPONSES["provider"].get("accepted_policies")
    if admises is not None and c["politique"] is not None:
        comparer("politique lue par openssl (%s) hors accepted_policies <=> refus de l'étape 5 (politique_refusee ou politique_differente)" % c["politique"], e["error_code"] in ("politique_refusee", "politique_differente"), c["politique"] not in admises)
dire("")

# ---------------------------------------------------------------------------
dire("== 2. Jetons embarqués dans les dossiers de CT-6 révision 0.2 (points-de-controle.json, CT-6 EX-A.17) : openssl ts -verify -digest <checkpoint_hash> -token_in")
DOSSIERS = "../ct-6/dossiers"
for nom in sorted(os.listdir(DOSSIERS)):
    chemin = os.path.join(DOSSIERS, nom, "points-de-controle.json")
    if not os.path.exists(chemin):
        continue
    partie = json.load(open(chemin, encoding="utf-8"))
    attendu = json.load(open(os.path.join(DOSSIERS, nom, "attendu.json"), encoding="utf-8"))
    echecs = attendu.get("failed_checks", [])
    dire("-- dossiers/%s (vérifications en échec attendues : %s)" % (nom, ", ".join(echecs) or "aucune"))
    if not isinstance(partie, dict) or not partie.get("anchors") or not partie["anchors"].get("rfc3161"):
        dire("  aucun jeton dans la partie (sans objet)")
        continue
    b64 = partie["anchors"]["rfc3161"]["token"]
    try:
        jeton = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as err:
        dire("  base64 illisible pour Python (%s) : sans objet" % err)
        continue
    canonique = base64.b64encode(jeton).decode() == b64
    dire("  base64 canonique (réencodage identique) : %s ; jeton de %d octets, SHA-256 %s" % (canonique, len(jeton), sha256_ossl(jeton)))
    fichier = os.path.join(TRAVAIL, nom + ".der")
    open(fichier, "wb").write(jeton)
    code, s = ossl(["ts", "-reply", "-token_in", "-in", fichier, "-text"])
    c = champs_reply("Status: Granted.\nTST info:\n" + s)
    comparer("messageImprint du jeton = checkpoint_hash de la partie", not ("K-7" in echecs and "autre-empreinte" in nom), c["condense"] == partie["checkpoint_hash"])
    code, s = ossl(["ts", "-verify", "-digest", partie["checkpoint_hash"][2:], "-token_in", "-in", fichier, "-attime", str(unix(c["gen_time"]))] + CA)
    v = verdict(s)
    if "K-7" in echecs and canonique:
        comparer("openssl ts -verify -digest <checkpoint_hash> -token_in (K-7 attendue en échec)", "FAILED", "OK" if v == "OK" else "FAILED")
        dire("  raison d'openssl : %s" % v)
    elif "K-7" in echecs:
        # Base64 non canonique (EX-4.14 de CT-6) : le refus vient de l'encodage,
        # relevé ici par réencodage (base64 de Python) ; openssl confirme que les
        # octets décodés sont ceux d'un jeton valide.
        comparer("base64 non canonique (réencodage différent) <=> K-7 attendue en échec", True, not canonique)
        comparer("openssl ts -verify -digest <checkpoint_hash> -token_in sur les octets décodés", "OK", v)
    else:
        comparer("openssl ts -verify -digest <checkpoint_hash> -token_in", "OK", v)
dire("")

dire("Discordances au total : %d" % len(DISCORDANCES))
for d in DISCORDANCES:
    dire("  - " + d)
dire("Limites de l'outil relevées : %d" % len(LIMITES))
for d in LIMITES:
    dire("  - " + d)
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
