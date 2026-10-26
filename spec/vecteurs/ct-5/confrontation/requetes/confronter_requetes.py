#!/usr/bin/env python3
# Confrontation des vecteurs CT-5 requetes/ par OpenSSL (CT-5, annexe A.6).
#
# Tout ce qui touche au DER est fait par l'exécutable openssl (ts -query,
# asn1parse, ts -verify, dgst) ; ce programme (Python, bibliothèque standard
# seulement) ne fait que le lancer, lire ses sorties texte et les comparer à
# requetes/requetes.json et requetes/refusees.json. Il n'emploie aucun code du
# dépôt et n'accède pas au réseau.
#
# Usage : python3 -I confronter_requetes.py <répertoire spec/vecteurs/ct-5> <répertoire de travail vide>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import json
import os
import re
import subprocess
import sys

if len(sys.argv) != 3:
    print("usage : confronter_requetes.py <spec/vecteurs/ct-5> <répertoire de travail>", file=sys.stderr)
    sys.exit(2)

RACINE = os.path.abspath(sys.argv[1])
TRAVAIL = os.path.abspath(sys.argv[2])
os.makedirs(TRAVAIL, exist_ok=True)
os.chdir(RACINE)  # chemins relatifs dans les commandes et la sortie

REQUETES = json.load(open("requetes/requetes.json", encoding="utf-8"))
REFUSEES = json.load(open("requetes/refusees.json", encoding="utf-8"))
REPONSES = json.load(open("reponses/reponses.json", encoding="utf-8"))
CA = ["-CAfile", "../ct-6/rfc3161/cles/ac-test.pem", "-untrusted", "../ct-6/rfc3161/cles/tsa-test.pem"]
SORTIE, DISCORDANCES = [], []


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
    out = []
    for l in sortie.splitlines():
        m = re.match(r"error:[0-9A-F]+:[^:]*:[^:]*:([^:]*):", l)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def champs_query(texte):
    """Champs de `openssl ts -query -text` : version, algorithme, condensé, politique, nonce, certReq."""
    c = {}
    m = re.search(r"^Version: (\d+)$", texte, re.M)
    c["version"] = int(m.group(1)) if m else None
    m = re.search(r"^Hash Algorithm: (\S+)$", texte, re.M)
    c["algorithme"] = m.group(1) if m else None
    hexs = re.findall(r"^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]?)+)", texte, re.M)
    c["condense"] = "0x" + "".join(re.sub(r"[^0-9a-f]", "", h) for h in hexs)
    m = re.search(r"^Policy OID: (.+)$", texte, re.M)
    c["politique"] = None if not m or m.group(1) == "unspecified" else m.group(1)
    m = re.search(r"^Nonce: (.+)$", texte, re.M)
    c["nonce"] = None if not m or m.group(1) == "unspecified" else "0x" + m.group(1)[2:].lower().rjust(16, "0")
    m = re.search(r"^Certificate required: (\w+)$", texte, re.M)
    c["cert_req"] = (m.group(1) == "yes") if m else None
    return c


def elements_asn1(texte):
    """Lignes de `openssl asn1parse` : (profondeur, longueur, type, valeur)."""
    out = []
    for l in texte.splitlines():
        m = re.match(r"\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(prim|cons): ([A-Z][A-Z ]*?[A-Z])\s*(?:\[HEX DUMP\])?(?::(.*))?$", l)
        if m:
            out.append((int(m.group(2)), int(m.group(4)), m.group(6).strip(), (m.group(7) or "").strip()))
    return out


code, version = ossl(["version"])
dire("Confrontation des vecteurs CT-5 requetes/ par %s" % version.strip())
dire("Entrées : requetes/requetes.json, requetes/refusees.json, requetes/*.tsq, reponses/granted-requete-point-k2.der (jeton de CT-1 §11.2), ../ct-6/rfc3161/cles/{ac-test,tsa-test}.pem")
dire("")

# ---------------------------------------------------------------------------
dire("== 1. Requêtes TimeStampReq (EX-5.1) : openssl ts -query -in -text")
for cas in REQUETES["cases"]:
    e, i = cas["expected"], cas["input"]
    fichier = "requetes/" + e["file"]
    octets = open(fichier, "rb").read()
    dire("-- %s (%s)" % (cas["id"], fichier))
    comparer("SHA-256 du fichier", e["sha256"], sha256_ossl(octets))
    comparer("taille", e["size"], len(octets))
    comparer("octets du fichier = der", e["der"], "0x" + octets.hex())
    code, s = ossl(["ts", "-query", "-in", fichier, "-text"])
    comparer("openssl ts -query -text : code de retour", 0, code)
    c = champs_query(s)
    comparer("Version", 1, c["version"])
    comparer("Hash Algorithm", "sha256", c["algorithme"])
    comparer("Message data (32 octets)", i["digest"], c["condense"])
    comparer("Policy OID", i["policy_oid"], c["politique"])
    comparer("Nonce", e["nonce"], c["nonce"])
    comparer("Certificate required", i["cert_req"], c["cert_req"])
    code, s = ossl(["asn1parse", "-inform", "DER", "-in", fichier])
    el = elements_asn1(s)
    types = [t for _, _, t, _ in el]
    attendus = ["SEQUENCE", "INTEGER", "SEQUENCE", "SEQUENCE", "OBJECT", "NULL", "OCTET STRING"] + (["OBJECT"] if i["policy_oid"] else []) + ["INTEGER", "BOOLEAN"]
    comparer("openssl asn1parse : suite des éléments (NULL explicite dans l'AlgorithmIdentifier)", attendus, types)
    nonce_el = [x for x in el if x[0] == 1 and x[2] == "INTEGER"][-1]
    bit_haut = int(e["nonce"], 16) >> 63 == 1
    comparer("openssl asn1parse : INTEGER du nonce de %d octets (%s)" % (9 if bit_haut else 8, "00 de tête, bit haut à 1" if bit_haut else "bit haut à 0"), 9 if bit_haut else 8, nonce_el[1])
    comparer("openssl asn1parse : valeur du nonce", e["nonce"][2:].upper().lstrip("0"), nonce_el[3].lstrip("0"))
    if i["policy_oid"]:
        oid_el = [x for x in el if x[0] == 1 and x[2] == "OBJECT"][0]
        comparer("openssl asn1parse : reqPolicy", i["policy_oid"], oid_el[3])
    comparer("openssl asn1parse : BOOLEAN certReq", "255", [x for x in el if x[2] == "BOOLEAN"][0][3])
dire("")

# ---------------------------------------------------------------------------
dire("== 2. Constructions refusées (AN-5, AN-6) : ce qu'openssl en dit")
for cas in REFUSEES["cases"]:
    dire("-- %s (règle %s : %s)" % (cas["id"], cas["expected"]["rule"], cas["expected"]["message"]))
    if "der" in cas["input"]:
        chemin = os.path.join(TRAVAIL, cas["id"] + ".tsq")
        open(chemin, "wb").write(bytes.fromhex(cas["input"]["der"][2:]))
        code, s = ossl(["ts", "-query", "-in", chemin, "-text"])
        dire("  openssl ts -query -text sur l'encodage non minimal : code %d%s" % (code, (" : " + "; ".join(erreurs(s))) if code else " (openssl relit le nonce sans refuser le zéro de tête : la règle d'encodage minimal est celle de CT-5, hors outil)"))
        code, s = ossl(["asn1parse", "-inform", "DER", "-in", chemin])
        nonce_el = [x for x in elements_asn1(s) if x[0] == 1 and x[2] == "INTEGER"][-1]
        comparer("openssl asn1parse : INTEGER du nonce de 9 octets pour une valeur à bit haut nul (encodage non minimal relevé)", 9, nonce_el[1])
    else:
        dire("  la référence refuse la construction avant tout encodage ; aucun octet à confronter (sans objet)")
dire("")

# ---------------------------------------------------------------------------
dire("== 3. Le jeton de CT-1 §11.2 répond à la requête d'EX-5.1 (openssl ts -verify -queryfile -token_in)")
jeton = [c for c in REPONSES["cases"] if c["id"] == "granted-requete-point-k2"][0]
der = "reponses/" + jeton["expected"]["token"]
comparer("SHA-256 de %s (jeton de CT-1 §11.2)" % der, jeton["expected"]["token_sha256"], sha256_ossl(open(der, "rb").read()))
code, s = ossl(["ts", "-verify", "-queryfile", "requetes/requete-point-k2.tsq", "-token_in", "-in", der] + CA)
comparer("openssl ts -verify -queryfile requetes/requete-point-k2.tsq -token_in -in %s" % der, "Verification: OK", "Verification: OK" if "Verification: OK" in s else "Verification: FAILED (" + "; ".join(erreurs(s)) + ")")
code, s = ossl(["ts", "-verify", "-digest", "6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "-token_in", "-in", der] + CA)
comparer("openssl ts -verify -digest <checkpointHash K2> -token_in", "Verification: OK", "Verification: OK" if "Verification: OK" in s else "Verification: FAILED (" + "; ".join(erreurs(s)) + ")")
dire("")

# ---------------------------------------------------------------------------
dire("== 4. Requête produite par openssl lui-même (EX-8.6, A.8)")
code, q = ossl_octets(["ts", "-query", "-digest", "6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "-sha256", "-cert", "-no_nonce"])
comparer("openssl ts -query -digest … -sha256 -cert -no_nonce : taille (59 octets sans nonce)", 59, len(q))
code, s = ossl(["asn1parse", "-inform", "DER"], entree=q)
comparer("openssl asn1parse de cette requête : mêmes éléments que CT-5 sans le nonce", ["SEQUENCE", "INTEGER", "SEQUENCE", "SEQUENCE", "OBJECT", "NULL", "OCTET STRING", "BOOLEAN"], [t for _, _, t, _ in elements_asn1(s)])
dire("")

dire("Discordances au total : %d" % len(DISCORDANCES))
for d in DISCORDANCES:
    dire("  - " + d)
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
