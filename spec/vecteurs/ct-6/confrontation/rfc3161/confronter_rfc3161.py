#!/usr/bin/env python3
# Confrontation des vecteurs CT-6 rfc3161/ par OpenSSL (CT-6, annexe A.8).
#
# Tout ce qui touche au DER, aux certificats, aux CRL, aux empreintes et aux
# signatures est fait par l'exécutable openssl (ts, cms, asn1parse, x509, crl,
# pkey, pkcs8, pkcs7, verify, dgst) ; ce programme ne fait que lancer openssl, lire
# ses sorties texte et les comparer à rfc3161/attendu.json. Il n'emploie aucun
# code du dépôt.
#
# Usage : python3 -I confronter_rfc3161.py <répertoire spec/vecteurs/ct-6> <répertoire de travail vide>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

if len(sys.argv) != 3:
    print("usage : confronter_rfc3161.py <spec/vecteurs/ct-6> <répertoire de travail>", file=sys.stderr)
    sys.exit(2)

RACINE = os.path.abspath(sys.argv[1])
TRAVAIL = os.path.abspath(sys.argv[2])
R = os.path.join(RACINE, "rfc3161")
os.makedirs(TRAVAIL, exist_ok=True)
os.chdir(R)  # chemins relatifs dans les commandes et la sortie

ATTENDU = json.load(open("attendu.json", encoding="utf-8"))
ANCRES = {}
for nom in os.listdir(os.path.join(RACINE, "ancres")):
    ANCRES["ancres/" + nom] = json.load(open(os.path.join(RACINE, "ancres", nom), encoding="utf-8"))

DISCORDANCES = []
SORTIE = []


def dire(*morceaux):
    SORTIE.append(" ".join(str(m) for m in morceaux))


def ossl(args, entree=None):
    """Lance openssl ; rend (code, sortie normalisée). Le préfixe de fil
    d'exécution des messages d'erreur (hexadécimal variable) est retiré."""
    r = subprocess.run(["openssl"] + args, input=entree, capture_output=True)
    texte = (r.stdout + r.stderr).decode("utf-8", "replace")
    lignes = []
    for l in texte.splitlines():
        if l.startswith("Using configuration from"):
            continue
        l = re.sub(r"^[0-9A-F]{8,}:error:", "error:", l)
        l = l.replace(TRAVAIL + os.sep, "<travail>/")  # aucun chemin local dans la sortie
        lignes.append(l)
    return r.returncode, "\n".join(lignes)


def court(sortie):
    """Résultat d'openssl verify : « OK » ou la raison du premier échec."""
    if sortie.strip().endswith(": OK"):
        return "OK"
    m = re.findall(r"error \d+ at \d+ depth lookup: (.*)", sortie)
    return m[0] if m else sortie.strip().splitlines()[-1]


def ossl_octets(args, entree=None):
    r = subprocess.run(["openssl"] + args, input=entree, capture_output=True)
    return r.returncode, r.stdout


def sha256_ossl(octets):
    code, sortie = ossl(["dgst", "-sha256", "-r"], entree=octets)
    assert code == 0, sortie
    return "0x" + sortie.split()[0].lower()


def erreurs(sortie):
    """Raisons d'échec d'openssl, sans le nom de fichier source ni le numéro de ligne."""
    out = []
    for l in sortie.splitlines():
        m = re.match(r"error:[0-9A-F]+:[^:]*:[^:]*:([^:]*):", l)
        if m:
            raison = m.group(1)
            v = re.search(r"Verify error: ?(.*)$", l)
            r = raison + (" (" + v.group(1) + ")" if v else "")
            if r not in out:  # chaque raison une fois, dans l'ordre d'openssl
                out.append(r)
    return out


def iso(texte_openssl):
    # « Nov  5 10:00:05 2026 GMT », fraction éventuelle « 10:00:05.5 »
    m = re.match(r"(\w{3})\s+(\d+) (\d\d):(\d\d):(\d\d)(\.\d+)? (\d{4}) GMT", texte_openssl.strip())
    mois = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split().index(m.group(1)) + 1
    frac = (m.group(6) or "").rstrip("0").rstrip(".")
    return "%s-%02d-%02dT%s:%s:%s%sZ" % (m.group(7), mois, int(m.group(2)), m.group(3), m.group(4), m.group(5), frac)


def unix(iso_z):
    return int(datetime.strptime(iso_z[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())


def lire_tst(jeton):
    """Champs du TSTInfo tels qu'openssl ts -reply -token_in -text les imprime."""
    code, s = ossl(["ts", "-reply", "-in", jeton, "-token_in", "-text"])
    t = {"code": code, "erreurs": erreurs(s)}
    if code != 0:
        return t
    t["version"] = re.search(r"^Version: (.*)$", s, re.M).group(1)
    t["politique"] = re.search(r"^Policy OID: (.*)$", s, re.M).group(1)
    t["algo_empreinte"] = re.search(r"^Hash Algorithm: (.*)$", s, re.M).group(1)
    bloc = re.search(r"^Message data:\n((?:\s+[0-9a-f]{4} - .*\n)+)", s, re.M).group(1)
    octets = ""
    for l in bloc.splitlines():
        octets += "".join(re.findall(r"\b[0-9a-f]{2}\b", l.split(" - ", 1)[1].split("  ")[0].replace("-", " ")))
    t["empreinte"] = "0x" + octets
    t["numero"] = re.search(r"^Serial number: (.*)$", s, re.M).group(1).lower()
    t["gen_time"] = iso(re.search(r"^Time stamp: (.*)$", s, re.M).group(1))
    t["precision"] = re.search(r"^Accuracy: (.*)$", s, re.M).group(1)
    t["ordre"] = re.search(r"^Ordering: (.*)$", s, re.M).group(1)
    t["nonce"] = re.search(r"^Nonce: (.*)$", s, re.M).group(1).lower()
    t["tsa"] = re.search(r"^TSA: (.*)$", s, re.M).group(1)
    ext = s.split("\nExtensions:", 1)[1].strip() if "\nExtensions:" in s else ""
    t["extensions"] = ext
    t["extensions_critiques"] = re.findall(r"^(\S+): critical$", ext, re.M)
    return t


def lire_asn1(jeton):
    """Lecture DER stricte de tout le fichier (asn1parse s'arrête sur un octet de trop)
    et extraction par openssl des octets de eContent, de message-digest et des certHash ESS."""
    code, s = ossl(["asn1parse", "-inform", "DER", "-in", jeton])
    a = {"code": code, "erreur_codage": "Error in encoding" in s}
    lignes = s.splitlines()
    for i, l in enumerate(lignes):
        if ":id-smime-ct-TSTInfo" in l and "econtent_off" not in a:
            # eContentType, puis [0] EXPLICIT, puis l'OCTET STRING eContent
            for l2 in lignes[i + 1:i + 4]:
                m = re.match(r"\s*(\d+):d=\d+\s+hl=\d+ l=\s*\d+ prim: OCTET STRING", l2)
                if m:
                    a["econtent_off"] = int(m.group(1))
                    break
        if l.rstrip().endswith(":messageDigest") and "message_digest" not in a:
            for l2 in lignes[i + 1:i + 4]:
                m = re.search(r"OCTET STRING\s+\[HEX DUMP\]:([0-9A-F]+)", l2)
                if m:
                    a["message_digest"] = "0x" + m.group(1).lower()
                    break
        if l.rstrip().endswith(":contentType") and "content_type" not in a:
            for l2 in lignes[i + 1:i + 4]:
                m = re.search(r"OBJECT\s+:(\S+)", l2)
                if m:
                    a["content_type"] = m.group(1)
                    break
        for nom, cle in ((":id-smime-aa-signingCertificateV2", "ess_v2"), (":id-smime-aa-signingCertificate", "ess_v1")):
            if l.rstrip().endswith(nom) and cle not in a:
                for l2 in lignes[i + 1:i + 8]:
                    m = re.search(r"OCTET STRING\s+\[HEX DUMP\]:([0-9A-F]+)", l2)
                    if m:
                        a[cle] = "0x" + m.group(1).lower()
                        break
    if "econtent_off" in a:
        tst = os.path.join(TRAVAIL, "tst-" + os.path.basename(jeton))
        c2, s2 = ossl(["asn1parse", "-inform", "DER", "-in", jeton, "-strparse", str(a["econtent_off"]), "-noout", "-out", tst])
        a["econtent_sha256"] = sha256_ossl(open(tst, "rb").read()) if c2 == 0 else None
        if c2 == 0:
            ecrire("tst-courant.der", open(tst, "rb").read())
    return a


def lire_tst_asn1(a):
    """Champs de TSTInfo lus par openssl asn1parse des octets de eContent (extraits par lire_asn1),
    quand openssl ts refuse le jeton : mêmes clés et mêmes formes que lire_tst."""
    tst = os.path.join(TRAVAIL, "tst-courant.der")
    lignes = ossl(["asn1parse", "-inform", "DER", "-in", tst])[1].splitlines()
    d1 = [l for l in lignes if re.search(r"d=1 ", l)]
    val = lambda l: l.rsplit(":", 1)[1].strip()
    t = {"version": str(int(val(d1[0]), 16)), "politique": val(d1[1])}
    algo = next(l for l in lignes if "d=3 " in l and "OBJECT" in l)
    t["algo_empreinte"] = val(algo)
    t["empreinte"] = "0x" + re.search(r"\[HEX DUMP\]:([0-9A-F]+)", next(l for l in lignes if "d=2 " in l and "OCTET STRING" in l)).group(1).lower()
    t["numero"] = "0x" + val(d1[3]).lower()
    g = re.match(r"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z", val(next(l for l in d1 if "GENERALIZEDTIME" in l)))
    t["gen_time"] = "%s-%s-%sT%s:%s:%s%sZ" % (g.group(1), g.group(2), g.group(3), g.group(4), g.group(5), g.group(6), g.group(7) or "")
    # accuracy : SEQUENCE { seconds INTEGER } ; nonce : INTEGER de premier niveau après accuracy
    i = next(k for k, l in enumerate(lignes) if "d=1 " in l and "GENERALIZEDTIME" in l)
    sec = int(val(lignes[i + 2]), 16) if "SEQUENCE" in lignes[i + 1] else None
    t["precision"] = "0x%02X seconds, unspecified millis, unspecified micros" % sec if sec is not None else "unspecified"
    apres = [l for l in lignes[i + 1:] if "d=1 " in l]
    t["nonce"] = next(("0x" + val(l).lower() for l in apres if "prim: INTEGER" in l), None)
    t["ordre"] = "no"
    t["tsa"] = None if not any("cont [ 0 ]" in l and "d=1 " in l for l in lignes) else "présent"
    t["extensions"] = ""
    t["extensions_critiques"] = []
    return t


def lire_cms(jeton):
    code, s = ossl(["cms", "-cmsout", "-print", "-inform", "DER", "-in", jeton, "-noout"])
    c = {"code": code, "erreurs": erreurs(s)}
    if code != 0:
        return c
    c["version_signeddata"] = re.search(r"d\.signedData: \n\s+version: (\d+)", s).group(1)
    si = s.split("signerInfos:", 1)[1]
    c["nb_signerinfos"] = len(re.findall(r"^\s{8}version: \d+$", si, re.M))
    c["version_signerinfo"] = re.search(r"^\s{8}version: (\d+)$", si, re.M).group(1)
    c["sid"] = "issuerAndSerialNumber" if "d.issuerAndSerialNumber" in si else "subjectKeyIdentifier"
    c["algo_condensat"] = re.search(r"digestAlgorithm: \n\s+algorithm: (\S+)", si).group(1)
    c["algo_signature"] = re.search(r"signatureAlgorithm: \n\s+algorithm: (\S+)", si).group(1)
    c["econtent_type"] = re.search(r"eContentType: (\S+)", s).group(1)
    return c


def certificats_du_jeton(jeton):
    code, s = ossl(["pkcs7", "-inform", "DER", "-in", jeton, "-print_certs"])
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", s, re.S)
    return pems


def der_de(pem):
    """DER d'un certificat PEM : par openssl x509 ; si openssl refuse de lire le
    certificat (tsa-cn-utf8-invalide.pem), par openssl asn1parse, qui décode le
    PEM sans interpréter le certificat."""
    code, der = ossl_octets(["x509", "-outform", "DER"], entree=pem.encode())
    if code == 0:
        return der
    sortie = os.path.join(TRAVAIL, "certificat-brut.der")
    code, s = ossl(["asn1parse", "-noout", "-out", sortie], entree=pem.encode())
    assert code == 0, s
    return open(sortie, "rb").read()


def x509_lisible(pem):
    """(True, "") si openssl x509 lit le certificat, sinon (False, raisons d'openssl). openssl x509
    ne donne que la raison de son chargeur (« unsupported ») : la raison du décodage est relevée par
    openssl crl2pkcs7 -certfile, qui lit le même PEM par l'autre chargeur d'openssl."""
    code, s = ossl(["x509", "-noout"], entree=pem.encode())
    if code == 0:
        return True, ""
    c2, s2 = ossl(["crl2pkcs7", "-nocrl", "-certfile", ecrire("illisible.pem", pem), "-out", os.path.join(TRAVAIL, "illisible.p7")])
    return False, "; ".join(erreurs(s) + erreurs(s2)) or s.strip().splitlines()[0]


def cle_publique(pem):
    """Clé publique (PEM) d'un certificat, extraite par openssl asn1parse (SubjectPublicKeyInfo,
    profondeur 2 de TBSCertificate) puis openssl pkey : vaut aussi pour un certificat qu'openssl x509 refuse."""
    der = ecrire("certificat.der", der_de(pem))
    lignes = ossl(["asn1parse", "-inform", "DER", "-in", der])[1].splitlines()
    i = next(k for k, l in enumerate(lignes) if l.rstrip().endswith(":rsaEncryption"))
    off = next(int(re.match(r"\s*(\d+):", l).group(1)) for l in reversed(lignes[:i]) if re.search(r"d=2 .*cons: SEQUENCE", l))
    spki = os.path.join(TRAVAIL, "spki.der")
    ossl(["asn1parse", "-inform", "DER", "-in", der, "-strparse", str(off), "-noout", "-out", spki])
    return ossl(["pkey", "-pubin", "-inform", "DER", "-in", spki, "-pubout"])[1]


def default_encode(der):
    """Valeurs DEFAULT encodées (X.690 §11.5, EX-9.21) relevées par openssl asn1parse : un BOOLEAN
    de valeur FALSE dans la structure (critical d'une extension, ordering de TSTInfo) ou dans la
    valeur d'une extension (cA de basicConstraints, lue par asn1parse -strparse). Rend la liste
    des emplacements relevés."""
    p = ecrire("default.der", der)
    lignes = ossl(["asn1parse", "-inform", "DER", "-in", p])[1].splitlines()
    ligne = re.compile(r"\s*(\d+):d=(\d+)\s+hl=\d+ l=\s*\d+ (prim|cons): (\S+(?: \S+)?)\s*(.*)$")
    lu = [ligne.match(l) for l in lignes]
    valeur = lambda x: x.group(5).lstrip(":").strip()
    trouves = []
    for k, m in enumerate(lu):
        if not m or m.group(3) != "prim":
            continue
        if m.group(4) == "BOOLEAN" and valeur(m) == "0":
            prec = lu[k - 1] if k else None
            trouves.append("BOOLEAN :0 après %s" % ((valeur(prec) or prec.group(4)) if prec else "rien"))
        # valeur d'une extension : OCTET STRING précédé, au même niveau, de l'OID (et du BOOLEAN critical)
        if m.group(4) == "OCTET STRING":
            oid = next((x for x in (lu[k - 1] if k else None, lu[k - 2] if k > 1 else None)
                        if x and x.group(4) == "OBJECT" and x.group(2) == m.group(2)), None)
            if oid is None:
                continue
            v = os.path.join(TRAVAIL, "valeur-extension.der")
            c, _ = ossl(["asn1parse", "-inform", "DER", "-in", p, "-strparse", m.group(1), "-noout", "-out", v])
            if c != 0:
                continue
            for l2 in ossl(["asn1parse", "-inform", "DER", "-in", v])[1].splitlines():
                if re.search(r"prim: BOOLEAN\s+:0$", l2):
                    trouves.append("BOOLEAN :0 dans la valeur de l'extension %s" % valeur(oid))
    return trouves


def sujet_compat(pem):
    """Sujet imprimé par openssl x509 -subject -nameopt compat (« /C=CH/O=…/CN=… »)."""
    return ossl(["x509", "-noout", "-subject", "-nameopt", "compat"], entree=pem.encode())[1].strip().split("=", 1)[1]


def x509_texte(pem):
    return ossl(["x509", "-noout", "-text", "-nameopt", "compat"], entree=pem.encode())[1]


def ecrire(nom, contenu):
    p = os.path.join(TRAVAIL, nom)
    with open(p, "w" if isinstance(contenu, str) else "wb") as f:
        f.write(contenu)
    return p


def comparer(libelle, valeur_vecteur, valeur_outil):
    ok = valeur_vecteur == valeur_outil
    dire("  %s : vecteur %s ; openssl %s : %s" % (libelle, valeur_vecteur, valeur_outil, "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, openssl %s" % (libelle, valeur_vecteur, valeur_outil))
    return ok


# ---------------------------------------------------------------------------
dire("Confrontation des vecteurs CT-6 rfc3161/ par", ossl(["version"])[1].strip())
dire("Entrées : rfc3161/attendu.json, rfc3161/{cles,crl,jetons}/, ancres/*.json")
dire("")

# 1. Clés, certificats et CRL de test
dire("== 1. Clés, certificats et CRL de test (EX-A.4, EX-A.5)")
for fichier, attendu in ATTENDU["keys"]["files"].items():
    if fichier.endswith(".cle.pem"):
        # openssl pkey -outform DER écrit la forme propre au type (PKCS #1) : PKCS #8 par openssl pkcs8 -topk8
        code, der = ossl_octets(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-in", fichier])
        comparer(fichier + " SHA-256 du PKCS #8 DER (openssl pkcs8 -topk8)", attendu, sha256_ossl(der))
        bits = re.search(r"\((\d+) bit", ossl(["pkey", "-in", fichier, "-noout", "-text"])[1]).group(1)
        comparer(fichier + " taille de clé RSA", "3072", bits)
    else:
        pem = open(fichier).read()
        lisible, raison = x509_lisible(pem)
        comparer(fichier + " SHA-256 du DER (%s)" % ("openssl x509" if lisible else "openssl asn1parse"), attendu, sha256_ossl(der_de(pem)))
        if not lisible:
            dire("  %s : openssl x509 refuse de lire le certificat : %s" % (fichier, raison))
        defauts = default_encode(der_de(pem))
        if defauts:
            dire("  %s : valeur DEFAULT encodée relevée par openssl asn1parse (X.690 §11.5) : %s" % (fichier, "; ".join(defauts)))
# Clé publique de chaque certificat (SubjectPublicKeyInfo extrait par asn1parse) égale à celle de sa clé
for fichier in ATTENDU["keys"]["files"]:
    if fichier.endswith(".cle.pem"):
        continue
    cle = "cles/ac-test.cle.pem" if fichier == "cles/ac-test.pem" else "cles/tsa-test.cle.pem"
    comparer(fichier + " clé publique = celle de " + cle, True, cle_publique(open(fichier).read()) == ossl(["pkey", "-in", cle, "-pubout"])[1])
# Chemin de chaque certificat sous ac-test.pem à 2026-11-05T10:00:05Z, relevé ; comparé pour tsa-test.pem
for fichier in ATTENDU["keys"]["files"]:
    if fichier.endswith(".cle.pem") or fichier == "cles/ac-test.pem":
        continue
    code, s = ossl(["verify", "-attime", str(unix("2026-11-05T10:00:05Z")), "-CAfile", "cles/ac-test.pem", fichier])
    if fichier == "cles/tsa-test.pem":
        comparer("openssl verify tsa-test.pem sous ac-test.pem à 2026-11-05T10:00:05Z", "cles/tsa-test.pem: OK", s.strip())
    else:
        releve = court(s) if code == 0 or "depth lookup" in s else ("; ".join(erreurs(s)) or s.strip().splitlines()[0])
        dire("  openssl verify %s sous ac-test.pem à 2026-11-05T10:00:05Z : %s" % (fichier, releve))
for fichier, attendu in ATTENDU["crls"].items():
    pem = open(fichier, "rb").read()
    code, der = ossl_octets(["crl", "-in", fichier, "-outform", "DER"])
    h_pem, h_der = sha256_ossl(pem), sha256_ossl(der)
    forme = "DER" if h_der == attendu else ("PEM" if h_pem == attendu else None)
    comparer(fichier + " SHA-256 (du DER ou du fichier PEM)", attendu, h_der if forme != "PEM" else h_pem)
    code, s = ossl(["crl", "-in", fichier, "-noout", "-text", "-CAfile", "cles/ac-test.pem"])
    comparer(fichier + " signature de l'AC (openssl crl -CAfile)", "verify OK", "verify OK" if re.search(r"^verify OK$", s, re.M) else "absent")
    comparer(fichier + " thisUpdate", "2026-11-06T00:00:00Z", iso(re.search(r"Last Update: (.*)", s).group(1)))
    revoques = re.findall(r"Serial Number: (\w+)\s+Revocation Date: ([^\n]+)(?:\s+CRL entry extensions:\s+X509v3 CRL Reason Code: \s+([^\n]+))?", s)
    if "revoquee" in fichier:
        comparer(fichier + " entrées révoquées (numéro, date, raison)", [("02", "2026-11-05T12:00:00Z", "Key Compromise")],
                 [(n, iso(d), r.strip()) for n, d, r in revoques])
    else:
        comparer(fichier + " entrées révoquées", [], revoques)
dire("")

# 2. Lecture et vérification de chaque jeton
dire("== 2. Chaque jeton : lecture par openssl et vérification à genTime (EX-A.5)")
PH = {}
for m in (1, 2, 3):
    PH[m] = next(t["period_hash"] for t in ATTENDU["tokens"] if t["file"] == "jetons/periode-%d.der" % m)
NONCE = {}
for m in (1, 2, 3):
    NONCE[m] = sha256_ossl(("noortrace/vecteurs/v0/ct-6/nonce-tsa/periode-%d" % m).encode())[:18]
# jetons des points de contrôle (révision 0.2, EX-A.13) : étiquette propre
NONCE_POINT = sha256_ossl(b"noortrace/vecteurs/v0/ct-6/nonce-tsa/point-de-controle/periode-1")[:18]

LECTURES = {}
for tok in ATTENDU["tokens"]:
    f = tok["file"]
    dire("-- %s (cible : %s ; altération : %s)" % (f, tok["target"] or "aucune", tok["alteration"] or "aucune"))
    comparer("SHA-256 du fichier", tok["sha256"], sha256_ossl(open(f, "rb").read()))
    a = lire_asn1(f)
    t = lire_tst(f)
    c = lire_cms(f)
    certs = certificats_du_jeton(f)
    LECTURES[f] = (t, a, c, certs)
    dire("  openssl ts -reply -token_in -text : code %d" % t["code"])
    if t["code"] != 0:
        # openssl ne lit pas le jeton (un certificat illisible) : TSTInfo est lu par asn1parse de eContent
        dire("  openssl ts -text refuse le jeton : %s ; TSTInfo lu par openssl asn1parse -strparse" % "; ".join(t["erreurs"]))
        t.update(lire_tst_asn1(a))
    comparer("empreinte (messageImprint)", tok["period_hash"], t["empreinte"])
    comparer("algorithme de l'empreinte", "sha256", t["algo_empreinte"])
    comparer("genTime", tok["gen_time"], t["gen_time"])
    comparer("serialNumber", "0x%x" % int(tok["serial_number"], 16), "0x%x" % int(t["numero"], 16) if t["numero"] else t["numero"])
    comparer("version de TSTInfo", "1", t["version"])
    comparer("politique (EX-A.5)", "1.3.6.1.4.1.99999.1.1", t["politique"])
    comparer("précision (EX-A.5 : 1 s)", "0x01 seconds, unspecified millis, unspecified micros", t["precision"])
    if tok.get("checkpoint"):
        comparer("nonce = 8 premiers octets de SHA-256(« …/nonce-tsa/point-de-controle/periode-1 ») (jeton d'un point, EX-A.13)", NONCE_POINT, t["nonce"])
    else:
        n = int(re.search(r"periode-(\d)", f).group(1)) if "periode-" in f else 1
        comparer("nonce = 8 premiers octets de SHA-256(« …/nonce-tsa/periode-%d »)" % n, NONCE[n], t["nonce"])
    if certs:
        comparer("tsa (directoryName) = sujet du certificat du jeton", "DirName:" + sujet_compat(certs[0]), t["tsa"])
    else:
        dire("  tsa : %s ; aucun certificat lu par openssl pkcs7 -print_certs" % (t["tsa"] or "absent"))
    dire("  extensions de TSTInfo lues par openssl : %s" % (t["extensions"].replace("\n", " | ") or "aucune"))
    if c["code"] == 0:
        dire("  openssl cms -cmsout -print : SignedData v%s, %d SignerInfo v%s (%s), eContentType %s, digestAlgorithm %s, signatureAlgorithm %s"
             % (c["version_signeddata"], c["nb_signerinfos"], c["version_signerinfo"], c["sid"], c["econtent_type"], c["algo_condensat"], c["algo_signature"]))
    else:
        dire("  openssl cms -cmsout -print : code %d : %s" % (c["code"], "; ".join(c["erreurs"])))
    dire("  openssl asn1parse (tout le fichier) : code %d%s" % (a["code"], ", « Error in encoding »" if a["erreur_codage"] else ""))
    dire("  certificats du jeton (openssl pkcs7 -print_certs) : %d, SHA-256 %s"
         % (len(certs), ", ".join(sha256_ossl(der_de(p)) for p in certs) or "aucun"))
    at = unix(t["gen_time"])
    code, s = ossl(["ts", "-verify", "-digest", tok["period_hash"][2:], "-in", f, "-token_in", "-CAfile", "cles/ac-test.pem", "-attime", str(at)])
    tok["_ts_verify"] = s
    res = "Verification: OK" if "Verification: OK" in s else "Verification: FAILED : " + "; ".join(erreurs(s))
    dire("  openssl ts -verify -digest <period_hash> -in %s -token_in -CAfile cles/ac-test.pem -attime %d : %s" % (f, at, res))
    pr = tok["openssl_ts_verify"]["presumed_result"]
    if pr is None:
        dire("  résultat non présumé par attendu.json ; relevé ci-dessus")
    elif pr.startswith("Verification: OK"):
        # « Verification: OK », suivi éventuellement d'une explication entre parenthèses
        comparer("résultat présumé par attendu.json (« %s »)" % pr, "Verification: OK", "Verification: OK" if "Verification: OK" in s else res)
    else:
        # raisons d'échec présumées, séparées par « / », sans l'explication entre parenthèses
        motifs = [{"refus de l'extendedKeyUsage non critique": "unsuitable certificate purpose"}.get(m.strip(), m.strip())
                  for m in re.sub(r"\s*\(.*\)$", "", pr).split(" / ")]
        comparer("résultat présumé par attendu.json (« %s »)" % pr, True, all(m in s for m in motifs) and "Verification: FAILED" in s)
    code, s = ossl(["cms", "-verify", "-inform", "DER", "-in", f, "-binary", "-CAfile", "cles/ac-test.pem", "-attime", str(at),
                    "-purpose", "timestampsign", "-out", os.path.join(TRAVAIL, "contenu.der")])
    dire("  openssl cms -verify -binary -CAfile cles/ac-test.pem -attime %d -purpose timestampsign : %s"
         % (at, "CMS Verification successful" if code == 0 else "code %d : %s" % (code, "; ".join(erreurs(s)))))
    tok["_cms_verify"] = (code, s)

autre = ATTENDU["openssl_ts_verify_other_period"]
code, s = ossl(["ts", "-verify", "-digest", PH[1][2:], "-in", "jetons/periode-2.der", "-token_in", "-CAfile", "cles/ac-test.pem",
                "-attime", str(unix("2026-11-05T11:00:05Z"))])
dire("-- jeton de la période 2 contre periodHash de la période 1 : %s" % ("; ".join(erreurs(s)) or "Verification: OK"))
comparer("résultat présumé par attendu.json (« %s »)" % autre["presumed_result"], True, autre["presumed_result"] in s)
dire("")


# 3. Vérification par vérification, pour chaque cas de attendu.json
def statut_openssl(cas):
    """Statut de chaque vérification T- tel qu'openssl permet de l'établir, avec le moyen employé.
    Valeurs : « reussi », « echoue », « hors_outil » (openssl ne fait pas cette vérification),
    ou None (sans ancre, openssl ne peut rien établir)."""
    f = cas["token"]
    t, a, c, certs = LECTURES[f]
    ancres = ANCRES.get(cas["anchors"]) if cas["anchors"] else None
    ph = cas["dossier_period_hash"]
    at = unix(t["gen_time"])
    res = {}
    # T-1 : structure ; asn1parse lit tout le fichier en DER, ts/cms lisent la structure, x509 lit
    # chaque certificat ; aucune valeur DEFAULT encodée (X.690 §11.5) dans TSTInfo ni dans les
    # certificats, relevée sur la sortie d'asn1parse (openssl lit ces valeurs sans les refuser)
    lisibles = t["code"] == 0 and c["code"] == 0 and all(x509_lisible(p)[0] for p in certs)
    if not lisibles:
        raison = "; ".join(t["erreurs"] or c["erreurs"]) or "certificat illisible"
        res["T-1"] = ("echoue", "openssl ts -text, cms -print et pkcs7 -print_certs refusent le jeton : %s" % raison)
        # le jeton n'est pas lu : openssl ne peut établir aucune autre vérification
        for i in ("T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10"):
            res[i] = (None, "jeton illisible par openssl")
        res["T-11"] = ("hors_outil", "statut qualifié déclaré par le réviseur : openssl ne le connaît pas")
        return res
    defauts = default_encode(open(os.path.join(TRAVAIL, "tst-" + os.path.basename(f)), "rb").read())
    for p in certs:
        defauts += default_encode(der_de(p))
    t1 = a["code"] == 0 and not a["erreur_codage"] and c["version_signeddata"] == "3" and not defauts \
        and c["nb_signerinfos"] == 1 and c["econtent_type"] == "id-smime-ct-TSTInfo" and t["version"] == "1" and len(certs) <= 16
    res["T-1"] = ("reussi" if t1 else "echoue", "asn1parse du fichier entier (code %d%s) ; SignedData v%s, %d SignerInfo, TSTInfo v%s ; valeur DEFAULT encodée : %s"
                  % (a["code"], ", Error in encoding" if a["erreur_codage"] else "", c["version_signeddata"], c["nb_signerinfos"], t["version"],
                     "; ".join(defauts) or "aucune"))
    # T-2 : empreinte
    t2 = t["algo_empreinte"] == "sha256" and t["empreinte"] == ph
    code, s = ossl(["ts", "-verify", "-digest", ph[2:], "-in", f, "-token_in", "-CAfile", "cles/ac-test.pem", "-attime", str(at)])
    res["T-2"] = ("reussi" if t2 else "echoue", "messageImprint lu par ts -text (%s, %s…) ; ts -verify -digest <periodHash du dossier> : %s"
                  % (t["algo_empreinte"], t["empreinte"][:18], "message imprint mismatch" if "message imprint mismatch" in s else "pas de message imprint mismatch"))
    # T-3 : attributs signés
    code_cms, s_cms = next(x["_cms_verify"] for x in ATTENDU["tokens"] if x["file"] == f)
    # condensat de eContent par la fonction de SignerInfo.digestAlgorithm, calculé par openssl dgst
    tst = open(os.path.join(TRAVAIL, "tst-" + os.path.basename(f)), "rb").read()
    code_d, s_d = ossl(["dgst", "-" + c["algo_condensat"], "-r"], entree=tst)
    condensat = "0x" + s_d.split()[0].lower()
    md_ok = a.get("message_digest") == condensat
    t3 = md_ok and a.get("content_type") == "id-smime-ct-TSTInfo" and ("ess_v1" in a or "ess_v2" in a) \
        and "content verify error" not in s_cms
    res["T-3"] = ("reussi" if t3 else "echoue", "message-digest %s… ; %s de eContent (asn1parse -strparse, dgst) %s… ; cms -verify : %s"
                  % ((a.get("message_digest") or "?")[:18], c["algo_condensat"], condensat[:18],
                     "content verify error" if "content verify error" in s_cms else "pas d'erreur de contenu"))
    # T-4 : certificat signataire (ESS) ; ts -verify contrôle signingCertificate(V2)
    s_ts = next(x["_ts_verify"] for x in ATTENDU["tokens"] if x["file"] == f)
    h_cert = sha256_ossl(der_de(certs[0])) if certs else None
    t4 = "ess cert id not found" not in s_ts and a.get("ess_v2") == h_cert
    res["T-4"] = ("reussi" if t4 else "echoue", "certHash ESSCertIDv2 %s… ; SHA-256 du certificat du jeton %s… ; ts -verify : %s"
                  % ((a.get("ess_v2") or "?")[:18], (h_cert or "?")[:18], "ess cert id not found" if "ess cert id not found" in s_ts else "ESS accepté"))
    # T-5 : algorithmes ; openssl n'a pas de liste d'algorithmes admis (il accepte SHA-1)
    bits = re.search(r"Public-Key: \((\d+) bit\)", x509_texte(certs[0])).group(1) if certs else "?"
    res["T-5"] = ("hors_outil", "valeurs lues par openssl : digestAlgorithm %s, signatureAlgorithm %s, clé RSA %s bits ; "
                  "openssl ts -verify %s ces algorithmes" % (c["algo_condensat"], c["algo_signature"], bits,
                                                              "accepte" if "Verification: OK" in s_ts else "ne se prononce pas sur"))
    # T-6 : signature
    # signature des seuls signedAttrs : -no_content_verify écarte le contrôle de message-digest (T-3),
    # -noverify celui du certificat (T-7, T-8)
    code_s, s_s = ossl(["cms", "-verify", "-inform", "DER", "-in", f, "-binary", "-noverify", "-no_content_verify",
                        "-out", os.path.join(TRAVAIL, "contenu.der")])
    sig_ko = code_s != 0
    res["T-6"] = ("echoue" if sig_ko else "reussi", "cms -verify -noverify -no_content_verify : %s"
                  % ("; ".join(erreurs(s_s)) if sig_ko else "CMS Verification successful (signature valide)"))
    # T-7 : chemin à genTime jusqu'à une autorité de l'ancre, et politique admise. -partial_chain : une
    # autorité peut être un certificat non autosigné (unité épinglée, EX-9.13), qu'openssl n'admet
    # comme ancre de confiance qu'avec cette option.
    if ancres is None:
        res["T-7"] = (None, "sans fichier d'ancres, aucun -CAfile : openssl ne peut établir aucun chemin")
    else:
        pem_s = ecrire("signataire.pem", certs[0])
        cafile = ecrire("ancre.pem", "".join(x["certificate"] for x in ancres["tsa_authorities"]))
        code, s = ossl(["verify", "-partial_chain", "-attime", str(at), "-CAfile", cafile, pem_s])
        pol = ancres["tsa_authorities"][0]["accepted_policies"]
        q = os.path.join(TRAVAIL, "requete.tsq")
        ossl(["ts", "-query", "-digest", t["empreinte"][2:], "-sha256", "-tspolicy", pol[0], "-no_nonce", "-out", q])
        code_q, s_q = ossl(["ts", "-verify", "-queryfile", q, "-in", f, "-token_in", "-CAfile", cafile, "-attime", str(at), "-partial_chain"])
        pol_ok = "policy mismatch" not in s_q
        t7 = code == 0 and s.strip().endswith(": OK") and pol_ok
        res["T-7"] = ("reussi" if t7 else "echoue", "openssl verify -partial_chain -attime genTime -CAfile <autorités de l'ancre> : %s ; ts -verify -queryfile (politique %s) : %s"
                      % (court(s), pol[0],
                         "policy mismatch" if not pol_ok else "politique acceptée"))
    # T-8 : usage horodatage
    cafile = ecrire("ac.pem", open("cles/ac-test.pem").read())
    pem_s = ecrire("signataire.pem", certs[0])
    code, s = ossl(["verify", "-purpose", "timestampsign", "-attime", str(at), "-CAfile", cafile, pem_s])
    t8 = "unsuitable certificate purpose" not in s
    res["T-8"] = ("reussi" if t8 else "echoue", "openssl verify -purpose timestampsign : %s" % ("accepté" if t8 else "unsuitable certificate purpose"))
    # T-9 : contenu de TSTInfo ; openssl lit les extensions mais ts -verify ne refuse pas une extension critique
    sujet = sujet_compat(certs[0])
    t9 = not t["extensions_critiques"] and t["tsa"] in (None, "DirName:" + sujet)
    res["T-9"] = ("reussi" if t9 else "echoue", "extensions critiques lues par ts -text : %s ; tsa absent ou égal au sujet du signataire : %s ; ts -verify : %s"
                  % (t["extensions_critiques"] or "aucune", t["tsa"] in (None, "DirName:" + sujet),
                     "Verification: OK" if "Verification: OK" in s_ts else "échec"))
    # T-10 : révocation ; openssl refuse une CRL postérieure à -attime : vérification à thisUpdate
    if ancres is None:
        res["T-10"] = (None, "sans fichier d'ancres, aucune CRL")
    else:
        # Les CRL de l'ancre ont thisUpdate = 2026-11-06T00:00:00Z, postérieur à genTime : openssl les juge
        # « not yet valid » à genTime ; la révocation du certificat signataire est donc vérifiée par
        # openssl verify -crl_check à thisUpdate (openssl refuse toute révocation, quelle qu'en soit la
        # raison ou la date : il ne départage pas les cas de EX-9.16). EX-9.16 prend la CRL du fichier
        # d'ancres qui vise le certificat d'une autorité (unité épinglée) sans en vérifier la signature ;
        # openssl ne lit une CRL qu'avec le certificat de son émetteur : ac-test.pem, émetteur des
        # certificats et des CRL de test, est donc ajouté au -CAfile.
        cafile = ecrire("ancre-crl.pem", "".join(x["certificate"] for x in ancres["tsa_authorities"]) + open("cles/ac-test.pem").read()
                        + "".join(ancres["revocation"]["crls"]))
        code_g, s_g = ossl(["verify", "-crl_check", "-attime", str(at), "-CAfile", cafile, pem_s])
        at_crl = unix("2026-11-06T00:00:00Z")
        code_c, s_c = ossl(["verify", "-crl_check", "-attime", str(at_crl), "-CAfile", cafile, pem_s])
        revoque = "certificate revoked" in s_c
        ok = code_c == 0 and s_c.strip().endswith(": OK")
        res["T-10"] = ("echoue" if revoque else ("reussi" if ok else "?"),
                       "openssl verify -crl_check du signataire à genTime : %s ; à thisUpdate des CRL (2026-11-06T00:00:00Z) : %s"
                       % (court(s_g), court(s_c)))
    # T-11 : statut qualifié déclaré par l'ancre : openssl ne lit aucune ancre de ce genre
    res["T-11"] = ("hors_outil", "statut qualifié déclaré par le réviseur : openssl ne le connaît pas")
    return res


dire("== 3. Vérification par vérification, cas de attendu.json (statut attendu / statut établi par openssl)")
BILAN = {"concorde": 0, "discordance": 0, "hors_outil": 0, "sans_objet": 0}
for cas in ATTENDU["cases"]:
    dire("-- %s, ancres %s, periodHash du dossier %s…" % (cas["token"], cas["anchors"] or "absentes", cas["dossier_period_hash"][:18]))
    res = statut_openssl(cas)
    for chk in cas["checks"]:
        i = chk["id"]
        att = chk["status"] + ("/" + chk["reason"] if chk["reason"] else "")
        st, moyen = res[i]
        if st == "hors_outil":
            verdict = "hors outil"
            BILAN["hors_outil"] += 1
        elif chk["status"] == "non_execute" or st is None:
            verdict = "sans objet (non exécutée par le vecteur ou sans ancre) ; openssl : %s" % (st or "rien")
            BILAN["sans_objet"] += 1
        elif st == chk["status"]:
            verdict = "concorde"
            BILAN["concorde"] += 1
        else:
            verdict = "DISCORDANCE (openssl : %s)" % st
            BILAN["discordance"] += 1
            DISCORDANCES.append("%s %s avec %s : vecteur %s, openssl %s (%s)" % (cas["token"], i, cas["anchors"], att, st, moyen))
        dire("  %-5s attendu %-28s %s — %s" % (i, att, verdict, moyen))
dire("")

# 4. Faits rapportés (EX-9.19) des cas où le contrôle 4 réussit, recalculés par openssl
def autorite_retenue(ancres, pem_s, at):
    """Autorité et chemin retenus selon la règle de EX-9.13 (« Chemin retenu ») : la première autorité,
    dans l'ordre du fichier d'ancres, pour laquelle openssl verify -partial_chain -show_chain trouve un
    chemin à genTime, chaque autorité étant essayée seule ; le chemin est celui qu'openssl imprime
    (certificats du signataire jusqu'à l'autorité). Rend (indice, nombre de certificats du chemin)."""
    for k, x in enumerate(ancres["tsa_authorities"]):
        ca = ecrire("autorite.pem", x["certificate"])
        args = ["verify", "-partial_chain", "-show_chain", "-attime", str(at), "-CAfile", ca]
        if x["intermediates"]:
            args += ["-untrusted", ecrire("intermediaires.pem", "".join(x["intermediates"]))]
        code, s = ossl(args + [pem_s])
        if code == 0 and ": OK" in s:
            return k, len(re.findall(r"^depth=\d+:", s, re.M))
    return None, 0


dire("== 4. Faits rapportés (EX-9.19), recalculés par openssl")
for cas in ATTENDU["cases"]:
    fa = cas.get("facts")
    if not fa:
        continue
    t, a, c, certs = LECTURES[cas["token"]]
    ancres = ANCRES[cas["anchors"]]
    dire("-- %s, ancres %s" % (cas["token"], cas["anchors"]))
    tx = x509_texte(certs[0])
    comparer("tsu_certificate_sha256", fa["tsu_certificate_sha256"], sha256_ossl(der_de(certs[0])))
    cn = re.search(r"/CN=([^/]+)", sujet_compat(certs[0]))
    comparer("tsu_subject_cn (sujet imprimé par openssl x509 -subject ; nul sans CN)", fa["tsu_subject_cn"], cn.group(1) if cn else None)
    comparer("gen_time", fa["gen_time"], t["gen_time"])
    sec = int(re.match(r"0x([0-9a-fA-F]+) seconds", t["precision"]).group(1), 16)
    comparer("accuracy", fa["accuracy"], {"seconds": sec, "millis": None, "micros": None} if "unspecified millis, unspecified micros" in t["precision"] else t["precision"])
    borne = (datetime.strptime(t["gen_time"][:19], "%Y-%m-%dT%H:%M:%S") + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
    comparer("upper_bound (genTime + accuracy)", fa["upper_bound"], borne)
    comparer("policy", fa["policy"], t["politique"])
    comparer("serial_number", fa["serial_number"], t["numero"])
    comparer("digest_algorithm", fa["digest_algorithm"], c["algo_condensat"])
    comparer("signature_algorithm", fa["signature_algorithm"], c["algo_signature"])
    comparer("key_bits", fa["key_bits"], int(re.search(r"Public-Key: \((\d+) bit\)", tx).group(1)))
    comparer("qualified_claim (qcStatements absent des extensions de TSTInfo)", fa["qualified_claim"], "qcStatements" in t["extensions"] or "1.3.6.1.5.5.7.1.3" in t["extensions"])
    pem_s = ecrire("signataire.pem", certs[0])
    k, longueur = autorite_retenue(ancres, pem_s, unix(t["gen_time"]))
    A = ancres["tsa_authorities"][k]
    comparer("authority (autorité retenue : openssl verify autorité par autorité, règle de EX-9.13 ; nom lu dans le fichier d'ancres)", fa["authority"], A["name"])
    q = A["qualified"]
    comparer("qualified (déclaration de l'autorité retenue, lue dans le fichier d'ancres)", fa["qualified"],
             {"framework": q["framework"], "source": q["source"]} if q else None)
    # une entrée par certificat du chemin autre que celui de l'autorité : le signataire si le chemin
    # a deux certificats, aucune si l'autorité est l'unité elle-même (chemin d'un certificat)
    attendues = []
    if longueur > 1:
        crl_pem = ancres["revocation"]["crls"][0]
        code, s = ossl(["crl", "-noout", "-lastupdate"], entree=crl_pem.encode())
        attendues.append({"certificate_sha256": sha256_ossl(der_de(certs[0])), "evidence": "crl", "issued_at": iso(s.split("=", 1)[1])})
    comparer("revocation (lastUpdate de la CRL de l'ancre, certificats du chemin hors autorité : %d)" % max(longueur - 1, 0), fa["revocation"], attendues)
dire("")

# 5. Verdict global d'openssl ts -verify (à genTime, -CAfile ac-test.pem) par jeton, contre attendu.json
dire("== 5. Verdict d'openssl ts -verify par jeton, avec ancres-test.json, contre les vérifications en échec de attendu.json")
LIMITES = []
for cas in ATTENDU["cases"]:
    if cas["anchors"] != "ancres/ancres-test.json":
        continue
    t = LECTURES[cas["token"]][0]
    code, s_ts = ossl(["ts", "-verify", "-digest", cas["dossier_period_hash"][2:], "-in", cas["token"], "-token_in",
                       "-CAfile", "cles/ac-test.pem", "-attime", str(unix(t["gen_time"]))])
    ok = "Verification: OK" in s_ts
    echecs = cas["failed_checks"]
    if ok == (not echecs):
        verdict = "concorde"
    else:
        verdict = "limite de l'outil : openssl ts -verify ne fait pas %s" % ", ".join(echecs)
        LIMITES.append("%s : attendu.json %s en échec ; openssl ts -verify : Verification: OK" % (cas["token"], ", ".join(echecs)))
    dire("  %-34s periodHash du dossier %s… ; attendu : %-12s openssl ts -verify : %-60s %s" % (cas["token"], cas["dossier_period_hash"][:10], ", ".join(echecs) or "aucun échec",
         "Verification: OK" if ok else "FAILED (" + "; ".join(erreurs(s_ts)) + ")", verdict))
dire("")
dire("Bilan des cas : %d concordances, %d discordances, %d hors outil, %d sans objet" %
     (BILAN["concorde"], BILAN["discordance"], BILAN["hors_outil"], BILAN["sans_objet"]))
dire("Discordances au total (sections 1 à 4) : %d" % len(DISCORDANCES))
for d in DISCORDANCES:
    dire("  - " + d)
dire("Verdicts d'openssl ts -verify qui ne disent pas « échec » là où attendu.json en relève un (limites de l'outil, section 5) : %d" % len(LIMITES))
for d in LIMITES:
    dire("  - " + d)
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
