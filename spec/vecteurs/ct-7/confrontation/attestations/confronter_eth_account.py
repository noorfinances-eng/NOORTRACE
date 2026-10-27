#!/usr/bin/env python3
# Confrontation des signatures d'attestation de périmètre des vecteurs CT-7,
# CT-1 et CT-6 par eth-account (spec/CT-7-securite-et-conformite.md, version
# 0.1, §7.2, EX-7.6, EX-7.7, AT-3, EX-A.25).
#
#   python -I confronter_eth_account.py <ct-7> <ct-1> <ct-6>
#
# (chemins de spec/vecteurs/ct-7, spec/vecteurs/ct-1 et spec/vecteurs/ct-6).
# Le programme ne lit aucun code du dépôt : il relit les vecteurs, recalcule
# lui-même D_P = Keccak-256(P_P ‖ JCS(P)) (JCS v0 de CT-1 §4) et porte sa
# propre référence de CT-7 (contrôle de forme d'EX-7.6, Keccak-256 et
# recouvrement secp256k1 écrits ici, sans bibliothèque). Signatures
# confrontées : attestations/exemple/ (condense.json et
# attestation-signee.json), chaque cas de attestations/attestations.json,
# chaque cas de attestations/croises.json (indice 0 : sur le message signé ;
# indice 1 : sur le message que le cas lui fait présenter), et la partie
# attestation-perimetre.json de chaque dossier de ct-1 et de ct-6 qui la
# porte. Pour chacune, il :
#
#   1. contrôle la forme avant la bibliothèque (EX-7.6) : 65 octets, r et s
#      dans [1, n − 1], s ≤ n/2, v ∈ {27, 28} ; CT-7 ne normalise jamais ;
#   2. recouvre l'adresse par Account.recover_message d'eth-account, avec la
#      signature telle que le vecteur la porte, sur
#      encode_defunct(primitive=<32 octets du condensé>) (EX-A.25), puis sur
#      encode_defunct(hexstr=<condensé>) ; pour le texte d'inscription de CT-3
#      d'un cas croisé, sur encode_defunct(primitive=<octets UTF-8 du texte>)
#      puis sur encode_defunct(text=<texte>) ; les deux appels doivent rendre
#      la même chose ;
#   3. compare à l'adresse attendue : celle que le vecteur nomme (adresse
#      déclarée quand AT-3 réussit, expected.recovered d'un cas, compte 1
#      pour le message signé d'un cas croisé), ou, à défaut, celle que
#      recouvre la référence de ce programme.
#
# Une attestation dont AT-1 échoue (texte JSON refusé par l'analyse stricte,
# forme refusée) n'a pas de D_P selon CT-7 ; ses signatures sont recouvertes
# sur le D_P d'une lecture permissive (0.0 lu comme 0, schéma non vérifié),
# adresse attendue celle de la référence.
#
# Verdicts (ceux de la confrontation de CT-3) : concorde,
# acceptee_par_la_bibliotheque, refusee_par_la_bibliotheque, discordance. Le
# code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un usage
# incorrect. La sortie ne porte aucun chemin local.

import importlib.metadata
import json
import os
import sys

from eth_account import Account
from eth_account.messages import encode_defunct

# ---------------------------------------------------------------------------
# Référence de ce programme : Keccak-256 et secp256k1 (sans bibliothèque).
# ---------------------------------------------------------------------------

_MASQUE = (1 << 64) - 1
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def _constantes_rc():
    rc, r = [], 1
    for _ in range(24):
        c = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                c ^= 1 << ((1 << j) - 1)
        rc.append(c)
    return rc


_RC = _constantes_rc()


def _rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & _MASQUE if k else x


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & _MASQUE) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(donnees):
    """Keccak-256 (remplissage 0x01 … 0x80, débit 136 octets), pas SHA3-256."""
    taux = 136
    m = bytearray(donnees)
    m.append(0x01)
    while len(m) % taux:
        m.append(0)
    m[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(m), taux):
        bloc = m[i:i + taux]
        for k in range(taux // 8):
            x, y = k % 5, k // 5
            a[x][y] ^= int.from_bytes(bloc[8 * k:8 * k + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[k % 5][k // 5].to_bytes(8, "little") for k in range(4))


P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)


def _double(q):
    if q is None or q[1] == 0:
        return None
    x, y, z = q
    a, b = x * x % P, y * y % P
    c = b * b % P
    d = 2 * ((x + b) ** 2 - a - c) % P
    e = 3 * a % P
    x3 = (e * e - 2 * d) % P
    return (x3, (e * (d - x3) - 8 * c) % P, 2 * y * z % P)


def _ajouter(q1, q2):
    if q1 is None:
        return q2
    if q2 is None:
        return q1
    x1, y1, z1 = q1
    x2, y2, z2 = q2
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    h, r = (u2 - u1) % P, (s2 - s1) % P
    if h == 0:
        return _double(q1) if r == 0 else None
    hh = h * h % P
    hhh = h * hh % P
    x3 = (r * r - hhh - 2 * u1 * hh) % P
    return (x3, (r * (u1 * hh - x3) - s1 * hhh) % P, z1 * z2 * h % P)


def _somme(k1, q1, k2, q2):
    """k1·q1 + k2·q2 (Shamir)."""
    q12 = _ajouter(q1, q2)
    acc = None
    for i in range(max(k1.bit_length(), k2.bit_length()) - 1, -1, -1):
        acc = _double(acc)
        b1, b2 = (k1 >> i) & 1, (k2 >> i) & 1
        if b1 and b2:
            acc = _ajouter(acc, q12)
        elif b1:
            acc = _ajouter(acc, q1)
        elif b2:
            acc = _ajouter(acc, q2)
    return acc


def condense_eip191(octets):
    """M = keccak256(0x19 ‖ « Ethereum Signed Message:\\n » ‖ longueur décimale ‖ octets) (EIP-191, version 0x45)."""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(octets)).encode("ascii") + octets)


def recouvrer_reference(octets, forme):
    """Adresse recouvrée par la référence sur une forme canonique (v ∈ {27, 28}), ou None."""
    r, s, v = int(forme[2:66], 16), int(forme[66:130], 16), int(forme[130:132], 16)
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != (v - 27):
        y = P - y
    e = int.from_bytes(condense_eip191(octets), "big")
    rinv = pow(r, -1, N)
    q = _somme((-e * rinv) % N, G, (s * rinv) % N, (x, y, 1))
    if q is None:
        return None
    zi = pow(q[2], -1, P)
    qx, qy = q[0] * zi * zi % P, q[1] * zi * zi * zi % P
    return "0x" + keccak256(qx.to_bytes(32, "big") + qy.to_bytes(32, "big"))[12:].hex()


def forme_ct7(sig):
    """Forme de CT-7 (CR-11, EX-7.6) : la signature en minuscules si elle est canonique, sinon None ; jamais normalisée."""
    if not isinstance(sig, str) or not sig.startswith("0x") or any(ch not in "0123456789abcdefABCDEF" for ch in sig[2:]):
        return None
    s0 = sig.lower()
    if len(s0) != 132:
        return None
    r, s, v = int(s0[2:66], 16), int(s0[66:130], 16), int(s0[130:], 16)
    if not (1 <= r < N and 1 <= s < N):
        return None
    return s0 if v in (27, 28) and s <= N // 2 else None


# ---------------------------------------------------------------------------
# JCS v0 (CT-1 §4) et D_P (CT-7 §7.2).
# ---------------------------------------------------------------------------

def jcs(v):
    """JCS v0 : clés triées par unités UTF-16, chaînes comme JSON.stringify, entiers sûrs seulement."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        v = int(v)  # lecture permissive : 0.0 lu comme 0, comme JSON.parse
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError("nombre hors de JCS v0")
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        cles = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in cles) + "}"
    raise ValueError("valeur hors de JCS v0")


P_P = "noortrace/attestation-perimetre/v0\n".encode("utf-8")


def condense_p(p):
    """D_P = Keccak-256(P_P ‖ JCS(P))."""
    return "0x" + keccak256(P_P + jcs(p).encode("utf-8")).hex()


# ---------------------------------------------------------------------------
# eth-account.
# ---------------------------------------------------------------------------

def _recouvrer(message, signature):
    try:
        return Account.recover_message(message, signature=signature).lower()
    except Exception:  # noqa: BLE001 - tout refus de la bibliothèque compte comme refus
        return None


def bibliotheque(d, texte, signature):
    """(adresse ou None, accord des deux formes d'appel)."""
    if texte is None:
        a = _recouvrer(encode_defunct(primitive=bytes.fromhex(d[2:])), signature)
        b = _recouvrer(encode_defunct(hexstr=d), signature)
    else:
        a = _recouvrer(encode_defunct(primitive=texte.encode("utf-8")), signature)
        b = _recouvrer(encode_defunct(text=texte), signature)
    return a, a == b


# ---------------------------------------------------------------------------
# Parcours des vecteurs.
# ---------------------------------------------------------------------------

def main():
    racines = sys.argv[1:]
    if len(racines) != 3 or not all(os.path.isfile(os.path.join(r, "INDEX.md")) for r in racines) or not os.path.isdir(os.path.join(racines[0], "attestations")):
        sys.stderr.write("usage : python -I confronter_eth_account.py <chemin de spec/vecteurs/ct-7> <chemin de spec/vecteurs/ct-1> <chemin de spec/vecteurs/ct-6>\n")
        return 2
    racine7, racine1, racine6 = racines

    def lire(*p):
        with open(os.path.join(*p), encoding="utf-8") as f:
            return json.load(f)

    lignes = []
    comptes = {"concorde": 0, "acceptee_par_la_bibliotheque": 0, "refusee_par_la_bibliotheque": 0, "discordance": 0}

    def confronter(famille, cas, indice, signature, d=None, texte=None, attendue=None, coherent=True):
        """Une signature sur le condensé d ou sur le texte ; `coherent` est faux si le vecteur contredit la référence."""
        forme = forme_ct7(signature)
        recouvree, accord = bibliotheque(d, texte, signature)
        octets = texte.encode("utf-8") if texte is not None else bytes.fromhex(d[2:])
        ref = recouvrer_reference(octets, forme) if forme else None
        cible = attendue if attendue is not None else ref
        if not accord or not coherent:
            verdict = "discordance"
        elif forme is None:
            verdict = "concorde" if recouvree is None else "acceptee_par_la_bibliotheque"
        elif recouvree is None:
            verdict = "discordance"
        else:
            verdict = "concorde" if recouvree == cible and ref == cible else "discordance"
        comptes[verdict] += 1
        lignes.append(f"{famille} | {cas} | {indice} | {recouvree or 'refusée'} | {cible if forme else 'forme refusée par CT-7'} | {verdict}")

    def statut(checks, ident):
        return next((c["status"] for c in checks if c["id"] == ident), None)

    # attestations/exemple/ : l'exemple de CT-7 §7.2, signé par les comptes 1 et 2.
    ex = os.path.join(racine7, "attestations", "exemple")
    exemple = lire(ex, "attestation.json")
    d_p = condense_p(exemple)
    jcs_exemple = jcs(exemple).encode("utf-8")
    condense = lire(ex, "condense.json")
    with open(os.path.join(ex, "jcs.txt"), "rb") as f:
        jcs_fichier = f.read()
    coherent = (jcs_exemple == jcs_fichier and condense["jcs_length"] == len(jcs_exemple) and condense["digest"] == d_p
                and condense["message"] == "0x" + condense_eip191(bytes.fromhex(d_p[2:])).hex())
    for i, s in enumerate(condense["signatures"]):
        confronter("attestations/exemple", "condense.json", i, s["signature"], d=d_p, attendue=s["address"], coherent=coherent)
    signee = lire(ex, "attestation-signee.json")
    coherent = signee["digest"] == d_p and jcs(signee["attestation"]) == jcs(exemple)
    for i, s in enumerate(signee["signatures"]):
        confronter("attestations/exemple", "attestation-signee.json", i, s["signature"], d=d_p, attendue=s["address"], coherent=coherent)

    # attestations/attestations.json : AT-1 réussie, l'adresse attendue est
    # expected.recovered[i] (nulle pour une forme que CT-7 refuse) ; AT-1 en
    # échec, celle de la référence sur le D_P de la lecture permissive.
    for c in lire(racine7, "attestations", "attestations.json")["cases"]:
        s_in = c["input"]["signed"]
        sig = json.loads(s_in) if isinstance(s_in, str) else s_in
        d = condense_p(sig["attestation"])
        e = c["expected"]
        at1 = statut(e["checks"], "AT-1") == "reussi"
        at3 = statut(e["checks"], "AT-3") == "reussi"
        for i, s in enumerate(sig["signatures"]):
            if at1:
                attendue = e["recovered"][i]
                coherent = d == e["digest"] and len(e["recovered"]) == len(sig["signatures"]) and (not at3 or e["recovered"][i] == s["address"])
            else:
                attendue, coherent = None, e["recovered"] is None
            confronter("attestations/cas", c["name"], i, s["signature"], d=d, attendue=attendue, coherent=coherent)

    # attestations/croises.json : indice 0, la signature sur le message que le
    # compte 1 a signé (adresse attendue : celle du compte 1) ; indice 1, la
    # même signature sur le message que le cas lui fait présenter (adresse
    # attendue : expected.recovered, qui n'est pas celle du compte 1).
    croises = lire(racine7, "attestations", "croises.json")
    d_c = lire(racine7, "ceremonies", "valide-creation-enregistreur", "attendu.json")["digest"]

    def message(m):
        return {"texte": m["text"]} if m["kind"] == "inscription" else {"d": m["digest"]}

    def coherent_message(m):
        if m["kind"] == "attestation":
            return m["digest"] == d_p
        if m["kind"] == "ceremonie":
            return m["digest"] == d_c
        return True

    for c in croises["cases"]:
        if c["presented_as"] == "attestation":
            presente = {"kind": "attestation", "digest": croises["attestation_digest"]}
        else:
            presente = {"kind": c["presented_as"], **c["target"]}
        coherent = (croises["attestation_digest"] == d_p and coherent_message(c["message"]) and coherent_message(presente)
                    and c["expected"]["recovered"] != croises["address"])
        confronter("attestations/croises", c["name"], 0, c["signature"], attendue=croises["address"], coherent=coherent, **message(c["message"]))
        confronter("attestations/croises", c["name"], 1, c["signature"], attendue=c["expected"]["recovered"], coherent=coherent, **message(presente))

    # Dossiers de ct-1 et de ct-6 qui portent la partie
    # attestation-perimetre.json (CT-7 A.7) : adresse déclarée attendue quand
    # AT-3 réussit ; sinon, celle de la référence. AT-2 réussie, D_P recalculé
    # doit égaler le digest déclaré.
    for famille, racine in (("ct-1/dossiers", racine1), ("ct-6/dossiers", racine6)):
        rep = os.path.join(racine, "dossiers")
        for n in sorted(x for x in os.listdir(rep) if os.path.isfile(os.path.join(rep, x, "attestation-perimetre.json"))):
            partie = lire(rep, n, "attestation-perimetre.json")
            if not isinstance(partie, dict) or not isinstance(partie.get("signed"), dict) or not isinstance(partie["signed"].get("signatures"), list):
                continue
            checks = lire(rep, n, "attendu.json")["perimeter_checks"]
            d = condense_p(partie["signed"]["attestation"])
            coherent = statut(checks, "AT-2") != "reussi" or d == partie["signed"]["digest"]
            at3 = statut(checks, "AT-3") == "reussi"
            for i, s in enumerate(partie["signed"]["signatures"]):
                confronter(famille, n, i, s["signature"], d=d, attendue=s["address"] if at3 else None, coherent=coherent)

    v = importlib.metadata.version
    sortie = [
        f"# Confrontation des signatures d'attestation des vecteurs CT-7, CT-1 et CT-6 par eth-account {v('eth-account')} (eth-keys {v('eth-keys')} ; Account.recover_message, encode_defunct)",
        "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
        *lignes,
        f"# bilan : {len(lignes)} signatures ; concorde {comptes['concorde']}, acceptee_par_la_bibliotheque {comptes['acceptee_par_la_bibliotheque']}, "
        f"refusee_par_la_bibliotheque {comptes['refusee_par_la_bibliotheque']}, discordance {comptes['discordance']}",
    ]
    sys.stdout.write("\n".join(sortie) + "\n")
    return 1 if comptes["discordance"] else 0


if __name__ == "__main__":
    sys.exit(main())
