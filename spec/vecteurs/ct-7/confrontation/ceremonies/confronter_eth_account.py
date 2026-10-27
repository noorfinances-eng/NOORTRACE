#!/usr/bin/env python3
# Confrontation des signatures des procès-verbaux de cérémonie des vecteurs
# CT-7 par eth-account (spec/CT-7-securite-et-conformite.md, version 0.1,
# §5.7, CR-11 de §5.8, EX-A.24).
#
#   python -I confronter_eth_account.py <chemin de spec/vecteurs/ct-7>
#
# Le programme ne lit aucun code du dépôt : il relit les vecteurs, recalcule
# lui-même D_C = Keccak-256(P_C ‖ JCS(V)) (V : le procès-verbal privé de son
# membre signatures ; JCS v0 de CT-1 §4) et porte sa propre référence de CT-7
# (contrôle de forme de CR-11, Keccak-256 et recouvrement secp256k1 écrits
# ici, sans bibliothèque). Pour chaque signature de chaque procès-verbal de
# ceremonies/, il :
#
#   1. contrôle la forme avant la bibliothèque (CR-11) : 65 octets, r et s
#      dans [1, n − 1], s ≤ n/2, v ∈ {27, 28} ; CT-7 ne normalise jamais ;
#   2. recouvre l'adresse par Account.recover_message d'eth-account, avec la
#      signature telle que le vecteur la porte, sur
#      encode_defunct(primitive=<32 octets de D_C>) (EX-A.24), puis sur
#      encode_defunct(hexstr=D_C) ; les deux doivent rendre la même chose ;
#   3. compare à l'adresse attendue : celle du participant quand attendu.json
#      la range parmi les signataires (signers), ou, à défaut, celle que
#      recouvre la référence de ce programme.
#
# Pour les cas où CR-1 échoue (attendu.json : digest nul), CT-7 ne définit pas
# D_C ; les signatures y sont recouvertes sur le D_C d'une lecture permissive
# (dernière occurrence d'une clé en double, 0.0 lu comme l'entier 0, schéma
# non vérifié), famille ceremonies/cr1-lecture-permissive, adresse attendue
# celle de la référence.
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
# JCS v0 (CT-1 §4) et D_C (CT-7 §5.7).
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


P_C = "noortrace/ceremonie-cles/v0\n".encode("utf-8")


def condense_c(pv):
    """D_C = Keccak-256(P_C ‖ JCS(V)), V le procès-verbal privé de son membre signatures."""
    v = {k: x for k, x in pv.items() if k != "signatures"}
    return "0x" + keccak256(P_C + jcs(v).encode("utf-8")).hex()


# ---------------------------------------------------------------------------
# eth-account.
# ---------------------------------------------------------------------------

def _recouvrer(message, signature):
    try:
        return Account.recover_message(message, signature=signature).lower()
    except Exception:  # noqa: BLE001 - tout refus de la bibliothèque compte comme refus
        return None


def bibliotheque(d, signature):
    """(adresse ou None, accord des deux formes d'appel)."""
    a = _recouvrer(encode_defunct(primitive=bytes.fromhex(d[2:])), signature)
    b = _recouvrer(encode_defunct(hexstr=d), signature)
    return a, a == b


# ---------------------------------------------------------------------------
# Parcours des vecteurs.
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2 or not os.path.isfile(os.path.join(sys.argv[1], "INDEX.md")) or not os.path.isdir(os.path.join(sys.argv[1], "ceremonies")):
        sys.stderr.write("usage : python -I confronter_eth_account.py <chemin de spec/vecteurs/ct-7>\n")
        return 2
    racine = sys.argv[1]

    def lire(*p):
        # Lecture permissive : json.load garde la dernière occurrence d'une clé.
        with open(os.path.join(racine, *p), encoding="utf-8") as f:
            return json.load(f)

    lignes = []
    comptes = {"concorde": 0, "acceptee_par_la_bibliotheque": 0, "refusee_par_la_bibliotheque": 0, "discordance": 0}

    def confronter(famille, cas, indice, signature, d, attendue=None, coherent=True, exclue=None):
        """Une signature sur le condensé d ; `exclue` : adresse que la référence ne doit pas recouvrir."""
        forme = forme_ct7(signature)
        recouvree, accord = bibliotheque(d, signature)
        ref = recouvrer_reference(bytes.fromhex(d[2:]), forme) if forme else None
        cible = attendue if attendue is not None else ref
        if not accord or not coherent or (forme and exclue is not None and ref == exclue):
            verdict = "discordance"
        elif forme is None:
            verdict = "concorde" if recouvree is None else "acceptee_par_la_bibliotheque"
        elif recouvree is None:
            verdict = "discordance"
        else:
            verdict = "concorde" if recouvree == cible and ref == cible else "discordance"
        comptes[verdict] += 1
        lignes.append(f"{famille} | {cas} | {indice} | {recouvree or 'refusée'} | {cible if forme else 'forme refusée par CT-7'} | {verdict}")

    rep = os.path.join(racine, "ceremonies")
    for nom in sorted(n for n in os.listdir(rep) if os.path.isfile(os.path.join(rep, n, "proces-verbal.json"))):
        attendu = lire("ceremonies", nom, "attendu.json")
        pv = lire("ceremonies", nom, "proces-verbal.json")
        d = condense_c(pv)
        permissive = attendu["digest"] is None
        famille = "ceremonies/cr1-lecture-permissive" if permissive else "ceremonies"
        adresses = {}
        for p in pv["participants"]:
            adresses.setdefault(p["id"], p["address"])
        for i, s in enumerate(pv["signatures"]):
            adresse = adresses.get(s["participant"])
            signataire = not permissive and adresse is not None and adresse in attendu["signers"]
            confronter(famille, nom, i, s["signature"], d,
                       attendue=adresse if signataire else None,
                       coherent=(not attendu["signers"]) if permissive else d == attendu["digest"],
                       exclue=adresse if not permissive and not signataire else None)

    v = importlib.metadata.version
    sortie = [
        f"# Confrontation des signatures des procès-verbaux des vecteurs CT-7 par eth-account {v('eth-account')} (eth-keys {v('eth-keys')} ; Account.recover_message, encode_defunct)",
        "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
        *lignes,
        f"# bilan : {len(lignes)} signatures ; concorde {comptes['concorde']}, acceptee_par_la_bibliotheque {comptes['acceptee_par_la_bibliotheque']}, "
        f"refusee_par_la_bibliotheque {comptes['refusee_par_la_bibliotheque']}, discordance {comptes['discordance']}",
    ]
    sys.stdout.write("\n".join(sortie) + "\n")
    return 1 if comptes["discordance"] else 0


if __name__ == "__main__":
    sys.exit(main())
