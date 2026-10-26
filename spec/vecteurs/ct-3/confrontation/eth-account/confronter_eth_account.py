#!/usr/bin/env python3
# Confrontation des signatures des vecteurs CT-3 par eth-account
# (spec/CT-3-approbations.md, révision 0.3, EX-A.14, EX-A.18, EX-9.22).
#
#   python -I confronter_eth_account.py <chemin de spec/vecteurs/ct-3>
#
# Le programme ne lit aucun code du dépôt : il relit les vecteurs, recalcule
# lui-même D_A (JCS des cinq chaînes de A, puis SHA-256 de
# « noortrace/approbation/v0\n » ‖ JCS(A), CT-1 §6.3) et porte sa propre
# référence de CT-3 (contrôle de forme d'EX-9.22, normalisation d'EX-9.3,
# Keccak-256 et recouvrement secp256k1 écrits ici, sans bibliothèque). Pour
# chaque signature des vecteurs, il :
#
#   1. contrôle la forme avant la bibliothèque (EX-9.22) : 65 octets, r et s
#      dans [1, n − 1], v ∈ {0, 1, 27, 28} là où CT-3 normalise (service,
#      console), v ∈ {27, 28} et s ≤ n/2 là où il ne normalise pas (noyau,
#      réviseur d'un annuaire exporté) ;
#   2. recouvre l'adresse par Account.recover_message d'eth-account, avec la
#      signature telle que le vecteur la porte, sur encode_defunct(hexstr=D_A)
#      pour un vote, et sur encode_defunct(primitive=<octets du message>) pour
#      un message d'inscription (EX-A.18) ; chaque recouvrement est refait par
#      l'autre forme admise, encode_defunct(primitive=<32 octets de D_A>) pour
#      un vote, encode_defunct(text=<message>) pour une inscription (texte
#      ASCII : ses octets UTF-8 sont ses octets), et les deux doivent rendre la
#      même chose ;
#   3. compare à l'adresse attendue : celle que le vecteur nomme (approbateur
#      d'un vote dont la signature a passé le contrôle, adresse inscrite,
#      adresse recouvrée attendue), ou, à défaut, celle que recouvre la
#      référence de ce programme sur la forme normalisée.
#
# Verdicts (EX-A.18) : concorde, acceptee_par_la_bibliotheque,
# refusee_par_la_bibliotheque, discordance. Les fichiers de clé valides de
# console/fichiers-cle/ sont déchiffrés par Account.decrypt. Le code de sortie
# est 0 sans discordance, 1 avec au moins une, 2 pour un usage incorrect. La
# sortie ne porte aucun chemin local.

import hashlib
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
    """H = keccak256(0x19 ‖ « Ethereum Signed Message:\\n » ‖ longueur décimale ‖ octets) (EIP-191, version 0x45)."""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(octets)).encode("ascii") + octets)


def recouvrer_reference(octets, forme):
    """Adresse recouvrée par la référence sur une forme normalisée (v ∈ {27, 28}), ou None."""
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


def forme_ct3(sig, normalise):
    """Forme de CT-3 (EX-9.22, EX-9.3) : la forme normalisée en minuscules, ou None si CT-3 la refuse."""
    if not isinstance(sig, str) or not sig.startswith("0x") or any(ch not in "0123456789abcdefABCDEF" for ch in sig[2:]):
        return None
    s0 = sig.lower()
    if len(s0) != 132:
        return None
    r, s, v = int(s0[2:66], 16), int(s0[66:130], 16), int(s0[130:], 16)
    if not (1 <= r < N and 1 <= s < N):
        return None
    if not normalise:
        return s0 if v in (27, 28) and s <= N // 2 else None
    if v in (0, 1):
        v += 27
    if v not in (27, 28):
        return None
    if s > N // 2:
        s, v = N - s, 55 - v
    return "0x" + s0[2:66] + format(s, "064x") + format(v, "02x")


# ---------------------------------------------------------------------------
# D_A (CT-1 §6.3).
# ---------------------------------------------------------------------------

def condense_a(a):
    """D_A = SHA-256(« noortrace/approbation/v0\\n » ‖ JCS(A)), A de cinq chaînes."""
    cles = ("decision", "journal_id", "org_id", "request_hash", "ticket")
    jcs = "{" + ",".join(json.dumps(k) + ":" + json.dumps(a[k], ensure_ascii=False) for k in cles) + "}"
    return "0x" + hashlib.sha256(("noortrace/approbation/v0\n" + jcs).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# eth-account.
# ---------------------------------------------------------------------------

def _recouvrer(message, signature):
    try:
        return Account.recover_message(message, signature=signature).lower()
    except Exception:  # noqa: BLE001 - tout refus de la bibliothèque compte comme refus
        return None


def bibliotheque(d_a, texte, signature):
    """(adresse ou None, accord des deux formes d'appel)."""
    if texte is None:
        a = _recouvrer(encode_defunct(hexstr=d_a), signature)
        b = _recouvrer(encode_defunct(primitive=bytes.fromhex(d_a[2:])), signature)
    else:
        a = _recouvrer(encode_defunct(primitive=texte.encode("utf-8")), signature)
        b = _recouvrer(encode_defunct(text=texte), signature)
    return a, a == b


# ---------------------------------------------------------------------------
# Parcours des vecteurs.
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2 or not os.path.isfile(os.path.join(sys.argv[1], "INDEX.md")):
        sys.stderr.write("usage : python -I confronter_eth_account.py <chemin de spec/vecteurs/ct-3>\n")
        return 2
    racine = sys.argv[1]

    def lire(*p):
        with open(os.path.join(racine, *p), encoding="utf-8") as f:
            return json.load(f)

    def fichiers(*p):
        d = os.path.join(racine, *p)
        return sorted(f for f in os.listdir(d) if f.endswith(".json")) if os.path.isdir(d) else []

    lignes = []
    comptes = {"concorde": 0, "acceptee_par_la_bibliotheque": 0, "refusee_par_la_bibliotheque": 0, "discordance": 0}

    def confronter(famille, cas, indice, signature, normalise, d_a=None, texte=None, attendue=None, coherent=True, admises=None):
        """Une signature ; `coherent` est faux si le vecteur contredit la référence ; `admises` borne la référence."""
        forme = forme_ct3(signature, normalise)
        recouvree, accord = bibliotheque(d_a, texte, signature)
        octets = texte.encode("utf-8") if texte is not None else bytes.fromhex(d_a[2:])
        ref = recouvrer_reference(octets, forme) if forme else None
        cible = attendue if attendue is not None else ref
        if not accord or not coherent:
            verdict = "discordance"
        elif forme is None:
            verdict = "concorde" if recouvree is None else "acceptee_par_la_bibliotheque"
        elif recouvree is None:
            verdict = "discordance" if forme == signature.lower() else "refusee_par_la_bibliotheque"
        else:
            verdict = "concorde" if recouvree == cible and ref == cible else "discordance"
        if forme is not None and admises is not None and ref not in admises:
            verdict = "discordance"
        comptes[verdict] += 1
        lignes.append(f"{famille} | {cas} | {indice} | {recouvree or 'refusée'} | {cible if forme else 'forme refusée par CT-3'} | {verdict}")

    # tickets/ : entrées voter (le service normalise, EX-9.3). La signature
    # passe le contrôle d'EX-9.10 dès que le vote est accepté ou refusé pour
    # une raison qui le suit.
    avant_signature = {"ticket_inconnu", "ticket_non_ouvert", "ticket_clos_aux_votes", "jeu_non_fige", "signature_invalide"}
    for f in fichiers("tickets"):
        t = lire("tickets", f)
        rh = {}
        for i, p in enumerate(t["steps"]):
            e = p["input"]
            if e["kind"] == "ouvrir":
                rh[e["data"]["ticket"]] = e["data"]["request_hash"]
            if e["kind"] != "voter":
                continue
            d = e["data"]
            if d["ticket"] not in rh:
                continue
            passe = p["expected"].get("accepted") or p["expected"].get("reason") not in avant_signature
            a = {"decision": d["decision"], "journal_id": t["journal_id"], "org_id": t["org_id"], "request_hash": rh[d["ticket"]], "ticket": d["ticket"]}
            confronter("tickets", f, i, d["signature"], True, d_a=condense_a(a), attendue=d["approver"] if passe else None)

    # decisions/ : signatures des remises (le noyau ne normalise pas, SG-5).
    # Les approbateurs sont attendus pour une remise scellée ou refusée après
    # SG-5 (SG-6, SG-7).
    apres_sg5 = {"approbateur_double", "approbateur_hors_jeu", "seuil_different_du_jeu", "expire_avec_signatures", "seuil_non_atteint", "auto_approbation"}
    for rep in ("valides", "invalides"):
        for f in fichiers("decisions", rep):
            c = lire("decisions", rep, f)
            ap = (c.get("remise") or {}).get("approval")
            if not ap or not isinstance(ap.get("signatures"), list):
                continue
            nomme = (c["expected"]["result"] == "scelle" or c["expected"]["reason"] in apres_sg5) and len(ap["approvers"]) == len(ap["signatures"])
            a = {"decision": ap["decision"], "journal_id": c["context"]["journal_id"], "org_id": c["context"]["org_id"], "request_hash": ap["request_hash"], "ticket": ap["ticket"]}
            for i, s in enumerate(ap["signatures"]):
                confronter("decisions", f"{rep}/{f}", i, s, False, d_a=condense_a(a), attendue=ap["approvers"][i] if nomme else None)

    # signatures/normalisation.json : vote approuve d'apr-0001 (demande 1,
    # journal-approbations), signé par l'un des comptes de test (A.8) ; la
    # forme normalisée de la référence doit être celle du vecteur.
    k = lire("constantes.json")
    comptes_test = {c["address"] for c in k["accounts"]}
    rh1 = "0x" + hashlib.sha256(k["labels"]["request"].replace("<k>", "1").encode("utf-8")).hexdigest()
    a1 = {"decision": "approuve", "journal_id": k["journal"]["journal_id"], "org_id": k["organization"]["org_id"], "request_hash": rh1, "ticket": "apr-0001"}
    for c in lire("signatures", "normalisation.json")["cases"]:
        confronter("signatures", f"normalisation.json#{c['id']}", 0, c["signature"], True, d_a=condense_a(a1),
                   coherent=forme_ct3(c["signature"], True) == c["expected"], admises=comptes_test)

    # console/requetes/ et console/reponses/ (la console normalise, EX-9.21).
    for f in fichiers("console", "requetes"):
        c = lire("console", "requetes", f)
        d_a = condense_a(c["input"]["a"])
        confronter("console/requetes", f, 0, c["expected"]["signature"], True, d_a=d_a, attendue=c["input"]["approver"],
                   coherent=d_a == c["expected"]["digests"]["d_a"])
    for f in fichiers("console", "reponses"):
        c = lire("console", "reponses", f)
        r = c["input"]["response"].get("result")
        if not isinstance(r, str) or len(r) < 3 or not r.startswith("0x") or any(ch not in "0123456789abcdefABCDEF" for ch in r[2:]):
            continue
        attendu = c["expected"]
        coherent = attendu["outcome"] != "accepte" or forme_ct3(r, True) == attendu["signature"]
        confronter("console/reponses", f, 0, r, True, d_a=condense_a(c["input"]["a"]), attendue=attendu.get("recovered"), coherent=coherent)

    # annuaire/ : inscriptions (le service normalise, EX-13.15), domaines
    # (AN-5), preuves des annuaires et des exports (le réviseur exige la forme
    # canonique, EX-13.19), requêtes inscrire des traces. messages.json ne
    # porte aucune signature.
    apres_signature = {"identite_desactivee", "adresse_deja_attribuee"}
    for c in lire("annuaire", "inscriptions.json")["cases"]:
        q = c["request"]
        passe = c["expected"]["accepted"] or c["expected"]["reason"] in apres_signature
        confronter("annuaire/inscriptions", c["id"], 0, q["signature"], True, texte=q["message"], attendue=q["address"] if passe else None)
    for c in lire("annuaire", "domaines.json")["cases"]:
        if c["kind"] == "inscription_comme_vote":
            confronter("annuaire/domaines", c["id"], 0, c["signature"], True, d_a=condense_a(c["A"]), attendue=c["expected"]["recovered"])
        else:
            confronter("annuaire/domaines", c["id"], 0, c["signature"], True, texte=c["message"], attendue=c["expected"]["recovered"])
    preuves_invalides = set()
    for c in lire("annuaire", "exports", "attendu.json")["cases"]:
        for e in c["errors"]:
            if e["code"] == "preuve_invalide":
                preuves_invalides.add((c["file"], e["pointer"]))
    for rep in ("annuaires", "exports"):
        for f in fichiers("annuaire", rep):
            if f == "attendu.json":
                continue
            doc = lire("annuaire", rep, f)
            for i, e in enumerate(doc.get("entries") or []):
                for j, ad in enumerate(e["addresses"]):
                    pointeur = f"/entries/{i}/addresses/{j}"
                    nomme = (f, pointeur + "/proof") not in preuves_invalides if rep == "exports" else True
                    confronter(f"annuaire/{rep}", f"{f}#{pointeur}", 0, ad["proof"]["signature"], False, texte=ad["proof"]["message"],
                               attendue=ad["address"] if nomme else None)
    for f in fichiers("annuaire", "traces"):
        for i, p in enumerate(lire("annuaire", "traces", f)["steps"]):
            q = p["request"]
            if p["method"] != "inscrire" or not isinstance(q.get("message"), str):
                continue
            passe = p["expected"]["accepted"] or p["expected"]["reason"] in apres_signature
            confronter("annuaire/traces", f, i, q["signature"], True, texte=q["message"], attendue=q["address"] if passe else None)

    # console/fichiers-cle/ : fichiers que CT-3 accepte, ou dont il refuse
    # seulement l'adresse, déchiffrés par Account.decrypt.
    lignes_cles = []
    for f in fichiers("console", "fichiers-cle"):
        c = lire("console", "fichiers-cle", f)
        if not (c["expected"]["outcome"] == "accepte" or c["expected"]["reason"] == "adresse_differente"):
            continue
        try:
            adresse = Account.from_key(Account.decrypt(c["input"]["keystore"], c["input"]["password"])).address.lower()
        except Exception:  # noqa: BLE001
            adresse = None
        verdict = "concorde" if adresse == c["expected"]["address"] else "discordance"
        comptes[verdict] += 1
        lignes_cles.append(f"console/fichiers-cle | {f} | 0 | {adresse or 'refusé'} | {c['expected']['address']} | {verdict}")

    v = importlib.metadata.version
    total = len(lignes) + len(lignes_cles)
    sortie = [
        f"# Confrontation des signatures des vecteurs CT-3 par eth-account {v('eth-account')} (eth-keys {v('eth-keys')}, eth-keyfile {v('eth-keyfile')} ; Account.recover_message, encode_defunct, Account.decrypt)",
        "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
        *lignes,
        *lignes_cles,
        f"# bilan : {total} signatures et fichiers ; concorde {comptes['concorde']}, acceptee_par_la_bibliotheque {comptes['acceptee_par_la_bibliotheque']}, "
        f"refusee_par_la_bibliotheque {comptes['refusee_par_la_bibliotheque']}, discordance {comptes['discordance']}",
    ]
    sys.stdout.write("\n".join(sortie) + "\n")
    return 1 if comptes["discordance"] else 0


if __name__ == "__main__":
    sys.exit(main())
