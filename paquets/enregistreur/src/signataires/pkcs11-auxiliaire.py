#!/usr/bin/env python3
# Auxiliaire PKCS#11 du signataire de classe A (CT-2 §11.2, EX-11.10).
#
# Le démon ne charge jamais la bibliothèque PKCS#11 du fabricant dans son
# propre processus : il lance cet auxiliaire (python3 -I -S, bibliothèque
# standard seule : ctypes) et lui parle par lignes JSON sur stdin/stdout.
# Motifs (LISEZMOI, lecture 174) : C_Sign est un appel bloquant que la boucle
# d'événements de Node.js ne pourrait pas interrompre (le délai
# `signer.timeout_ms` d'EX-11.18 ne serait pas tenu) ; une bibliothèque de
# fabricant qui plante n'emporte que l'auxiliaire ; aucun module natif npm à
# compiler.
#
# Arguments : <module PKCS#11> <étiquette du jeton>. Première ligne de stdin :
# le code PIN en hexadécimal (jamais en argument ni en variable
# d'environnement, que /proc rend lisibles). Requêtes, une par ligne :
#   {"op": "public_key", "label": "<étiquette de la clé>"}
#     -> {"ok": true, "public_key": "<64 hex>", "ec_params": "<hex>",
#         "ec_params_form": "curveName" | "oid", "ec_point_form": "brut" | "der",
#         "extractable": bool|null, "sensitive": bool|null}
#   {"op": "sign", "label": "...", "mechanism": <entier>, "message": "<hex>"}
#     -> {"ok": true, "signature": "<hex>"}
#   {"op": "health"} -> {"ok": true}
# Erreur : {"ok": false, "error": "<texte sans secret>", "rv": <CKR_*>|null}.
#
# Seules l'identité d'usage et les opérations d'usage sont employées
# (EX-11.4) : aucune génération, aucune destruction, aucun export.

import ctypes
import json
import sys

CK_ULONG = ctypes.c_ulong
CK_RV = CK_ULONG
CK_VOID_P = ctypes.c_void_p
CK_BYTE_P = ctypes.POINTER(ctypes.c_ubyte)
CK_ULONG_P = ctypes.POINTER(CK_ULONG)

# Constantes OASIS PKCS#11 (2.40, 3.0, 3.1).
CKR_OK = 0x0
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKF_SERIAL_SESSION = 0x4
CKU_USER = 1
CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3
CKK_EC_EDWARDS = 0x40
CKA_CLASS = 0x0
CKA_LABEL = 0x3
CKA_KEY_TYPE = 0x100
CKA_SENSITIVE = 0x103
CKA_SIGN = 0x108
CKA_EXTRACTABLE = 0x162
CKA_EC_PARAMS = 0x180
CKA_EC_POINT = 0x181

# CKA_EC_PARAMS d'une clé Ed25519 (EX-11.10) : curveName PrintableString
# « edwards25519 » ou OID 1.3.101.112 (RFC 8410).
EC_PARAMS_NOM = bytes.fromhex("130c656477617264733235353139")
EC_PARAMS_OID = bytes.fromhex("06032b6570")

# Ordre des pointeurs de CK_FUNCTION_LIST (PKCS#11 2.40, § 5.13).
FONCTIONS = (
    "C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo "
    "C_GetTokenInfo C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN C_SetPIN "
    "C_OpenSession C_CloseSession C_CloseAllSessions C_GetSessionInfo C_GetOperationState "
    "C_SetOperationState C_Login C_Logout C_CreateObject C_CopyObject C_DestroyObject "
    "C_GetObjectSize C_GetAttributeValue C_SetAttributeValue C_FindObjectsInit C_FindObjects "
    "C_FindObjectsFinal C_EncryptInit C_Encrypt C_EncryptUpdate C_EncryptFinal C_DecryptInit "
    "C_Decrypt C_DecryptUpdate C_DecryptFinal C_DigestInit C_Digest C_DigestUpdate C_DigestKey "
    "C_DigestFinal C_SignInit C_Sign C_SignUpdate C_SignFinal C_SignRecoverInit C_SignRecover "
    "C_VerifyInit C_Verify C_VerifyUpdate C_VerifyFinal C_VerifyRecoverInit C_VerifyRecover "
    "C_DigestEncryptUpdate C_DecryptDigestUpdate C_SignEncryptUpdate C_DecryptVerifyUpdate "
    "C_GenerateKey C_GenerateKeyPair C_WrapKey C_UnwrapKey C_DeriveKey C_SeedRandom "
    "C_GenerateRandom C_GetFunctionStatus C_CancelFunction C_WaitForSlotEvent"
).split()


class CK_VERSION(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [(n, CK_VOID_P) for n in FONCTIONS]


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [("type", CK_ULONG), ("pValue", CK_VOID_P), ("ulValueLen", CK_ULONG)]


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [("mechanism", CK_ULONG), ("pParameter", CK_VOID_P), ("ulParameterLen", CK_ULONG)]


SIGNATURES = {
    "C_Initialize": (CK_VOID_P,),
    "C_GetSlotList": (ctypes.c_ubyte, ctypes.POINTER(CK_ULONG), CK_ULONG_P),
    "C_GetTokenInfo": (CK_ULONG, CK_VOID_P),
    "C_OpenSession": (CK_ULONG, CK_ULONG, CK_VOID_P, CK_VOID_P, CK_ULONG_P),
    "C_CloseSession": (CK_ULONG,),
    "C_GetSessionInfo": (CK_ULONG, CK_VOID_P),
    "C_Login": (CK_ULONG, CK_ULONG, CK_BYTE_P, CK_ULONG),
    "C_GetAttributeValue": (CK_ULONG, CK_ULONG, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG),
    "C_FindObjectsInit": (CK_ULONG, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG),
    "C_FindObjects": (CK_ULONG, ctypes.POINTER(CK_ULONG), CK_ULONG, CK_ULONG_P),
    "C_FindObjectsFinal": (CK_ULONG,),
    "C_SignInit": (CK_ULONG, ctypes.POINTER(CK_MECHANISM), CK_ULONG),
    "C_Sign": (CK_ULONG, CK_BYTE_P, CK_ULONG, CK_BYTE_P, CK_ULONG_P),
}


class ErreurPkcs11(Exception):
    def __init__(self, texte, rv=None):
        super().__init__(texte)
        self.rv = rv


class Jeton:
    def __init__(self, module, etiquette, pin):
        self.bib = ctypes.CDLL(module)
        liste = ctypes.POINTER(CK_FUNCTION_LIST)()
        obtenir = self.bib.C_GetFunctionList
        obtenir.restype = CK_RV
        obtenir.argtypes = (ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST)),)
        self.verifier(obtenir(ctypes.byref(liste)), "C_GetFunctionList")
        self.f = {}
        for nom, args in SIGNATURES.items():
            adresse = getattr(liste.contents, nom)
            if not adresse:
                raise ErreurPkcs11(f"{nom} absent du module")
            self.f[nom] = ctypes.CFUNCTYPE(CK_RV, *args)(adresse)
        rv = self.f["C_Initialize"](None)
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise ErreurPkcs11("C_Initialize", rv)
        self.etiquette = etiquette
        self.pin = pin
        self.session = None
        self.ouvrir()

    @staticmethod
    def verifier(rv, nom):
        if rv != CKR_OK:
            raise ErreurPkcs11(f"{nom} : CKR 0x{rv:x}", rv)

    def emplacement(self):
        n = CK_ULONG(0)
        self.verifier(self.f["C_GetSlotList"](1, None, ctypes.byref(n)), "C_GetSlotList")
        slots = (CK_ULONG * max(n.value, 1))()
        self.verifier(self.f["C_GetSlotList"](1, slots, ctypes.byref(n)), "C_GetSlotList")
        voulu = self.etiquette.encode("utf-8").ljust(32, b" ")[:32]
        for i in range(n.value):
            info = ctypes.create_string_buffer(1024)
            if self.f["C_GetTokenInfo"](slots[i], info) != CKR_OK:
                continue
            if info.raw[:32] == voulu:
                return slots[i]
        raise ErreurPkcs11("jeton introuvable (étiquette)")

    def ouvrir(self):
        slot = self.emplacement()
        h = CK_ULONG(0)
        self.verifier(self.f["C_OpenSession"](slot, CKF_SERIAL_SESSION, None, None, ctypes.byref(h)), "C_OpenSession")
        tampon = (ctypes.c_ubyte * len(self.pin)).from_buffer_copy(self.pin) if self.pin else None
        rv = self.f["C_Login"](h.value, CKU_USER, tampon, len(self.pin))
        if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
            self.f["C_CloseSession"](h.value)
            raise ErreurPkcs11("C_Login refusé", rv)
        self.session = h.value

    def objet(self, classe, etiquette):
        lab = etiquette.encode("utf-8")
        valeurs = [CK_ULONG(classe), CK_ULONG(CKK_EC_EDWARDS)]
        tlab = ctypes.create_string_buffer(lab, len(lab))
        modele = (CK_ATTRIBUTE * 3)(
            CK_ATTRIBUTE(CKA_CLASS, ctypes.cast(ctypes.byref(valeurs[0]), CK_VOID_P), ctypes.sizeof(CK_ULONG)),
            CK_ATTRIBUTE(CKA_KEY_TYPE, ctypes.cast(ctypes.byref(valeurs[1]), CK_VOID_P), ctypes.sizeof(CK_ULONG)),
            CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(tlab, CK_VOID_P), len(lab)),
        )
        self.verifier(self.f["C_FindObjectsInit"](self.session, modele, 3), "C_FindObjectsInit")
        trouves = (CK_ULONG * 2)()
        n = CK_ULONG(0)
        try:
            self.verifier(self.f["C_FindObjects"](self.session, trouves, 2, ctypes.byref(n)), "C_FindObjects")
        finally:
            self.f["C_FindObjectsFinal"](self.session)
        if n.value == 0:
            raise ErreurPkcs11("clé CKK_EC_EDWARDS introuvable sous cette étiquette")
        if n.value > 1:
            raise ErreurPkcs11("plusieurs clés sous cette étiquette")
        return trouves[0]

    def attribut(self, objet, type_):
        a = (CK_ATTRIBUTE * 1)(CK_ATTRIBUTE(type_, None, 0))
        rv = self.f["C_GetAttributeValue"](self.session, objet, a, 1)
        if rv != CKR_OK:
            return None
        tampon = ctypes.create_string_buffer(a[0].ulValueLen)
        a[0].pValue = ctypes.cast(tampon, CK_VOID_P)
        self.verifier(self.f["C_GetAttributeValue"](self.session, objet, a, 1), "C_GetAttributeValue")
        return tampon.raw[: a[0].ulValueLen]

    def booleen(self, objet, type_):
        v = self.attribut(objet, type_)
        return None if v is None or len(v) != 1 else v[0] != 0

    def cle_publique(self, etiquette):
        pub = self.objet(CKO_PUBLIC_KEY, etiquette)
        params = self.attribut(pub, CKA_EC_PARAMS)
        if params == EC_PARAMS_NOM:
            forme_params = "curveName"
        elif params == EC_PARAMS_OID:
            forme_params = "oid"
        else:
            raise ErreurPkcs11("CKA_EC_PARAMS n'est pas edwards25519 (EX-11.10)")
        point = self.attribut(pub, CKA_EC_POINT)
        if point is None:
            raise ErreurPkcs11("CKA_EC_POINT illisible")
        if len(point) == 32:
            forme_point = "brut"
        elif len(point) == 34 and point[0] == 0x04 and point[1] == 0x20:
            # OCTET STRING DER autour des 32 octets (forme de certains jetons ; lecture 175).
            point, forme_point = point[2:], "der"
        else:
            raise ErreurPkcs11("CKA_EC_POINT : 32 octets attendus")
        priv = self.objet(CKO_PRIVATE_KEY, etiquette)
        return {
            "public_key": point.hex(),
            "ec_params": params.hex(),
            "ec_params_form": forme_params,
            "ec_point_form": forme_point,
            "extractable": self.booleen(priv, CKA_EXTRACTABLE),
            "sensitive": self.booleen(priv, CKA_SENSITIVE),
            "sign": self.booleen(priv, CKA_SIGN),
        }

    def signer(self, etiquette, mecanisme, message):
        priv = self.objet(CKO_PRIVATE_KEY, etiquette)
        # Sans paramètre : Ed25519 pur (EX-11.10, table des schémas de PKCS#11 3.1 § 6.3.14).
        mech = CK_MECHANISM(mecanisme, None, 0)
        self.verifier(self.f["C_SignInit"](self.session, ctypes.byref(mech), priv), "C_SignInit")
        m = (ctypes.c_ubyte * max(len(message), 1)).from_buffer_copy(message or b"\0")
        sig = (ctypes.c_ubyte * 64)()
        n = CK_ULONG(64)
        # Une seule partie (EX-11.10) : C_Sign, jamais C_SignUpdate/C_SignFinal.
        self.verifier(self.f["C_Sign"](self.session, m, len(message), sig, ctypes.byref(n)), "C_Sign")
        return bytes(sig[: n.value])

    def sante(self):
        info = ctypes.create_string_buffer(64)
        rv = self.f["C_GetSessionInfo"](self.session, info)
        if rv != CKR_OK:
            # Session perdue (jeton retiré, module redémarré) : une réouverture.
            self.ouvrir()


def repondre(objet):
    sys.stdout.write(json.dumps(objet) + "\n")
    sys.stdout.flush()


def principal():
    if len(sys.argv) != 3:
        sys.stderr.write("usage : pkcs11-auxiliaire.py <module> <étiquette du jeton>\n")
        return 2
    ligne = sys.stdin.readline()
    try:
        pin = bytes.fromhex(ligne.strip())
    except ValueError:
        repondre({"ok": False, "error": "PIN illisible", "rv": None})
        return 2
    try:
        jeton = Jeton(sys.argv[1], sys.argv[2], pin)
    except (OSError, ErreurPkcs11) as e:
        repondre({"ok": False, "error": f"ouverture : {e}", "rv": getattr(e, "rv", None)})
        return 3
    repondre({"ok": True, "pret": True})
    for ligne in sys.stdin:
        try:
            r = json.loads(ligne)
            op = r.get("op")
            if op == "public_key":
                repondre({"ok": True, **jeton.cle_publique(r["label"])})
            elif op == "sign":
                repondre({"ok": True, "signature": jeton.signer(r["label"], int(r["mechanism"]), bytes.fromhex(r["message"])).hex()})
            elif op == "health":
                jeton.sante()
                repondre({"ok": True})
            else:
                repondre({"ok": False, "error": "opération inconnue", "rv": None})
        except ErreurPkcs11 as e:
            repondre({"ok": False, "error": str(e), "rv": e.rv})
        except (ValueError, KeyError, TypeError) as e:
            repondre({"ok": False, "error": f"requête mal formée : {type(e).__name__}", "rv": None})
    return 0


if __name__ == "__main__":
    sys.exit(principal())
