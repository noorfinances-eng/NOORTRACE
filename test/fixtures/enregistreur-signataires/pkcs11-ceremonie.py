#!/usr/bin/env python3
# Cérémonie de test (CT-7 §5, réduite) sur un jeton PKCS#11 logiciel : génère
# une paire Ed25519 (CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS), non
# extractible et sensible, sous une étiquette ; ou une paire extractible pour
# les essais de refus. Identité d'administration : jamais employée par le
# démon (EX-11.4), d'où ce script séparé de l'auxiliaire.
#
# usage : pkcs11-ceremonie.py <module> <jeton> <pin> <étiquette> <forme : curveName|oid> [extractible]

import ctypes
import importlib.util
import os
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
AUX = os.path.join(ICI, "..", "..", "..", "paquets", "enregistreur", "src", "signataires", "pkcs11-auxiliaire.py")
sys.dont_write_bytecode = True  # aucun __pycache__ dans le paquet
spec = importlib.util.spec_from_file_location("auxiliaire", AUX)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055
CKA_TOKEN = 0x1
CKA_PRIVATE = 0x2
CKA_VERIFY = 0x10A


def attributs(liste):
    gardes = []
    tab = (A.CK_ATTRIBUTE * len(liste))()
    for i, (t, v) in enumerate(liste):
        if isinstance(v, bool):
            b = ctypes.c_ubyte(1 if v else 0)
            gardes.append(b)
            tab[i] = A.CK_ATTRIBUTE(t, ctypes.cast(ctypes.byref(b), A.CK_VOID_P), 1)
        else:
            b = ctypes.create_string_buffer(v, len(v))
            gardes.append(b)
            tab[i] = A.CK_ATTRIBUTE(t, ctypes.cast(b, A.CK_VOID_P), len(v))
    return tab, gardes


def main():
    module, jeton, pin, etiquette, forme = sys.argv[1:6]
    extractible = len(sys.argv) > 6 and sys.argv[6] == "extractible"
    j = A.Jeton(module, jeton, pin.encode())
    # Session en lecture-écriture (CKF_RW_SESSION) : celle de l'auxiliaire est en lecture seule.
    h = A.CK_ULONG(0)
    j.verifier(j.f["C_OpenSession"](j.emplacement(), A.CKF_SERIAL_SESSION | 0x2, None, None, ctypes.byref(h)), "C_OpenSession")
    j.session = h.value
    liste = ctypes.POINTER(A.CK_FUNCTION_LIST)()
    j.bib.C_GetFunctionList(ctypes.byref(liste))
    gen = ctypes.CFUNCTYPE(A.CK_RV, A.CK_ULONG, ctypes.POINTER(A.CK_MECHANISM), ctypes.POINTER(A.CK_ATTRIBUTE), A.CK_ULONG,
                           ctypes.POINTER(A.CK_ATTRIBUTE), A.CK_ULONG, A.CK_ULONG_P, A.CK_ULONG_P)(liste.contents.C_GenerateKeyPair)
    params = A.EC_PARAMS_NOM if forme == "curveName" else A.EC_PARAMS_OID
    lab = etiquette.encode()
    pub, g1 = attributs([(CKA_TOKEN, True), (A.CKA_LABEL, lab), (A.CKA_EC_PARAMS, params), (CKA_VERIFY, True)])
    priv, g2 = attributs([(CKA_TOKEN, True), (CKA_PRIVATE, True), (A.CKA_LABEL, lab), (A.CKA_SIGN, True),
                          (A.CKA_SENSITIVE, not extractible), (A.CKA_EXTRACTABLE, extractible)])
    mech = A.CK_MECHANISM(CKM_EC_EDWARDS_KEY_PAIR_GEN, None, 0)
    hp, hs = A.CK_ULONG(0), A.CK_ULONG(0)
    rv = gen(j.session, ctypes.byref(mech), pub, len(pub), priv, len(priv), ctypes.byref(hp), ctypes.byref(hs))
    if rv != 0:
        sys.stderr.write(f"C_GenerateKeyPair : CKR 0x{rv:x}\n")
        return 1
    print(j.cle_publique(etiquette)["public_key"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
