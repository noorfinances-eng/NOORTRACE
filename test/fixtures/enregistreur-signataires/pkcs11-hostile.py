#!/usr/bin/env python3
# Auxiliaire PKCS#11 hostile des tests : l'auxiliaire livré, dont la
# signature est altérée selon NOORTRACE_TEST_PKCS11_MODE :
#   longueur      signature tronquée à 63 octets
#   autre_message signature (valide) d'un autre message
#   autre_cle     signature par la clé d'étiquette NOORTRACE_TEST_PKCS11_AUTRE
#   lent          ne répond jamais à une signature
# Sert à éprouver la vérification d'EX-11.6 et le délai d'EX-11.18.

import importlib.util
import os
import sys
import time

ICI = os.path.dirname(os.path.abspath(__file__))
AUX = os.path.join(ICI, "..", "..", "..", "paquets", "enregistreur", "src", "signataires", "pkcs11-auxiliaire.py")
sys.dont_write_bytecode = True  # aucun __pycache__ dans le paquet
spec = importlib.util.spec_from_file_location("auxiliaire", AUX)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

MODE = os.environ.get("NOORTRACE_TEST_PKCS11_MODE", "")
signer = A.Jeton.signer


def hostile(self, etiquette, mecanisme, message):
    if MODE == "lent":
        time.sleep(3600)
    if MODE == "autre_message":
        return signer(self, etiquette, mecanisme, message + b"\0")
    if MODE == "autre_cle":
        return signer(self, os.environ["NOORTRACE_TEST_PKCS11_AUTRE"], mecanisme, message)
    sig = signer(self, etiquette, mecanisme, message)
    return sig[:63] if MODE == "longueur" else sig


A.Jeton.signer = hostile
sys.exit(A.principal())
