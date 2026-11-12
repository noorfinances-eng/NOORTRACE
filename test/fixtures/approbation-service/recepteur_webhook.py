"""Récepteur de webhook de notifications, tiers des essais du service
d'approbation (CT-3 EX-13.41, EX-13.42 ; CT-9 TI-21, TA-102).

Écrit avec la seule bibliothèque standard de Python : il recalcule sur les
octets reçus le HMAC-SHA256 de clé K sur « noortrace/notification/v0\\n » ‖
corps, le compare à l'en-tête NOORTRACE-Signature par hmac.compare_digest,
consigne chaque requête (une ligne JSON par requête dans le fichier de
sortie), puis répond selon le scénario : une liste dont chaque élément est un
statut HTTP, ou « silence » (aucune réponse) ; au-delà de la liste, 200. Une
signature fausse ou absente reçoit 401, comme le relais d'un client le
devrait (EX-13.41).

Usage : python3 -I recepteur_webhook.py --cle <fichier> --sortie <fichier>
          [--scenario <fichier JSON>] [--cert <PEM> --key <PEM>]
Écrit {"port": <port>} sur la sortie standard quand il écoute (127.0.0.1).
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import ssl
import sys
import threading
import time

PREFIXE = b"noortrace/notification/v0\n"


def principal():
    p = argparse.ArgumentParser()
    p.add_argument("--cle", required=True)
    p.add_argument("--sortie", required=True)
    p.add_argument("--scenario")
    p.add_argument("--cert")
    p.add_argument("--key")
    a = p.parse_args()
    with open(a.cle, "rb") as f:
        cle = f.read().strip()
    scenario = []
    if a.scenario:
        with open(a.scenario, "r", encoding="utf-8") as f:
            scenario = json.load(f)
    verrou = threading.Lock()
    etat = {"rang": 0}

    class Gestion(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            corps = self.rfile.read(n)
            mac = hmac.new(cle, PREFIXE + corps, hashlib.sha256).hexdigest()
            entete = self.headers.get("NOORTRACE-Signature")
            valide = entete is not None and hmac.compare_digest(entete.encode("latin-1"), ("sha256=" + mac).encode("ascii"))
            with verrou:
                rang = etat["rang"]
                if valide:
                    etat["rang"] += 1
                reponse = scenario[rang] if valide and rang < len(scenario) else (200 if valide else 401)
                ligne = {
                    "t": time.time(),
                    "path": self.path,
                    "content_type": self.headers.get("Content-Type"),
                    "signature": entete,
                    "mac_recalcule": mac,
                    "signature_valide": valide,
                    "corps_b64": base64.b64encode(corps).decode("ascii"),
                    "reponse": reponse,
                }
                with open(a.sortie, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ligne) + "\n")
                    f.flush()
            if reponse == "silence":
                time.sleep(120)
                return
            corps_rep = b"{}"
            self.send_response(int(reponse))
            if 300 <= int(reponse) < 400:
                self.send_header("Location", "http://127.0.0.1:9/ailleurs")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps_rep)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(corps_rep)

    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gestion)
    serveur.daemon_threads = True
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)
        serveur.socket = ctx.wrap_socket(serveur.socket, server_side=True)
    sys.stdout.write(json.dumps({"port": serveur.server_address[1]}) + "\n")
    sys.stdout.flush()
    serveur.serve_forever()


if __name__ == "__main__":
    principal()
