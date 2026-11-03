"""Scénario TI-13 du SDK Python ``noortrace-sdk`` (CT-2 6.5), le même que
``scenario.mjs`` pour le SDK JavaScript : chaque fonction de l'interface
publique contre le démon réel du banc, puis le démon arrêté (session ouverte
avant l'arrêt) et un démon muet au-delà de ``delai_s``. Écrit sur sa sortie
standard une ligne JSON par étape, normalisée pour la comparaison entre les
deux langages (identifiants d'appel et de ticket ramenés à leur présence).

    python scenario.py <phase> <prise> <run_id>
    phase : « interface » (démon en marche), « arrete » (démon arrêté après
    l'ouverture d'une session : le banc l'arrête quand le script écrit
    ``pret-a-couper``), « muet » (prise d'un démon qui ne répond jamais).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "paquets" / "sdk-python" / "src"))

from noortrace_sdk import AppelNonAutorise, ClientNoortrace, NoortraceErreur  # noqa: E402


def sortie(etape, valeur):
    print(json.dumps({"etape": etape, "valeur": valeur}, sort_keys=True), flush=True)


def debut(d):
    return {"call": d.call is not None, "decision": d.decision, "ticket": d.ticket is not None, "ticket_state": d.ticket_state}


def erreur(e):
    nom = type(e).__name__
    attrs = {k: getattr(e, k) for k in ("envoyee", "raison", "decision", "ticket_state") if hasattr(e, k)}
    if "ticket" in dir(e):
        attrs["ticket"] = getattr(e, "ticket") is not None
    return {"classe": nom, **attrs}


def interface(prise, run_id):
    client = ClientNoortrace(socket=prise, delai_s=10)
    session = client.ouvrir(run_id=run_id)
    ref = session.declarer_contexte("autre", '{"note":"contexte ti13"}', media_type="application/json")
    sortie("declarer_contexte", {"sha256": ref.sha256, "length": ref.length, "redacted": ref.redacted})
    d1 = session.debut_appel("lire_fiche", {"id": "F1"}, classe="lecture", contexte=[ref.sha256])
    sortie("debut_appel_lecture", debut(d1))
    s1 = session.fin_appel(d1, {"fiche": "F1", "etat": "ouverte"}, False, 5)
    sortie("fin_appel", {"seq": isinstance(s1.seq, int), "hash": isinstance(s1.hash, str) and len(s1.hash) == 66})
    executions = []

    def ecrire_note(id, note):
        executions.append(id)
        return {"ok": True, "id": id}

    r2 = session.appel_outil("ecrire_note", {"id": "F1", "note": "relue"}, ecrire_note, classe="ecriture")
    sortie("appel_outil_ecriture", {"resultat": r2, "executions": len(executions)})
    sortie("debut_appel_a_approuver", debut(session.debut_appel("approuver_virement", {"montant": "9000.00"}, classe="ecriture")))
    sortie("debut_appel_refuse", debut(session.debut_appel("refuser_virement", {"montant": "1.00"}, classe="ecriture")))
    try:
        session.appel_outil("refuser_virement", {"montant": "2.00"}, ecrire_note, classe="ecriture")
        sortie("appel_outil_refuse", "aucune exception")
    except AppelNonAutorise as e:
        sortie("appel_outil_refuse", {**erreur(e), "texte": e.texte, "executions": len(executions)})
    e5 = session.echange_modele("autre", "simule", {"q": "statut"}, {"r": "ouvert"}, 200, 3, False)
    sortie("echange_modele", {"seq": isinstance(e5.seq, int), "hash": isinstance(e5.hash, str)})
    sortie("fermer", session.fermer())


def arrete(prise, run_id):
    client = ClientNoortrace(socket=prise, delai_s=2, reprises=0)
    session = client.ouvrir(run_id=run_id)
    print(json.dumps({"etape": "pret-a-couper"}), flush=True)
    sys.stdin.readline()
    executions = []
    try:
        session.appel_outil("ecrire_note", {"id": "F2", "note": "x"}, lambda id, note: executions.append(id), classe="ecriture")
        sortie("appel_outil_demon_arrete", "aucune exception")
    except NoortraceErreur as e:
        sortie("appel_outil_demon_arrete", {**erreur(e), "executions": len(executions)})
    try:
        ClientNoortrace(socket=prise, delai_s=2, reprises=0).ouvrir(run_id=run_id)
        sortie("ouvrir_demon_arrete", "aucune exception")
    except NoortraceErreur as e:
        sortie("ouvrir_demon_arrete", erreur(e))


def muet(prise, run_id):
    try:
        ClientNoortrace(socket=prise, delai_s=0.5, reprises=0).ouvrir(run_id=run_id)
        sortie("ouvrir_demon_muet", "aucune exception")
    except NoortraceErreur as e:
        sortie("ouvrir_demon_muet", erreur(e))


if __name__ == "__main__":
    {"interface": interface, "arrete": arrete, "muet": muet}[sys.argv[1]](sys.argv[2], sys.argv[3])
