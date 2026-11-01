"""Confrontation des paquets réviseurs de CT-8 par tarfile de Python.

CT-8, annexe A.15 (EX-A.32 à EX-A.35). N'emploie que la bibliothèque standard
(tarfile, hashlib, json, os, sys), aucun code du dépôt, aucune connexion.

Pour chaque archive de spec/vecteurs/ct-8/paquets/ (ordre des octets du nom) :

- SHA-256 de l'archive (hashlib), comparé à archive_sha256 de cas.json ;
- membres lus par tarfile : type, nom, taille, mode, propriétaires, date,
  cible de lien, en-têtes pax ;
- extraction par extractall(filter="data") dans un répertoire neuf et vide,
  exception éventuelle ; liens extraits ; entrées apparues hors de la
  destination ;
- SHA-256 (hashlib) de chaque fichier déclaré par le manifeste extrait,
  fichiers extraits absents du manifeste, membres lus comparés au manifeste ;
- résultat comparé à l'attendu de CT-8 (cas.json, cas sans option qui porte
  sur l'archive), selon la même règle que confronter_gnutar.sh : paquet
  intact lu sans écart ; écart au manifeste (PR-8) trouvé ; autre refus de
  CT-8 (PR-4, PR-5, PR-6) concordant si tarfile refuse l'extraction, sinon
  consigné comme limite de l'outil.

Code 0 sans discordance, 1 avec au moins une discordance, 2 en cas d'usage
incorrect.

    python3 -I confronter_tarfile.py <répertoire des paquets> \
        <répertoire de travail vide>
"""
import hashlib
import json
import os
import sys
import tarfile

TYPES = {
    tarfile.REGTYPE: "fichier",
    tarfile.AREGTYPE: "fichier-ancien",
    tarfile.LNKTYPE: "lien-physique",
    tarfile.SYMTYPE: "lien-symbolique",
    tarfile.DIRTYPE: "repertoire",
}
MANIFESTE = "paquet-reviseur/MANIFESTE.json"


def sha256_fichier(chemin):
    with open(chemin, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def sans_doublon(paires):
    cles = [k for k, _ in paires]
    if len(cles) != len(set(cles)):
        raise ValueError("clé en double")
    return dict(paires)


def lister(titre, elements, aucun="aucun"):
    if not elements:
        print(f"{titre} : {aucun}")
        return
    print(f"{titre} : {len(elements)}")
    for e in elements:
        print(f"  {e}")


def masquer(texte, travail, paquets):
    return texte.replace(travail, "<travail>").replace(paquets, "<paquets>")


def hors_destination(travail, paquets):
    """Entrées qui ne sont ni aux/, ni extraits/, ni extraits/<archive>/, ni
    extraits/<archive>/dest/ : trois niveaux au-dessus de chaque destination
    sont surveillés, comme dans confronter_gnutar.sh."""
    hors = []
    for n in os.listdir(travail):
        if n not in ("aux", "extraits"):
            hors.append(n)
    extraits = os.path.join(travail, "extraits")
    for n in os.listdir(extraits):
        p = os.path.join(extraits, n)
        if os.path.islink(p) or not os.path.isdir(p) or not os.path.isfile(os.path.join(paquets, n + ".tar")):
            hors.append(f"extraits/{n}")
            continue
        for k in os.listdir(p):
            if k != "dest" or os.path.islink(os.path.join(p, k)):
                hors.append(f"extraits/{n}/{k}")
    return sorted(hors, key=lambda x: x.encode())


def main(argv):
    if len(argv) != 3:
        print("usage : python3 -I confronter_tarfile.py <répertoire des paquets> <répertoire de travail vide>", file=sys.stderr)
        return 2
    paquets = os.path.realpath(argv[1])
    travail = os.path.realpath(argv[2])
    if not os.path.isdir(paquets) or not os.path.isdir(travail):
        print("répertoire absent", file=sys.stderr)
        return 2
    if os.listdir(travail):
        print("répertoire de travail non vide", file=sys.stderr)
        return 2
    try:
        with open(os.path.join(paquets, "cas.json"), "rb") as f:
            cas = json.loads(f.read(), object_pairs_hook=sans_doublon)["cases"]
    except (OSError, ValueError, KeyError) as e:
        print(f"cas.json illisible : {type(e).__name__}", file=sys.stderr)
        return 2
    os.mkdir(os.path.join(travail, "extraits"), 0o700)
    os.mkdir(os.path.join(travail, "aux"), 0o700)
    archives = sorted((n for n in os.listdir(paquets) if n.endswith(".tar") and os.path.isfile(os.path.join(paquets, n))), key=lambda n: n.encode())
    print(f"# Confrontation des paquets réviseurs de CT-8 par Python {sys.version.split()[0]}, tarfile, extractall(filter=\"data\"), hashlib")
    print(f"# Archives : {len(archives)} ; cas.json : {len(cas)} cas")
    bilan = {"concorde": 0, "limite_de_l_outil": 0, "discordance": 0}

    for archive in archives:
        nom = archive[:-4]
        chemin = os.path.join(paquets, archive)
        print()
        print(f"== {archive}")
        base = [c for c in cas if c["archive"] == archive and c["options"]["expected_sha256"] is None and c["options"]["anchors"] is None]
        if not base:
            print("attendu : aucun cas sans option dans cas.json : DISCORDANCE")
            bilan["discordance"] += 1
            continue
        base = base[0]
        statut = base["expected"]["package_status"]
        regle = ",".join(c["id"] for c in base["expected"]["checks"] if c["status"] == "echoue")
        calcule = sha256_fichier(chemin)
        attendu = base["archive_sha256"].removeprefix("0x")
        sha_ok = calcule == attendu
        print(f"hashlib : {calcule} ; cas.json : concorde" if sha_ok else f"hashlib : {calcule} ; cas.json : {attendu} : DISCORDANCE")
        if statut == "intact":
            print(f"attendu (cas.json, cas {base['name']}) : paquet intact")
        else:
            print(f"attendu (cas.json, cas {base['name']}) : paquet {statut}, {regle} en échec")

        dest = os.path.join(travail, "extraits", nom, "dest")
        os.makedirs(dest, 0o700)
        with tarfile.open(chemin, mode="r:") as t:
            membres = t.getmembers()
            print(f"-- membres lus (tarfile) : {len(membres)}")
            for m in membres:
                pax = json.dumps(m.pax_headers, ensure_ascii=False, sort_keys=True)
                print(f"{TYPES.get(m.type, repr(m.type))} {m.name!r} taille={m.size} mode={m.mode:04o} "
                      f"uid={m.uid} gid={m.gid} uname={m.uname!r} gname={m.gname!r} mtime={m.mtime} "
                      f"lien={m.linkname!r} pax={pax}")
            try:
                t.extractall(dest, filter="data")
                outil = "accepte"
                print("-- extraction (extractall, filter=\"data\", répertoire neuf et vide) : réussie")
            except (tarfile.TarError, OSError) as e:
                outil = "refuse"
                print(f"-- extraction (extractall, filter=\"data\", répertoire neuf et vide) : refusée, {type(e).__name__}")
                print(f"message : {masquer(str(e), travail, paquets)}")

        liens = []
        fichiers = []
        for racine, reps, noms in os.walk(dest):
            for n in reps + noms:
                p = os.path.join(racine, n)
                rel = os.path.relpath(p, dest)
                if os.path.islink(p):
                    liens.append(f"{rel} -> {os.readlink(p)}")
                elif n in noms and os.path.isfile(p):
                    fichiers.append(rel)
        liens.sort()
        lister("-- liens extraits", liens)
        hors = hors_destination(travail, paquets)
        lister("-- entrées hors de la destination", hors, "aucune")

        ecarts = []
        m = os.path.join(dest, *MANIFESTE.split("/"))
        try:
            if os.path.islink(m):
                raise ValueError("lien")
            with open(m, "rb") as f:
                declares = json.loads(f.read(), object_pairs_hook=sans_doublon)["files"]
            if not isinstance(declares, list):
                raise TypeError("files")
        except (OSError, ValueError, KeyError, TypeError):
            declares = None
        if declares is None:
            print("-- manifeste extrait : absent ou illisible ; manifeste non extrait")
            nb_ecarts = 1
        else:
            print(f"-- manifeste extrait : {len(declares)} fichiers déclarés")
            for d in declares:
                p = os.path.join(dest, "paquet-reviseur", *d["path"].split("/"))
                if not os.path.isfile(p) or os.path.islink(p):
                    ecarts.append(f"{d['path']} : absent")
                elif "0x" + sha256_fichier(p) != d["sha256"]:
                    ecarts.append(f"{d['path']} : SHA-256 différent")
            noms_declares = {"paquet-reviseur/" + d["path"] for d in declares}
            for p in sorted(fichiers, key=lambda x: x.encode()):
                if p != MANIFESTE and p not in noms_declares:
                    ecarts.append(f"{p} : extrait, absent du manifeste")
            lister("-- écarts au manifeste (hashlib, fichiers extraits)", ecarts)
            tailles = {"paquet-reviseur/" + d["path"]: d["size"] for d in declares}
            vus = set()
            lus = []
            for mb in membres:
                if mb.name == MANIFESTE:
                    continue
                if mb.name in vus:
                    lus.append(f"nom répété : {mb.name}")
                    continue
                vus.add(mb.name)
                if not mb.isreg():
                    lus.append(f"membre d'un autre type ({TYPES.get(mb.type, repr(mb.type))}) : {mb.name}")
                elif mb.name not in tailles:
                    lus.append(f"membre non déclaré : {mb.name}")
                elif mb.size != tailles[mb.name]:
                    lus.append(f"taille {mb.size} au lieu de {tailles[mb.name]} : {mb.name}")
            lus += [f"déclaré, non lu : {d}" for d in tailles if d not in vus]
            lus.sort(key=lambda x: x.encode())
            lister("-- membres lus contre le manifeste (nom, type, taille)", lus)
            nb_ecarts = len(ecarts) + len(lus) + len(liens)

        if hors:
            verdict = "DISCORDANCE (écriture hors de la destination)"
        elif not sha_ok:
            verdict = "DISCORDANCE (archive autre que celle de cas.json)"
        elif statut == "intact":
            verdict = "concorde" if outil == "accepte" and nb_ecarts == 0 else "DISCORDANCE"
        elif regle == "PR-8":
            verdict = "concorde" if nb_ecarts > 0 or outil == "refuse" else "DISCORDANCE"
        else:
            verdict = "concorde" if outil == "refuse" else "limite_de_l_outil"
        print(f"-- résultat : tarfile {outil} ; écarts au manifeste {nb_ecarts} ; verdict {verdict}")
        bilan["discordance" if verdict.startswith("DISCORDANCE") else verdict] += 1

    print()
    print(f"# bilan : {len(archives)} archives ; concorde {bilan['concorde']}, limite_de_l_outil {bilan['limite_de_l_outil']}, discordance {bilan['discordance']}")
    return 0 if bilan["discordance"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
