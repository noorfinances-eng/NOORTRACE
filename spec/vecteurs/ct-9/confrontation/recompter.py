#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recomptage indépendant de CT-9 (annexe A.11, EX-A.18).

Usage : python3 -I spec/vecteurs/ct-9/confrontation/recompter.py <racine>

Bibliothèque standard seule ; aucune ligne de code du dépôt n'est reprise :
les règles sont relues dans le texte de CT-9 (0.1, 0.2, 3.3, 4.1, 4.2, 5.1,
5.2, 5.5, 10.7, 10.8, 11.5, 12.2, A.6, A.11) et traduites en expressions
régulières propres à ce programme. Il recompte :

- les identifiants définis par spec/CT-1-*.md à CT-8-*.md (5.2), par
  spécification et par famille, puis la règle (a) de 5.1 (couvert par une
  entrée, par une justification NC-, non couvert ; identifiant cité inconnu,
  EX-5.5) ;
- les occurrences de « CT-9 » dans ces fichiers et spec/README.md, leur clé
  de section (0.2) et les lignes TC- (règle (c)) ;
- les menaces et les risques acceptés de spec/vecteurs/ct-7/menaces.json
  contre les TA- du catalogue (règle (b), 10.2, 10.6) et l'index des TA- par
  menace ;
- les titres describe/it de test/*.test.js et les étapes « - name: » de
  .github/workflows/ci.yml cités par les entrées exécutables (règle (d),
  EX-4.2) ;
- les it de test/adversarial.test.js dont le titre commence par « TA- »
  (EX-10.7, 10.8, EX-A.11) ;
- les lignes TM- et TR- des tables 11.5 et 12.2 du texte et du catalogue et
  les identifiants de leurs covers ; la table des chiffres de 5.5.

Chaque compte est comparé à spec/vecteurs/ct-9/couverture.json, au catalogue
et aux chiffres écrits dans le texte de CT-9. Sortie : texte déterministe
(aucun chemin absolu, aucune date, aucune version d'outil), publié sous
confrontation/sorties/recompte.txt. Codes : 0 sans discordance ; 1 avec au
moins une ; 2 si l'usage ou un fichier est incorrect. Un écart voulu,
déclaré avec sa raison dans LISEZMOI.md (EX-A.18), est imprimé « [DECLARE] »
et ne compte pas comme discordance.
"""

import json
import os
import re
import sys

# --- 5.2 : identifiants définis par une spécification ---------------------
# « les EX- en gras (**EX-s.k** ou **EX-s.k () »
RE_EX = re.compile(r"\*\*(EX-[0-9A-Z]+\.[0-9]+)(?:\*\*| \()")
# « les familles à la première cellule d'une ligne de table (| XX-k |, gras
# retiré) » ; les familles de la table de 5.2 ont un à trois majuscules,
# parfois deux groupes (AV-AT, AV-PR).
RE_FAMILLE = re.compile(
    r"^\|\s*(?:\*\*)?([A-Z]{1,3}(?:-[A-Z]{1,3})?-[0-9]+)(?:\*\*)?\s*\|")
# CT-8 seulement : « les lignes DM-n en début de ligne », « **IR-n**,
# **IC-n** en gras », « RB-1 à RB-8 lus dans les titres ### 10.12 à
# ### 10.19 ».
RE_DM = re.compile(r"^(DM-[0-9]+)\b")
RE_IR_IC = re.compile(r"\*\*(I[RC]-[0-9]+)\*\*")
RE_RB = re.compile(r"^### 10\.1[2-9] (RB-[1-8])\b")
EXCLUS = ("CT-", "EIP-")
RE_SPEC = re.compile(r"^CT-([1-8])-[^/]*\.md$")
RE_NUMERO = re.compile(r"-[0-9]+$|\.[0-9]+$")

# --- 0.2 : clé de section d'une occurrence de « CT-9 » ---------------------
RE_TITRE = re.compile(r"^#{2,4} (.+?)\s*$")
RE_NUMERO_TITRE = re.compile(r"^(?:[0-9]+(?:\.[0-9]+)*\.?|[A-Z]\.[0-9]+)$")

# --- EX-4.2 : titres de tests et étapes de CI ------------------------------
# Avant de chercher describe( et it(, le source JavaScript est masqué : les
# commentaires, les expressions rationnelles littérales et l'intérieur des
# chaînes (", ', `) sont remplacés par des espaces, les délimiteurs des
# chaînes restent. Le titre est le texte source entre ses délimiteurs,
# échappements compris, avant toute interpolation.
AVANT_RATIONNELLE = set("(,=:[!&|?{};+-*%<>~^")
MOTS_AVANT_RATIONNELLE = {"return", "typeof", "case", "in", "of", "void",
                          "delete", "throw", "new", "else", "do", "yield", "await"}
RE_APPEL = re.compile(r"(?<![A-Za-z0-9_$.])(describe|it)\(\s*(?=[\"'`])")
RE_NAME = re.compile(r"^\s*- name: (.*?)\s*$")

# --- EX-10.7 : titre d'un it de test/adversarial.test.js -------------------
RE_TITRE_TA = re.compile(
    r"^(TA-[0-9]+(?: et TA-[0-9]+)*) \((MN-[0-9]+(?:, MN-[0-9]+)*)")

NIVEAUX = ("TU", "TV", "TI", "TE", "TA", "TM", "TR", "TQ")

ECARTS = []       # discordances : chacune rend le code 1
DECLARES = []     # écarts voulus, déclarés avec leur raison dans LISEZMOI.md
LIGNES = []


def dire(texte=""):
    LIGNES.append(texte)


def ecart(texte):
    ECARTS.append(texte)


def declare(texte):
    DECLARES.append(texte)


def lire(racine, *rel):
    with open(os.path.join(racine, *rel), encoding="utf-8") as f:
        return f.read()


def lire_json(racine, *rel):
    return json.loads(lire(racine, *rel))


def nombre(ident):
    m = re.search(r"([0-9]+)$", ident)
    return int(m.group(1)) if m else 0


def famille(ident):
    """« EX-10.3 » → « EX-10 » ; « AV-AT-3 » → « AV-AT » ; « MN-17 » → « MN »."""
    return RE_NUMERO.sub("", ident)


def tri_ident(ident):
    return (famille(ident), nombre(ident), ident)


def liste(ids, n=12):
    ids = sorted(ids, key=tri_ident)
    return ", ".join(ids[:n]) + (" …" if len(ids) > n else "")


# ---------------------------------------------------------------------------
def identifiants(ct, texte):
    """Identifiants définis par une spécification, règles de 5.2."""
    ids = set()
    code = False
    for ligne in texte.split("\n"):
        if ligne.startswith("```"):
            code = not code
            continue
        if ct == "CT-8":
            # Les lignes DM-n sont dans un bloc de code (le modèle de
            # dimensionnement) : 5.2 les compte « en début de ligne ».
            m = RE_DM.match(ligne)
            if m:
                ids.add(m.group(1))
        if code:
            continue
        for m in RE_EX.finditer(ligne):
            ids.add(m.group(1))
        m = RE_FAMILLE.match(ligne)
        if m and not m.group(1).startswith(EXCLUS):
            ids.add(m.group(1))
        if ct == "CT-8":
            for m in RE_IR_IC.finditer(ligne):
                ids.add(m.group(1))
            m = RE_RB.match(ligne)
            if m:
                ids.add(m.group(1))
    return ids


def familles(ids):
    d = {}
    for x in ids:
        d[famille(x)] = d.get(famille(x), 0) + 1
    return d


def texte_familles(d):
    return ", ".join("%s %d" % (k, d[k]) for k in sorted(d))


def table_5_2(texte_ct9):
    """Lignes « | CT-n (v) | EX | vérifications | total | familles | »."""
    out = {}
    for ligne in texte_ct9.split("\n"):
        m = re.match(r"^\| (CT-[1-8]) \([0-9.]+\) \| ([0-9]+) \| ([0-9]+) \| ([0-9]+) \| (.*) \|$", ligne)
        if m:
            fam = {}
            for morceau in m.group(5).split(", "):
                nom, n = morceau.rsplit(" ", 1)
                fam[nom] = int(n)
            out[m.group(1)] = (int(m.group(2)), int(m.group(3)), int(m.group(4)), fam)
    return out


# ---------------------------------------------------------------------------
def occurrences_ct9(texte, prefixe):
    """Occurrences de « CT-9 » et leur clé de section (0.2)."""
    cles = []
    lignes = 0
    section = "« en-tête »"
    code = False
    for ligne in texte.split("\n"):
        if ligne.startswith("```"):
            code = not code
        elif not code:
            m = RE_TITRE.match(ligne)
            if m:
                titre = m.group(1)
                premier = titre.split(" ", 1)[0]
                if RE_NUMERO_TITRE.match(premier):
                    section = "§" + premier.rstrip(".")
                else:
                    section = "« " + titre + " »"
        n = ligne.count("CT-9")
        if n:
            lignes += 1
            cles.extend([prefixe + " " + section] * n)
    return cles, lignes


def phrase_0_2(texte_ct9):
    """« (CT-1 : 1 ; … ; `spec/README.md` : 10 occurrences sur 5 lignes) »."""
    debut = texte_ct9.index("### 0.2 ")
    fin = texte_ct9.index("<!-- table TC -->")
    zone = texte_ct9[debut:fin]
    out = {}
    for m in re.finditer(r"(CT-[1-8]|`spec/README\.md`)\s+:\s+([0-9]+)(?:\s+occurrences\s+sur\s+([0-9]+)\s+lignes)?", zone):
        out[m.group(1)] = (int(m.group(2)), int(m.group(3)) if m.group(3) else int(m.group(2)))
    m = re.search(r"\*\*([0-9]+) occurrences sur ([0-9]+) lignes\*\*", zone)
    total = (int(m.group(1)), int(m.group(2))) if m else None
    return out, total


# ---------------------------------------------------------------------------
def cellules(ligne):
    corps = ligne.strip()
    if not (corps.startswith("|") and corps.endswith("|")):
        return None
    return [c.strip() for c in corps[1:-1].split("|")]


def tables_du_texte(texte_ct9):
    """Blocs « <!-- table X --> » : lignes de la table (en-tête compris)."""
    lignes = texte_ct9.split("\n")
    out = {}
    for i, l in enumerate(lignes):
        m = re.match(r"^<!-- table ([A-Za-z]+) -->$", l)
        if not m:
            continue
        bloc = []
        for j in range(i + 1, len(lignes)):
            if not lignes[j].startswith("|"):
                break
            bloc.append(lignes[j])
        out[m.group(1)] = bloc
    return out


def lignes_table(bloc):
    """Cellules des lignes de données (après l'en-tête et la règle)."""
    return [cellules(l) for l in bloc[2:]]


# ---------------------------------------------------------------------------
def masquer(source):
    """Masque du source : commentaires, rationnelles et intérieurs de chaînes
    remplacés par des espaces (les sauts de ligne sont gardés). Retourne le
    masque et, par position du délimiteur ouvrant, l'intervalle du titre."""
    n = len(source)
    masque = list(source)
    chaines = {}
    i = 0
    dernier = ""          # dernier caractère ou mot significatif lu
    while i < n:
        c = source[i]
        if c == "/" and source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                masque[k] = " "
            i = j
            continue
        if c == "/" and source.startswith("/*", i):
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if masque[k] != "\n":
                    masque[k] = " "
            i = j
            continue
        if c in "\"'`":
            j = i + 1
            profondeur = 0
            while j < n:
                d = source[j]
                if d == "\\":
                    j += 2
                    continue
                if c == "`" and source.startswith("${", j):
                    profondeur += 1
                    j += 2
                    continue
                if c == "`" and profondeur and d == "}":
                    profondeur -= 1
                elif d == c and not profondeur:
                    break
                elif c != "`" and d == "\n":
                    break
                j += 1
            chaines[i] = (i + 1, j)
            for k in range(i + 1, j):
                if masque[k] != "\n":
                    masque[k] = " "
            i = j + 1
            dernier = "\""
            continue
        if c == "/" and (dernier == "" or dernier in AVANT_RATIONNELLE or dernier in MOTS_AVANT_RATIONNELLE):
            j = i + 1
            classe = False
            while j < n and source[j] != "\n":
                d = source[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "[":
                    classe = True
                elif d == "]":
                    classe = False
                elif d == "/" and not classe:
                    break
                j += 1
            j += 1
            while j < n and (source[j].isalpha()):
                j += 1
            for k in range(i, j):
                masque[k] = " "
            i = j
            dernier = "/"
            continue
        if c.isalnum() or c in "_$":
            j = i
            while j < n and (source[j].isalnum() or source[j] in "_$"):
                j += 1
            dernier = source[i:j]
            i = j
            continue
        if not c.isspace():
            dernier = c
        i += 1
    return "".join(masque), chaines


def analyser_tests(source):
    """describe/it d'un fichier mocha (EX-4.2).

    Retourne (describes, its) : describes = liste de (titre, debut, fin) ;
    its = liste de (titre, position). Les accolades sont comptées sur le
    masque ; le titre est le texte source entre ses délimiteurs."""
    masque, chaines = masquer(source)
    fermante = {}
    pile = []
    for k, c in enumerate(masque):
        if c == "{":
            pile.append(k)
        elif c == "}" and pile:
            fermante[pile.pop()] = k
    describes, its = [], []
    for m in RE_APPEL.finditer(masque):
        pos = m.end()
        if pos not in chaines:
            continue
        a, b = chaines[pos]
        titre = source[a:b]
        if m.group(1) == "it":
            its.append((titre, m.start()))
        else:
            ouvrante = masque.find("{", b)
            fin = fermante.get(ouvrante, len(masque))
            describes.append((titre, m.start(), fin))
    return describes, its


def titre_existe(index, cite):
    if cite["file"] not in index:
        return False
    describes, its = index[cite["file"]]
    blocs = [(a, b) for t, a, b in describes if t == cite["describe"]]
    if not blocs:
        return False
    if cite.get("it") is None:
        return True
    return any(t == cite["it"] and any(a <= p <= b for a, b in blocs) for t, p in its)


# ---------------------------------------------------------------------------
def etat_attendu(status):
    if status["state"] == "a_ecrire":
        return "à écrire (étape %d)" % status["phase2_step"]
    return "exécutable"


def main(argv):
    if len(argv) != 2:
        print("usage : python3 -I recompter.py <racine du dépôt>", file=sys.stderr)
        return 2
    racine = argv[1]
    try:
        couverture = lire_json(racine, "spec", "vecteurs", "ct-9", "couverture.json")
        catalogue = lire_json(racine, "spec", "vecteurs", "ct-9", "catalogue.json")
        index_ta = lire_json(racine, "spec", "vecteurs", "ct-9", "index-ta-par-menace.json")
        menaces = lire_json(racine, "spec", "vecteurs", "ct-7", "menaces.json")
        texte_ct9 = lire(racine, "spec", "CT-9-plan-de-tests.md")
        readme = lire(racine, "spec", "README.md")
        ci = lire(racine, ".github", "workflows", "ci.yml")
        fichiers = {}
        for nom in sorted(os.listdir(os.path.join(racine, "spec"))):
            m = RE_SPEC.match(nom)
            if m:
                fichiers["CT-" + m.group(1)] = lire(racine, "spec", nom)
        if len(fichiers) != 8:
            raise OSError("spec/CT-1-*.md à CT-8-*.md : %d fichiers trouvés" % len(fichiers))
        sources_tests = {}
        for nom in sorted(os.listdir(os.path.join(racine, "test"))):
            if nom.endswith(".test.js"):
                sources_tests["test/" + nom] = lire(racine, "test", nom)
    except (OSError, ValueError) as e:
        print("fichier illisible : %s" % e, file=sys.stderr)
        return 2

    tests = catalogue["tests"]
    par_id = {t["id"]: t for t in tests}
    tables = tables_du_texte(texte_ct9)

    dire("Recomptage indépendant de CT-9 (annexe A.11, EX-A.18)")
    dire("Programme : confrontation/recompter.py, python3 -I, bibliothèque standard.")
    dire("Comparé à : couverture.json, catalogue.json, index-ta-par-menace.json,")
    dire("menaces.json et aux chiffres écrits dans le texte de CT-9.")

    # 1. Identifiants (5.2) ---------------------------------------------------
    dire()
    dire("1. Identifiants définis par CT-1 à CT-8 (5.2)")
    inventaire = {ct: identifiants(ct, fichiers[ct]) for ct in sorted(fichiers)}
    par_spec = {p["spec"]: p for p in couverture["identifiers"]["per_spec"]}
    t52 = table_5_2(texte_ct9)
    total = 0
    for ct in sorted(inventaire):
        ids = inventaire[ct]
        total += len(ids)
        fam = familles(ids)
        n_ex = sum(1 for x in ids if x.startswith("EX-"))
        fam_hors_ex = {k: v for k, v in fam.items() if not k.startswith("EX-")}
        dire("  %s : %d identifiants (%d EX-, %d de famille), %d familles" % (
            ct, len(ids), n_ex, len(ids) - n_ex, len(fam)))
        dire("    familles : %s" % texte_familles(fam))
        p = par_spec.get(ct)
        if p is None:
            ecart("%s : absent de couverture.json identifiers.per_spec" % ct)
        else:
            if p["total"] != len(ids):
                ecart("%s : %d identifiants recomptés, couverture.json en publie %d" % (ct, len(ids), p["total"]))
            if p["families"] != fam:
                ecart("%s : familles recomptées %s ; couverture.json : %s" % (ct, texte_familles(fam), texte_familles(p["families"])))
        ligne = t52.get(ct)
        if ligne is None:
            ecart("%s : absent de la table de 5.2" % ct)
        else:
            ex52, ver52, tot52, fam52 = ligne
            if (ex52, ver52, tot52) != (n_ex, len(ids) - n_ex, len(ids)):
                ecart("%s : table de 5.2 (%d, %d, %d) ; recompte (%d, %d, %d)" % (
                    ct, ex52, ver52, tot52, n_ex, len(ids) - n_ex, len(ids)))
            if fam52 != fam_hors_ex:
                ecart("%s : familles de la table de 5.2 %s ; recompte %s" % (ct, texte_familles(fam52), texte_familles(fam_hors_ex)))
    dire("  total : %d identifiants ; couverture.json : %d ; table de 5.2 : %d" % (
        total, couverture["identifiers"]["total"], sum(v[2] for v in t52.values())))
    if total != couverture["identifiers"]["total"]:
        ecart("total des identifiants : %d recomptés, %d publiés" % (total, couverture["identifiers"]["total"]))
    dire("  comparaison par spécification (total et familles) : %s" % (
        "égale" if all(par_spec.get(ct, {}).get("total") == len(inventaire[ct]) and par_spec.get(ct, {}).get("families") == familles(inventaire[ct]) for ct in inventaire) else "différente"))

    # 2. Règle (a) ---------------------------------------------------------------
    dire()
    dire("2. Règle (a) : couverture de chaque identifiant (5.1, EX-5.5)")
    par_entree = set()
    for t in tests:
        for c in t["covers"]:
            if "§" not in c:
                par_entree.add(c)
        for mn in t["threats"]:
            par_entree.add("CT-7 " + mn)
    par_nc = set()
    for nc in catalogue["non_tests"]:
        for c in nc["covers"]:
            if "§" not in c:
                par_nc.add(c)
    connus = {ct + " " + x for ct in inventaire for x in inventaire[ct]}
    inconnus = sorted((par_entree | par_nc) - connus)
    resume = {}
    for ct in sorted(inventaire):
        a = b = c = 0
        non_couverts = []
        for x in inventaire[ct]:
            cle = ct + " " + x
            if cle in par_entree:
                a += 1
            elif cle in par_nc:
                b += 1
            else:
                c += 1
                non_couverts.append(x)
        resume[ct] = (len(inventaire[ct]), a, b, c)
        p = par_spec.get(ct, {})
        dire("  %s : %d identifiants, %d par une entrée, %d par un NC-, %d non couvert(s)" % (ct, len(inventaire[ct]), a, b, c))
        if (p.get("covered_by_tests"), p.get("covered_by_nc"), p.get("uncovered")) != (a, b, c):
            ecart("%s : règle (a) recomptée (%d, %d, %d), couverture.json (%s, %s, %s)" % (
                ct, a, b, c, p.get("covered_by_tests"), p.get("covered_by_nc"), p.get("uncovered")))
        if non_couverts:
            ecart("%s : non couverts %s" % (ct, liste(non_couverts)))
    A = sum(v[1] for v in resume.values())
    B = sum(v[2] for v in resume.values())
    C = sum(v[3] for v in resume.values())
    I = couverture["identifiers"]
    dire("  total : %d par une entrée, %d par un NC-, %d non couvert(s), %d cité(s) inconnu(s)" % (A, B, C, len(inconnus)))
    dire("  couverture.json : %d, %d, %d, %d" % (I["covered_by_tests"], I["covered_by_nc"], I["uncovered"], len(I["unknown_cited"])))
    if (A, B, C, len(inconnus)) != (I["covered_by_tests"], I["covered_by_nc"], I["uncovered"], len(I["unknown_cited"])):
        ecart("règle (a) : totaux recomptés (%d, %d, %d, %d) différents de couverture.json" % (A, B, C, len(inconnus)))
    for x in inconnus:
        ecart("identifiant cité inconnu (EX-5.5) : %s" % x)
    # Chiffres de 5.5 écrits dans le texte.
    debut = texte_ct9.index("### 5.5 ")
    fin = texte_ct9.index("\n## 6. ")
    zone = texte_ct9[debut:fin]
    m = re.search(r"([0-9]+) identifiants définis par CT-1 à CT-8 : ([0-9]+) couverts par une entrée,\s+([0-9]+) par une justification NC-, \*\*([0-9]+) non couvert", zone)
    if m and tuple(int(x) for x in m.groups()) != (total, A, B, C):
        ecart("5.5 : « %s identifiants, %s, %s, %s » ; recompte (%d, %d, %d, %d)" % (m.groups() + (total, A, B, C)))
    if not m:
        ecart("5.5 : phrase des identifiants introuvable")
    par_spec_55 = {"CT-" + a: (int(b), int(c), int(d)) for a, b, c, d in re.findall(r"CT-([1-8]) ([0-9]+), ([0-9]+),\s+([0-9]+)", zone)}
    dire("  chiffres par spécification de 5.5 : %d lignes lues, %s" % (
        len(par_spec_55), "égaux au recompte" if all(par_spec_55.get(ct) == (resume[ct][0], resume[ct][1], resume[ct][2]) for ct in resume) else "différents"))
    for ct in sorted(resume):
        if par_spec_55.get(ct) != (resume[ct][0], resume[ct][1], resume[ct][2]):
            ecart("5.5 : %s %s dans le texte, recompte %s" % (ct, par_spec_55.get(ct), resume[ct][:3]))

    # 3. Occurrences de « CT-9 » (0.2, règle (c)) --------------------------------
    dire()
    dire("3. Occurrences de « CT-9 » et lignes TC- (0.2, règle (c))")
    cles = []
    total_lignes = 0
    attendu_0_2, total_0_2 = phrase_0_2(texte_ct9)
    tc_cles = [r["key"] for r in catalogue["traceability"]]
    for ct in sorted(fichiers):
        c, l = occurrences_ct9(fichiers[ct], ct)
        cles.extend(c)
        total_lignes += l
        n_tc = sum(1 for k in tc_cles if k.startswith(ct + " "))
        dire("  %s : %d occurrence(s) sur %d ligne(s) ; texte 0.2 : %s ; lignes TC- : %d" % (
            ct, len(c), l, "%d sur %d" % attendu_0_2[ct] if ct in attendu_0_2 else "absent", n_tc))
        if attendu_0_2.get(ct) != (len(c), l):
            ecart("0.2 : %s annonce %s, recompte %s" % (ct, attendu_0_2.get(ct), (len(c), l)))
        if n_tc != len(c):
            ecart("%s : %d occurrences, %d lignes TC-" % (ct, len(c), n_tc))
    c, l = occurrences_ct9(readme, "`spec/README.md`")
    cles.extend(c)
    total_lignes += l
    n_tc = sum(1 for k in tc_cles if k.startswith("`spec/README.md` "))
    dire("  spec/README.md : %d occurrence(s) sur %d ligne(s) ; texte 0.2 : %s ; lignes TC- : %d" % (
        len(c), l, "%d sur %d" % attendu_0_2["`spec/README.md`"] if "`spec/README.md`" in attendu_0_2 else "absent", n_tc))
    if attendu_0_2.get("`spec/README.md`") != (len(c), l) or n_tc != len(c):
        ecart("spec/README.md : 0.2 annonce %s, recompte (%d, %d), %d lignes TC-" % (attendu_0_2.get("`spec/README.md`"), len(c), l, n_tc))
    T = couverture["traceability"]
    dire("  total : %d occurrences sur %d lignes ; texte 0.2 : %s ; couverture.json : %d occurrences, %d lignes TC- ; catalogue : %d lignes TC-" % (
        len(cles), total_lignes, "%d sur %d" % total_0_2 if total_0_2 else "absent", T["occurrences"], T["rows"], len(tc_cles)))
    if total_0_2 != (len(cles), total_lignes):
        ecart("0.2 : total annoncé %s, recompte (%d, %d)" % (total_0_2, len(cles), total_lignes))
    if (T["occurrences"], T["rows"], len(T["missing"]), len(T["orphans"])) != (len(cles), len(cles), 0, 0) or len(tc_cles) != len(cles):
        ecart("règle (c) : %d occurrences recomptées, couverture.json %d/%d (manques %d, orphelines %d), catalogue %d" % (
            len(cles), T["occurrences"], T["rows"], len(T["missing"]), len(T["orphans"]), len(tc_cles)))
    if sorted(cles) == sorted(tc_cles):
        dire("  clés de section (dernier titre de niveau 2 à 4 hors bloc de code) : multi-ensemble égal à traceability[].key")
    else:
        manque = sorted(set(cles) - set(tc_cles))
        orphelines = sorted(set(tc_cles) - set(cles))
        ecart("règle (c) : clés recomptées sans ligne TC- %s ; lignes TC- sans occurrence %s ; comptes par clé %s" % (
            manque, orphelines, "égaux" if sorted(cles) == sorted(tc_cles) else "différents"))
    # Table TC du texte.
    lignes_tc = lignes_table(tables.get("TC", []))
    ids_tc_texte = [l[0] for l in lignes_tc if l]
    cles_tc_texte = [re.sub(r" \(l\. [0-9]+\)$", "", l[1]) for l in lignes_tc if l]
    dire("  table TC du texte : %d lignes ; identifiants et clés dans l'ordre du catalogue : %s" % (
        len(lignes_tc), "oui" if ids_tc_texte == [r["id"] for r in catalogue["traceability"]] and cles_tc_texte == tc_cles else "non"))
    if ids_tc_texte != [r["id"] for r in catalogue["traceability"]] or cles_tc_texte != tc_cles:
        ecart("table TC du texte : identifiants ou clés différents du catalogue")

    # 4. Menaces et risques acceptés (règle (b), 10.2, 10.6, EX-A.13) -------------
    dire()
    dire("4. Menaces, TA- et risques acceptés (règle (b), 10.2, 10.6, EX-A.13)")
    threats = menaces["threats"]
    ids_mn = [t["id"] for t in threats]
    ta_menace = {t["adversarial"]["threat"]: t for t in tests if t["level"] == "TA" and t["adversarial"]["threat"] is not None}
    scenarios = [t for t in tests if t["level"] == "TA" and t["adversarial"]["threat"] is None]
    dans_threats = {mn for t in tests if t["level"] == "TA" for mn in t["threats"]}
    sans_ta = [mn for mn in ids_mn if mn not in dans_threats]
    defauts = 0
    for th in threats:
        mn = th["id"]
        t = ta_menace.get(mn)
        if t is None:
            ecart("%s : aucune entrée TA- ne porte cette menace dans adversarial.threat" % mn)
            defauts += 1
            continue
        adv = t["adversarial"]
        attendu_id = "TA-" + mn.split("-")[1]
        verif = [
            (t["id"] == attendu_id, "identifiant %s pour %s" % (t["id"], mn)),
            (t["threats"] == [mn], "threats %s" % t["threats"]),
            (adv["component"] == th["component"], "component %s / %s" % (adv["component"], th["component"])),
            (adv["threat_test_text"] == th["test"], "threat_test_text différent du membre test"),
            (t["covers"] == th["response"]["refs"], "covers différents de response.refs"),
            (adv["accepted_risk"] == ((th.get("residual") or {}).get("accepted_risk") or {}).get("id"), "accepted_risk %s" % adv["accepted_risk"]),
        ]
        for ok, msg in verif:
            if not ok:
                ecart("%s : %s" % (t["id"], msg))
                defauts += 1
    dire("  menaces.json : %d menaces ; catalogue : %d TA- à menace, %d scénarios (adversarial.threat nul), %d TA- en tout" % (
        len(ids_mn), len(ta_menace), len(scenarios), sum(1 for t in tests if t["level"] == "TA")))
    dire("  règle (b) : %d menace(s) sans TA- ; couverture.json : %d menaces, %d avec un TA-, %d sans" % (
        len(sans_ta), couverture["threats"]["total"], couverture["threats"]["with_ta"], len(couverture["threats"]["without_ta"])))
    if sans_ta or (couverture["threats"]["total"], couverture["threats"]["with_ta"], len(couverture["threats"]["without_ta"])) != (len(ids_mn), len(ids_mn), 0):
        ecart("règle (b) : sans TA- %s ; couverture.json %s" % (sans_ta, couverture["threats"]))
    dire("  TA-n ↔ MN-n (identifiant, threats, component, covers = response.refs, threat_test_text = test, accepted_risk) : %d défaut(s)" % defauts)
    m = re.search(r"([0-9]+) menaces sur ([0-9]+) avec un TA-", zone)
    if m and (int(m.group(1)), int(m.group(2))) != (len(ids_mn) - len(sans_ta), len(ids_mn)):
        ecart("5.5 : « %s menaces sur %s » ; recompte %d sur %d" % (m.group(1), m.group(2), len(ids_mn) - len(sans_ta), len(ids_mn)))
    # Scénarios.
    for s in scenarios:
        comp = s["adversarial"].get("composition") or []
        inconnus_c = [x for x in comp if x not in par_id]
        if inconnus_c or not comp:
            ecart("%s : composition %s" % (s["id"], inconnus_c or "vide"))
            continue
        cov = set()
        thr = set()
        for x in comp:
            cov |= set(par_id[x]["covers"])
            thr |= set(par_id[x]["threats"])
        if set(s["covers"]) != cov or set(s["threats"]) != thr:
            ecart("%s : covers ou threats différents de l'union des composés" % s["id"])
    dire("  scénarios : %s ; chacun compose des TA- connus, covers et threats = union des composés : %s" % (
        ", ".join(s["id"] for s in scenarios), "oui" if not any(e.startswith(s["id"] + " :") for s in scenarios for e in ECARTS) else "non"))
    # Risques acceptés.
    ra_menaces = {}
    for th in threats:
        ra = (th.get("residual") or {}).get("accepted_risk")
        if ra:
            ra_menaces[ra["id"]] = (ra, th["id"])
    ra_catalogue = {r["id"]: r for r in catalogue["accepted_risks"]}
    defauts_ra = 0
    for rid in sorted(set(ra_menaces) | set(ra_catalogue), key=tri_ident):
        if rid not in ra_menaces or rid not in ra_catalogue:
            ecart("%s : présent dans %s seulement" % (rid, "menaces.json" if rid in ra_menaces else "le catalogue"))
            defauts_ra += 1
            continue
        ra, mn = ra_menaces[rid]
        r = ra_catalogue[rid]
        ta = ta_menace.get(mn)
        if (r["name"], r["bound"], r["owner"], r["threat"]) != (ra["name"], ra["bound"], ra["owner"], mn):
            ecart("%s : nom, borne, porteur ou menace différents de menaces.json" % rid)
            defauts_ra += 1
        if ta is None or r["test"] != ta["id"] or r["test_state"] != ta["status"]["state"]:
            ecart("%s : test %s / état %s ne suivent pas le TA- de %s" % (rid, r["test"], r["test_state"], mn))
            defauts_ra += 1
    dire("  risques acceptés : %d dans menaces.json, %d dans le catalogue, %d défaut(s) (nom, borne, porteur, menace, test, état)" % (
        len(ra_menaces), len(ra_catalogue), defauts_ra))
    # Index des TA- par menace.
    defauts_index = 0
    idx = index_ta["index"]
    if sorted(idx, key=tri_ident) != sorted(ids_mn, key=tri_ident):
        ecart("index-ta-par-menace.json : menaces %d, menaces.json %d" % (len(idx), len(ids_mn)))
        defauts_index += 1
    for mn in ids_mn:
        e = idx.get(mn)
        t = ta_menace.get(mn)
        if e is None or t is None:
            continue
        sc = sorted((s["id"] for s in scenarios if t["id"] in (s["adversarial"].get("composition") or [])), key=tri_ident)
        if (e["test"], e["state"], sorted(e["scenarios"], key=tri_ident)) != (t["id"], t["status"]["state"], sc):
            ecart("index-ta-par-menace.json : %s → %s ; catalogue (%s, %s, %s)" % (mn, e, t["id"], t["status"]["state"], sc))
            defauts_index += 1
    dire("  index-ta-par-menace.json : %d menaces, %d défaut(s) (test, état, scénarios)" % (len(idx), defauts_index))

    # 5. Titres de tests et étapes de CI (règle (d), EX-4.2) ---------------------
    dire()
    dire("5. Titres de tests et étapes de CI cités par les entrées exécutables (règle (d), EX-4.2)")
    index = {}
    n_describe = n_it = 0
    for f in sorted(sources_tests):
        d, i = analyser_tests(sources_tests[f])
        index[f] = (d, i)
        n_describe += len(d)
        n_it += len(i)
    etapes = []
    for ligne in ci.split("\n"):
        m = RE_NAME.match(ligne)
        if m:
            etapes.append(m.group(1))
    executables = 0
    cites = 0
    absents = []
    for t in tests:
        if t["status"]["state"] != "executable":
            continue
        executables += 1
        for c in t["status"].get("tests", []):
            cites += 1
            if not titre_existe(index, c):
                absents.append("%s : %s | %s | %s" % (t["id"], c["file"], c["describe"], c.get("it")))
        for s in t["status"].get("ci_steps", []):
            cites += 1
            if s not in etapes:
                absents.append("%s : étape « %s »" % (t["id"], s))
    E = couverture["executable"]
    dire("  test/*.test.js : %d fichiers, %d describe, %d it ; ci.yml : %d étapes « - name: »" % (len(index), n_describe, n_it, len(etapes)))
    dire("  %d entrées exécutables citent %d titres ou étapes ; %d absent(s)" % (executables, cites, len(absents)))
    dire("  couverture.json : %d exécutables, %d cités, %d absent(s)" % (E["total"], E["titles_checked"], len(E["titles_missing"])))
    if (executables, cites, len(absents)) != (E["total"], E["titles_checked"], len(E["titles_missing"])):
        ecart("règle (d) : (%d, %d, %d) recomptés, couverture.json (%d, %d, %d)" % (
            executables, cites, len(absents), E["total"], E["titles_checked"], len(E["titles_missing"])))
    for a in absents:
        ecart("titre ou étape absent : " + a)
    m = re.search(r"([0-9]+) entrées exécutables citant ([0-9]+) titres", zone)
    if m and (int(m.group(1)), int(m.group(2))) != (executables, cites):
        ecart("5.5 : « %s entrées exécutables citant %s titres » ; recompte (%d, %d)" % (m.group(1), m.group(2), executables, cites))

    # 6. test/adversarial.test.js (EX-10.7, 10.8, EX-A.11) -----------------------
    dire()
    dire("6. it de test/adversarial.test.js (EX-10.7, 10.8, EX-A.11)")
    d_adv, i_adv = index.get("test/adversarial.test.js", ([], []))
    its_ta = [t for t, _ in i_adv if t.startswith("TA-")]
    cites_ta = set()
    mal_formes = []
    sans_tue = []
    ex_10_4 = []
    for titre in its_ta:
        m = RE_TITRE_TA.match(titre)
        if not m:
            mal_formes.append(titre)
            continue
        ids = m.group(1).split(" et ")
        mns = m.group(2).split(", ")
        if [x.split("-")[1] for x in ids] != [x.split("-")[1] for x in mns]:
            mal_formes.append(titre)
        cites_ta.update(ids)
        if not (titre.endswith("(tué)") or titre.endswith("(tués)")):
            # EX-10.4 et EX-10.7 : les oracles sur un vecteur (TA-23, TA-72)
            # portent « oracle sur le vecteur » à la place de « (tué) » ; leur
            # mutant est la régénération observée par la CI.
            tete = titre.split(" : ", 1)[0]
            if "oracle sur le vecteur" in tete or "oracle sur les vecteurs" in tete:
                ex_10_4.append(tete)
            else:
                sans_tue.append(tete)
    citant = sorted((t["id"] for t in tests if t["level"] == "TA" and t["status"]["state"] == "executable"
                     and any(c["file"] == "test/adversarial.test.js" for c in t["status"].get("tests", []))), key=tri_ident)
    hors_catalogue = sorted((x for x in cites_ta if x not in par_id), key=tri_ident)
    non_executables = sorted((x for x in cites_ta if x in par_id and (par_id[x]["status"]["state"] != "executable"
                              or x not in citant)), key=tri_ident)
    sans_it_propre = [x for x in citant if x not in cites_ta]
    describes_avec_it = sorted({t for t, a, b in d_adv if any(a <= p <= b for _, p in i_adv)
                                and not any(a < a2 and b2 < b and any(a2 <= p <= b2 for _, p in i_adv) for _, a2, b2 in d_adv)})
    m_a11 = re.search(r"Il contient, au [0-9-]+, ([0-9]+) `it`", texte_ct9)
    m_108 = re.search(r"Résultat : « ([0-9]+) passing", texte_ct9)
    dire("  %d it, %d dont le titre commence par « TA- », %d describe de composant ; EX-A.11 : %s it ; 10.8 : %s passing" % (
        len(i_adv), len(its_ta), len(describes_avec_it), m_a11.group(1) if m_a11 else "?", m_108.group(1) if m_108 else "?"))
    if len(i_adv) != len(its_ta):
        ecart("test/adversarial.test.js : %d it dont %d seulement commencent par « TA- »" % (len(i_adv), len(its_ta)))
    if not m_a11 or int(m_a11.group(1)) != len(i_adv):
        ecart("EX-A.11 annonce %s it, recompte %d" % (m_a11.group(1) if m_a11 else "?", len(i_adv)))
    if not m_108 or int(m_108.group(1)) != len(i_adv):
        ecart("10.8 annonce %s passing, recompte %d it" % (m_108.group(1) if m_108 else "?", len(i_adv)))
    dire("  titres TA-n (MN-n) : %d mal formé(s) ; finissant par « (tué) » ou « (tués) » : %d sur %d ; oracle sur un vecteur (EX-10.4) : %d" % (
        len(mal_formes), len(its_ta) - len(sans_tue) - len(ex_10_4), len(its_ta), len(ex_10_4)))
    if ex_10_4:
        dire("  EX-10.4 et EX-10.7 : %d it à oracle sur un vecteur, sans « (tué) » (forme admise) : %s" % (len(ex_10_4), " ; ".join(ex_10_4)))
    for titre in mal_formes:
        ecart("EX-10.7 : titre mal formé « %s »" % titre[:100])
    if sans_tue:
        ecart("EX-10.7 : %d it dont le titre ne finit ni par « (tué) » ni par « (tués) » : %s" % (len(sans_tue), " ; ".join(sans_tue)))
    dire("  identifiants TA- distincts cités par ces titres : %d ; hors catalogue : %d ; non exécutables ou ne citant pas le fichier : %d" % (
        len(cites_ta), len(hors_catalogue), len(non_executables)))
    for x in hors_catalogue:
        ecart("%s cité par un it de test/adversarial.test.js sans entrée au catalogue" % x)
    for x in non_executables:
        ecart("%s cité par un it de test/adversarial.test.js sans entrée exécutable citant ce fichier" % x)
    dire("  entrées TA- exécutables citant test/adversarial.test.js : %d ; sans it à leur nom (elles citent les it d'autres TA-) : %s" % (
        len(citant), ", ".join(sans_it_propre) if sans_it_propre else "aucune"))
    # Chaque titre d'it TA- doit être cité par l'entrée de chaque TA- qu'il nomme.
    non_cites = []
    for titre in its_ta:
        m = RE_TITRE_TA.match(titre)
        if not m:
            continue
        for x in m.group(1).split(" et "):
            if x in par_id and not any(c.get("it") == titre for c in par_id[x]["status"].get("tests", [])):
                non_cites.append("%s (« %s »)" % (x, titre[:60]))
    dire("  titres d'it TA- non cités par l'entrée qu'ils nomment : %d" % len(non_cites))
    for x in non_cites:
        ecart("it de test/adversarial.test.js non cité par son entrée : %s" % x)

    # 7. Tables TM et TR (11.5, 12.2) -------------------------------------------
    dire()
    dire("7. Lignes TM- et TR- du texte (11.5, 12.2) et du catalogue")
    for niveau, col_etat, n_col in (("TM", 7, 9), ("TR", 7, 8)):
        entrees = [t for t in tests if t["level"] == niveau]
        lignes = lignes_table(tables.get(niveau, []))
        mal = [l for l in lignes if not l or len(l) != n_col]
        ids_texte = [l[0] for l in lignes if l]
        ordre = ids_texte == [t["id"] for t in entrees]
        etats = 0
        mesures = 0
        for l, t in zip([l for l in lignes if l and len(l) == n_col], entrees):
            attendu = etat_attendu(t["status"])
            if "complement" in t["status"]:
                if "complément à écrire (étape %d)" % t["status"]["complement"]["phase2_step"] not in l[col_etat]:
                    etats += 1
            elif not l[col_etat].startswith(attendu):
                etats += 1
            if niveau == "TM" and (l[8] != "—" or t["measure"]["measured"] is not None):
                mesures += 1
        covers = sorted({c for t in entrees for c in t["covers"] if "§" not in c})
        inconnus_c = [c for c in covers if c not in connus]
        dire("  %s- : %d lignes dans le texte, %d entrées ; mêmes identifiants dans le même ordre : %s ; %d ligne(s) mal formée(s) ; %d état(s) en désaccord%s" % (
            niveau, len(lignes), len(entrees), "oui" if ordre else "non", len(mal), etats,
            " ; %d mesure(s) non vide(s)" % mesures if niveau == "TM" else ""))
        dire("    covers : %d identifiants distincts, %d inconnu(s)" % (len(covers), len(inconnus_c)))
        if not ordre or mal or etats or mesures or inconnus_c:
            ecart("table %s : ordre %s, mal formées %d, états %d, mesures %d, inconnus %s" % (niveau, ordre, len(mal), etats, mesures, inconnus_c))
    # Table des chiffres par niveau (5.5).
    stats = lignes_table(tables.get("stats", []))
    attendu_stats = []
    for n in NIVEAUX:
        e = [t for t in tests if t["level"] == n]
        ex = [t for t in e if t["status"]["state"] == "executable"]
        attendu_stats.append([n + "-", str(len(e)), str(len(ex)), str(sum(1 for t in ex if "complement" in t["status"])), str(len(e) - len(ex))])
    attendu_stats.append(["Total"] + [str(sum(int(l[k]) for l in attendu_stats)) for k in range(1, 5)])
    dire("  table des chiffres par niveau (5.5) : %d lignes ; égale au recompte sur le catalogue : %s" % (
        len(stats), "oui" if stats == attendu_stats else "non"))
    if stats != attendu_stats:
        ecart("table stats : texte %s ; recompte %s" % (stats, attendu_stats))
    dire("  catalogue : %d entrées (%s)" % (len(tests), ", ".join("%s %d" % (n, sum(1 for t in tests if t["level"] == n)) for n in NIVEAUX)))
    if len(set(t["id"] for t in tests)) != len(tests):
        ecart("catalogue : identifiants d'entrées en double")
    if couverture["verdict"] != "reussi" or couverture["errors"]:
        ecart("couverture.json : verdict %s, %d erreur(s)" % (couverture["verdict"], len(couverture["errors"])))

    # Bilan -----------------------------------------------------------------------
    dire()
    dire("Bilan : %d discordance(s) ; %d écart(s) déclaré(s) dans LISEZMOI.md" % (len(ECARTS), len(DECLARES)))
    for e in ECARTS:
        dire("  [DISCORDANCE] " + e)
    for e in DECLARES:
        dire("  [DECLARE] " + e)
    sys.stdout.write("\n".join(LIGNES) + "\n")
    return 1 if ECARTS else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
