#!/usr/bin/env python3
# Confrontation des cas pieces-modele/gemini-* des vecteurs CT-2 par le SDK
# Python officiel google-genai (CT-2, annexe B.5, révision 0.5).
#
# Ce programme n'emploie aucun code du dépôt : il lit les fichiers des
# vecteurs, les fait analyser par les types et par le client de google-genai
# (modèles pydantic à alias camelCase qui refusent les membres inconnus), et
# compare ce que l'outil en lit à ce que les vecteurs disent. Le client du SDK
# est branché sur un transport HTTP simulé (httpx.MockTransport, sans réseau) :
# il construit la requête qu'il enverrait et lit la réponse enregistrée du
# vecteur, octet pour octet, par son propre chemin (lecture du flux, erreurs,
# conversion en objets).
#
# Usage : python -I confronter_gemini.py <répertoire spec/vecteurs/ct-2>
# Code de retour : 0 si aucune discordance, 1 sinon, 2 pour un usage incorrect.

import hashlib
import json
import logging
import os
import sys
import warnings
from importlib import metadata

if len(sys.argv) != 2:
    print("usage : confronter_gemini.py <spec/vecteurs/ct-2>", file=sys.stderr)
    sys.exit(2)

import httpx  # noqa: E402  (dépendance de google-genai)
import pydantic  # noqa: E402
from google import genai  # noqa: E402
from google.genai import errors, types  # noqa: E402
from google.genai._api_client import HttpResponse  # noqa: E402  (lecteur de flux du SDK, R11-F16)

RACINE = os.path.abspath(sys.argv[1])
MODELE = os.path.join(RACINE, "pieces-modele")
SORTIE, DISCORDANCES, LIMITES, DIVERGENCES = [], [], [], []
logging.getLogger("google_genai").setLevel(logging.CRITICAL)  # avertissements du SDK : hors sortie

# Membres de GenerateContentRequest du document de découverte de l'API
# Gemini, révision 20261024 (CT-2 R11-F11 pour v1beta, R11-F2 pour v1),
# recopiés ici pour que le programme ne contacte aucun réseau.
CLES_REQUETE = {
    "v1beta": ["cachedContent", "contents", "continuationToken", "generationConfig", "labels", "model", "safetySettings", "serviceTier", "store", "systemInstruction", "toolConfig", "tools"],
    "v1": ["contents", "continuationToken", "generationConfig", "model", "safetySettings", "serviceTier", "store", "systemInstruction", "toolConfig", "tools"],
}
# Membre de premier niveau du corps -> (type du SDK, tableau ?)
TYPES_REQUETE = {
    "contents": (types.Content, True),
    "systemInstruction": (types.Content, False),
    "tools": (types.Tool, True),
    "toolConfig": (types.ToolConfig, False),
    "generationConfig": (types.GenerationConfig, False),
    "safetySettings": (types.SafetySetting, True),
}
# Clés que l'enregistreur ajoute à une forme consolidée (CT-2 EX-5.18).
PREFIXE_NOORTRACE = "noortrace_"
CLE_FICTIVE = "cle-fictive-de-confrontation"
BASE = "https://passerelle.invalid/"


def dire(*m):
    SORTIE.append(" ".join(str(x) for x in m))


def jc(v):
    """Écriture JSON compacte et stable d'une valeur, pour la sortie."""
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fmt(v):
    return jc(v) if isinstance(v, (dict, list)) else str(v)


def comparer(libelle, vecteur, outil):
    ok = vecteur == outil
    dire("  %s : vecteur %s ; outil %s : %s" % (libelle, fmt(vecteur), fmt(outil), "concorde" if ok else "DISCORDANCE"))
    if not ok:
        DISCORDANCES.append("%s : vecteur %s, outil %s" % (libelle, fmt(vecteur), fmt(outil)))
    return ok


def limite(libelle, texte):
    dire("  %s : LIMITE DE L'OUTIL : %s" % (libelle, texte))
    LIMITES.append("%s : %s" % (libelle, texte))


def divergence(libelle, regle, texte):
    dire("  %s : divergence voulue (%s) : %s" % (libelle, regle, texte))
    DIVERGENCES.append("%s (%s) : %s" % (libelle, regle, texte))


def sha256(octets):
    return "0x" + hashlib.sha256(octets).hexdigest()


def lire(cas, nom):
    return open(os.path.join(MODELE, cas, nom), "rb").read()


def lire_json(cas, nom):
    return json.loads(lire(cas, nom).decode("utf-8"))


def ecarts(attendu, lu, chemin="$"):
    """Différences entre une valeur JSON et sa relecture : tout ce que l'analyse a perdu, ajouté ou transformé."""
    if isinstance(attendu, dict) and isinstance(lu, dict):
        out = []
        for k in sorted(set(attendu) | set(lu)):
            if k not in lu:
                out.append("%s.%s perdu (%s)" % (chemin, k, jc(attendu[k])))
            elif k not in attendu:
                out.append("%s.%s ajouté (%s)" % (chemin, k, jc(lu[k])))
            else:
                out += ecarts(attendu[k], lu[k], "%s.%s" % (chemin, k))
        return out
    if isinstance(attendu, list) and isinstance(lu, list):
        if len(attendu) != len(lu):
            return ["%s : %d éléments relus au lieu de %d" % (chemin, len(lu), len(attendu))]
        out = []
        for i, (a, b) in enumerate(zip(attendu, lu)):
            out += ecarts(a, b, "%s[%d]" % (chemin, i))
        return out
    if jc(attendu) != jc(lu):
        return ["%s : %s relu %s" % (chemin, jc(attendu), jc(lu))]
    return []


def erreurs_pydantic(e):
    return ["%s à %s" % (x["type"], ".".join(str(p) for p in x["loc"]) or "$") for x in e.errors(include_url=False)]


def analyser(modele, valeur):
    """model_validate_json du type du SDK, puis relecture (model_dump par alias, sans les membres nuls)."""
    with warnings.catch_warnings(record=True) as avert:
        warnings.simplefilter("always")
        try:
            obj = modele.model_validate_json(json.dumps(valeur, ensure_ascii=False))
        except pydantic.ValidationError as e:
            return "refuse", erreurs_pydantic(e), None
        relu = obj.model_dump(mode="json", by_alias=True, exclude_none=True)
    notes = ecarts(valeur, relu) + ["avertissement : %s" % str(w.message).splitlines()[0] for w in avert]
    return "accepte", notes, obj


# Cas dont l'index de candidat est lu par EX-5.27 (1) et EX-5.35 pas 4, et non comme le SDK, qui convertit
# l'index (chaîne "0", nombre 1.0) en entier et prend candidates[0] de chaque morceau sans réassembler par index :
# divergences voulues, publiées avec leur règle.
REGLES_INDEX = {
    "gemini-flux-index": "EX-5.35 pas 4, EX-5.27 (1) : un index \"0\" n'est pas un index, le fragment est ignoré",
    "gemini-flux-index-desordre": "EX-5.35 pas 4, 5.5 : candidats créés dans l'ordre de première apparition, intent tiré de candidates[0] de la forme",
    "gemini-flux-index-limites": "EX-5.27 (1), EX-8.1 : index lu en double précision ; 1.0 vaut 1, 9007199254740993 vaut 2^53, 9007199254740994 est refusé",
}


def confronter_type(libelle, modele, valeur, attendu="accepte", regle=None):
    """Une valeur des vecteurs analysée par un type du SDK : acceptée sans perte, sinon discordance (ou divergence voulue si `regle`)."""
    issue, notes, obj = analyser(modele, valeur)
    nom = "types.%s.model_validate_json" % modele.__name__
    if issue == "accepte" and not notes:
        comparer("%s : %s, relecture identique" % (libelle, nom), attendu, "accepte")
    elif issue == "accepte":
        if regle:
            comparer("%s : %s" % (libelle, nom), attendu, "accepte")
            divergence(libelle, regle, "relu avec écart : " + " ; ".join(notes))
        else:
            comparer("%s : %s, relecture identique" % (libelle, nom), "accepte sans ecart", "accepte avec ecart : " + " ; ".join(notes))
    else:
        if attendu == "refuse":
            comparer("%s : %s" % (libelle, nom), "refuse", "refuse")
            dire("    raisons du SDK : %s" % " ; ".join(notes))
        else:
            comparer("%s : %s" % (libelle, nom), attendu, "refuse : " + " ; ".join(notes))
    return obj


def sse_ex514(octets):
    """Valeurs data distribuées selon CT-2 EX-5.14 et EX-5.34 (relu du texte de la spécification, pas du code du dépôt)."""
    texte = octets.decode("utf-8")
    if texte.startswith("\ufeff"):
        texte = texte[1:]
    lignes = texte.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lignes and lignes[-1] == "":
        lignes.pop()  # fin de la dernière ligne, pas une ligne vide
    valeurs, tampon = [], None
    for ligne in lignes:
        if ligne == "":
            if tampon is not None:
                valeurs.append("\n".join(tampon))
            tampon = None
            continue
        if ligne.startswith(":"):
            continue
        champ, _, valeur = ligne.partition(":")
        if valeur.startswith(" "):
            valeur = valeur[1:]
        if champ == "data":
            tampon = (tampon or []) + [valeur]
    if tampon is not None and "\n".join(tampon) != "":
        valeurs.append("\n".join(tampon))  # EX-5.34 : data final sans ligne vide, distribué
    return valeurs


class Transport:
    """Transport httpx simulé : retient la requête du SDK et rend la réponse enregistrée du vecteur."""

    def __init__(self, statut, type_contenu, corps):
        self.statut, self.type_contenu, self.corps, self.requetes = statut, type_contenu, corps, []

    def __call__(self, requete):
        self.requetes.append(requete)
        entetes = {"content-type": self.type_contenu} if self.type_contenu else {}
        return httpx.Response(self.statut, headers=entetes, content=self.corps)


def client(transport, version):
    options = types.HttpOptions(
        base_url=BASE,
        api_version=version,
        httpx_client=httpx.Client(transport=httpx.MockTransport(transport), trust_env=False),
    )
    return genai.Client(vertexai=False, api_key=CLE_FICTIVE, http_options=options)


def snake(nom):
    return "".join("_" + c.lower() if c.isupper() else c for c in nom)


def appeler(transport, version, flux, modele, requete):
    """Appel de generate_content(_stream) avec les valeurs de la requête du vecteur. Rend (réponses, erreur)."""
    c = client(transport, version)
    config = {}
    for cle, v in requete.items():
        if cle == "contents" or cle == "model":
            continue
        if cle == "generationConfig":
            for k2, v2 in v.items():
                config[snake(k2)] = v2
        else:
            config[snake(cle)] = v
    contenus = [types.Content.model_validate(x) for x in requete.get("contents", [])]
    cfg = types.GenerateContentConfig.model_validate(config) if config else None
    reponses = []
    try:
        if flux:
            for r in c.models.generate_content_stream(model=modele, contents=contenus, config=cfg):
                reponses.append(r)
        else:
            reponses.append(c.models.generate_content(model=modele, contents=contenus, config=cfg))
    except errors.APIError as e:
        return reponses, e
    return reponses, None


# Membres propres au SDK, absents de GenerateContentResponse de l'API (R11-F12) :
# en-têtes HTTP, historique de l'appel automatique de fonctions, sortie analysée.
MEMBRES_SDK = ("sdkHttpResponse", "automaticFunctionCallingHistory", "parsed")


def sans_sdk(dump):
    return {k: v for k, v in dump.items() if k not in MEMBRES_SDK}


def texte_sdk(reponses):
    morceaux = [r.text for r in reponses if r.text is not None]
    return "".join(morceaux) if morceaux else None


def appels_sdk(reponses):
    out = []
    for r in reponses:
        for fc in r.function_calls or []:
            out.append({"id": fc.id, "name": fc.name, "arguments": fc.args if fc.args is not None else {}})
    return out


VERSIONS = {p: metadata.version(p) for p in ["google-genai", "pydantic", "pydantic-core", "httpx"]}
dire("Confrontation des vecteurs CT-2 pieces-modele/gemini-* par google-genai %s (pydantic %s, pydantic-core %s, httpx %s)" % (VERSIONS["google-genai"], VERSIONS["pydantic"], VERSIONS["pydantic-core"], VERSIONS["httpx"]))
dire("Entrées : pieces-modele/gemini-*/{requete.json, requete.brut, requete-ligne.json, reponse.json, reponse.sse, reponse-morceaux.json, reponse-entetes.json, attendu.json}")
dire("Types : modèles pydantic du SDK (alias camelCase, membres inconnus refusés : extra='forbid', google/genai/_common.py) ; client : genai.Client sur un transport httpx simulé, sans réseau")
dire("")

CAS = sorted(n for n in os.listdir(MODELE) if n.startswith("gemini-"))
ATTENDUS = {n: lire_json(n, "attendu.json") for n in CAS}

# ---------------------------------------------------------------------------
dire("== 1. Corps des requêtes : clés de premier niveau (document de découverte, R11-F11, R11-F2) et membres analysés par les types du SDK")
for cas in CAS:
    a = ATTENDUS[cas]
    fichiers = sorted(os.listdir(os.path.join(MODELE, cas)))
    if "requete.brut" in fichiers:
        brut = lire(cas, "requete.brut")
        dire("-- %s (requete.brut, SHA-256 %s)" % (cas, sha256(brut)))
        # Clé en double : refusée par CT-2 (EX-5.7 point 2), lue par l'analyseur JSON de pydantic (la dernière l'emporte).
        try:
            c = pydantic.TypeAdapter(dict).validate_json(brut)
            lu = "analysable, clés %s, contents de %d élément(s)" % (sorted(c), len(c.get("contents", [])))
        except pydantic.ValidationError as e:
            lu = "refuse : " + " ; ".join(erreurs_pydantic(e))
        dire("  vecteur : refus %s (statut %s)" % (a["refused"]["reason"], a["refused"]["status"]))
        divergence("analyseur JSON de pydantic (TypeAdapter(dict).validate_json)", "EX-5.7 point 2", "clé en double admise, la dernière occurrence l'emporte : " + lu)
        continue
    octets = lire(cas, "requete.json")
    requete = json.loads(octets)
    ligne = a.get("request_line")
    version = "v1" if ligne and ligne["target"].startswith("/v1/") else "v1beta"
    dire("-- %s (requete.json, SHA-256 %s, route %s)" % (cas, sha256(octets), version))
    inconnues = sorted(k for k in requete if k not in CLES_REQUETE[version])
    comparer("clés de premier niveau hors de GenerateContentRequest (%s)" % version, [], inconnues)
    for cle in sorted(requete):
        if cle not in TYPES_REQUETE:
            dire("  %s : sans type du SDK pour ce membre (valeur %s)" % (cle, jc(requete[cle])))
            continue
        modele, tableau = TYPES_REQUETE[cle]
        if tableau:
            for i, el in enumerate(requete[cle]):
                confronter_type("%s[%d]" % (cle, i), modele, el)
        else:
            confronter_type(cle, modele, requete[cle])
dire("")

# ---------------------------------------------------------------------------
dire("== 2. Requêtes reconstruites par le client du SDK (generate_content et generate_content_stream, transport simulé) : cible et corps envoyés")
for cas in CAS:
    a = ATTENDUS[cas]
    if a["via"] != "passerelle" or not os.path.exists(os.path.join(MODELE, cas, "requete.json")):
        continue
    requete = lire_json(cas, "requete.json")
    ligne = a["request_line"]["target"]
    version = "v1" if ligne.startswith("/v1/") else "v1beta"
    flux = ":streamGenerateContent" in ligne
    segment = a["model_segment"] or "gemini-exemple"
    dire("-- %s (cible reçue %s)" % (cas, ligne))
    t = Transport(200, "application/json", b"{}" if not flux else b'data: {"candidates":[]}\n\n')
    # Sans contents, le corps n'a pas la forme attendue (EX-5.7 point 3) : le SDK refuse de le construire.
    construction = "construite" if "contents" in requete else "refusee"
    try:
        appeler(t, version, flux, segment, requete)
    except Exception as e:  # le SDK refuse de construire la requête
        comparer("construction de la requête par le SDK", construction, "refusee")
        dire("    raison du SDK : %s : %s" % (type(e).__name__, str(e).splitlines()[0]))
        continue
    comparer("construction de la requête par le SDK", construction, "construite")
    if not t.requetes:
        comparer("requête envoyée par le SDK", "une", "aucune")
        continue
    envoyee = t.requetes[0]
    cible = envoyee.url.raw_path.decode("ascii")
    corps = json.loads(envoyee.content) if envoyee.content else None
    attendu_corps = {k: v for k, v in requete.items() if k != "model"}
    if a["upstream_target"] is not None:
        comparer("cible envoyée par le SDK = upstream_target", a["upstream_target"], cible)
    else:
        dire("  cible envoyée par le SDK : %s ; vecteur : refus %s de la cible reçue %s (le SDK n'émet pas cette cible : sans objet)" % (cible, a["refused"]["reason"], ligne))
    if corps.get("generationConfig") == {} and "generationConfig" not in attendu_corps:
        # Avec une configuration (systemInstruction, tools, toolConfig), le SDK
        # envoie generationConfig, vide quand aucun paramètre de génération n'est donné.
        del corps["generationConfig"]
        dire("  ajout du SDK sans valeur : generationConfig {} (retiré avant comparaison)")
    d = ecarts(attendu_corps, corps)
    paires = []
    for x in d:
        if " perdu (" in x:
            chemin, valeur = x.split(" perdu (", 1)
            base, _, nom = chemin.rpartition(".")
            jumeau = "%s.%s ajouté (%s" % (base, snake(nom), valeur)
            if jumeau in d:
                paires += [x, jumeau]
    if paires and len(paires) == len(d):
        comparer("corps envoyé par le SDK = requete.json, aux noms de membres près", [], [])
        limite("corps envoyé par le SDK", "membre(s) émis en snake_case au lieu du nom de l'API en lowerCamelCase : " + " ; ".join(x for x in paires if " perdu (" in x).replace(" perdu (", " émis en snake_case ("))
    else:
        comparer("corps envoyé par le SDK = requete.json (même valeur JSON)", [], d)
    comparer("en-tête x-goog-api-key envoyé (clé dans l'en-tête, jamais dans l'URL, EX-5.29)", True, envoyee.headers.get("x-goog-api-key") == CLE_FICTIVE and "key=" not in envoyee.url.query.decode("ascii"))
dire("")

# ---------------------------------------------------------------------------
dire("== 3. Réponses : lecture du flux par le SDK (HttpResponse.segments) et par EX-5.14 / EX-5.34 ; chaque objet par types.GenerateContentResponse")
for cas in CAS:
    a = ATTENDUS[cas]
    fichiers = os.listdir(os.path.join(MODELE, cas))
    if "reponse.sse" in fichiers:
        octets = lire(cas, "reponse.sse")
        entetes = lire_json(cas, "reponse-entetes.json")
        dire("-- %s (reponse.sse, SHA-256 %s, statut %s, %s)" % (cas, sha256(octets), entetes["status"], entetes["content-type"]))
        lecture = HttpResponse({"content-type": entetes["content-type"]}, httpx.Response(entetes["status"], content=octets))
        try:
            segments_sdk = list(lecture.segments())
        except errors.UnknownApiResponseError:
            segments_sdk = ["exception UnknownApiResponseError"]
        if entetes["status"] >= 400:
            # Corps d'erreur sans data: (forme observée, R11-F19) : le SDK le lit par équilibre des accolades.
            corps = json.loads(octets)
            comparer("objets lus par le SDK (corps d'erreur JSON sans data:)", [corps], segments_sdk)
            comparer("corps analysé par l'enregistreur (EX-5.31) = objet lu par le SDK", json.loads(a["pieces"]["response"]["bytes"])["noortrace_http_error"]["body"], segments_sdk[0] if segments_sdk else None)
            continue
        valeurs = sse_ex514(octets)
        objets = [json.loads(v) for v in valeurs]
        comparer("nombre de data distribués (EX-5.14, EX-5.34) et d'objets lus par le SDK", len(objets), len(segments_sdk))
        comparer("objets data = objets lus par le SDK, dans l'ordre", True, objets == segments_sdk)
        for i, o in enumerate(objets):
            if isinstance(o, dict) and isinstance(o.get("error"), dict):
                confronter_type("data[%d] (morceau d'erreur, EX-5.35 pas 2)" % i, types.GenerateContentResponse, o, attendu="refuse")
            elif cas in REGLES_INDEX:
                confronter_type("data[%d]" % i, types.GenerateContentResponse, o, regle=REGLES_INDEX[cas])
            else:
                confronter_type("data[%d]" % i, types.GenerateContentResponse, o)
    elif "reponse.json" in fichiers:
        octets = lire(cas, "reponse.json")
        entetes = lire_json(cas, "reponse-entetes.json")
        dire("-- %s (reponse.json, SHA-256 %s, statut %s, %s)" % (cas, sha256(octets), entetes["status"], entetes["content-type"]))
        corps = json.loads(octets)
        if entetes["status"] >= 400:
            confronter_type("corps d'erreur (statut %d)" % entetes["status"], types.GenerateContentResponse, corps, attendu="refuse")
        else:
            confronter_type("corps", types.GenerateContentResponse, corps)
    elif "reponse-morceaux.json" in fichiers:
        octets = lire(cas, "reponse-morceaux.json")
        morceaux = json.loads(octets)
        dire("-- %s (reponse-morceaux.json, SHA-256 %s, %d morceaux, membres retirés par EX-6.8 : %s)" % (cas, sha256(octets), len(morceaux), a["removed_members"]))
        for i, m in enumerate(morceaux):
            retire = {k: v for k, v in m.items() if k not in a["removed_members"]}
            confronter_type("morceau[%d] sans %s" % (i, "/".join(a["removed_members"])), types.GenerateContentResponse, retire)
            if retire != m:
                # Le membre retiré est un champ du type du SDK (sdk_http_response), pas un membre de l'API.
                confronter_type("morceau[%d] tel que déclaré (objet du SDK sérialisé)" % i, types.GenerateContentResponse, m)
    else:
        dire("-- %s : aucune réponse (refus de la passerelle, section 6)" % cas)
dire("")

# ---------------------------------------------------------------------------
dire("== 4. Réponses lues par le client complet du SDK (transport simulé) : objets, erreurs, texte (intent) et appels de fonction (tool_calls)")
for cas in CAS:
    a = ATTENDUS[cas]
    fichiers = os.listdir(os.path.join(MODELE, cas))
    if a["refused"] is not None:
        continue
    if a["via"] == "sdk":
        # Réponse déclarée par le SDK (EX-6.8) : les morceaux, tels que déclarés, relus en objets du SDK.
        morceaux = lire_json(cas, "reponse-morceaux.json")
        dire("-- %s (reponse-morceaux.json, %d morceaux, objets du SDK reconstruits)" % (cas, len(morceaux)))
        reponses = [types.GenerateContentResponse.model_validate(m) for m in morceaux]
        comparer("intent = concaténation des GenerateContentResponse.text (candidat 0, sans thought)", a["intent"], texte_sdk(reponses))
        comparer("tool_calls = GenerateContentResponse.function_calls (id, name, args)", a["tool_calls"], appels_sdk(reponses))
        continue
    requete = lire_json(cas, "requete.json")
    ligne = a["request_line"]["target"]
    version = "v1" if ligne.startswith("/v1/") else "v1beta"
    flux = ":streamGenerateContent" in ligne
    entetes = lire_json(cas, "reponse-entetes.json")
    nom = "reponse.sse" if flux else "reponse.json"
    octets = lire(cas, nom)
    dire("-- %s (%s, statut %s)" % (cas, nom, entetes["status"]))
    t = Transport(entetes["status"], entetes["content-type"], octets)
    if "contents" not in requete:
        dire("  sans objet : le SDK ne construit pas de requête sans contents (section 2) ; la réponse est lue en section 3")
        continue
    reponses, erreur = appeler(t, version, flux, a["model_segment"], requete)
    if entetes["status"] >= 400:
        corps = json.loads(a["pieces"]["response"]["bytes"])["noortrace_http_error"]["body"]["error"]
        comparer("errors.APIError levée (code, status, message) = corps analysé par l'enregistreur (EX-5.31)", [corps["code"], corps["status"], corps["message"]], [erreur.code, erreur.status, erreur.message] if erreur else None)
        comparer("is_error", True, a["is_error"])
        continue
    if flux:
        valeurs = sse_ex514(octets)
        objets = [json.loads(v) for v in valeurs]
    else:
        objets = [json.loads(octets)]
    bons = [o for o in objets if not (isinstance(o, dict) and isinstance(o.get("error"), dict))]
    n_avant_erreur = next((i for i, o in enumerate(objets) if isinstance(o, dict) and isinstance(o.get("error"), dict)), len(objets))
    comparer("objets GenerateContentResponse rendus avant toute erreur", n_avant_erreur, len(reponses))
    for i, r in enumerate(reponses):
        d = ecarts(objets[i], sans_sdk(r.model_dump(mode="json", by_alias=True, exclude_none=True)))
        if cas in REGLES_INDEX and d:
            divergence("réponse[%d] relue par le client" % i, REGLES_INDEX[cas], " ; ".join(d))
        else:
            comparer("réponse[%d] relue par le client (sans les membres propres au SDK) = objet reçu" % i, [], d)
    consolide = a["consolidated"] or {}
    erreur_flux = consolide.get("noortrace_erreur_flux")
    if erreur_flux is not None:
        comparer("errors.APIError levée sur le morceau d'erreur (code, status, message) = noortrace_erreur_flux", [erreur_flux["code"], erreur_flux["status"], erreur_flux["message"]], [erreur.code, erreur.status, erreur.message] if erreur else None)
    else:
        comparer("aucune erreur levée par le client", None, None if erreur is None else "%s %s" % (erreur.code, erreur.status))
    intent = a["intent"]
    if isinstance(intent, dict) or (intent is None and a["pieces"] and a["pieces"]["intent"]):
        dire("  intent : référence à une pièce (texte rédigé ou long) : sans objet ; texte du SDK %s" % jc(texte_sdk(reponses)))
    elif cas in REGLES_INDEX:
        if texte_sdk(reponses) != intent:
            divergence("intent = concaténation des GenerateContentResponse.text", REGLES_INDEX[cas], "vecteur %s, SDK %s (le SDK prend candidates[0] de chaque morceau, sans réassembler par index)" % (jc(intent), jc(texte_sdk(reponses))))
        else:
            comparer("intent = concaténation des GenerateContentResponse.text", intent, texte_sdk(reponses))
    else:
        comparer("intent = concaténation des GenerateContentResponse.text (candidat 0, sans thought)", intent, texte_sdk(reponses))
    comparer("tool_calls = GenerateContentResponse.function_calls (id, name, args)", a["tool_calls"], appels_sdk(reponses))
dire("")

# ---------------------------------------------------------------------------
dire("== 5. Formes consolidées (EX-5.35) par types.GenerateContentResponse, sans puis avec les clés noortrace_* (EX-5.18)")
for cas in CAS:
    a = ATTENDUS[cas]
    if a["consolidated"] is None:
        continue
    c = a["consolidated"]
    propre = {k: v for k, v in c.items() if not k.startswith(PREFIXE_NOORTRACE)}
    ajoutees = sorted(k for k in c if k.startswith(PREFIXE_NOORTRACE))
    dire("-- %s (consolidated, clés ajoutées par l'enregistreur : %s)" % (cas, ajoutees))
    confronter_type("forme consolidée sans les clés noortrace_*", types.GenerateContentResponse, propre)
    if ajoutees:
        confronter_type("forme consolidée avec %s (refus attendu : membre inconnu du type)" % "/".join(ajoutees), types.GenerateContentResponse, c, attendu="refuse")
dire("")

# ---------------------------------------------------------------------------
dire("== 6. Refus de la passerelle (EX-5.30, AIP-193) lus par le client du SDK (errors.APIError)")
for cas in CAS:
    a = ATTENDUS[cas]
    r = a["refused"]
    if r is None:
        continue
    dire("-- %s (statut %d, raison %s, Content-Type %s)" % (cas, r["status"], r["reason"], r["content_type"]))
    if os.path.exists(os.path.join(MODELE, cas, "requete.json")):
        requete = lire_json(cas, "requete.json")
    else:
        requete = {"contents": [{"role": "user", "parts": [{"text": "x"}]}]}
    flux = ":streamGenerateContent" in a["request_line"]["target"]
    corps = json.dumps(r["body"]).encode("utf-8") if r["body"] is not None else b""
    t = Transport(r["status"], r["content_type"], corps)
    try:
        _, erreur = appeler(t, "v1beta", flux, "gemini-exemple", requete)
    except Exception as e:
        comparer("lecture du refus par le SDK", "errors.APIError", "exception %s" % type(e).__name__)
        continue
    if r["body"] is None:
        comparer("errors.APIError levée (code ; corps vide)", r["status"], erreur.code if erreur else None)
        continue
    e = r["body"]["error"]
    comparer("errors.APIError levée (code, status, message) = corps de refus", [e["code"], e["status"], e["message"]], [erreur.code, erreur.status, erreur.message] if erreur else None)
    comparer("classe d'erreur du SDK pour le statut %d" % r["status"], "ClientError", type(erreur).__name__ if erreur else None)
dire("")

# ---------------------------------------------------------------------------
dire("Cas gemini-* : %d ; discordances : %d ; limites de l'outil : %d ; divergences voulues : %d" % (len(CAS), len(DISCORDANCES), len(LIMITES), len(DIVERGENCES)))
for d in DIVERGENCES:
    dire("  divergence voulue : " + d)
for d in LIMITES:
    dire("  limite : " + d)
for d in DISCORDANCES:
    dire("  DISCORDANCE : " + d)
dire("Discordances au total : %d" % len(DISCORDANCES))
print("\n".join(SORTIE))
sys.exit(1 if DISCORDANCES else 0)
