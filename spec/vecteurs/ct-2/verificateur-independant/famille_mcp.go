// Famille pieces-mcp (annexe B.4) : appels/<cas>/ (hote.jsonl, amont.jsonl,
// attendu.json) et agregation/ (serveurs.json, attendu.json).
//
// Conventions de lecture (l'annexe B ne les fixe pas, voir README) : dans
// hote.jsonl, « in » est reçu de l'hôte et « out » rendu à l'hôte ; dans
// amont.jsonl, « out » est envoyé au serveur d'outils et « in » reçu de lui.

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func famillePiecesMCP(rap *Rapport, ctx *contexteCT2) {
	dir := filepath.Join(ctx.racine, "pieces-mcp")
	if !fichierExiste(dir) {
		rap.Erreur("pieces-mcp/ : absent (annexe B.4)")
		return
	}
	appels := filepath.Join(dir, "appels")
	cas := sousRepertoires(appels)
	if len(cas) == 0 {
		rap.Erreur("pieces-mcp/appels/ : aucun cas (annexe B.4)")
	}
	for _, c := range cas {
		verifierAppelMCP(rap, ctx, filepath.Join(appels, c), "appels/"+c)
	}
	// B.4, cas obligatoires de la version 0.3 : refus par la politique sans
	// ticket pour un hôte moderne (le résultat exact d'EX-4.49), ticket en
	// attente pour un hôte hérité (le signal sans resultType)
	for _, e := range []struct{ cas, issue string }{
		{"appels/approbation-refus", IssueRefus + "/moderne"},
		{"appels/approbation-en-attente", IssueEnAttente + "/héritée"},
	} {
		obt := ctx.issuesApprobation[e.cas]
		if obt == "" {
			obt = "absent"
		}
		rap.Comparer(FamillePiecesMCP, e.cas, "cas obligatoire d'approbation (B.4) : issue d'EX-7.16 et ère de l'hôte", e.issue, obt)
	}
	ag := filepath.Join(dir, "agregation")
	if !fichierExiste(ag) {
		rap.Erreur("pieces-mcp/agregation/ : absent (annexe B.4)")
		return
	}
	if fichierExiste(filepath.Join(ag, "serveurs.json")) {
		verifierAgregation(rap, ag, "agregation")
	}
	for _, s := range sousRepertoires(ag) {
		if fichierExiste(filepath.Join(ag, s, "serveurs.json")) {
			verifierAgregation(rap, filepath.Join(ag, s), "agregation/"+s)
		}
	}
}

func verifierAppelMCP(rap *Rapport, ctx *contexteCT2, dir, nom string) {
	f := FamillePiecesMCP
	att := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))
	if att == nil {
		return
	}
	ctx.appels[nom] = att
	hote, err := LireTranscription(filepath.Join(dir, "hote.jsonl"))
	if err != nil {
		rap.Erreur("pieces-mcp/%s/hote.jsonl : %v", nom, err)
		return
	}
	amont, err := LireTranscription(filepath.Join(dir, "amont.jsonl"))
	if err != nil {
		rap.Erreur("pieces-mcp/%s/amont.jsonl : %v", nom, err)
		return
	}
	cadrage := "ligne"
	if chaineDe(att, "transports", "host") == "http" {
		cadrage = "corps" // corps POST : un CR entre jetons est admis (EX-4.43)
	}
	pol := ctx.piiV1

	// 1. Liste servie à la connexion d'hôte : l'échange tools/list qui précède (EX-4.45).
	listeReq := trouverRequete(hote, "in", "tools/list")
	var servie *Value
	if listeReq != nil {
		if r := trouverReponse(hote, "out", listeReq.id()); r != nil {
			servie = r.Val.Get("result").Get("tools")
		}
	}
	if !EstTableau(servie) {
		rap.Erreur("pieces-mcp/%s : aucune liste servie (tools/list) dans hote.jsonl (B.4)", nom)
		return
	}
	// 2. La requête reçue : la ligne « in » qui suit l'échange tools/list.
	var recue, rendue *LigneTranscription
	for i, l := range hote {
		if l.Dir == "in" && l != listeReq {
			recue = l
			for _, m := range hote[i+1:] {
				if m.Dir == "out" {
					rendue = m
					break
				}
			}
			break
		}
	}
	if recue == nil || rendue == nil {
		rap.Erreur("pieces-mcp/%s : requête reçue ou réponse rendue absente de hote.jsonl", nom)
		return
	}
	lu := LireRequeteHote(recue.Ligne, cadrage)
	rejete := att.Get("rejected")
	rap.Comparer(f, nom, "rejected (refus au pas 1 de 4.4)", texteOuAbsent(rejete), fmt.Sprint(lu.Erreur != nil))
	if rendue.Val == nil {
		rap.Erreur("pieces-mcp/%s : réponse rendue illisible", nom)
		return
	}
	rap.Comparer(f, nom, "réponse rendue sans CR ni LF (EX-4.43)", "oui", oui(!bytes.ContainsAny(rendue.Ligne, "\r\n")))
	if lu.Erreur != nil {
		comparerValeur(rap, f, nom, "error_rendered = erreur du pas 1 (4.4, EX-4.3, EX-4.43, EX-4.44)", att.Get("error_rendered"), lu.Erreur)
		comparerValeur(rap, f, nom, "erreur rendue à l'hôte", lu.Erreur, rendue.Val.Get("error"))
		comparerCodeEX424(rap, nom, rendue.Val.Get("error"))
		idRendu := "(absent)"
		if id := rendue.Val.Get("id"); id != nil {
			idRendu = string(rendue.Ligne[id.Debut:id.Fin])
		}
		rap.Comparer(f, nom, "id rendu = octets de l'id lu, ou null", lu.IDTexte, idRendu)
		rap.Comparer(f, nom, "aucun relais amont (lignes dans amont.jsonl)", "0", fmt.Sprint(len(amont)))
		for _, k := range []string{"pieces", "is_error", "duration_ms"} {
			rap.Comparer(f, nom, k+" (ni pièce ni événement)", "null", texteOuAbsent(att.Get(k)))
		}
		// B.4 : protocols.host est la version vue côté hôte (la requête
		// refusée est illisible : celle de tools/list) ; amont.jsonl étant
		// vide, protocols.server est déclaratif.
		if pr := att.Get("protocols"); EstObjet(pr) {
			vh, sh := versionHote(hote, listeReq)
			comparerVersion(rap, nom, "protocols.host", chaineDe(pr, "host"), vh, sh)
			horsPerimetre(rap, f, nom, "protocols.server", chaineDe(pr, "server"), "aucun échange amont dans la transcription (refus au pas 1) : déclaratif (B.4)")
		}
		return
	}
	appel := lu.Msg
	params := appel.Get("params")
	annonce := chaineDe(params, "name")
	alias, origine, prefixe := DecouperNomAnnonce(annonce)
	if !prefixe {
		alias = chaineDe(att, "server_alias")
	}
	rap.Comparer(f, nom, "tool_announced (params.name reçu)", chaineDe(att, "tool_announced"), annonce)
	rap.Comparer(f, nom, "tool_original (découpage au premier __, EX-4.10)", chaineDe(att, "tool_original"), origine)
	rap.Comparer(f, nom, "server_alias", chaineDe(att, "server_alias"), alias)

	// approbation (EX-4.49, EX-7.16) : réponse d'evaluer simulée par le cas ;
	// les issues sans relais rendent un résultat de l'enregistreur.
	if apv := att.Get("approval"); apv == nil {
		rap.Comparer(f, nom, "approval présent (B.4 : null ou { response })", "présent", "absent")
	} else if !apv.IsNull() {
		rep := apv.Get("response")
		issue, invalide := IssueReponseEvaluer(rep)
		rap.ComparerAvecNote(f, nom, "approval.response : combinaison de la table d'EX-7.16", "valide", valideOu(invalide), invalide == "", texteOuAbsent(rep))
		if invalide == "" && issue != IssueRelais && issue != IssueRelaisApprouv {
			verifierIssueSansRelais(rap, ctx, nom, att, hote, amont, servie, recue, rendue, lu, issue, rep)
			return
		}
	}
	if rr := att.Get("result_rendered"); rr == nil {
		rap.Comparer(f, nom, "result_rendered présent (B.4 : null ou résultat de l'enregistreur)", "présent", "absent")
	} else {
		rap.Comparer(f, nom, "result_rendered (appel relayé : aucun résultat rendu par l'enregistreur lui-même, EX-4.49)", "null", texteOuAbsent(rr))
	}

	// relais amont : octets des arguments recopiés sans blancs (EX-4.20, EX-4.43)
	relais := trouverRequete(amont, "out", "tools/call")
	var reponseAmont *LigneTranscription
	if relais != nil {
		reponseAmont = trouverReponse(amont, "in", relais.id())
		pr := relais.Val.Get("params")
		rap.Comparer(f, nom, "params.name relayé = nom d'origine (4.4 pas 9)", origine, chaineDe(pr, "name"))
		rap.Comparer(f, nom, "id amont de forme e-<douze chiffres> (4.4 pas 9)", "oui", oui(reIDAmont.MatchString(chaineDe(relais.Val, "id"))))
		rap.Comparer(f, nom, "ligne amont sans CR ni LF (EX-4.43)", "oui", oui(!bytes.ContainsAny(relais.Ligne, "\r\n")))
		ah, aa := params.Get("arguments"), pr.Get("arguments")
		attendus := "(absent)"
		if ah != nil {
			attendus = string(SansBlancs(recue.Ligne[ah.Debut:ah.Fin]))
		}
		rap.Comparer(f, nom, "octets de params.arguments relayés = octets reçus sans blancs non significatifs (EX-4.20, EX-4.43)", attendus, octetsDe(relais, aa))
		if ci := pr.Get("_meta").Get(CleClientInfo); ci != nil {
			comparerValeur(rap, f, nom, "_meta clientInfo relayé = identité de l'enregistreur (EX-4.7)",
				Objet("name", Chaine(NomEnregistreur), "version", Chaine(VersionEnregistreurVecteurs)), ci)
		}
	} else {
		rap.Erreur("pieces-mcp/%s : aucun tools/call relayé dans amont.jsonl", nom)
		return
	}

	pieces := att.Get("pieces")
	// arguments
	args := params.Get("arguments")
	if args == nil {
		args = ObjetVide() // 8.2 : {} si absent
	}
	pArgs, _, errArgs := PieceRedigeeJSON(pol, "arguments", annonce, args)
	comparerPiece(rap, f, nom, "arguments", pieces.Get("arguments"), pArgs, errArgs)

	// erreur rendue, résultat, is_error
	erreurRendue := rendue.Val.Get("error")
	codeRendu, _ := EntierDe(erreurRendue.Get("code"))
	erreurEnregistreur := false
	switch codeRendu {
	case CodeDelai, CodeAnnulation, CodeInjoignable:
		erreurEnregistreur = true
	case CodeTaille:
		erreurEnregistreur = chaineDe(erreurRendue, "data", "direction") == "reponse"
	}
	var pRes *Piece
	var errRes error
	var estErreur bool
	var erreurAttendue *Value // erreur que l'hôte doit recevoir, ou nil
	switch {
	case erreurEnregistreur:
		pRes, _, errRes = PieceRedigeeJSON(pol, "resultat", annonce, Objet("noortrace_jsonrpc_error", Copier(erreurRendue)))
		estErreur = true
		erreurAttendue = erreurRendue
	case reponseAmont != nil && reponseAmont.Val.Has("result"):
		r := reponseAmont.Val.Get("result")
		if r.Kind != KindObject {
			// 4.4 pas 12 : result qui n'est pas un objet = erreur de protocole du serveur
			erreurAttendue = Objet("code", Entier(-32603), "message", Chaine("noortrace: resultat amont invalide"), "data", Objet("result_type", Chaine(typeJSONDe(r))))
			pRes, _, errRes = PieceRedigeeJSON(pol, "resultat", annonce, Objet("noortrace_jsonrpc_error", Copier(erreurAttendue)))
			estErreur = true
		} else {
			pRes, _, errRes = PieceRedigeeJSON(pol, "resultat", annonce, r)
			ie := r.Get("isError")
			estErreur = ie != nil && ie.Kind == KindBool && ie.Bool
		}
	case reponseAmont != nil && reponseAmont.Val.Has("error"):
		erreurAttendue = reponseAmont.Val.Get("error")
		pRes, _, errRes = PieceRedigeeJSON(pol, "resultat", annonce, Objet("noortrace_jsonrpc_error", Copier(erreurAttendue)))
		estErreur = true
	default:
		rap.Erreur("pieces-mcp/%s : ni réponse amont ni erreur de l'enregistreur rendue", nom)
		return
	}
	comparerPiece(rap, f, nom, "result", pieces.Get("result"), pRes, errRes)
	rap.Comparer(f, nom, "is_error", texteOuAbsent(att.Get("is_error")), strconv.FormatBool(estErreur))

	// définition servie, définition courante, liste annoncée, contexte (EX-4.45, EX-7.7)
	verifierContexteAppel(rap, nom, att, servie, annonce)

	// duration_ms = t_reponse − t_envoi (4.4 pas 11) ; issues sans réponse : EX-4.48
	attDur := att.Get("duration_ms")
	var tReponse time.Time
	source := ""
	switch {
	case codeRendu == CodeDelai:
		tm, _ := EntierDe(erreurRendue.Get("data").Get("timeout_ms"))
		tReponse = relais.T.Add(time.Duration(tm) * time.Millisecond)
		source = "délai : t_envoi + timeout_ms (EX-4.48)"
		if an := trouverAnnulation(amont, relais); an != nil {
			rap.Comparer(f, nom, "annulation amont envoyée à t_envoi + timeout_ms (EX-4.22)", FormaterHorodatage(tReponse), FormaterHorodatage(an.T))
		} else {
			rap.Comparer(f, nom, "annulation amont (notifications/cancelled, EX-4.22)", "présente", "absente")
		}
	case codeRendu == CodeInjoignable && erreurEnregistreur:
		for _, l := range amont {
			if l.EOF {
				tReponse = l.T
			}
		}
		source = "perte : fin de fichier de la sortie standard du serveur (EX-4.48)"
	case codeRendu == CodeTaille && erreurEnregistreur:
		for _, l := range amont {
			if l.Dir == "in" && !l.EOF && int64(len(l.Ligne)) > 0 && l.Val != nil && l.id() == relais.id() {
				tReponse = l.T
			}
		}
		source = "taille : instant où la borne est atteinte (EX-4.48)"
	case reponseAmont != nil:
		tReponse = reponseAmont.T
		source = "réponse amont (4.4 pas 11)"
	}
	if tReponse.IsZero() || relais.T.IsZero() {
		horsPerimetre(rap, f, nom, "duration_ms", texteOuAbsent(attDur), "t_reponse non lisible dans la transcription")
	} else {
		rap.ComparerAvecNote(f, nom, "duration_ms = t_reponse − t_envoi", texteOuAbsent(attDur), fmt.Sprint(tReponse.Sub(relais.T).Milliseconds()),
			texteOuAbsent(attDur) == fmt.Sprint(tReponse.Sub(relais.T).Milliseconds()), source)
	}
	if !tReponse.IsZero() {
		rap.Comparer(f, nom, "réponse rendue après t_reponse (EX-4.19)", "oui", oui(rendue.T.After(tReponse)))
	}

	// erreur rendue à l'hôte et id recopié depuis le texte de l'hôte (4.4 pas 14)
	idRendu := "(absent)"
	if id := rendue.Val.Get("id"); id != nil {
		idRendu = string(rendue.Ligne[id.Debut:id.Fin])
	}
	rap.Comparer(f, nom, "id rendu = octets de l'id reçu (4.4 pas 14)", lu.IDTexte, idRendu)
	attErr := att.Get("error_rendered")
	switch {
	case attErr == nil:
		rap.Comparer(f, nom, "error_rendered présent", "oui", "non")
	case erreurAttendue == nil:
		rap.Comparer(f, nom, "error_rendered", "null", texteOuAbsent(attErr))
		rap.Comparer(f, nom, "aucune erreur rendue (réponse result)", "oui", oui(erreurRendue == nil && rendue.Val.Has("result")))
	default:
		comparerValeur(rap, f, nom, "error_rendered", erreurAttendue, attErr)
		comparerValeur(rap, f, nom, "erreur rendue à l'hôte : même code, message et data (4.4 pas 12 et 14)", erreurAttendue, erreurRendue)
	}
	if erreurRendue != nil {
		code, _ := EntierDe(erreurRendue.Get("code"))
		if msg, ok := MessagesErreurs[code]; ok {
			rap.Comparer(f, nom, fmt.Sprintf("message fixe du code %d (EX-4.24)", code), msg, chaineDe(erreurRendue, "message"))
		}
		// une erreur de l'enregistreur lui-même (préfixe « noortrace: » du
		// message, EX-4.24) porte un code admis ; une erreur relayée du
		// serveur garde le sien (4.4 pas 14)
		if erreurEnregistreur || strings.HasPrefix(chaineDe(erreurRendue, "message"), "noortrace:") {
			comparerCodeEX424(rap, nom, erreurRendue)
		}
	}
	if tm := att.Get("timeout_ms"); tm != nil {
		rap.Comparer(f, nom, "timeout_ms = data.timeout_ms de l'erreur -31011 rendue (EX-4.22)", texteOuAbsent(tm), texteOuAbsent(erreurRendue.Get("data").Get("timeout_ms")))
	}
	if lim, ok := EntierDe(att.Get("limits").Get("response_max_bytes")); ok {
		rap.Comparer(f, nom, "limits.response_max_bytes = data.limit_bytes de l'erreur -31013 rendue", fmt.Sprint(lim), texteOuAbsent(erreurRendue.Get("data").Get("limit_bytes")))
		var lue *LigneTranscription
		for _, l := range amont {
			if l.Dir == "in" && !l.EOF && l.Val != nil && l.id() == relais.id() {
				lue = l
			}
		}
		if lue != nil {
			rap.Comparer(f, nom, "réponse amont au-delà de limits.response_max_bytes (4.4 pas 11)", "oui", oui(int64(len(lue.Ligne)) > lim))
		}
	}
	// ères de protocole déclarées (4.2) : version vue côté hôte et côté serveur
	if pr := att.Get("protocols"); EstObjet(pr) {
		vh, sh := versionHote(hote, &LigneTranscription{Val: appel})
		vs, ss := versionServeur(amont, relais)
		comparerVersion(rap, nom, "protocols.host", chaineDe(pr, "host"), vh, sh)
		comparerVersion(rap, nom, "protocols.server", chaineDe(pr, "server"), vs, ss)
		if chaineDe(pr, "host") != VersionModerne && chaineDe(pr, "server") == VersionModerne {
			m := relais.Val.Get("params").Get("_meta")
			rap.Comparer(f, nom, "_meta requis ajoutés vers le serveur moderne (protocolVersion, clientCapabilities, EX-4.4)", "oui",
				oui(chaineDe(m, "io.modelcontextprotocol/protocolVersion") == VersionModerne && m.Get("io.modelcontextprotocol/clientCapabilities") != nil))
		}
	}
	// résultat rendu = résultat amont aux réécritures près (4.4 pas 14)
	if rendue.Val.Has("result") && reponseAmont != nil && reponseAmont.Val.Has("result") {
		rh, ra := sansIdentiteServeur(rendue.Val.Get("result")), sansIdentiteServeur(reponseAmont.Val.Get("result"))
		if !ra.Has("resultType") {
			Retirer(rh, "resultType")
		}
		comparerValeur(rap, f, nom, "result rendu = result amont, serverInfo et resultType ajoutés exceptés (4.4 pas 14)", ra, rh)
		if si := rendue.Val.Get("result").Get("_meta").Get(CleServerInfo); si != nil {
			comparerValeur(rap, f, nom, "_meta serverInfo rendu = identité de l'enregistreur (EX-4.4)",
				Objet("name", Chaine(NomEnregistreur), "version", Chaine(VersionEnregistreurVecteurs)), si)
		}
	}
}

// verifierContexteAppel recalcule la définition servie, la définition
// courante, la liste annoncée, le contexte (EX-4.45, EX-7.7) et la classe
// (EX-14.1) d'un appel, relayé ou non.
func verifierContexteAppel(rap *Rapport, nom string, att, servie *Value, annonce string) {
	f := FamillePiecesMCP
	pieces := att.Get("pieces")
	var defServie *Value
	for _, d := range servie.Arr {
		if chaineDe(d, "name") == annonce {
			defServie = d
		}
	}
	var pDef, pListe, pCour *Piece
	var errDef, errListe error
	if defServie != nil {
		pDef, errDef = PieceJSON(defServie, false, MediaJSONExplicite)
	}
	comparerPiece(rap, f, nom, "definition (servie)", pieces.Get("definition"), pDef, errDef)
	pListe, errListe = PieceJSON(Objet("tools", servie), false, MediaJSONExplicite)
	comparerPiece(rap, f, nom, "list (liste annoncée servie)", pieces.Get("list"), pListe, errListe)
	defCourante := defServie
	if dc := pieces.Get("definition_current"); dc != nil && !dc.IsNull() {
		// la liste courante n'est pas dans les transcriptions : cohérence de l'attendu
		if b := dc.Get("bytes"); EstChaine(b) {
			rap.Comparer(f, nom, "definition_current · cohérence de l'attendu : sha256(bytes) = sha256", chaineDe(dc, "sha256"), Hex0x(SHA256([]byte(b.Str))))
			if v, err := ParseJSON([]byte(b.Str)); err == nil {
				rap.Comparer(f, nom, "definition_current · bytes en JCS intégral", b.Str, doitIntegral(v))
				rap.Comparer(f, nom, "definition_current · name = nom annoncé", annonce, chaineDe(v, "name"))
				pCour, _ = PieceJSON(v, false, MediaJSONExplicite)
				defCourante = v
			}
		}
		if pDef != nil && pCour != nil {
			rap.Comparer(f, nom, "definition_current différente de la définition servie (autre sha256)", "oui", oui(pCour.SHA256Hex() != pDef.SHA256Hex()))
		}
	}
	if defCourante != nil {
		rap.Comparer(f, nom, "class (EX-14.1 : définition courante, readOnlyHint, sans configuration dans le vecteur)", chaineDe(att, "class"), ClasseOutil(defCourante))
	}
	ctxAttendu := TableauVide()
	ref := func(p *Piece) *Value {
		return Objet("sha256", Chaine(p.SHA256Hex()), "length", Entier(int64(len(p.Octets))), "redacted", Booleen(false), "media_type", Chaine(MediaJSONExplicite), "kind", Chaine("autre"))
	}
	if pDef != nil {
		ctxAttendu.Arr = append(ctxAttendu.Arr, ref(pDef))
	}
	if pCour != nil && (pDef == nil || pCour.SHA256Hex() != pDef.SHA256Hex()) {
		ctxAttendu.Arr = append(ctxAttendu.Arr, ref(pCour))
	}
	if pListe != nil {
		ctxAttendu.Arr = append(ctxAttendu.Arr, ref(pListe))
	}
	comparerValeur(rap, f, nom, "context : définition servie, définition courante si elle diffère, liste annoncée (EX-4.45)", att.Get("context"), ctxAttendu)

}

// valideOu rend « valide », ou « invalide : <raison> ».
func valideOu(raison string) string {
	if raison == "" {
		return "valide"
	}
	return "invalide : " + raison
}

// comparerCodeEX424 vérifie qu'une erreur rendue par l'enregistreur lui-même
// porte un code admis par EX-4.24 (version 0.3).
func comparerCodeEX424(rap *Rapport, nom string, erreur *Value) {
	code, ok := EntierDe(erreur.Get("code"))
	if !ok {
		rap.Comparer(FamillePiecesMCP, nom, "code de l'erreur rendue (EX-4.24)", "entier", texteOuAbsent(erreur.Get("code")))
		return
	}
	admis, raison := CodeAdmisEX424(code)
	obt := "admis"
	if !admis {
		obt = "refusé : " + raison
	}
	rap.Comparer(FamillePiecesMCP, nom, fmt.Sprintf("code %d rendu par l'enregistreur : table de 4.4 ou code standard, hors des plages réservées (EX-4.24)", code), "admis", obt)
}

// verifierIssueSansRelais vérifie un cas d'approbation sans relais (B.4) :
// refus par la politique, ticket nouveau ou en attente, ticket refusé ou
// expiré. Aucun échange amont, pièce « arguments » du pas 4, ni résultat, ni
// is_error, ni duration_ms ; l'hôte reçoit le résultat d'EX-4.49. Les cas
// d'approbation sont rendus en mode d'attente « erreur », celui de la
// configuration de référence (B.4, CT-3 EX-11.1) : le signal en_attente est
// rendu aussitôt ; attendu.json ne porte pas de membre mode.
func verifierIssueSansRelais(rap *Rapport, ctx *contexteCT2, nom string, att *Value, hote, amont []*LigneTranscription, servie *Value, recue, rendue *LigneTranscription, lu RequeteLue, issue string, rep *Value) {
	f := FamillePiecesMCP
	appel := lu.Msg
	params := appel.Get("params")
	annonce := chaineDe(params, "name")
	rap.Comparer(f, nom, "aucun relais amont (lignes dans amont.jsonl)", "0", fmt.Sprint(len(amont)))
	pieces := att.Get("pieces")
	args := params.Get("arguments")
	if args == nil {
		args = ObjetVide()
	}
	pArgs, _, errArgs := PieceRedigeeJSON(ctx.piiV1, "arguments", annonce, args)
	comparerPiece(rap, f, nom, "arguments (pièce écrite au pas 4)", pieces.Get("arguments"), pArgs, errArgs)
	for _, k := range []string{"result"} {
		rap.Comparer(f, nom, "pieces."+k+" (aucun relais, B.4)", "null", texteOuAbsent(pieces.Get(k)))
	}
	for _, k := range []string{"is_error", "duration_ms", "error_rendered"} {
		rap.Comparer(f, nom, k+" (aucun relais, B.4)", "null", texteOuAbsent(att.Get(k)))
	}
	verifierContexteAppel(rap, nom, att, servie, annonce)

	// ère de l'hôte (4.2) : resultType pour l'ère moderne seulement (EX-4.49)
	vh, sh := versionHote(hote, &LigneTranscription{Val: appel})
	moderne := vh == VersionModerne
	if moderne {
		ctx.issuesApprobation[nom] = issue + "/moderne"
	} else {
		ctx.issuesApprobation[nom] = issue + "/héritée"
	}
	if pr := att.Get("protocols"); EstObjet(pr) {
		comparerVersion(rap, nom, "protocols.host", chaineDe(pr, "host"), vh, sh)
		horsPerimetre(rap, f, nom, "protocols.server", chaineDe(pr, "server"), "aucun échange amont dans la transcription (appel non relayé) : déclaratif (B.4)")
	}
	attendu := ResultatAttendu(issue, rep, moderne)
	comparerValeur(rap, f, nom, "result_rendered (EX-4.49, issue "+issue+" d'EX-7.16)", att.Get("result_rendered"), attendu)
	if rendue.Val.Has("error") || !rendue.Val.Has("result") {
		rap.Comparer(f, nom, "réponse rendue : result, jamais une erreur JSON-RPC (EX-4.49, EX-14.5)", "result", "error")
		return
	}
	comparerValeur(rap, f, nom, "result de la ligne rendue = result_rendered", att.Get("result_rendered"), rendue.Val.Get("result"))
	rap.Comparer(f, nom, "ligne rendue, octets exacts : membres dans l'ordre des exemples d'EX-4.49, id recopié (4.4 pas 14)", LigneResultat(lu.IDTexte, attendu), string(rendue.Ligne))
	rap.Comparer(f, nom, "réponse rendue sans structuredContent (EX-4.49)", "(absent)", texteOuAbsent(rendue.Val.Get("result").Get("structuredContent")))
	if r := chaineDe(rep, "rule"); r != "" {
		rap.Comparer(f, nom, "texte rendu sans le nom de la règle (EX-4.49, CT-3 EX-11.8)", "oui", oui(!strings.Contains(string(rendue.Ligne), r)))
	}
	if !recue.T.IsZero() && !rendue.T.IsZero() {
		rap.Comparer(f, nom, "réponse rendue après la requête reçue", "oui", oui(rendue.T.After(recue.T)))
	}
}

// typeJSONDe rend le type JSON d'une valeur pour data.result_type (4.4 pas 12).
func typeJSONDe(v *Value) string {
	switch v.Kind {
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindBool:
		return "boolean"
	case KindArray:
		return "array"
	case KindNull:
		return "null"
	}
	return "object"
}

// octetsDe rend le texte exact d'une valeur dans sa ligne, ou « (absent) ».
func octetsDe(l *LigneTranscription, v *Value) string {
	if v == nil || v.Fin <= v.Debut || v.Fin > len(l.Ligne) {
		return "(absent)"
	}
	return string(l.Ligne[v.Debut:v.Fin])
}

// ---------------------------------------------------------------- agrégation

func verifierAgregation(rap *Rapport, dir, nom string) {
	f := FamillePiecesMCP
	serveurs := lireFichierJSON(rap, filepath.Join(dir, "serveurs.json"))
	att := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))
	if serveurs == nil || att == nil {
		return
	}
	liste := serveurs
	prefixe := true
	page := 100
	if EstObjet(serveurs) {
		liste = serveurs.Get("servers")
		if p := serveurs.Get("prefix"); p != nil && p.Kind == KindBool {
			prefixe = p.Bool
		}
		if n, ok := EntierDe(serveurs.Get("page_size")); ok {
			page = int(n)
		}
	}
	if p := att.Get("prefix"); p != nil && p.Kind == KindBool {
		prefixe = p.Bool // réglage tools.prefix du cas
	}
	if n, ok := EntierDe(att.Get("page_size")); ok {
		page = int(n)
	}
	if !EstTableau(liste) {
		rap.Erreur("pieces-mcp/%s/serveurs.json : tableau de serveurs attendu", nom)
		return
	}
	var normalisations []Normalisation
	if ns := att.Get("normalisations"); EstTableau(ns) {
		for _, n := range ns.Arr {
			san := n.Get("sanitize")
			normalisations = append(normalisations, Normalisation{Gabarit: chaineDe(n, "template"), Normaliser: san != nil && san.Kind == KindBool && san.Bool})
		}
	}
	ag := Agreger(liste, prefixe, page, normalisations...)
	reconnu := false
	// refus de configuration (cas « collision sans préfixe ») : clé non fixée
	// par l'annexe B.4, plusieurs graphies reconnues
	for _, k := range []string{"configuration_refusee", "config_refused", "configuration_refused", "refused", "config_error", "refus_configuration"} {
		if v := att.Get(k); v != nil {
			reconnu = true
			refus := v.Kind == KindBool && v.Bool || EstChaine(v) && v.Str != "" || EstObjet(v)
			rap.ComparerAvecNote(f, nom, "refus de configuration ("+k+", EX-4.10)", oui(refus), oui(ag.RefusConfig), refus == ag.RefusConfig,
				"raisons de ce vérificateur : "+strings.Join(ag.RaisonsRefus, " ; ")+" ; attendu : "+texteOuAbsent(att.Get("erreurs")))
		}
	}
	if ag.RefusConfig && att.Get("announced") == nil {
		rap.Note("pieces-mcp/%s : configuration refusée, aucune liste servie", nom)
	}
	if a := att.Get("announced"); EstTableau(a) {
		reconnu = true
		// empreinte de la définition annoncée (EX-4.16), si l'attendu la donne
		parNom := map[string]OutilAnnonce{}
		for _, x := range ag.Annonces {
			parNom[x.Annonce] = x
		}
		for _, x := range a.Arr {
			if d := chaineDe(x, "definition_sha256"); d != "" {
				obt := "outil non annoncé"
				if o, ok := parNom[chaineDe(x, "announced")]; ok {
					c, err := CanoniqueIntegral(o.Definition)
					if err != nil {
						obt = err.Error()
					} else {
						obt = Hex0x(SHA256(c))
					}
				}
				rap.Comparer(f, nom, "definition_sha256 de "+abrege(chaineDe(x, "announced"))+" = SHA-256(JCS intégral de l'outil annoncé) (EX-4.16)", d, obt)
			}
		}
	}
	if a := att.Get("announced"); EstTableau(a) {
		var attendu, obtenu []string
		for _, x := range a.Arr {
			attendu = append(attendu, fmt.Sprintf("%s|%s|%s|%s", chaineDe(x, "server_alias"), chaineDe(x, "original"), chaineDe(x, "announced"), chaineDe(x, "class")))
		}
		for _, x := range ag.Annonces {
			obtenu = append(obtenu, fmt.Sprintf("%s|%s|%s|%s", x.Alias, x.Origine, x.Annonce, x.Classe))
		}
		rap.Comparer(f, nom, "announced (alias|origine|annoncé|classe, ordre déterministe EX-4.13)", strings.Join(attendu, " ; "), strings.Join(obtenu, " ; "))
	}
	if r := att.Get("rejected"); EstTableau(r) {
		reconnu = true
		var attendu, obtenu []string
		for _, x := range r.Arr {
			attendu = append(attendu, chaineDe(x, "server_alias")+"|"+chaineDe(x, "original")+"|"+chaineDe(x, "reason"))
		}
		for _, x := range ag.Rejets {
			obtenu = append(obtenu, x.Alias+"|"+x.Origine+"|"+x.Raison)
		}
		sort.Strings(attendu)
		sort.Strings(obtenu)
		rap.Comparer(f, nom, "rejected (alias|origine|raison, raisons fixes d'EX-4.11)", strings.Join(attendu, " ; "), strings.Join(obtenu, " ; "))
	}
	if p := att.Get("pages"); EstTableau(p) {
		reconnu = true
		var attendu, obtenu []string
		for _, pg := range p.Arr {
			var noms []string
			if EstTableau(pg) {
				for _, x := range pg.Arr {
					if EstChaine(x) {
						noms = append(noms, x.Str)
					} else {
						noms = append(noms, chaineDe(x, "name"))
					}
				}
			}
			attendu = append(attendu, fmt.Sprintf("[%s]", strings.Join(noms, ",")))
		}
		for _, pg := range ag.Pages {
			obtenu = append(obtenu, fmt.Sprintf("[%s]", strings.Join(pg, ",")))
		}
		rap.Comparer(f, nom, fmt.Sprintf("pages (taille %d, EX-4.13)", page), strings.Join(attendu, " "), strings.Join(obtenu, " "))
	}
	if !reconnu {
		rap.Erreur("pieces-mcp/%s/attendu.json : aucune valeur attendue reconnue (B.4 : announced, rejected, pages)", nom)
	}
}

// trouverAnnulation rend la notification notifications/cancelled envoyée au
// serveur pour la requête relayée, s'il y en a une.
func trouverAnnulation(amont []*LigneTranscription, relais *LigneTranscription) *LigneTranscription {
	if relais == nil {
		return nil
	}
	for _, l := range amont {
		if l.Dir == "out" && l.methode() == "notifications/cancelled" && doitIntegral(l.Val.Get("params").Get("requestId")) == relais.id() {
			return l
		}
	}
	return nil
}

// VersionModerne est la révision MCP de référence (0.3).
const VersionModerne = "2026-07-28"

// versionHote rend la version de protocole vue côté hôte : _meta de la
// requête (ère moderne), sinon la version répondue à initialize (ère
// héritée), sinon "" ; et la source.
func versionHote(hote []*LigneTranscription, appel *LigneTranscription) (string, string) {
	if v := chaineDe(appel.Val, "params", "_meta", "io.modelcontextprotocol/protocolVersion"); v != "" {
		return v, "_meta de la requête de l'hôte"
	}
	if ini := trouverRequete(hote, "in", "initialize"); ini != nil {
		if r := trouverReponse(hote, "out", ini.id()); r != nil {
			return chaineDe(r.Val, "result", "protocolVersion"), "réponse à initialize rendue à l'hôte"
		}
	}
	return "", "requête sans _meta et sans initialize dans la transcription : ère héritée"
}

// versionServeur : version répondue par le serveur à initialize, sinon _meta
// de la requête relayée.
func versionServeur(amont []*LigneTranscription, relais *LigneTranscription) (string, string) {
	if ini := trouverRequete(amont, "out", "initialize"); ini != nil {
		if r := trouverReponse(amont, "in", ini.id()); r != nil {
			return chaineDe(r.Val, "result", "protocolVersion"), "réponse du serveur à initialize"
		}
	}
	if relais != nil {
		if v := chaineDe(relais.Val, "params", "_meta", "io.modelcontextprotocol/protocolVersion"); v != "" {
			return v, "_meta de la requête relayée"
		}
	}
	return "", "aucune version dans la transcription amont"
}

func comparerVersion(rap *Rapport, nom, grandeur, attendu, vu, source string) {
	f := FamillePiecesMCP
	if vu != "" {
		rap.ComparerAvecNote(f, nom, grandeur+" (4.2)", attendu, vu, attendu == vu, "source : "+source)
		return
	}
	// sans version écrite, seule l'ère se déduit : requête sans _meta = ère héritée
	ere := "héritée"
	if attendu == VersionModerne {
		ere = "moderne"
	}
	rap.ComparerAvecNote(f, nom, grandeur+" : ère (4.2)", ere+" ("+attendu+")", "héritée", ere == "héritée", source)
}
