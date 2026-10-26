// Cas pieces-modele/gemini-* (annexe B.5, révision 0.5) : chaque valeur
// d'attendu.json est recalculée depuis requete-ligne.json, requete.json (ou
// requete.brut), requete-entetes.json, reponse-entetes.json, reponse.json ou
// reponse.sse (ou reponse-morceaux.json pour gemini-sdk-*), selon 5.3.3,
// 5.4.5, 5.5, EX-6.8 et EX-8.5.

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// LibelleGemini : libellé de fournisseur des cas gemini-* (B.5).
const LibelleGemini = "gemini"

// calculGemini est ce que ce vérificateur recalcule pour un cas gemini.
type calculGemini struct {
	route, segment, cibleAmont, via *Value
	refus                           *Value
	statut                          *Value
	consolide                       *Value
	pieceRequete, pieceReponse      *Piece
	piecePrompt, pieceIntent        *Piece
	codeModel, promptVersion        *Value
	intent                          *Value
	appels                          *Value
	estErreur                       *Value
	incomplet                       bool
	retires                         []string
	notes                           []string
}

func refusGemini(statut int64, raison string, ct *Value, corps *Value) *Value {
	if corps == nil {
		corps = Nul()
	}
	return Objet("status", Entier(statut), "reason", Chaine(raison), "content_type", ct, "body", corps)
}

func verifierCasGemini(rap *Rapport, ctx *contexteCT2, dir, nom string) {
	f := FamillePiecesModele
	att := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))
	if att == nil {
		return
	}
	pol := ctx.piiV1
	options := att.Get("options")
	enLigne := chaineDe(options, "prompt_in_request") == "inline"
	sdk := strings.HasPrefix(nom, "gemini-sdk-")
	c := &calculGemini{route: Nul(), segment: Nul(), cibleAmont: Nul(), refus: Nul(), statut: Nul(), consolide: Nul(),
		codeModel: Nul(), promptVersion: Nul(), intent: Nul(), appels: TableauVide(), estErreur: Nul()}
	rap.Comparer(f, nom, "format (cas gemini-*, B.5)", chaineDe(att, "format"), FormatGemini)
	rap.Comparer(f, nom, "provider_label (libellé gemini, B.5)", chaineDe(att, "provider_label"), LibelleGemini)
	// en-têtes de requête : aucun en-tête d'authentification (B.5, 5.3)
	if e := filepath.Join(dir, "requete-entetes.json"); fichierExiste(e) {
		if h := lireFichierJSON(rap, e); EstObjet(h) {
			for _, m := range h.Obj {
				switch strings.ToLower(m.Key) {
				case "authorization", "x-api-key", "api-key", "x-goog-api-key", "proxy-authorization", "cookie", "set-cookie":
					rap.Comparer(f, nom, "requete-entetes.json sans en-tête d'authentification (B.5)", "aucun", m.Key)
				}
			}
		}
	}
	var ligne *Value
	var rg RequeteGemini
	if sdk {
		c.via = Chaine("sdk")
		ligne = Nul()
	} else {
		c.via = Chaine("passerelle")
		ligne = lireFichierJSON(rap, filepath.Join(dir, "requete-ligne.json"))
		if ligne == nil {
			return
		}
		rg = AnalyserCibleGemini(chaineDe(ligne, "method"), chaineDe(ligne, "target"), RoutesGemini)
	}
	comparerValeur(rap, f, nom, "request_line (= requete-ligne.json, B.5)", att.Get("request_line"), ligne)
	finir := func() { comparerCasGemini(rap, f, nom, att, c) }
	if !sdk {
		if rg.CheminInvalide {
			rap.Erreur("pieces-modele/%s : chemin refusé par la normalisation d'EX-5.2 (400), forme d'attendu non fixée par B.5", nom)
			return
		}
		if !rg.Trouvee {
			// EX-5.28 : 404 sans relais, sans corps propre au format, aucune pièce
			c.refus = refusGemini(404, "route_inconnue", Nul(), Nul())
			finir()
			return
		}
		c.route, c.segment = Chaine(rg.Route), Chaine(rg.Segment)
		// pas 3 : hôte inconnu (host_known: false, B.5) → 401, corps d'EX-5.30
		if hk := ligne.Get("host_known"); hk != nil && hk.Kind == KindBool && !hk.Bool {
			c.refus = refusGemini(401, "hote_inconnu", Chaine(rg.TypeRefusGemini()), CorpsErreurGemini("hote_inconnu"))
			finir()
			return
		}
		if rg.RaisonRequete != "" {
			c.refus = refusGemini(400, rg.RaisonRequete, Chaine(rg.TypeRefusGemini()), CorpsErreurGemini(rg.RaisonRequete))
			finir()
			return
		}
	}
	// corps de la requête (pas 5) : JSON strict, sinon refus (EX-5.7 point 2)
	var req *Value
	if brut := filepath.Join(dir, "requete.brut"); fichierExiste(brut) {
		octets, err := os.ReadFile(brut)
		if err != nil {
			rap.Erreur("pieces-modele/%s/requete.brut : %v", nom, err)
			return
		}
		v, err := ParseJSON(octets)
		if err != nil {
			c.refus = refusGemini(400, "corps_non_analysable", Chaine(rg.TypeRefusGemini()), CorpsErreurGemini("corps_non_analysable"))
			finir()
			return
		}
		req = v
	} else {
		req = lireFichierJSON(rap, filepath.Join(dir, "requete.json"))
		if req == nil {
			return
		}
	}
	// pas 6 : serveurs MCP déclarés au fournisseur (provider_mcp absent : refuser)
	if !sdk && ServeursMCPFournisseur(req) {
		c.refus = refusGemini(400, "serveurs_mcp_fournisseur", Chaine(rg.TypeRefusGemini()), CorpsErreurGemini("serveurs_mcp_fournisseur"))
		finir()
		return
	}
	// pas 6 bis : contenu en cache du fournisseur (provider_cache absent : refuser)
	if !sdk && CacheFournisseur(req) {
		c.refus = refusGemini(400, "cache_fournisseur", Chaine(rg.TypeRefusGemini()), CorpsErreurGemini("cache_fournisseur"))
		finir()
		return
	}
	if !sdk {
		c.cibleAmont = Chaine(rg.CibleAmont())
	}
	// pas 7 et 8 : forme attendue, prompt système, pièce « requête »
	deForme := RequeteGeminiDeForme(req)
	avant, _ := CanoniqueIntegral(req)
	corps := req
	if deForme {
		if texte, ok := PromptSystemeGemini(req); ok {
			if enLigne {
				corps = RedigerPromptGeminiEnPlace(req, pol)
			} else {
				corps = RemplacerPromptGemini(req)
			}
			c.piecePrompt, _ = PieceRedigeeTexte(pol, "prompt_systeme", "", texte)
			c.promptVersion = Chaine(c.piecePrompt.SHA256Hex())
		}
	}
	if pr, _, err := PieceRedigeeJSON(pol, "requete", "", corps); err == nil {
		pr.Redigee = string(pr.Octets) != string(avant)
		c.pieceRequete = pr
	}
	// réponse
	var statut int64
	var ct *Value
	var rep *Value // forme en clair (corps JSON hors flux, ou forme consolidée)
	var brut []byte
	formeBrute := false
	erreurDeclaree := false
	if sdk {
		// echangeModele (EX-6.8) : status et is_error sont des paramètres déclarés
		// par le SDK, lus dans echange-sdk.json (B.5)
		es := lireFichierJSON(rap, filepath.Join(dir, "echange-sdk.json"))
		if es == nil {
			return
		}
		n, ok := EntierDe(es.Get("status"))
		if !ok {
			rap.Erreur("pieces-modele/%s/echange-sdk.json : status déclaré absent (paramètre de echangeModele)", nom)
			return
		}
		statut = n
		if d := es.Get("is_error"); d != nil && d.Kind == KindBool {
			erreurDeclaree = d.Bool
		}
		ct = Nul()
		morceaux := lireFichierJSON(rap, filepath.Join(dir, "reponse-morceaux.json"))
		if morceaux == nil {
			return
		}
		r, retires := RetirerMembresSDK(morceaux)
		c.retires = retires
		switch {
		case statut >= 400:
			rep = r
		case EstTableau(r) && len(r.Arr) == 0:
			rep = Objet("noortrace_flux_incomplet", Booleen(true))
			c.incomplet = true
		case EstTableau(r):
			k := ConsoliderGemini(r.Arr, true)
			if k.Forme == nil {
				rap.Erreur("pieces-modele/%s : aucun morceau valide (EX-6.8 ne fixe pas la pièce)", nom)
				return
			}
			rep = k.Forme
			c.incomplet = k.Incomplet
		default:
			rep = r
		}
		if EstTableau(r) && statut < 400 {
			c.consolide = Copier(rep)
		}
	} else {
		st, ctv, ok := statutReponse(dir)
		if !ok {
			rap.Erreur("pieces-modele/%s/reponse-entetes.json : statut absent (B.5)", nom)
			return
		}
		statut, ct = st, ctv
		if ct == nil {
			ct = Nul()
		}
		media := ""
		if EstChaine(ct) {
			media = TypeDeMedia(ct.Str)
		}
		sse := filepath.Join(dir, "reponse.sse")
		chemin := filepath.Join(dir, "reponse.json")
		if fichierExiste(sse) {
			chemin = sse
		}
		octets, err := os.ReadFile(chemin)
		if err != nil {
			rap.Erreur("pieces-modele/%s : réponse illisible : %v", nom, err)
			return
		}
		brut = octets
		switch {
		case statut >= 400:
			// EX-5.31 : analysé en JSON strict quel que soit le Content-Type
			if v, err := ParseJSON(octets); err == nil {
				rep = v
			}
		case media == MediaFluxSSE:
			a := &AnalyseurSSE{}
			a.Ecrire(octets)
			evs, final := a.FinGemini()
			if final {
				c.notes = append(c.notes, "data final sans ligne vide distribué (EX-5.34, sse_data_final_sans_ligne_vide)")
			}
			var vals []*Value
			for _, e := range evs {
				v, err := ParseJSON([]byte(e.Data))
				if err != nil {
					v = nil
				}
				vals = append(vals, v)
			}
			k := ConsoliderGemini(vals, true)
			c.incomplet = k.Incomplet
			if k.Forme != nil {
				rep = k.Forme
				c.consolide = Copier(k.Forme)
			} else {
				formeBrute = true
			}
			// fragmentation : octet par octet, mêmes valeurs distribuées
			a1 := &AnalyseurSSE{}
			for i := range octets {
				a1.Ecrire(octets[i : i+1])
			}
			evs1, _ := a1.FinGemini()
			rap.Comparer(f, nom, "analyse SSE invariante à la fragmentation (EX-5.14, EX-5.34)",
				Hex0x(SHA256([]byte(EvenementsTexte(evs)))), Hex0x(SHA256([]byte(EvenementsTexte(evs1)))))
		case EstTypeJSON(media):
			if v, err := ParseJSON(octets); err == nil {
				rep = v
			}
		}
	}
	c.statut = Entier(statut)
	// pièce « réponse » (5.3.1 pas 7, EX-5.31, EX-6.8 pas 4)
	var repRedigee *Value
	switch {
	case statut >= 400:
		var bodyV *Value
		switch {
		case rep != nil:
			bodyV = Copier(rep)
		case len(brut) == 0:
			bodyV = Nul()
		case utf8.Valid(brut):
			bodyV = Chaine(string(brut))
		default:
			bodyV = Objet("noortrace_non_redigeable", Objet("content_type", Copier(ct), "length", Entier(int64(len(brut))), "reason", Chaine("non_utf8")))
		}
		forme := Objet("noortrace_http_error", Objet("status", Entier(statut), "content_type", Copier(ct), "body", bodyV))
		c.pieceReponse, _, _ = PieceRedigeeJSON(pol, "reponse", "", forme)
		c.estErreur = Booleen(true)
	case formeBrute || rep == nil:
		c.pieceReponse = PieceBrute(pol, "reponse", brut, ct)
		c.estErreur = Booleen(true)
	default:
		p, res, _ := PieceRedigeeJSON(pol, "reponse", "", rep)
		c.pieceReponse = p
		repRedigee = res.Valeur
		c.estErreur = Booleen(c.incomplet || EstObjet(rep.Get("noortrace_erreur_flux")))
	}
	// EX-6.8 : is_error = déclaré OU calculé
	if erreurDeclaree {
		c.estErreur = Booleen(true)
	}
	// code.model (EX-5.36, EX-6.8 pas 5)
	if sdk {
		c.codeModel = CodeModelSDKGemini(LibelleGemini, repRedigee, req, pol)
	} else {
		c.codeModel = CodeModelGemini(LibelleGemini, repRedigee, rg.Segment, pol)
	}
	// intent (EX-5.21, colonne Gemini de 5.5) et appels de fonction
	if statut < 400 && repRedigee != nil {
		if t, ok := IntentGemini(repRedigee); ok {
			clair, _ := IntentGemini(rep)
			redige := t != clair
			if redige || utf8.RuneCountInString(t) > 4096 {
				c.pieceIntent = &Piece{Octets: []byte(t), Redigee: redige, MediaType: MediaTexte}
				c.intent = Objet("sha256", Chaine(c.pieceIntent.SHA256Hex()), "length", Entier(int64(len(t))),
					"redacted", Booleen(redige), "media_type", Chaine(MediaTexte))
			} else {
				c.intent = Chaine(t)
			}
		}
		for _, a := range AppelsGemini(rep) {
			c.appels.Arr = append(c.appels.Arr, Objet("id", a.ID, "name", Chaine(a.Nom), "arguments", a.Args))
		}
	}
	for _, n := range c.notes {
		rap.Note("pieces-modele/%s : %s", nom, n)
	}
	finir()
}

func comparerCasGemini(rap *Rapport, f, nom string, att *Value, c *calculGemini) {
	comparerValeur(rap, f, nom, "route (EX-5.28)", att.Get("route"), c.route)
	comparerValeur(rap, f, nom, "model_segment (EX-5.28)", att.Get("model_segment"), c.segment)
	comparerValeur(rap, f, nom, "upstream_target (EX-5.28, EX-5.29)", att.Get("upstream_target"), c.cibleAmont)
	comparerValeur(rap, f, nom, "via", att.Get("via"), c.via)
	comparerValeur(rap, f, nom, "refused (EX-5.28 à EX-5.32, EX-5.7)", att.Get("refused"), c.refus)
	retires := TableauVide()
	for _, r := range c.retires {
		retires.Arr = append(retires.Arr, Chaine(r))
	}
	comparerValeur(rap, f, nom, "removed_members (EX-6.8 pas 3)", att.Get("removed_members"), retires)
	comparerValeur(rap, f, nom, "status", att.Get("status"), c.statut)
	comparerValeur(rap, f, nom, "consolidated (EX-5.35)", att.Get("consolidated"), c.consolide)
	pieces := att.Get("pieces")
	if !c.refus.IsNull() {
		comparerValeur(rap, f, nom, "pieces (refus : aucune pièce, aucun événement)", pieces, Nul())
	} else {
		comparerPiece(rap, f, nom, "request", pieces.Get("request"), c.pieceRequete, nil)
		comparerPiece(rap, f, nom, "response", pieces.Get("response"), c.pieceReponse, nil)
		comparerPiece(rap, f, nom, "system_prompt", pieces.Get("system_prompt"), c.piecePrompt, nil)
		if pi := pieces.Get("intent"); pi != nil {
			comparerPiece(rap, f, nom, "intent (pièce text/plain, EX-5.21)", pi, c.pieceIntent, nil)
		}
	}
	comparerValeur(rap, f, nom, "code_model (EX-5.36, EX-6.8)", att.Get("code_model"), c.codeModel)
	comparerValeur(rap, f, nom, "prompt_version (EX-8.6)", att.Get("prompt_version"), c.promptVersion)
	comparerValeur(rap, f, nom, "intent (colonne Gemini de 5.5, EX-5.21)", att.Get("intent"), c.intent)
	comparerValeur(rap, f, nom, "tool_calls (functionCall de candidates[0], 5.5)", att.Get("tool_calls"), c.appels)
	comparerValeur(rap, f, nom, "is_error", att.Get("is_error"), c.estErreur)
	rap.Comparer(f, nom, "incomplete (noortrace_flux_incomplet)", texteOuAbsent(att.Get("incomplete")), strconv.FormatBool(c.incomplet))
}
