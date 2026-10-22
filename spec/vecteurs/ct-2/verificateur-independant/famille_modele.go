// Famille pieces-modele (annexe B.5) : un répertoire par cas,
// <fournisseur>-<cas>/ { requete.json, requete-entetes.json, reponse.json ou
// reponse.sse, attendu.json }.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RoutesParDefaut est la colonne « Route par défaut » de la table de 5.2.
var RoutesParDefaut = map[string]string{
	"anthropic":      "/v1/messages",
	"bedrock-mantle": "/anthropic/v1/messages",
	FormatChat:       "/v1/chat/completions",
	FormatResponses:  "/v1/responses",
}

// routeDeCas déduit le format et le libellé de fournisseur du nom du cas
// (B.5 : anthropic-messages-*, openai-chat-*, openai-responses-*,
// bedrock-mantle-* même corps qu'Anthropic, libellé bedrock-mantle).
func routeDeCas(nom string) (format, libelle string) {
	switch {
	case strings.HasPrefix(nom, "anthropic-messages-"):
		return FormatAnthropic, "anthropic"
	case strings.HasPrefix(nom, "openai-chat-"):
		return FormatChat, "openai"
	case strings.HasPrefix(nom, "openai-responses-"):
		return FormatResponses, "openai"
	case strings.HasPrefix(nom, "bedrock-mantle-"):
		return FormatAnthropic, "bedrock-mantle"
	}
	return "", ""
}

// CalculModele est ce que ce vérificateur recalcule pour un échange.
type CalculModele struct {
	Format, Libelle string
	Requete         *Value
	Reponse         *Value // corps hors flux, ou forme consolidée
	Consolidation   *Consolidation
	PieceRequete    *Piece
	PieceReponse    *Piece
	PiecePrompt     *Piece
	CodeModel       *Value
	PromptVersion   *Value
	Intent          *Value // chaîne, null, ou référence
	PieceIntent     *Piece
	EstErreur       bool
	Incomplet       bool
	Appels          []AppelOutil
	Statut          int64 // statut HTTP (0 : inconnu)
	ContentType     *Value
	PromptEnLigne   bool   // prompt_in_request: "inline" (EX-8.5)
	Brut            []byte // corps de réponse reçu (hors flux), pour une pièce non JSON ou un corps d'erreur
}

// CorpsRequeteInvalide est le corps d'erreur de la passerelle pour une
// requête non analysable (EX-5.7), au format du fournisseur.
func CorpsRequeteInvalide(format string) *Value {
	msg := "noortrace: corps de requete non analysable"
	if format == FormatAnthropic {
		return Objet("type", Chaine("error"), "error", Objet("type", Chaine("invalid_request_error"), "message", Chaine(msg)))
	}
	return Objet("error", Objet("message", Chaine(msg), "type", Chaine("invalid_request_error"), "param", Nul(), "code", Chaine("noortrace_requete_invalide")))
}

func famillePiecesModele(rap *Rapport, ctx *contexteCT2) {
	dir := filepath.Join(ctx.racine, "pieces-modele")
	cas := sousRepertoires(dir)
	if len(cas) == 0 {
		rap.Erreur("pieces-modele/ : absent ou vide (annexe B.5)")
		return
	}
	for _, c := range cas {
		verifierCasModele(rap, ctx, filepath.Join(dir, c), c)
	}
}

// statutReponse lit le statut HTTP et le Content-Type d'entrée d'un cas
// (hors flux ou en flux), s'ils sont fournis : reponse-entetes.json ({ "status" ou
// ":status", "content-type" }) ou reponse-statut.json. L'annexe B.5 ne
// fournit pas ces entrées (voir README).
func statutReponse(dir string) (int64, *Value, bool) {
	for _, nom := range []string{"reponse-entetes.json", "reponse-statut.json", "statut.json"} {
		b, err := os.ReadFile(filepath.Join(dir, nom))
		if err != nil {
			continue
		}
		v, err := ParseJSON(b)
		if err != nil {
			continue
		}
		var st int64
		var ok bool
		for _, k := range []string{"status", ":status", "statut"} {
			if n, o := EntierDe(v.Get(k)); o {
				st, ok = n, true
			} else if s := chaineDe(v, k); s != "" {
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					st, ok = n, true
				}
			}
		}
		var ct *Value
		for _, k := range []string{"content-type", "Content-Type", "content_type"} {
			if x := v.Get(k); x != nil {
				ct = x
			}
		}
		if ok {
			return st, ct, true
		}
	}
	return 0, nil, false
}

func verifierCasModele(rap *Rapport, ctx *contexteCT2, dir, nom string) {
	f := FamillePiecesModele
	att := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))
	if att == nil {
		return
	}
	format, libelle := routeDeCas(nom)
	if format == "" {
		rap.Erreur("pieces-modele/%s : nom de cas hors des formes de B.5", nom)
		return
	}
	rap.Comparer(f, nom, "format (déduit du nom du cas)", chaineDe(att, "format"), format)
	rap.Comparer(f, nom, "provider_label (déduit du nom du cas)", chaineDe(att, "provider_label"), libelle)
	if r := att.Get("route"); r != nil {
		cle := libelle
		if format != FormatAnthropic {
			cle = format
		}
		rap.Comparer(f, nom, "route (route par défaut de la table de 5.2)", texteOuAbsent(r), RoutesParDefaut[cle])
	}
	options := att.Get("options")
	enLigne := chaineDe(options, "prompt_in_request") == "inline"
	var req *Value
	if brut := filepath.Join(dir, "requete.brut"); fichierExiste(brut) {
		// requête reçue telle quelle : si elle ne s'analyse pas en JSON strict,
		// la passerelle refuse par 400 sans relais ni événement (EX-5.7)
		octets, err := os.ReadFile(brut)
		if err != nil {
			rap.Erreur("pieces-modele/%s/requete.brut : %v", nom, err)
			return
		}
		v, err := ParseJSON(octets)
		if err != nil {
			attendu := Objet("status", Entier(400), "reason", Chaine("corps_non_analysable"), "body", CorpsRequeteInvalide(format))
			comparerValeur(rap, f, nom, "refused : 400, corps d'erreur au format du fournisseur (EX-5.7)", att.Get("refused"), attendu)
			for _, k := range []string{"pieces", "status", "code_model", "intent"} {
				rap.Comparer(f, nom, k+" (aucun événement, EX-5.7)", "null", texteOuAbsent(att.Get(k)))
			}
			rap.Comparer(f, nom, "réponse présente dans le vecteur (rien n'est relayé, EX-5.7)", "non", oui(fichierExiste(filepath.Join(dir, "reponse.json")) || fichierExiste(filepath.Join(dir, "reponse.sse"))))
			return
		}
		req = v
	} else {
		req = lireFichierJSON(rap, filepath.Join(dir, "requete.json"))
	}
	if req == nil {
		return
	}
	if r := att.Get("refused"); r != nil && !r.IsNull() {
		rap.Comparer(f, nom, "refused (requête JSON stricte : relayée)", "null", texteOuAbsent(r))
	}
	if e := filepath.Join(dir, "requete-entetes.json"); fichierExiste(e) {
		if h := lireFichierJSON(rap, e); EstObjet(h) {
			for _, m := range h.Obj {
				switch strings.ToLower(m.Key) {
				case "authorization", "x-api-key", "api-key", "proxy-authorization", "cookie", "set-cookie":
					rap.Comparer(f, nom, "requete-entetes.json sans en-tête d'authentification (B.5)", "aucun", m.Key)
				}
			}
		}
	}
	calc := &CalculModele{Format: format, Libelle: libelle, Requete: req, PromptEnLigne: enLigne}
	st, ct, okSt := statutReponse(dir)
	if !okSt {
		rap.Erreur("pieces-modele/%s/reponse-entetes.json : statut absent (B.5)", nom)
		return
	}
	calc.Statut, calc.ContentType = st, ct
	media := ""
	if EstChaine(ct) {
		media = TypeDeMedia(ct.Str)
	}
	sse := filepath.Join(dir, "reponse.sse")
	if fichierExiste(sse) {
		octets, err := os.ReadFile(sse)
		if err != nil {
			rap.Erreur("pieces-modele/%s/reponse.sse : %v", nom, err)
			return
		}
		rap.Comparer(f, nom, "type de média de la réponse en flux (5.3.1 pas 5, EX-5.11)", MediaFluxSSE, media)
		evs, _ := AnalyserSSE(octets)
		c, _ := Consolider(format, evs)
		calc.Consolidation = c
		calc.Reponse = c.Forme
		calc.EstErreur = c.EstErreur()
		calc.Incomplet = c.Incomplet
		comparerValeur(rap, f, nom, "forme consolidée (5.4)", att.Get("consolidated"), c.Forme)
		// fragmentation : le flux découpé octet par octet donne les mêmes événements
		a := &AnalyseurSSE{}
		for i := range octets {
			a.Ecrire(octets[i : i+1])
		}
		evs1 := a.Fin()
		rap.Comparer(f, nom, "analyse SSE invariante à la fragmentation (flux entier puis octet par octet, EX-5.14)",
			fmt.Sprintf("%d événements, SHA-256 %s", len(evs), Hex0x(SHA256([]byte(EvenementsTexte(evs))))),
			fmt.Sprintf("%d événements, SHA-256 %s", len(evs1), Hex0x(SHA256([]byte(EvenementsTexte(evs1))))))
		for _, n := range c.Notes {
			rap.Note("pieces-modele/%s : %s", nom, n)
		}
	} else {
		octets, err := os.ReadFile(filepath.Join(dir, "reponse.json"))
		if err != nil {
			rap.Erreur("pieces-modele/%s/reponse.json : %v", nom, err)
			return
		}
		calc.Brut = octets
		if cv := att.Get("consolidated"); cv != nil && !cv.IsNull() {
			rap.Comparer(f, nom, "consolidated hors flux", "null", doitIntegral(cv))
		}
		// 5.3.1 pas 5 : seul un corps de type de média JSON est analysé
		if EstTypeJSON(media) {
			if v, err := ParseJSON(octets); err == nil {
				calc.Reponse = v
			}
		}
		calc.EstErreur = calc.Statut >= 400 || calc.Reponse == nil
	}
	calculerEchange(ctx.piiV1, calc)

	if st := att.Get("status"); st != nil {
		rap.Comparer(f, nom, "status (statut HTTP de la réponse)", texteOuAbsent(st), fmt.Sprint(calc.Statut))
	}
	pieces := att.Get("pieces")
	if pi := pieces.Get("intent"); pi != nil {
		comparerPiece(rap, f, nom, "intent (pièce text/plain, EX-5.21)", pi, calc.PieceIntent, nil)
	}
	comparerPiece(rap, f, nom, "request", pieces.Get("request"), calc.PieceRequete, nil)
	comparerPiece(rap, f, nom, "response", pieces.Get("response"), calc.PieceReponse, nil)
	comparerPiece(rap, f, nom, "system_prompt", pieces.Get("system_prompt"), calc.PiecePrompt, nil)
	comparerValeur(rap, f, nom, "code_model (EX-5.19)", att.Get("code_model"), calc.CodeModel)
	comparerValeur(rap, f, nom, "prompt_version (EX-8.6)", att.Get("prompt_version"), calc.PromptVersion)
	attIntent := att.Get("intent")
	switch {
	case EstObjet(attIntent) && calc.PieceIntent != nil:
		comparerPiece(rap, f, nom, "intent (référence, EX-5.21)", attIntent, calc.PieceIntent, nil)
	default:
		comparerValeur(rap, f, nom, "intent (EX-5.21)", attIntent, calc.Intent)
	}
	rap.Comparer(f, nom, "is_error", texteOuAbsent(att.Get("is_error")), strconv.FormatBool(calc.EstErreur))
	rap.Comparer(f, nom, "incomplete", texteOuAbsent(att.Get("incomplete")), strconv.FormatBool(calc.Incomplet))
	if tc := att.Get("tool_calls"); tc != nil {
		obt := TableauVide()
		for _, a := range calc.Appels {
			args := a.Arguments
			if args == nil {
				args = Nul()
			}
			obt.Arr = append(obt.Arr, Objet("id", Chaine(a.ID), "name", Chaine(a.Nom), "arguments", Copier(args)))
		}
		comparerValeur(rap, f, nom, "tool_calls (table de 5.5, arguments en clair)", tc, obt)
	}
}

// calculerEchange recalcule les pièces et grandeurs d'un échange de modèle
// (5.3.1, 5.5, 8.2) avec la politique de rédaction donnée.
func calculerEchange(pol *Politique, c *CalculModele) {
	deForme := RequeteDeForme(c.Format, c.Requete)
	avant, _ := CanoniqueIntegral(c.Requete)
	corps := c.Requete
	texte, present := "", false
	if deForme {
		texte, present = PromptSysteme(c.Format, c.Requete)
	}
	if present {
		if c.PromptEnLigne {
			corps = RedigerPromptEnPlace(c.Format, c.Requete, pol) // EX-8.5, mode inline
		} else {
			corps = RemplacerPromptSysteme(c.Format, c.Requete) // défaut : reference
		}
		c.PiecePrompt, _ = PieceRedigeeTexte(pol, "prompt_systeme", "", texte)
		c.PromptVersion = Chaine(c.PiecePrompt.SHA256Hex())
	} else {
		c.PromptVersion = Nul()
	}
	pr, resReq, err := PieceRedigeeJSON(pol, "requete", "", corps)
	var requeteRedigee *Value
	if err == nil {
		pr.Redigee = string(pr.Octets) != string(avant) // EX-10.16 : le jeton compte comme rédaction
		c.PieceRequete = pr
		requeteRedigee = resReq.Valeur
	}
	// réponse
	var reponseRedigee *Value
	switch {
	case c.Statut >= 400:
		ct := Nul()
		if c.ContentType != nil {
			ct = Copier(c.ContentType)
		}
		var corpsErreur *Value
		switch {
		case c.Reponse != nil:
			corpsErreur = Copier(c.Reponse)
		case len(c.Brut) == 0:
			corpsErreur = Nul()
		case utf8.Valid(c.Brut):
			corpsErreur = Chaine(string(c.Brut))
		default:
			corpsErreur = Objet("noortrace_non_redigeable", Objet("content_type", Copier(ct), "length", Entier(int64(len(c.Brut))), "reason", Chaine("non_utf8")))
		}
		forme := Objet("noortrace_http_error", Objet("status", Entier(c.Statut), "content_type", ct, "body", corpsErreur))
		c.PieceReponse, _, _ = PieceRedigeeJSON(pol, "reponse", "", forme)
	case c.Reponse == nil && c.Consolidation != nil:
		// aucune forme : la pièce serait le flux tel quel (EX-8.7), non recalculée ici
	case c.Reponse == nil:
		c.PieceReponse = PieceBrute(pol, "reponse", c.Brut, c.ContentType)
	default:
		p, res, _ := PieceRedigeeJSON(pol, "reponse", "", c.Reponse)
		c.PieceReponse = p
		reponseRedigee = res.Valeur
	}
	// code.model : réponse rédigée, à défaut requête rédigée de la forme attendue (EX-5.7, EX-5.19)
	reqModele := Nul()
	if deForme && requeteRedigee != nil {
		reqModele = requeteRedigee
	}
	c.CodeModel = CodeModel(c.Libelle, reqModele, reponseRedigee)
	// intent : extrait de la réponse rédigée ; référence si rédigé ou au-delà de 4096 (EX-5.21)
	c.Intent = Nul()
	if c.Statut < 400 && reponseRedigee != nil {
		if t, ok := TexteAssistant(c.Format, reponseRedigee); ok {
			clair, _ := TexteAssistant(c.Format, c.Reponse)
			redige := t != clair
			if redige || utf8.RuneCountInString(t) > 4096 {
				c.PieceIntent = &Piece{Octets: []byte(t), Redigee: redige, MediaType: MediaTexte}
				c.Intent = Objet("sha256", Chaine(c.PieceIntent.SHA256Hex()), "length", Entier(int64(len(t))),
					"redacted", Booleen(redige), "media_type", Chaine(MediaTexte))
			} else {
				c.Intent = Chaine(t)
			}
		}
		c.Appels = AppelsOutils(c.Format, c.Reponse)
	}
}
