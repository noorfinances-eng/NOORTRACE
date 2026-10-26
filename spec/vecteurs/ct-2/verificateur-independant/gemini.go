// Format gemini de la passerelle (CT-2 révision 0.5) : route et segment de
// modèle (EX-5.28), chaîne de requête (EX-5.29), corps d'erreur AIP-193
// (EX-5.30), réponse d'erreur amont (EX-5.31), serveurs MCP déclarés au
// fournisseur (EX-5.32), data final (EX-5.34), forme consolidée (EX-5.35),
// code.model (EX-5.36), colonne Gemini de 5.5, remplacement du prompt
// (EX-8.5) et échange déclaré par le SDK (EX-6.8).

package main

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// FormatGemini est la valeur de format d'une route Gemini.
const FormatGemini = "gemini"

// RoutesGemini : chemins de collection des modèles de B.5 (« route
// /v1beta/models, libellé gemini, sauf mention » ; /v1/models pour
// gemini-v1-non-flux), une route par version (EX-5.28).
var RoutesGemini = []string{"/v1beta/models", "/v1/models"}

// reSegmentModele est le motif du segment de modèle d'EX-5.28.
var reSegmentModele = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)

// Content-Type des réponses produites par une route gemini (EX-5.30).
const (
	TypeErreurGeminiJSON = "application/json; charset=UTF-8"
	TypeErreurGeminiSSE  = "text/event-stream"
)

// MessagesErreurGemini : corps exacts de la table d'EX-5.30, par raison.
var MessagesErreurGemini = map[string]struct {
	Statut  int64
	Message string
	Nom     string
}{
	"corps_non_analysable":     {400, "noortrace: corps de requete non analysable", "INVALID_ARGUMENT"},
	"cle_dans_url":             {400, "noortrace: cle d'API dans l'URL refusee", "INVALID_ARGUMENT"},
	"flux_sans_sse":            {400, "noortrace: streamGenerateContent exige alt=sse", "INVALID_ARGUMENT"},
	"parametre_non_admis":      {400, "noortrace: parametre de requete non admis", "INVALID_ARGUMENT"},
	"serveurs_mcp_fournisseur": {400, "noortrace: serveurs MCP declares au fournisseur refuses", "INVALID_ARGUMENT"},
	"cache_fournisseur":        {400, "noortrace: contenu en cache du fournisseur refuse", "INVALID_ARGUMENT"},
	"hote_inconnu":             {401, "noortrace: hote non authentifie", "UNAUTHENTICATED"},
	"taille":                   {413, "noortrace: corps de requete trop grand", "INVALID_ARGUMENT"},
	"content_encoding":         {415, "noortrace: requete comprimee refusee", "INVALID_ARGUMENT"},
	"mode_degrade":             {503, "noortrace: echange bloque, enregistreur en mode degrade", "UNAVAILABLE"},
	"delai":                    {504, "noortrace: delai du fournisseur depasse", "DEADLINE_EXCEEDED"},
}

// CorpsErreurGemini rend le corps AIP-193 d'EX-5.30 pour une raison.
func CorpsErreurGemini(raison string) *Value {
	m, ok := MessagesErreurGemini[raison]
	if !ok {
		return nil
	}
	return Objet("error", Objet("code", Entier(m.Statut), "message", Chaine(m.Message), "status", Chaine(m.Nom)))
}

// RequeteGemini est le résultat des pas 2 et 4 du chemin de données (5.3.3).
type RequeteGemini struct {
	Route, Segment, Methode string // Methode : generateContent ou streamGenerateContent
	Trouvee                 bool
	CheminInvalide          bool   // 400 d'EX-5.2 (normalisation)
	RaisonRequete           string // refus d'EX-5.29, "" si admise
	AltSSE                  bool   // un paramètre alt de valeur sse est présent
}

// estNonReserve : caractères non réservés de la RFC 3986.
func estNonReserve(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func valHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// NormaliserChemin applique la normalisation d'EX-5.2 : refus de %2F, d'un
// segment . ou .., d'une barre doublée, d'un octet hors de l'ASCII imprimable ;
// décodage des encodages pourcent de caractères non réservés.
func NormaliserChemin(p string) (string, bool) {
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return "", false
		}
	}
	if strings.Contains(strings.ToLower(p), "%2f") || strings.Contains(p, "//") {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) && valHex(p[i+1]) >= 0 && valHex(p[i+2]) >= 0 {
			c := byte(valHex(p[i+1])<<4 | valHex(p[i+2]))
			if estNonReserve(c) {
				sb.WriteByte(c)
				i += 2
				continue
			}
		}
		sb.WriteByte(p[i])
	}
	n := sb.String()
	for _, s := range strings.Split(n, "/") {
		if s == "." || s == ".." {
			return "", false
		}
	}
	return n, true
}

// decoderPourcent décode l'encodage pourcent d'un nom ou d'une valeur (EX-5.29).
func decoderPourcent(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && valHex(s[i+1]) >= 0 && valHex(s[i+2]) >= 0 {
			b = append(b, byte(valHex(s[i+1])<<4|valHex(s[i+2])))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

// AnalyserCibleGemini applique EX-5.2, EX-5.28 et EX-5.29 à une ligne de
// requête reçue (méthode, cible telle que reçue).
func AnalyserCibleGemini(methode, cible string, routes []string) RequeteGemini {
	var r RequeteGemini
	chemin, requete, aRequete := cible, "", false
	if i := strings.IndexByte(cible, '?'); i >= 0 {
		chemin, requete, aRequete = cible[:i], cible[i+1:], true
	}
	n, ok := NormaliserChemin(chemin)
	if !ok {
		r.CheminInvalide = true
		return r
	}
	if methode != "POST" {
		return r
	}
	for _, route := range routes {
		if !strings.HasPrefix(n, route+"/") {
			continue
		}
		reste := n[len(route)+1:]
		for _, m := range []string{"generateContent", "streamGenerateContent"} {
			if strings.HasSuffix(reste, ":"+m) {
				seg := reste[:len(reste)-len(m)-1]
				if reSegmentModele.MatchString(seg) {
					r.Route, r.Segment, r.Methode, r.Trouvee = route, seg, m, true
				}
			}
		}
		if r.Trouvee {
			break
		}
	}
	if !r.Trouvee {
		return r
	}
	// EX-5.29 : chaîne de requête interprétée
	type param struct{ nom, val string }
	var ps []param
	if aRequete && requete != "" {
		for _, e := range strings.Split(requete, "&") {
			nom, val := e, ""
			if i := strings.IndexByte(e, '='); i >= 0 {
				nom, val = e[:i], e[i+1:]
			}
			ps = append(ps, param{decoderPourcent(nom), decoderPourcent(val)})
		}
	}
	cle := false
	for _, p := range ps {
		if p.nom == "key" {
			cle = true
		}
		if p.nom == "alt" && p.val == "sse" {
			r.AltSSE = true
		}
	}
	switch {
	case cle:
		r.RaisonRequete = "cle_dans_url"
	case r.Methode == "streamGenerateContent" && !r.AltSSE:
		r.RaisonRequete = "flux_sans_sse"
	case r.Methode == "streamGenerateContent" && len(ps) != 1:
		r.RaisonRequete = "parametre_non_admis"
	case r.Methode == "generateContent" && len(ps) > 1,
		r.Methode == "generateContent" && len(ps) == 1 && !(ps[0].nom == "alt" && ps[0].val == "json"):
		r.RaisonRequete = "parametre_non_admis"
	}
	return r
}

// TypeRefusGemini : Content-Type d'une réponse produite par la route
// (EX-5.30) : text/event-stream pour un streamGenerateContent avec alt=sse,
// application/json; charset=UTF-8 sinon (generateContent, flux_sans_sse).
func (r RequeteGemini) TypeRefusGemini() string {
	if r.Methode == "streamGenerateContent" && r.AltSSE {
		return TypeErreurGeminiSSE
	}
	return TypeErreurGeminiJSON
}

// CibleAmont : cible reconstruite vers l'amont (EX-5.28, EX-5.29).
func (r RequeteGemini) CibleAmont() string {
	c := r.Route + "/" + r.Segment + ":" + r.Methode
	if r.Methode == "streamGenerateContent" {
		c += "?alt=sse"
	}
	return c
}

// ServeursMCPFournisseur : un élément de tools est un objet qui porte
// mcpServers (ou mcp_servers, même règle) avec une valeur autre que null et
// [] (EX-5.32).
func ServeursMCPFournisseur(req *Value) bool {
	t := req.Get("tools")
	if !EstTableau(t) {
		return false
	}
	for _, e := range t.Arr {
		if !EstObjet(e) {
			continue
		}
		for _, nom := range []string{"mcpServers", "mcp_servers"} {
			m := e.Get(nom)
			if m == nil || m.IsNull() || (EstTableau(m) && len(m.Arr) == 0) {
				continue
			}
			return true
		}
	}
	return false
}

// CacheFournisseur : le corps porte cachedContent (ou cached_content) non
// null (EX-5.32, refus cache_fournisseur sous provider_cache refuser).
func CacheFournisseur(req *Value) bool {
	if !EstObjet(req) {
		return false
	}
	for _, nom := range []string{"cachedContent", "cached_content"} {
		if v := req.Get(nom); v != nil && !v.IsNull() {
			return true
		}
	}
	return false
}

// RequeteGeminiDeForme : contents est un tableau (EX-5.7 point 3).
func RequeteGeminiDeForme(req *Value) bool { return EstObjet(req) && EstTableau(req.Get("contents")) }

// PromptSystemeGemini : colonne Gemini de 5.5 (systemInstruction objet à
// parts tableau : text des éléments, joints par « \n »).
func PromptSystemeGemini(req *Value) (string, bool) {
	si := req.Get("systemInstruction")
	if !EstObjet(si) || !EstTableau(si.Get("parts")) {
		return "", false
	}
	var t []string
	for _, p := range si.Get("parts").Arr {
		if x := p.Get("text"); EstChaine(x) {
			t = append(t, x.Str)
		}
	}
	return strings.Join(t, "\n"), true
}

// RemplacerPromptGemini : mode reference d'EX-8.5 (parts devient
// [{"text": "[REDIGE:prompt-systeme]"}], les autres membres restent).
func RemplacerPromptGemini(req *Value) *Value {
	c := Copier(req)
	si := c.Get("systemInstruction")
	if EstObjet(si) && EstTableau(si.Get("parts")) {
		Definir(si, "parts", &Value{Kind: KindArray, Arr: []*Value{Objet("text", Chaine(JetonPromptSysteme))}})
	}
	return c
}

// RedigerPromptGeminiEnPlace : mode inline d'EX-8.5 (le text de chaque
// élément de systemInstruction.parts rédigé par les règles prompt_systeme).
func RedigerPromptGeminiEnPlace(req *Value, pol *Politique) *Value {
	c := Copier(req)
	si := c.Get("systemInstruction")
	if !EstObjet(si) || !EstTableau(si.Get("parts")) || pol == nil {
		return c
	}
	for _, p := range si.Get("parts").Arr {
		if t := p.Get("text"); EstChaine(t) {
			Definir(p, "text", pol.Appliquer("prompt_systeme", "", t).Valeur)
		}
	}
	return c
}

// AucunDetecteur : aucun détecteur de texte d'aucune règle de la politique
// (quels que soient portée, outils, path) ne trouve de correspondance
// (EX-5.36, comme EX-7.2).
func AucunDetecteur(pol *Politique, s string) bool {
	if pol == nil {
		return true
	}
	for _, r := range pol.Regles {
		for _, d := range r.Detecteurs {
			if d.Type == "champ" {
				continue
			}
			if _, n := pol.RedigerTexte(r.Action, d, s); n > 0 {
				return false
			}
		}
	}
	return true
}

func tronquer256(s string) string {
	if utf8.RuneCountInString(s) > 256 {
		return string([]rune(s)[:256])
	}
	return s
}

// CodeModelGemini : EX-5.36 (passerelle) ; repli = segment admis.
func CodeModelGemini(libelle string, repRedigee *Value, repli string, pol *Politique) *Value {
	if mv := repRedigee.Get("modelVersion"); EstChaine(mv) && mv.Str != "" {
		return Chaine(tronquer256(libelle + "/" + mv.Str))
	}
	if repli != "" && reSegmentModele.MatchString(repli) && AucunDetecteur(pol, repli) {
		return Chaine(tronquer256(libelle + "/" + repli))
	}
	return Nul()
}

// IntentGemini : colonne Gemini de 5.5 (text des parts de
// candidates[0].content.parts sans thought: true, sans séparateur ; vide →
// absent).
func IntentGemini(rep *Value) (string, bool) {
	c := rep.Get("candidates")
	if !EstTableau(c) || len(c.Arr) == 0 {
		return "", false
	}
	return textesPartsGemini(c.Arr[0].Get("content").Get("parts"), -1)
}

// textesPartsGemini joint, sans séparateur, les text des parts d'indice
// inférieur à fin (fin < 0 : toutes), hors parts thought: true.
func textesPartsGemini(parts *Value, fin int) (string, bool) {
	if !EstTableau(parts) {
		return "", false
	}
	var sb strings.Builder
	for i, p := range parts.Arr {
		if fin >= 0 && i >= fin {
			break
		}
		if th := p.Get("thought"); th != nil && th.Kind == KindBool && th.Bool {
			continue
		}
		if t := p.Get("text"); EstChaine(t) {
			sb.WriteString(t.Str)
		}
	}
	if sb.Len() == 0 {
		return "", false
	}
	return sb.String(), true
}

// AppelGemini : part functionCall de candidates[0].content.parts (5.5).
type AppelGemini struct {
	ID       *Value // chaîne ou null
	Nom      string
	Args     *Value // objet ; {} si absent
	Position int
}

// AppelsGemini : appels demandés au client (colonne Gemini de 5.5).
func AppelsGemini(rep *Value) []AppelGemini {
	var out []AppelGemini
	c := rep.Get("candidates")
	if !EstTableau(c) || len(c.Arr) == 0 {
		return nil
	}
	parts := c.Arr[0].Get("content").Get("parts")
	if !EstTableau(parts) {
		return nil
	}
	for i, p := range parts.Arr {
		fc := p.Get("functionCall")
		if !EstObjet(fc) {
			continue
		}
		id := Nul()
		if x := fc.Get("id"); EstChaine(x) {
			id = Chaine(x.Str)
		}
		args := fc.Get("args")
		if args == nil {
			args = ObjetVide()
		}
		out = append(out, AppelGemini{ID: id, Nom: chaineDe(fc, "name"), Args: Copier(args), Position: i})
	}
	return out
}

// FinGemini termine le flux d'une route gemini : comme Fin, mais une
// dernière ligne non vide sans fin de ligne est d'abord lue comme une ligne,
// puis un tampon data non vide resté sans ligne vide finale est distribué
// (EX-5.34).
func (a *AnalyseurSSE) FinGemini() ([]EvenementSSE, bool) {
	if !a.bomTraitee && len(a.debut) > 0 {
		a.bomTraitee = true
		reste := a.debut
		a.debut = nil
		a.octets(reste)
	}
	if len(a.ligne) > 0 {
		a.traiterLigne()
	}
	distribueFinal := false
	if a.data.Len() > 0 {
		a.distribuer()
		distribueFinal = true
	}
	a.ligne = nil
	a.typeEv = ""
	return a.Evenements, distribueFinal
}

// ConsoliderGemini applique EX-5.35 aux valeurs distribuées (chaînes data à
// analyser, ou valeurs déjà analysées pour le SDK, EX-6.8). finCorpsNormale
// dit si le corps amont s'est terminé normalement (pas 6).
func ConsoliderGemini(valeurs []*Value, finCorpsNormale bool) *Consolidation {
	c := &Consolidation{}
	var forme *Value
	arret := false
	reduite := false
	var candidats []*Value
	parIndex := map[int64]*Value{}
	for _, v := range valeurs {
		if arret || !EstObjet(v) {
			c.Ignores++
			continue
		}
		if e := v.Get("error"); EstObjet(e) {
			if forme == nil {
				// pas 2 : erreur avant tout morceau valide, forme réduite
				forme = ObjetVide()
				reduite = true
			}
			Definir(forme, "noortrace_erreur_flux", Copier(e))
			c.Erreur = true
			arret = true
			continue
		}
		if forme == nil {
			forme = ObjetVide()
		}
		for _, m := range v.Obj {
			if m.Key != "candidates" {
				Definir(forme, m.Key, Copier(m.Val))
				continue
			}
			if !EstTableau(m.Val) {
				c.Ignores++
				continue
			}
			for _, frag := range m.Val.Arr {
				if !EstObjet(frag) {
					c.Ignores++
					continue
				}
				var n int64
				if iv := frag.Get("index"); iv != nil {
					k, ok := indexAdmis(iv)
					if !ok {
						c.Ignores++
						continue
					}
					n = k
				}
				cand := parIndex[n]
				if cand == nil {
					cand = Objet("index", Entier(n), "content", Objet("parts", TableauVide()))
					parIndex[n] = cand
					candidats = append(candidats, cand)
				}
				for _, fm := range frag.Obj {
					switch fm.Key {
					case "index":
					case "content":
						if !EstObjet(fm.Val) {
							c.Ignores++
							continue
						}
						cc := cand.Get("content")
						for _, cm := range fm.Val.Obj {
							if cm.Key != "parts" {
								Definir(cc, cm.Key, Copier(cm.Val))
								continue
							}
							if !EstTableau(cm.Val) {
								c.Ignores++
								continue
							}
							parts := cc.Get("parts")
							for _, p := range cm.Val.Arr {
								if !EstObjet(p) {
									c.Ignores++
									continue
								}
								parts.Arr = append(parts.Arr, Copier(p))
							}
						}
					default:
						Definir(cand, fm.Key, Copier(fm.Val))
					}
				}
			}
		}
	}
	if forme == nil {
		// pas 7 : aucune forme ; la pièce est le flux brut
		c.Incomplet = true
		return c
	}
	if reduite {
		// pas 2 : la forme réduite est exactement {"noortrace_erreur_flux": …}
		c.Incomplet = true
		c.Forme = forme
		return c
	}
	if len(candidats) > 0 {
		Definir(forme, "candidates", &Value{Kind: KindArray, Arr: candidats})
	}
	normale := false
	if finCorpsNormale {
		for _, cd := range candidats {
			if fr := cd.Get("finishReason"); EstChaine(fr) && fr.Str != "" {
				normale = true
			}
		}
		if len(candidats) == 0 && EstObjet(forme.Get("promptFeedback")) {
			normale = true
		}
	}
	if !normale {
		Definir(forme, "noortrace_flux_incomplet", Booleen(true))
		c.Incomplet = true
	}
	c.Forme = forme
	return c
}

// MembresSDKRetires : membres retirés par EX-6.8 pas 3.
var MembresSDKRetires = []string{"sdkHttpResponse", "automaticFunctionCallingHistory", "parsed"}

// RetirerMembresSDK retire les membres d'EX-6.8 pas 3 de l'objet de premier
// niveau (ou de chaque élément d'un tableau) ; rend la copie et les noms
// retirés, dans l'ordre de leur premier retrait.
func RetirerMembresSDK(rep *Value) (*Value, []string) {
	c := Copier(rep)
	vus := map[string]bool{}
	var noms []string
	retirer := func(o *Value) {
		if !EstObjet(o) {
			return
		}
		for _, n := range MembresSDKRetires {
			if Retirer(o, n) && !vus[n] {
				vus[n] = true
				noms = append(noms, n)
			}
		}
	}
	if EstTableau(c) {
		for _, e := range c.Arr {
			retirer(e)
		}
	} else {
		retirer(c)
	}
	return c, noms
}

// CodeModelSDKGemini : EX-6.8 pas 5.
func CodeModelSDKGemini(libelle string, repRedigee, req *Value, pol *Politique) *Value {
	if mv := repRedigee.Get("modelVersion"); EstChaine(mv) && mv.Str != "" {
		return Chaine(tronquer256(libelle + "/" + mv.Str))
	}
	if m := req.Get("model"); EstChaine(m) {
		s := strings.TrimPrefix(m.Str, "models/")
		if reSegmentModele.MatchString(s) && AucunDetecteur(pol, s) {
			return Chaine(tronquer256(libelle + "/" + s))
		}
	}
	return Nul()
}
