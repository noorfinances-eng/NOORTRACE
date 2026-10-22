// Extraction (CT-2 §5.5) : prompt système, remplacement du prompt dans la
// pièce « requête » (5.3.1 pas 3, EX-8.5), code.model (EX-5.19), intent
// (EX-5.21), appels d'outils demandés par le modèle (pour 5.6).

package main

import (
	"strings"
	"unicode/utf8"
)

// JetonPromptSysteme remplace le prompt système dans la pièce « requête »
// (model.prompt_in_request: "reference", défaut ; EX-10.7).
const JetonPromptSysteme = "[REDIGE:prompt-systeme]"

// textesContenu rend les textes d'un contenu de message : la chaîne, ou le
// membre text (chaîne) de chacune de ses parties dont le type est admis.
func textesContenu(c *Value, types ...string) []string {
	switch {
	case EstChaine(c):
		return []string{c.Str}
	case EstTableau(c):
		var out []string
		for _, p := range c.Arr {
			if t := p.Get("text"); EstChaine(t) && dansEnum(chaineDe(p, "type"), types) {
				out = append(out, t.Str)
			}
		}
		return out
	}
	return nil
}

func estRoleSysteme(m *Value) bool {
	r := chaineDe(m, "role")
	return r == "system" || r == "developer"
}

// PromptSysteme extrait le texte du prompt système d'une requête selon la
// table de 5.5 ; le second résultat vaut faux s'il n'y en a pas.
//   - anthropic-messages : system, chaîne, ou concaténation des text de ses
//     blocs de type text, séparés par « \n » ;
//   - openai-chat : concaténation, dans l'ordre, des content des messages de
//     rôle system et developer (chaîne, ou text de leurs parties de type
//     text), « \n » ;
//   - openai-responses : instructions, puis les items de rôle developer ou
//     system de input (chaîne, ou text des parties input_text ou text), « \n ».
func PromptSysteme(format string, req *Value) (string, bool) {
	var textes []string
	present := false
	switch format {
	case "anthropic-messages":
		s := req.Get("system")
		if s == nil || s.IsNull() {
			return "", false
		}
		present = true
		textes = textesContenu(s, "text")
	case "openai-chat":
		if ms := req.Get("messages"); EstTableau(ms) {
			for _, m := range ms.Arr {
				if estRoleSysteme(m) {
					present = true
					textes = append(textes, textesContenu(m.Get("content"), "text")...)
				}
			}
		}
	case "openai-responses":
		if ins := req.Get("instructions"); EstChaine(ins) {
			present = true
			textes = append(textes, ins.Str)
		}
		if in := req.Get("input"); EstTableau(in) {
			for _, m := range in.Arr {
				if estRoleSysteme(m) {
					present = true
					textes = append(textes, textesContenu(m.Get("content"), "input_text", "text")...)
				}
			}
		}
	}
	if !present {
		return "", false
	}
	return strings.Join(textes, "\n"), true
}

// RedigerPromptEnPlace rend une copie de la requête où chaque chaîne porteuse
// du prompt système est remplacée par le résultat des règles de portée
// prompt_systeme appliquées à cette seule chaîne (prompt_in_request:
// "inline", EX-8.5).
func RedigerPromptEnPlace(format string, req *Value, pol *Politique) *Value {
	c := Copier(req)
	r := func(v *Value) *Value {
		if !EstChaine(v) || pol == nil {
			return v
		}
		return pol.Appliquer("prompt_systeme", "", v).Valeur
	}
	parties := func(contenu *Value, types ...string) *Value {
		if EstChaine(contenu) {
			return r(contenu)
		}
		if EstTableau(contenu) {
			for _, p := range contenu.Arr {
				if t := p.Get("text"); EstChaine(t) && dansEnum(chaineDe(p, "type"), types) {
					Definir(p, "text", r(t))
				}
			}
		}
		return contenu
	}
	switch format {
	case "anthropic-messages":
		if s := c.Get("system"); s != nil {
			Definir(c, "system", parties(s, "text"))
		}
	case "openai-chat":
		if ms := c.Get("messages"); EstTableau(ms) {
			for _, m := range ms.Arr {
				if estRoleSysteme(m) && m.Has("content") {
					Definir(m, "content", parties(m.Get("content"), "text"))
				}
			}
		}
	case "openai-responses":
		if ins := c.Get("instructions"); EstChaine(ins) {
			Definir(c, "instructions", r(ins))
		}
		if in := c.Get("input"); EstTableau(in) {
			for _, m := range in.Arr {
				if estRoleSysteme(m) && m.Has("content") {
					Definir(m, "content", parties(m.Get("content"), "input_text", "text"))
				}
			}
		}
	}
	return c
}

// RequeteDeForme dit si un corps de requête a la forme attendue du format
// (EX-5.7) : messages (tableau) pour Messages et Chat Completions, input ou
// previous_response_id pour Responses.
func RequeteDeForme(format string, req *Value) bool {
	if !EstObjet(req) {
		return false
	}
	if format == "openai-responses" {
		return req.Has("input") || req.Has("previous_response_id")
	}
	return EstTableau(req.Get("messages"))
}

// RemplacerPromptSysteme rend une copie de la requête où le prompt système
// est remplacé par le jeton [REDIGE:prompt-systeme] : membre system
// (Anthropic), content de chaque message system/developer (Chat), membre
// instructions et content de chaque item system/developer de input
// (Responses). Choix documenté : la valeur entière est remplacée par la
// chaîne jeton, qu'elle soit une chaîne ou un tableau de blocs.
func RemplacerPromptSysteme(format string, req *Value) *Value {
	c := Copier(req)
	jeton := Chaine(JetonPromptSysteme)
	switch format {
	case "anthropic-messages":
		if s := c.Get("system"); s != nil && !s.IsNull() {
			Definir(c, "system", jeton)
		}
	case "openai-chat":
		if ms := c.Get("messages"); EstTableau(ms) {
			for _, m := range ms.Arr {
				if estRoleSysteme(m) && m.Has("content") {
					Definir(m, "content", Chaine(JetonPromptSysteme))
				}
			}
		}
	case "openai-responses":
		if ins := c.Get("instructions"); EstChaine(ins) {
			Definir(c, "instructions", jeton)
		}
		if in := c.Get("input"); EstTableau(in) {
			for _, m := range in.Arr {
				if estRoleSysteme(m) && m.Has("content") {
					Definir(m, "content", Chaine(JetonPromptSysteme))
				}
			}
		}
	}
	return c
}

// ModeleReponse rend le champ model de la réponse (corps hors flux ou forme
// consolidée) selon la table de 5.5.
func ModeleReponse(rep *Value) (string, bool) {
	if m := rep.Get("model"); EstChaine(m) {
		return m.Str, true
	}
	return "", false
}

// CodeModel applique EX-5.19 : « <libellé>/<model de la réponse> », à défaut
// celui de la requête, sinon null ; tronqué à 256 caractères.
func CodeModel(libelle string, req, rep *Value) *Value {
	m, ok := ModeleReponse(rep)
	if !ok {
		if mr := req.Get("model"); EstChaine(mr) {
			m, ok = mr.Str, true
		}
	}
	if !ok {
		return Nul()
	}
	s := libelle + "/" + m
	if utf8.RuneCountInString(s) > 256 {
		s = string([]rune(s)[:256])
	}
	return Chaine(s)
}

// TexteAssistant rend le texte produit par l'assistant selon la table de 5.5
// (ligne intent) ; faux s'il n'y en a pas.
func TexteAssistant(format string, rep *Value) (string, bool) {
	switch format {
	case "anthropic-messages":
		var t []string
		present := false
		if c := rep.Get("content"); EstTableau(c) {
			for _, b := range c.Arr {
				if chaineDe(b, "type") == "text" {
					if x := b.Get("text"); EstChaine(x) {
						present = true
						t = append(t, x.Str)
					}
				}
			}
		}
		return strings.Join(t, "\n"), present
	case "openai-chat":
		ch := rep.Get("choices")
		if !EstTableau(ch) || len(ch.Arr) == 0 {
			return "", false
		}
		c := ch.Arr[0].Get("message").Get("content")
		if !EstChaine(c) {
			return "", false
		}
		return c.Str, true
	case "openai-responses":
		var t []string
		present := false
		if out := rep.Get("output"); EstTableau(out) {
			for _, it := range out.Arr {
				if chaineDe(it, "type") != "message" {
					continue
				}
				if cs := it.Get("content"); EstTableau(cs) {
					for _, p := range cs.Arr {
						if chaineDe(p, "type") == "output_text" {
							if x := p.Get("text"); EstChaine(x) {
								present = true
								t = append(t, x.Str)
							}
						}
					}
				}
			}
		}
		return strings.Join(t, "\n"), present
	}
	return "", false
}

// AppelOutil est un appel d'outil demandé par le modèle (table de 5.5).
type AppelOutil struct {
	ID, Nom   string
	Arguments *Value // input (Anthropic) ou chaîne arguments (OpenAI)
	Position  int    // index du bloc (Anthropic) ou de l'item (Responses)
}

// AppelsOutils extrait les appels d'outils demandés par le modèle.
func AppelsOutils(format string, rep *Value) []AppelOutil {
	var out []AppelOutil
	switch format {
	case "anthropic-messages":
		if c := rep.Get("content"); EstTableau(c) {
			for i, b := range c.Arr {
				if chaineDe(b, "type") == "tool_use" {
					out = append(out, AppelOutil{ID: chaineDe(b, "id"), Nom: chaineDe(b, "name"), Arguments: b.Get("input"), Position: i})
				}
			}
		}
	case "openai-chat":
		if ch := rep.Get("choices"); EstTableau(ch) && len(ch.Arr) > 0 {
			if tcs := ch.Arr[0].Get("message").Get("tool_calls"); EstTableau(tcs) {
				for i, tc := range tcs.Arr {
					out = append(out, AppelOutil{ID: chaineDe(tc, "id"), Nom: chaineDe(tc, "function", "name"), Arguments: tc.Get("function").Get("arguments"), Position: i})
				}
			}
		}
	case "openai-responses":
		if o := rep.Get("output"); EstTableau(o) {
			for i, it := range o.Arr {
				if chaineDe(it, "type") == "function_call" {
					out = append(out, AppelOutil{ID: chaineDe(it, "call_id"), Nom: chaineDe(it, "name"), Arguments: it.Get("arguments"), Position: i})
				}
			}
		}
	}
	return out
}

// TexteAvantAppel rend le texte de l'assistant qui précède un appel (5.6) :
// Anthropic, blocs text d'index inférieur ; Chat, choices[0].message.content ;
// Responses, output_text des items message d'index inférieur.
func TexteAvantAppel(format string, rep *Value, a AppelOutil) (string, bool) {
	switch format {
	case "openai-chat":
		return TexteAssistant(format, rep)
	case "anthropic-messages", "openai-responses":
		tronque := Copier(rep)
		cle := "content"
		if format == "openai-responses" {
			cle = "output"
		}
		if t := tronque.Get(cle); EstTableau(t) && a.Position <= len(t.Arr) {
			t.Arr = t.Arr[:a.Position]
		}
		return TexteAssistant(format, tronque)
	}
	return "", false
}
