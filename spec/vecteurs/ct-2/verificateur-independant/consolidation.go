// Réassemblage des flux en forme consolidée, fournisseur par fournisseur
// (CT-2 §5.4.2 à §5.4.4, EX-5.15 à EX-5.18). Les seules clés ajoutées par
// l'enregistreur sont noortrace_flux_incomplet, noortrace_erreur_flux et
// noortrace_input_json_invalide.

package main

import (
	"fmt"
	"math"
	"sort"
)

// indexAdmis applique EX-5.27 (1) : un nombre JSON de valeur entière, entre 0
// et 2^53 (une chaîne n'est pas un index).
func indexAdmis(v *Value) (int64, bool) {
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	f, err := NombreDouble(v.Num)
	if err != nil || f != math.Trunc(f) || f < 0 || f > 9007199254740992 {
		return 0, false
	}
	return int64(f), true
}

// Consolidation est le résultat d'un réassemblage.
type Consolidation struct {
	Forme     *Value // nil si aucune forme n'a pu être construite
	Incomplet bool
	Erreur    bool // erreur en flux, ou réponse « failed » (Responses)
	Ignores   int  // événements ignorés (ping, inconnus, data non JSON)
	Notes     []string
}

// EstErreur dit si l'échange est en erreur (EX-5.13, 5.4) : flux incomplet ou
// erreur en flux.
func (c *Consolidation) EstErreur() bool { return c.Incomplet || c.Erreur }

// Consolider applique la règle du format.
func Consolider(format string, evs []EvenementSSE) (*Consolidation, error) {
	switch format {
	case "anthropic-messages":
		return ConsoliderAnthropic(evs), nil
	case "openai-chat":
		return ConsoliderChat(evs), nil
	case "openai-responses":
		return ConsoliderResponses(evs), nil
	}
	return nil, fmt.Errorf("format %q inconnu", format)
}

func typeDonnees(ev EvenementSSE, d *Value) string {
	if t := d.Get("type"); EstChaine(t) {
		return t.Str
	}
	return ev.Type
}

// ConsoliderAnthropic applique EX-5.15.
func ConsoliderAnthropic(evs []EvenementSSE) *Consolidation {
	c := &Consolidation{}
	tampons := map[int64]*string{}
	fini := false
	for _, ev := range evs {
		if fini || c.Erreur {
			c.Ignores++ // ce qui suit message_stop ou error est ignoré
			continue
		}
		d, err := ParseJSON([]byte(ev.Data))
		if err != nil || !EstObjet(d) {
			c.Ignores++
			continue
		}
		t := typeDonnees(ev, d)
		if c.Forme == nil && t != "message_start" && t != "ping" && t != "error" {
			c.Incomplet = true // événement avant message_start
			c.Notes = append(c.Notes, "événement « "+t+" » avant message_start")
			c.Ignores++
			continue
		}
		switch t {
		case "message_start":
			if c.Forme != nil {
				c.Ignores++
				continue
			}
			m := d.Get("message")
			if !EstObjet(m) {
				c.Ignores++
				continue
			}
			c.Forme = Copier(m)
		case "content_block_start":
			idx, ok := indexAdmis(d.Get("index"))
			blk := d.Get("content_block")
			contenu := c.Forme.Get("content")
			if !EstTableau(contenu) {
				contenu = TableauVide()
				Definir(c.Forme, "content", contenu)
			}
			// EX-5.27 (2) : index au plus égal à la longueur courante, aucun trou
			if !ok || idx > int64(len(contenu.Arr)) || !EstObjet(blk) {
				c.Ignores++
				continue
			}
			if idx == int64(len(contenu.Arr)) {
				contenu.Arr = append(contenu.Arr, Copier(blk))
			} else {
				contenu.Arr[idx] = Copier(blk)
			}
			delete(tampons, idx)
			if chaineDe(blk, "type") == "tool_use" {
				vide := ""
				tampons[idx] = &vide
			}
		case "content_block_delta":
			idx, ok := indexAdmis(d.Get("index"))
			delta := d.Get("delta")
			b := blocAnthropic(c.Forme, idx)
			if !ok || b == nil || !EstObjet(delta) {
				c.Ignores++
				continue
			}
			// EX-5.27 (3) : un membre absent ou mal typé fait ignorer le delta
			switch chaineDe(delta, "type") {
			case "text_delta":
				if x := delta.Get("text"); EstChaine(x) {
					Definir(b, "text", Chaine(chaineDe(b, "text")+x.Str))
				} else {
					c.Ignores++
				}
			case "input_json_delta":
				if x := delta.Get("partial_json"); EstChaine(x) {
					tp := tampons[idx]
					if tp == nil {
						vide := ""
						tp = &vide
						tampons[idx] = tp // tampon créé au premier input_json_delta (EX-5.15 pas 3)
					}
					*tp += x.Str
				} else {
					c.Ignores++
				}
			case "thinking_delta":
				if x := delta.Get("thinking"); EstChaine(x) {
					Definir(b, "thinking", Chaine(chaineDe(b, "thinking")+x.Str))
				} else {
					c.Ignores++
				}
			case "signature_delta":
				if x := delta.Get("signature"); EstChaine(x) {
					Definir(b, "signature", Copier(x))
				} else {
					c.Ignores++
				}
			case "citations_delta":
				x := delta.Get("citation")
				if !EstObjet(x) {
					c.Ignores++
					break
				}
				cit := b.Get("citations")
				if !EstTableau(cit) {
					cit = TableauVide()
					Definir(b, "citations", cit)
				}
				cit.Arr = append(cit.Arr, Copier(x))
			default:
				c.Ignores++
			}
		case "content_block_stop":
			idx, ok := indexAdmis(d.Get("index"))
			b := blocAnthropic(c.Forme, idx)
			if !ok || b == nil {
				c.Ignores++
				continue
			}
			if tp := tampons[idx]; tp != nil {
				delete(tampons, idx)
				if *tp == "" {
					Definir(b, "input", ObjetVide())
				} else if v, err := ParseJSON([]byte(*tp)); err == nil {
					Definir(b, "input", v)
				} else {
					Definir(b, "input", ObjetVide())
					Definir(b, "noortrace_input_json_invalide", Chaine(*tp))
				}
			}
		case "message_delta":
			if delta := d.Get("delta"); EstObjet(delta) {
				for _, m := range delta.Obj {
					Definir(c.Forme, m.Key, Copier(m.Val))
				}
			}
			if u := d.Get("usage"); EstObjet(u) {
				fu := c.Forme.Get("usage")
				if !EstObjet(fu) {
					fu = ObjetVide()
					Definir(c.Forme, "usage", fu)
				}
				for _, m := range u.Obj {
					Definir(fu, m.Key, Copier(m.Val))
				}
			}
		case "message_stop":
			fini = true
		case "error":
			if c.Forme == nil {
				c.Forme = ObjetVide()
				c.Notes = append(c.Notes, "error avant message_start : forme réduite à noortrace_erreur_flux")
			}
			Definir(c.Forme, "noortrace_erreur_flux", Copier(d))
			c.Erreur = true
		default: // ping et types inconnus
			c.Ignores++
		}
	}
	if !fini && !c.Erreur {
		c.Incomplet = true
	}
	if c.Incomplet && c.Forme != nil {
		Definir(c.Forme, "noortrace_flux_incomplet", Booleen(true))
	}
	return c
}

func blocAnthropic(forme *Value, idx int64) *Value {
	if forme == nil {
		return nil
	}
	contenu := forme.Get("content")
	if !EstTableau(contenu) || idx < 0 || idx >= int64(len(contenu.Arr)) {
		return nil
	}
	b := contenu.Arr[idx]
	if !EstObjet(b) {
		return nil
	}
	return b
}

// ConsoliderChat applique EX-5.16.
func ConsoliderChat(evs []EvenementSSE) *Consolidation {
	c := &Consolidation{}
	fini := false
	idPremier := ""
	idDe := func(d *Value) string {
		if v := d.Get("id"); v != nil {
			return doitIntegral(v)
		}
		return "null"
	}
	type cleAppel struct{ choix, appel string }
	fixes := map[cleAppel]map[string]bool{}
	for _, ev := range evs {
		if fini {
			c.Ignores++
			continue
		}
		if ev.Data == "[DONE]" {
			fini = true
			continue
		}
		d, err := ParseJSON([]byte(ev.Data))
		if err != nil || !EstObjet(d) {
			c.Ignores++
			continue
		}
		if c.Forme == nil {
			c.Forme = ObjetVide()
			for _, k := range []string{"id", "created", "model", "system_fingerprint", "service_tier"} {
				if v := d.Get(k); v != nil {
					Definir(c.Forme, k, Copier(v))
				}
			}
			Definir(c.Forme, "object", Chaine("chat.completion"))
			Definir(c.Forme, "choices", TableauVide())
			idPremier = idDe(d)
		} else if idDe(d) != idPremier {
			c.Incomplet = true
			c.Notes = append(c.Notes, "chunk d'id différent du premier : flux tenu pour coupé")
			break
		}
		choix := c.Forme.Get("choices")
		if ch := d.Get("choices"); EstTableau(ch) {
			for _, cv := range ch.Arr {
				idx := cv.Get("index")
				if _, ok := indexAdmis(idx); !EstObjet(cv) || !ok {
					c.Ignores++
					continue
				}
				cidx := doitIntegral(idx)
				var cible *Value
				for _, x := range choix.Arr {
					if doitIntegral(x.Get("index")) == cidx {
						cible = x
						break
					}
				}
				if cible == nil {
					cible = Objet("index", Copier(idx),
						"message", Objet("role", Chaine("assistant"), "content", Nul()),
						"finish_reason", Nul())
					choix.Arr = append(choix.Arr, cible)
				}
				msg := cible.Get("message")
				if delta := cv.Get("delta"); EstObjet(delta) {
					if r := delta.Get("role"); EstChaine(r) {
						Definir(msg, "role", Copier(r))
					}
					if t := delta.Get("content"); EstChaine(t) {
						Definir(msg, "content", Chaine(chaineDe(msg, "content")+t.Str))
					}
					if t := delta.Get("refusal"); EstChaine(t) {
						Definir(msg, "refusal", Chaine(chaineDe(msg, "refusal")+t.Str))
					}
					if tcs := delta.Get("tool_calls"); EstTableau(tcs) {
						appels := msg.Get("tool_calls")
						if !EstTableau(appels) {
							appels = TableauVide()
							Definir(msg, "tool_calls", appels)
						}
						for _, fr := range tcs.Arr {
							ti := fr.Get("index")
							if _, ok := indexAdmis(ti); !EstObjet(fr) || !ok {
								c.Ignores++
								continue
							}
							tidx := doitIntegral(ti)
							var appel *Value
							for _, x := range appels.Arr {
								if doitIntegral(x.Get("index")) == tidx {
									appel = x
									break
								}
							}
							if appel == nil {
								appel = Objet("index", Copier(ti), "id", Nul(), "type", Chaine("function"),
									"function", Objet("name", Chaine(""), "arguments", Chaine("")))
								appels.Arr = append(appels.Arr, appel)
							}
							k := cleAppel{cidx, tidx}
							if fixes[k] == nil {
								fixes[k] = map[string]bool{}
							}
							if v := fr.Get("id"); v != nil && !v.IsNull() && !fixes[k]["id"] {
								Definir(appel, "id", Copier(v))
								fixes[k]["id"] = true
							}
							if v := fr.Get("type"); v != nil && !v.IsNull() && !fixes[k]["type"] {
								Definir(appel, "type", Copier(v))
								fixes[k]["type"] = true
							}
							fn := appel.Get("function")
							if ff := fr.Get("function"); EstObjet(ff) {
								if v := ff.Get("name"); v != nil && !v.IsNull() && !fixes[k]["name"] {
									Definir(fn, "name", Copier(v))
									fixes[k]["name"] = true
								}
								if v := ff.Get("arguments"); EstChaine(v) {
									Definir(fn, "arguments", Chaine(chaineDe(fn, "arguments")+v.Str))
								}
							}
						}
					}
				}
				if fr := cv.Get("finish_reason"); fr != nil && !fr.IsNull() {
					Definir(cible, "finish_reason", Copier(fr))
				}
			}
		}
		if u := d.Get("usage"); u != nil && !u.IsNull() {
			Definir(c.Forme, "usage", Copier(u))
		}
	}
	if !fini {
		c.Incomplet = true
	}
	if c.Incomplet && c.Forme != nil {
		Definir(c.Forme, "noortrace_flux_incomplet", Booleen(true))
	}
	return c
}

var evenementsResponse = map[string]bool{
	"response.created": true, "response.in_progress": true, "response.completed": true,
	"response.failed": true, "response.incomplete": true,
}

// ConsoliderResponses applique EX-5.17.
func ConsoliderResponses(evs []EvenementSSE) *Consolidation {
	c := &Consolidation{}
	dernier := ""
	items := map[int64]*Value{}
	var erreur *Value
	for _, ev := range evs {
		d, err := ParseJSON([]byte(ev.Data))
		if err != nil || !EstObjet(d) {
			c.Ignores++
			continue
		}
		t := typeDonnees(ev, d)
		switch {
		case evenementsResponse[t]:
			if r := d.Get("response"); EstObjet(r) {
				dernier = t
				c.Forme = Copier(r)
			} else {
				c.Ignores++
			}
		case t == "response.output_item.done":
			oi, ok := indexAdmis(d.Get("output_index"))
			if !ok || d.Get("item") == nil {
				c.Ignores++
				continue
			}
			items[oi] = Copier(d.Get("item"))
		case t == "error":
			code, message := d.Get("code"), d.Get("message")
			if code == nil {
				code = Nul()
			}
			if message == nil {
				message = Nul()
			}
			erreur = Objet("code", Copier(code), "message", Copier(message))
			c.Erreur = true
		default:
			c.Ignores++ // deltas non accumulés, autres événements
		}
	}
	switch dernier {
	case "response.completed", "response.incomplete":
	case "response.failed":
		c.Erreur = true
	default:
		c.Incomplet = true
		if c.Forme != nil {
			Definir(c.Forme, "noortrace_flux_incomplet", Booleen(true))
			out := c.Forme.Get("output")
			if !EstTableau(out) {
				out = TableauVide()
				Definir(c.Forme, "output", out)
			}
			var idx []int64
			for k := range items {
				idx = append(idx, k)
			}
			sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
			for _, k := range idx {
				switch {
				case k < int64(len(out.Arr)):
					out.Arr[k] = items[k]
				case k == int64(len(out.Arr)):
					out.Arr = append(out.Arr, items[k])
				default:
					c.Ignores++ // EX-5.27 (2) : aucun trou
				}
			}
		}
	}
	if erreur != nil {
		if c.Forme == nil {
			c.Forme = ObjetVide()
		}
		Definir(c.Forme, "noortrace_erreur_flux", erreur)
	}
	return c
}
