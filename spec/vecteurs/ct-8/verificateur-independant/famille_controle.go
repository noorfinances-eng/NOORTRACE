// Famille « controle-prealable » (CT-8 §6, annexe A.4, EX-A.22) :
// l'exemple de 6.3 réévalué et égal au rapport imprimé ; chaque cas de
// spec/vecteurs/ct-8/controle-prealable réévalué depuis ses observations,
// son profil, son seuil et sa liste `only`, et confronté à `attendu` :
// verdict, code de sortie, et, vérification par vérification, `status`,
// `reason`, `blocking`, `expected` et `measured` (quand le texte en fixe la
// forme) ; la table d'A.4 relue et confrontée.

package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

var reIP = regexp.MustCompile(`IP-[0-9]+`)

// FamilleControle réévalue l'exemple de 6.3 et chaque cas.
func FamilleControle(c *Contexte) {
	const f = "controle-prealable"
	sec, err := c.Texte.Section("### 6.3 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	bo, err1 := BlocApres(sec, "<!-- schema: controle-prealable/observations -->")
	br, err2 := BlocApres(sec, "<!-- schema: controle-prealable -->")
	if err1 != nil || err2 != nil {
		c.Rap.Erreur("6.3 : blocs d'exemple introuvables")
		return
	}
	obsEx, err1 := AnalyserJSON([]byte(bo))
	rapEx, err2 := AnalyserJSON([]byte(br))
	if err1 != nil || err2 != nil {
		c.Rap.Erreur("6.3 : exemple illisible")
		return
	}
	c.ValiderSchema(f, "exemple 6.3", "controle-prealable-v0", "#/$defs/observations", obsEx)
	c.ValiderSchema(f, "exemple 6.3", "controle-prealable-v0", "", rapEx)
	r := EvaluerIP(rapEx.Get("profile").Str, obsEx, nil, nil)
	t1, _ := Stringify2(ValeurRapportIP(r))
	t2, _ := Stringify2(rapEx)
	c.Rap.Comparer(f, "exemple 6.3", "rapport entier (JSON.stringify)", t2, t1)

	// Seuil du cas pret-production : local_bytes de l'exemple de 9.5.
	localEx := ""
	if coef, err := LireCoefficients(c.Texte); err == nil {
		if s9, err := c.Texte.Section("### 9.5 "); err == nil {
			if b, err := BlocApres(s9, "<!-- schema: dimensionnement -->"); err == nil {
				if v, err := AnalyserJSON([]byte(b)); err == nil {
					localEx = NombreES6(totalDim(Dimensionner(v, coef), "local_bytes"))
				}
			}
		}
	}

	rep := c.Chemin("controle-prealable")
	type res struct {
		profil, verdict string
		nonReussies     []string
	}
	resultats := map[string]res{}
	var noms []string
	for _, nf := range Fichiers(rep, ".json") {
		cas := strings.TrimSuffix(nf, ".json")
		noms = append(noms, cas)
		v, b, ok := c.LireJSON(filepath.Join(rep, nf))
		if !ok {
			continue
		}
		c.Forme(f, cas, b)
		c.ValiderSchema(f, cas, "controle-prealable-v0", "#/$defs/cas", v)
		var only []string
		if o := v.Get("only"); o != nil {
			for _, x := range o.Arr {
				only = append(only, x.Str)
			}
		}
		profil := v.Get("profile").Str
		obs := v.Get("observations")
		r := EvaluerIP(profil, obs, v.Get("storage_free_min_bytes"), only)
		att := v.Get("attendu")
		comparerRapportIP(c, f, cas, r, att)
		var nr []string
		for _, ch := range r.Checks {
			if ch.Status != "reussi" {
				nr = append(nr, ch.ID)
			}
		}
		resultats[cas] = res{profil, r.Verdict, nr}
		switch cas {
		case "pret-rapide":
			c.Rap.Constater(f, cas, "observations égales à l'exemple de 6.3", Egales(obs, obsEx), "")
		case "pret-production":
			c.Rap.Comparer(f, cas, "seuil d'espace = local_bytes de l'exemple de 9.5 (A.4)", localEx, TexteValeur(v.Get("storage_free_min_bytes")))
			var adr []string
			for _, p := range obs.Get("ports").Arr {
				if p.Get("address").Str != "127.0.0.1" {
					adr = append(adr, p.Get("address").Str)
				}
			}
			c.Rap.Comparer(f, cas, "variante de production (A.4) : processeurs, mémoire, espace libre",
				"8 ; 16 Gio ; 600 Gio", NombreES6(nombre(obs.Get("cpus")))+" ; "+NombreES6(nombre(obs.Get("memory_bytes"))/gio)+" Gio ; "+
					NombreES6(nombre(obs.Chemin("storage", "free_bytes"))/gio)+" Gio")
			c.Rap.Comparer(f, cas, "variante de production (A.4) : ports publiés hors 127.0.0.1 sur 192.0.2.40",
				"[192.0.2.40, 192.0.2.40]", Liste(adr))
			c.Rap.Comparer(f, cas, "variante de production (A.4) : images par condensé, cache déclaré", "true ; true",
				TexteValeur(obs.Chemin("compose", "all_images_by_digest"))+" ; "+TexteValeur(obs.Chemin("declarations", "write_cache_protected")))
		}
	}

	// Table d'A.4.
	secA, err := c.Texte.Section("### A.4 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	tab, err := TableEntete(secA, "Cas", "Profil")
	if err != nil {
		c.Rap.Erreur("A.4 : %v", err)
		return
	}
	var dansTable []string
	for _, l := range tab.Lignes {
		cas := SansCode(l[0])
		dansTable = append(dansTable, cas)
		r, ok := resultats[cas]
		if !ok {
			c.Rap.Comparer(f, cas, "cas de la table d'A.4 présent", "présent", "absent")
			continue
		}
		c.Rap.Comparer(f, cas, "A.4 : profil", SansCode(l[1]), r.profil)
		verdict := strings.Fields(SansCode(l[3]))[0]
		c.Rap.Comparer(f, cas, "A.4 : verdict", verdict, r.verdict)
		var manquants []string
		for _, id := range reIP.FindAllString(l[3], -1) {
			if !contient(r.nonReussies, id) {
				manquants = append(manquants, id)
			}
		}
		c.Rap.Comparer(f, cas, "A.4 : vérifications nommées non réussies", "[]", Liste(manquants))
	}
	c.Rap.Comparer(f, "ct-8/controle-prealable", "cas des fichiers = cas de la table d'A.4", Liste(dansTable), Liste(trierCas(noms, dansTable)))
}

func comparerRapportIP(c *Contexte, f, cas string, r RapportIP, att *Value) {
	rp := c.Rap
	rp.Comparer(f, cas, "version", TexteValeur(att.Get("version")), "0")
	rp.Comparer(f, cas, "profile", TexteValeur(att.Get("profile")), TexteValeur(VStr(r.Profile)))
	rp.Comparer(f, cas, "checked_at (celui des observations)", TexteValeur(att.Get("checked_at")), TexteValeur(VStr(r.CheckedAt)))
	rp.Comparer(f, cas, "tool (celui des observations)", TexteValeur(att.Get("tool")), TexteValeur(VStr(r.Tool)))
	rp.Comparer(f, cas, "verdict (EX-6.3)", TexteValeur(att.Get("verdict")), TexteValeur(VStr(r.Verdict)))
	rp.Comparer(f, cas, "exit_code (EX-6.3)", TexteValeur(att.Get("exit_code")), TexteValeur(VInt(int64(r.ExitCode))))
	rp.Comparer(f, cas, "membres du rapport", Liste(att.Cles()), "[version, profile, checked_at, tool, verdict, exit_code, checks]")
	checks := att.Get("checks")
	if checks == nil || len(checks.Arr) != len(r.Checks) {
		rp.Comparer(f, cas, "nombre de vérifications", "13", "illisible")
		return
	}
	for i, ch := range r.Checks {
		a := checks.Arr[i]
		g := ch.ID
		rp.Comparer(f, cas, g+" id", TexteValeur(a.Get("id")), TexteValeur(VStr(ch.ID)))
		rp.Comparer(f, cas, g+" status", TexteValeur(a.Get("status")), TexteValeur(VStr(ch.Status)))
		reason := VNull()
		if ch.Reason != "" {
			reason = VStr(ch.Reason)
		}
		rp.Comparer(f, cas, g+" reason", TexteValeur(a.Get("reason")), TexteValeur(reason))
		rp.Comparer(f, cas, g+" blocking", TexteValeur(a.Get("blocking")), TexteValeur(VBool(ch.Blocking)))
		rp.Comparer(f, cas, g+" expected", TexteValeur(a.Get("expected")), TexteValeur(ch.Expected))
		if ch.Measured == nil {
			rp.HorsPerimetre(f, cas, g+" measured", TexteValeur(a.Get("measured")), ch.NonFixe)
		} else {
			rp.Comparer(f, cas, g+" measured", TexteValeur(a.Get("measured")), TexteValeur(ch.Measured))
		}
	}
}
