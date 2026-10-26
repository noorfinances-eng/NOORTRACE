// INDEX.md, révision 0.5 (B.7) : familles otel, worm et cout-agent, cas
// gemini-* ; constantes de worm/ ; mention des unités symboliques ; table
// des coûts de cout-agent/ recalculée.

package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

var reLigneCoutIndex = regexp.MustCompile("^\\| `([a-z0-9-]+)` \\| ([0-9.]+) \\| ([0-9.]+) \\|$")

func familleIndexRevision05(rap *Rapport, ctx *contexteCT2, texte string, present func(string) string) {
	f := FamilleIndex
	for _, fam := range []string{"otel", "worm", "cout-agent"} {
		rap.Comparer(f, "INDEX.md", "famille "+fam+"/ décrite (B.7, révision 0.5)", "présent", present("`"+fam+"/`"))
	}
	for _, c := range sousRepertoires(filepath.Join(ctx.racine, "otel")) {
		rap.Comparer(f, "INDEX.md", "cas otel/"+c+" listé (B.7)", "présent", present("`"+c+"/`"))
	}
	for _, c := range sousRepertoires(filepath.Join(ctx.racine, "pieces-modele")) {
		if strings.HasPrefix(c, "gemini-") {
			rap.Comparer(f, "INDEX.md", "cas pieces-modele/"+c+" listé (B.7)", "présent", present("`"+c+"/`"))
		}
	}
	rap.Comparer(f, "INDEX.md", "worm/ : bucket imprimé (B.7, B.9)", "présent", present("`"+BucketWormDemo+"`"))
	rap.Comparer(f, "INDEX.md", "worm/ : préfixe imprimé (B.7, B.9)", "présent", present("`"+PrefixeWormDemo+"`"))
	rap.Comparer(f, "INDEX.md", "worm/ : période de démonstration imprimée (B.7, B.9)", "présent", present("`1794304800`"))
	rap.Comparer(f, "INDEX.md", "cout-agent/ : prix en unités symboliques (B.7, B.10)", "présent", present("unités symboliques"))
	// table des coûts de la section cout-agent/
	i := strings.Index(texte, "## `cout-agent/`")
	if i < 0 {
		return
	}
	doc := lireFichierJSON(rap, filepath.Join(ctx.racine, "cout-agent", "cas.json"))
	if doc == nil {
		return
	}
	calc := map[string]SortiesCout{}
	for _, c := range doc.Get("cases").Arr {
		if in, manque := lireEntreesCout(c.Get("input")); len(manque) == 0 {
			calc[chaineDe(c, "id")] = CoutAgent(in)
		}
	}
	for _, l := range strings.Split(texte[i:], "\n") {
		m := reLigneCoutIndex.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		s, ok := calc[m[1]]
		if !ok {
			rap.Comparer(f, "INDEX.md", "cout-agent/"+m[1]+" : cas de la table présent dans cas.json", "présent", "absent")
			continue
		}
		rap.Comparer(f, "INDEX.md", "cout-agent/"+m[1]+" : C et C_J imprimés (EX-16.4, EX-16.5)", m[2]+" / "+m[3], NombreES6(Arrondi3(s.C))+" / "+NombreES6(Arrondi3(s.CJ)))
	}
}
