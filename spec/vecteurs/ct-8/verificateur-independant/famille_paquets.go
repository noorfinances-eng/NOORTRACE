// Famille « paquets » (CT-8 §13, annexe A.10, EX-A.24) : chaque archive de
// cas.json lue deux fois (lecture brute d'EX-13.14 et archive/tar), et les
// deux lectures accordées ; PR-1 à PR-12, état du paquet, avertissements et
// code de retour recalculés pour chaque cas avec ses options ; SHA-256 et
// tailles des archives et de chaque fichier ; valide.tar confronté à sa
// description (13.5, EX-A.11) et au texte (manifeste de 13.3, instructions
// de 13.11, rapport de 13.7) ; chaque variante confrontée à valide.tar et à
// la description que le texte en donne (table d'EX-A.13) ; la table
// d'EX-A.13 relue.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var reHex32 = regexp.MustCompile("0x[0-9a-f]{64}")

// joindre rend des lignes jointes par des espaces.
func joindre(l []string) string { return strings.Join(l, " ") }

// cleEntree identifie une entrée par son en-tête et ses données.
func cleEntree(e EntreeTar) string { return string(e.Entete) + SHA256Hex(e.Donnees) }

// FamillePaquets recalcule chaque cas de paquets/cas.json.
func FamillePaquets(c *Contexte) {
	const f = "paquets"
	rep := c.Chemin("paquets")
	schema := c.Schemas["paquet-reviseur-v0"]
	cas, octetsCas, ok := c.LireJSON(filepath.Join(rep, "cas.json"))
	if !ok {
		return
	}
	c.Forme(f, "cas.json", octetsCas)
	c.ValiderSchema(f, "cas.json", "paquet-reviseur-v0", "#/$defs/fichier_cas", cas)

	secA10, err := c.Texte.Section("### A.10 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	texteA10 := joindre(secA10)
	reTotaux := regexp.MustCompile(`\(([0-9]+) archives, ([0-9 ]+) octets en tout ; SHA-256 de ` + "`cas.json` `(0x[0-9a-f]{64})`")
	if m := reTotaux.FindStringSubmatch(texteA10); m == nil {
		c.Rap.Erreur("EX-A.13 : décompte des archives introuvable")
	} else {
		c.Rap.Comparer(f, "cas.json", "SHA-256 (EX-A.13)", m[3], SHA256Hex(octetsCas))
		var total int64
		tars := Fichiers(rep, ".tar")
		for _, t := range tars {
			n, _ := taille(filepath.Join(rep, t))
			total += n
		}
		c.Rap.Comparer(f, "paquets/*.tar", "nombre d'archives (EX-A.13)", m[1], strconv.Itoa(len(tars)))
		c.Rap.Comparer(f, "paquets/*.tar", "octets en tout (EX-A.13)", strings.ReplaceAll(m[2], " ", ""), strconv.FormatInt(total, 10))
	}

	// Lecture de chaque archive, une fois.
	archives := map[string][]byte{}
	resultats := map[string]ResultatPaquet{}
	for _, t := range Fichiers(rep, ".tar") {
		b, ok := c.LireFichier(filepath.Join(rep, t))
		if !ok {
			continue
		}
		archives[t] = b
		r := EvaluerPaquet(b, "", schema)
		resultats[t] = r
		// EX-A.24 : deux lectures accordées sur chaque entrée qu'archive/tar rend.
		if r.ErrBrut != nil {
			c.Rap.Erreur("%s : lecture brute en échec (%v)", t, r.ErrBrut)
			continue
		}
		ecarts := AccordLectures(r.Entrees, r.Lib)
		c.Rap.Constater(f, t, fmt.Sprintf("archive/tar et lecture brute accordées sur les %d entrées rendues", len(r.Lib)), len(ecarts) == 0, strings.Join(ecarts, " ; "))
		errLib := "aucune"
		if r.ErrLib != nil {
			errLib = r.ErrLib.Error()
		}
		c.Rap.Comparer(f, t, "entrées : archive/tar (erreur) = lecture brute", fmt.Sprintf("%d (aucune)", len(r.Entrees)), fmt.Sprintf("%d (%s)", len(r.Lib), errLib))
		var tailles []int64
		for _, e := range r.Entrees {
			tailles = append(tailles, e.Size)
		}
		c.Rap.Comparer(f, t, "longueur L d'EX-13.14", strconv.FormatInt(LongueurArchive(tailles), 10), strconv.Itoa(len(b)))
	}

	// Cas de cas.json.
	racineDepot := filepath.Join(c.Spec, "..")
	var exemple *Value
	for _, k := range cas.Get("cases").Arr {
		nom := k.Get("name").Str
		if nom == "fichier-altere" {
			exemple = k
		}
		arch := k.Get("archive").Str
		b, ok := archives[arch]
		if !ok {
			c.Rap.Erreur("%s : archive %s absente", nom, arch)
			continue
		}
		c.Rap.Comparer(f, nom, "archive_sha256", k.Get("archive_sha256").Str, SHA256Hex(b))
		opt := k.Get("options")
		empreinte := ""
		if e := opt.Get("expected_sha256"); !e.EstNull() {
			empreinte = e.Str
		}
		ancres := opt.Get("anchors")
		if !ancres.EstNull() {
			_, err := os.Stat(filepath.Join(racineDepot, ancres.Str))
			c.Rap.Constater(f, nom, "fichier --ancres lisible (sinon code 2, EX-13.24)", err == nil, fmt.Sprint(err))
		}
		r := EvaluerPaquet(b, empreinte, schema)
		ex := k.Get("expected")
		c.Rap.Comparer(f, nom, "package_status", ex.Get("package_status").Str, r.Etat)
		pr := map[string]string{}
		for i, ch := range r.Checks {
			a := ex.Get("checks").Arr[i]
			pr[ch.ID] = a.Get("status").Str
			c.Rap.Comparer(f, nom, ch.ID+" id", a.Get("id").Str, ch.ID)
			attendu := a.Get("status").Str + " (" + TexteValeur(a.Get("reason")) + ")"
			if ch.Status == "" {
				c.Rap.HorsPerimetre(f, nom, ch.ID+" statut", attendu, ch.Detail)
				continue
			}
			reason := "null"
			if ch.Reason != "" {
				reason = strconv.Quote(ch.Reason)
			}
			c.Rap.Comparer(f, nom, ch.ID+" statut (raison)", attendu, ch.Status+" ("+reason+")")
		}
		var av []string
		for _, w := range ex.Get("warnings").Arr {
			av = append(av, w.Str)
		}
		pr11 := r.Checks[10].Status
		pr12 := r.Checks[11].Status
		if pr12 == "" {
			pr12 = pr["PR-12"] // AV-PR-2 suit PR-12, hors périmètre ici
		}
		c.Rap.Comparer(f, nom, "warnings (13.9)", Liste(av), Liste(Avertissements(r, !ancres.EstNull(), pr11, pr12)))
		var chemins, attChemins []string
		var codes []int64
		for _, d := range ex.Get("dossiers").Arr {
			attChemins = append(attChemins, d.Get("path").Str)
			n, _ := d.Get("exit_code").Entier()
			codes = append(codes, n)
			c.Rap.HorsPerimetre(f, nom, "code de "+d.Get("path").Str, strconv.FormatInt(n, 10), "code de CT-6, non recalculé (EX-A.24)")
		}
		if r.Etat == "intact" {
			for _, d := range r.Manifeste.Get("dossiers").Arr {
				chemins = append(chemins, d.Get("path").Str)
			}
		}
		c.Rap.Comparer(f, nom, "dossiers vérifiés, dans l'ordre du manifeste (EX-13.25, pas 6)", Liste(attChemins), Liste(chemins))
		code, _ := ex.Get("exit_code").Entier()
		c.Rap.Comparer(f, nom, "exit_code (EX-13.26)", strconv.FormatInt(code, 10), strconv.FormatInt(CodeRetour(r.Etat, codes), 10))
	}

	// Exemple de cas imprimé en A.10.
	if bl, err := BlocApres(secA10, "<!-- schema: paquet-reviseur/cas -->"); err == nil {
		v, err := AnalyserJSON([]byte(bl))
		if err != nil {
			c.Rap.Erreur("A.10 : exemple de cas illisible (%v)", err)
		} else {
			c.ValiderSchema(f, "exemple A.10", "paquet-reviseur-v0", "#/$defs/cas", v)
			c.Rap.Constater(f, "fichier-altere", "égal à l'exemple de cas d'A.10", exemple != nil && Egales(v, exemple), "")
		}
	}

	// EX-13.1 : 17 cas, dont onze de code 4 ; sept cas désignés par A.10.
	n4 := 0
	var tous []string
	for _, k := range cas.Get("cases").Arr {
		tous = append(tous, k.Get("name").Str)
		if x, _ := k.Chemin("expected", "exit_code").Entier(); x == 4 {
			n4++
		}
	}
	c.Rap.Comparer(f, "cas.json", "nombre de cas (EX-13.1, point 1)", "17", strconv.Itoa(len(tous)))
	c.Rap.Comparer(f, "cas.json", "cas de code 4 (EX-13.1, point 4 : onze)", "11", strconv.Itoa(n4))
	var manquants []string
	for _, n := range []string{"valide", "fichier-altere", "fichier-manquant", "fichier-en-trop", "manifeste-altere", "chemin-hors-archive", "lien-symbolique"} {
		if !contient(tous, n) {
			manquants = append(manquants, n)
		}
	}
	c.Rap.Comparer(f, "cas.json", "les sept cas qu'A.10 désigne", "[]", Liste(manquants))
	// EX-A.15 : cas observation.
	var obs *Value
	for _, k := range cas.Get("cases").Arr {
		if k.Get("name").Str == "observation" {
			obs = k
		}
	}
	if obs == nil {
		c.Rap.Comparer(f, "cas.json", "cas observation (EX-A.15)", "présent", "absent")
	} else {
		e := obs.Get("expected")
		c.Rap.Comparer(f, "observation", "EX-A.15 : archive", "observation.tar", obs.Get("archive").Str)
		c.Rap.Comparer(f, "observation", "EX-A.15 : code", "0", TexteValeur(e.Get("exit_code")))
		var ds []string
		for _, d := range e.Get("dossiers").Arr {
			ds = append(ds, d.Get("path").Str+" "+TexteValeur(d.Get("exit_code"))+" "+TexteValeur(d.Get("observation_mode"))+" "+TexteValeur(d.Get("observation")))
		}
		c.Rap.Comparer(f, "observation", "EX-A.15 : dossiers (chemin, code, observation_mode, observation)", "[dossiers/seq-1 0 true null, dossiers/seq-3 0 true \"a_approuver\"]", Liste(ds))
		o := e.Get("observation")
		c.Rap.Comparer(f, "observation", "EX-A.15 : summary.observation", "2 0 1 0 0",
			TexteValeur(o.Get("dossiers"))+" "+TexteValeur(o.Get("autorise"))+" "+TexteValeur(o.Get("a_approuver"))+" "+TexteValeur(o.Get("refuse"))+" "+TexteValeur(o.Get("inconnu")))
	}

	verifierTablePaquets(c, secA10, cas, archives)
	valide, ok := resultats["valide.tar"]
	if !ok || valide.Etat != "intact" {
		c.Rap.Erreur("valide.tar illisible ou non conforme : confrontations au texte impossibles")
		return
	}
	verifierValideTexte(c, valide)
	verifierDescription(c, valide)
	verifierVariantes(c, resultats)
}

// verifierTablePaquets relit la table d'EX-A.13.
func verifierTablePaquets(c *Contexte, sec []string, cas *Value, archives map[string][]byte) {
	const f = "paquets"
	tab, err := TableEntete(sec, "Cas", "Archive")
	if err != nil {
		c.Rap.Erreur("EX-A.13 : %v", err)
		return
	}
	parNom := map[string]*Value{}
	var noms []string
	for _, k := range cas.Get("cases").Arr {
		parNom[k.Get("name").Str] = k
		noms = append(noms, k.Get("name").Str)
	}
	var dansTable []string
	tiret := func(xs []string) string {
		if len(xs) == 0 {
			return "—"
		}
		return strings.Join(xs, ", ")
	}
	for _, l := range tab.Lignes {
		nom := SansCode(l[0])
		dansTable = append(dansTable, nom)
		k := parNom[nom]
		if k == nil {
			c.Rap.Comparer(f, nom, "cas de la table d'EX-A.13 dans cas.json", "présent", "absent")
			continue
		}
		g := "EX-A.13 : "
		arch := k.Get("archive").Str
		b := archives[arch]
		cell := SansCode(l[1])
		c.Rap.Comparer(f, nom, g+"archive", strings.Fields(cell)[0], arch)
		mT := regexp.MustCompile(`\(([0-9 ]+) octets`).FindStringSubmatch(cell)
		if mT != nil {
			c.Rap.Comparer(f, nom, g+"taille", strings.ReplaceAll(mT[1], " ", ""), strconv.Itoa(len(b)))
		}
		c.Rap.Comparer(f, nom, g+"SHA-256", reHex32.FindString(cell), SHA256Hex(b))
		opt := k.Get("options")
		o := SansCode(l[2])
		switch {
		case o == "—":
			c.Rap.Comparer(f, nom, g+"options", "null, null", TexteValeur(opt.Get("expected_sha256"))+", "+TexteValeur(opt.Get("anchors")))
		case strings.HasPrefix(o, "--empreinte de l'archive"):
			c.Rap.Comparer(f, nom, g+"--empreinte de l'archive", SHA256Hex(b), opt.Get("expected_sha256").Str)
		case strings.HasPrefix(o, "--empreinte "):
			p := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(o, "--empreinte ")), "…")
			c.Rap.Constater(f, nom, g+"--empreinte "+p+"…", strings.HasPrefix(opt.Get("expected_sha256").Str, p) && opt.Get("expected_sha256").Str != SHA256Hex(b), opt.Get("expected_sha256").Str)
		case strings.HasPrefix(o, "--ancres "):
			c.Rap.Comparer(f, nom, g+"--ancres", strings.TrimPrefix(o, "--ancres "), opt.Get("anchors").Str)
		default:
			c.Rap.Erreur("EX-A.13 : options %q non lues", o)
		}
		ex := k.Get("expected")
		code, _ := ex.Get("exit_code").Entier()
		c.Rap.Comparer(f, nom, g+"code", l[3], strconv.FormatInt(code, 10))
		c.Rap.Comparer(f, nom, g+"paquet", SansCode(l[4]), ex.Get("package_status").Str)
		var echecs, av, codes []string
		for _, ch := range ex.Get("checks").Arr {
			if ch.Get("status").Str == "echoue" {
				echecs = append(echecs, ch.Get("id").Str)
			}
		}
		for _, w := range ex.Get("warnings").Arr {
			av = append(av, w.Str)
		}
		for _, d := range ex.Get("dossiers").Arr {
			n, _ := d.Get("exit_code").Entier()
			codes = append(codes, strconv.FormatInt(n, 10))
		}
		c.Rap.Comparer(f, nom, g+"PR- en échec", l[5], tiret(echecs))
		c.Rap.Comparer(f, nom, g+"avertissements", l[6], tiret(av))
		c.Rap.Comparer(f, nom, g+"codes des dossiers", l[7], tiret(codes))
		c.Rap.Comparer(f, nom, g+"ce qui change = description du cas", l[8], k.Get("description").Str)
	}
	c.Rap.Comparer(f, "cas.json", "cas = lignes de la table d'EX-A.13, dans l'ordre", Liste(dansTable), Liste(noms))
}

func entreeNommee(r ResultatPaquet, nom string) (EntreeTar, bool) {
	for _, e := range r.Entrees {
		if e.NomComplet() == racinePaquet+"/"+nom {
			return e, true
		}
	}
	return EntreeTar{}, false
}

// verifierValideTexte confronte valide.tar au manifeste de 13.3, aux
// instructions de 13.11 et au rapport du cas fichier-altere de 13.7.
func verifierValideTexte(c *Contexte, r ResultatPaquet) {
	const f = "paquets"
	s13, err := c.Texte.Section("### 13.3 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	m := regexp.MustCompile(`paquet allégé \(([0-9]+) fichiers, ([0-9 ]+) octets ; manifeste de ([0-9 ]+) octets, SHA-256 ` + "`(0x[0-9a-f]{64})`").FindStringSubmatch(joindre(s13))
	man, _ := entreeNommee(r, "MANIFESTE.json")
	if m == nil {
		c.Rap.Erreur("13.3 : décompte du manifeste introuvable")
	} else {
		var octets int64
		for _, x := range r.Manifeste.Get("files").Arr {
			n, _ := x.Get("size").Entier()
			octets += n
		}
		c.Rap.Comparer(f, "valide.tar", "13.3 : fichiers décrits", m[1], strconv.Itoa(len(r.Manifeste.Get("files").Arr)))
		c.Rap.Comparer(f, "valide.tar", "13.3 : octets décrits", strings.ReplaceAll(m[2], " ", ""), strconv.FormatInt(octets, 10))
		c.Rap.Comparer(f, "valide.tar", "13.3 : taille du manifeste", strings.ReplaceAll(m[3], " ", ""), strconv.Itoa(len(man.Donnees)))
		c.Rap.Comparer(f, "valide.tar", "13.3 : SHA-256 du manifeste", m[4], r.MSHA256)
	}
	if bl, err := BlocApres(s13, "<!-- schema: paquet-reviseur -->"); err == nil {
		v, err := AnalyserJSON([]byte(bl))
		if err == nil {
			c.ValiderSchema(f, "exemple 13.3", "paquet-reviseur-v0", "", v)
			c.Rap.Constater(f, "valide.tar", "MANIFESTE.json égal au manifeste de 13.3", Egales(v, r.Manifeste), "")
		} else {
			c.Rap.Erreur("13.3 : %v", err)
		}
	}
	s, _ := Stringify2(r.Manifeste)
	c.Rap.Constater(f, "valide.tar", "MANIFESTE.json écrit par JSON.stringify(m, null, 2) + saut de ligne (EX-13.12)", s+"\n" == string(man.Donnees), "")
	c.Rap.Comparer(f, "valide.tar", "membres du manifeste dans l'ordre de la table de 13.3",
		"[format, version, label, created_at, prepared_by, dossiers, attestation, verifier, instructions, files]", Liste(r.Manifeste.Cles()))
	c.Rap.Comparer(f, "valide.tar", "created_at (EX-A.12 : 1 793 059 200 secondes)", "1793059200", strconv.FormatInt(r.Entrees[0].Mtime, 10))

	// 13.11 : instructions, octet pour octet. Les blocs contiennent des
	// titres Markdown : on les lit dans le texte entier, après le titre de
	// 13.11, et non dans la section que Section découperait à ces titres.
	var s1311 []string
	for i, l := range c.Texte.Lignes {
		if strings.HasPrefix(l, "### 13.11 ") {
			s1311 = c.Texte.Lignes[i:]
			break
		}
	}
	if len(s1311) < 20 {
		c.Rap.Erreur("13.11 introuvable")
		return
	}
	shas := reHex32.FindAllString(joindre(s1311[:20]), -1)
	for i, nom := range []string{"LISEZMOI.md", "README.md"} {
		bl, err := BlocApres(s1311, "<!-- fichier: "+nom+" -->")
		if err != nil {
			c.Rap.Erreur("13.11 : %v", err)
			continue
		}
		e, ok := entreeNommee(r, nom)
		c.Rap.Constater(f, "valide.tar", nom+" égal au bloc de 13.11 (EX-13.9, EX-13.36)", ok && string(e.Donnees) == bl, "")
		if i < len(shas) {
			c.Rap.Comparer(f, "valide.tar", nom+" : SHA-256 d'EX-13.36", shas[i], SHA256Hex([]byte(bl)))
		}
	}

	// 13.7 : rapport du cas fichier-altere et résumé de contrefacon-coherente.
	s137, err := c.Texte.Section("### 13.7 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	bl, err := BlocApres(s137, "<!-- schema: paquet-reviseur/rapport -->")
	if err != nil {
		c.Rap.Erreur("13.7 : %v", err)
		return
	}
	rv, err := AnalyserJSON([]byte(bl))
	if err != nil {
		c.Rap.Erreur("13.7 : %v", err)
		return
	}
	c.ValiderSchema(f, "exemple 13.7", "paquet-reviseur-v0", "#/$defs/rapport", rv)
	b, ok := c.LireFichier(c.Chemin("paquets", "fichier-altere.tar"))
	if !ok {
		return
	}
	fa := EvaluerPaquet(b, "", c.Schemas["paquet-reviseur-v0"])
	c.Rap.Comparer(f, "fichier-altere", "13.7 : taille et SHA-256 de l'archive", TexteValeur(rv.Chemin("inputs", "archive", "size"))+" "+rv.Chemin("inputs", "archive", "sha256").Str,
		strconv.Itoa(fa.Taille)+" "+fa.SHA256)
	if fa.Manifeste != nil {
		var octets int64
		for _, x := range fa.Manifeste.Get("files").Arr {
			n, _ := x.Get("size").Entier()
			octets += n
		}
		mv := rv.Get("manifest")
		c.Rap.Comparer(f, "fichier-altere", "13.7 : manifest (SHA-256, libellé, created_at, prepared_by, fichiers, octets)",
			strings.Join([]string{mv.Get("sha256").Str, mv.Get("label").Str, mv.Get("created_at").Str, mv.Get("prepared_by").Str, TexteValeur(mv.Get("files")), TexteValeur(mv.Get("bytes"))}, " | "),
			strings.Join([]string{fa.MSHA256, fa.Manifeste.Get("label").Str, fa.Manifeste.Get("created_at").Str, fa.Manifeste.Get("prepared_by").Str, strconv.Itoa(len(fa.Manifeste.Get("files").Arr)), strconv.FormatInt(octets, 10)}, " | "))
	}
	for i, ch := range rv.Get("checks").Arr {
		g := fa.Checks[i]
		reason := "null"
		if g.Reason != "" {
			reason = strconv.Quote(g.Reason)
		}
		c.Rap.Comparer(f, "fichier-altere", "13.7 : "+g.ID+" statut (raison)", ch.Get("status").Str+" ("+TexteValeur(ch.Get("reason"))+")", g.Status+" ("+reason+")")
		if g.ID == "PR-2" {
			c.Rap.HorsPerimetre(f, "fichier-altere", "13.7 : PR-2 détail", ch.Get("detail").Str, "texte d'une vérification non exécutée, propre à l'outil")
			continue
		}
		c.Rap.Comparer(f, "fichier-altere", "13.7 : "+g.ID+" détail", ch.Get("detail").Str, g.Detail)
	}
	c.Rap.Comparer(f, "fichier-altere", "13.7 : package_status, exit_code", rv.Get("package_status").Str+", "+TexteValeur(rv.Get("exit_code")),
		fa.Etat+", "+strconv.FormatInt(CodeRetour(fa.Etat, nil), 10))
	// Résumé de contrefacon-coherente : SHA-256 du manifeste recalculé.
	mC := regexp.MustCompile(`contrefacon-coherente\.tar, [0-9]+ octets, SHA-256 (0x[0-9a-f]{64}) Manifeste +: SHA-256 (0x[0-9a-f]{64})`).FindStringSubmatch(joindre(s137))
	if bc, ok := c.LireFichier(c.Chemin("paquets", "contrefacon-coherente.tar")); ok && mC != nil {
		rc := EvaluerPaquet(bc, "", c.Schemas["paquet-reviseur-v0"])
		c.Rap.Comparer(f, "contrefacon-coherente", "13.7 : SHA-256 de l'archive et du manifeste recalculé", mC[1]+" "+mC[2], rc.SHA256+" "+rc.MSHA256)
	} else if mC == nil {
		c.Rap.Erreur("13.7 : résumé de contrefacon-coherente introuvable")
	}
}

// verifierDescription confronte description.json à l'exemple de 13.5 et
// chaque fichier de valide.tar à sa source (EX-13.17, EX-13.18, EX-A.11).
func verifierDescription(c *Contexte, r ResultatPaquet) {
	const f = "paquets"
	rep := c.Chemin("paquets")
	d, b, ok := c.LireJSON(filepath.Join(rep, "description.json"))
	if !ok {
		return
	}
	c.Forme(f, "description.json", b)
	c.ValiderSchema(f, "description.json", "paquet-reviseur-v0", "#/$defs/description_source", d)
	if s, err := c.Texte.Section("### 13.5 "); err == nil {
		if bl, err := BlocApres(s, "<!-- schema: paquet-reviseur/description_source -->"); err == nil {
			if v, err := AnalyserJSON([]byte(bl)); err == nil {
				c.Rap.Constater(f, "description.json", "égale à la description de 13.5", Egales(v, d), "")
			}
		}
	}
	// Fichiers attendus, d'après la description et EX-13.18.
	attendus := map[string]string{} // chemin dans le paquet → source
	dossiers := VArr()
	for _, x := range d.Get("dossiers").Arr {
		src := filepath.Join(rep, x.Get("source").Str)
		nomD := filepath.Base(src)
		idx, _, ok := c.LireJSON(filepath.Join(src, "dossier.json"))
		if !ok {
			return
		}
		attendus["dossiers/"+nomD+"/dossier.json"] = filepath.Join(src, "dossier.json")
		for _, p := range idx.Get("parts").Arr {
			if p.Get("present").Bool {
				attendus["dossiers/"+nomD+"/"+p.Get("file").Str] = filepath.Join(src, p.Get("file").Str)
			}
		}
		un := func(cle, rep2 string) *Value {
			v := x.Get(cle)
			if v.EstNull() {
				return VNull()
			}
			s := filepath.Join(rep, v.Str)
			attendus[rep2+"/"+filepath.Base(s)] = s
			return VStr(rep2 + "/" + filepath.Base(s))
		}
		dossiers.Arr = append(dossiers.Arr, VObj("path", VStr("dossiers/"+nomD), "anchors", un("anchors", "ancres"), "bitcoin_headers", un("bitcoin_headers", "entetes")))
	}
	if a := d.Get("attestation"); !a.EstNull() {
		attendus["attestation/attestation-signee.json"] = filepath.Join(rep, a.Get("signed").Str)
		attendus["attestation/jeu-approbateurs.json"] = filepath.Join(rep, a.Get("approver_set").Str)
	}
	for _, p := range d.Get("pieces").Arr {
		s := filepath.Join(rep, p.Str)
		attendus["pieces/"+filepath.Base(s)] = s
	}
	c.Rap.Constater(f, "valide.tar", "dossiers du manifeste = dossiers de la description (ordre, ancres, en-têtes)", Egales(dossiers, r.Manifeste.Get("dossiers")), "")
	c.Rap.Comparer(f, "valide.tar", "label, created_at, prepared_by = description",
		d.Get("label").Str+" | "+d.Get("created_at").Str+" | "+d.Get("prepared_by").Str,
		r.Manifeste.Get("label").Str+" | "+r.Manifeste.Get("created_at").Str+" | "+r.Manifeste.Get("prepared_by").Str)
	c.Rap.Comparer(f, "valide.tar", "verifier (include_verifier faux : paquet allégé)", TexteValeur(VNull()), TexteValeur(r.Manifeste.Get("verifier")))
	presents := map[string]bool{}
	for _, x := range r.Manifeste.Get("files").Arr {
		p := x.Get("path").Str
		presents[p] = true
		if p == "LISEZMOI.md" || p == "README.md" {
			continue // confrontés au texte de 13.11
		}
		src, ok := attendus[p]
		if !ok {
			c.Rap.Comparer(f, "valide.tar", p, "absent de la description", "présent")
			continue
		}
		sb, err := os.ReadFile(src)
		e, _ := entreeNommee(r, p)
		c.Rap.Constater(f, "valide.tar", p+" = source octet pour octet ("+strings.TrimPrefix(src, c.Spec+string(filepath.Separator))+")", err == nil && bytes.Equal(sb, e.Donnees), fmt.Sprint(err))
	}
	for p := range attendus {
		if !presents[p] {
			c.Rap.Comparer(f, "valide.tar", p, "présent (description)", "absent")
		}
	}
}

// verifierVariantes confronte chaque variante à valide.tar : EX-A.12 (« ne
// diffère que d'une chose ») et la colonne « Ce qui change » d'EX-A.13.
func verifierVariantes(c *Contexte, res map[string]ResultatPaquet) {
	const f = "paquets"
	v := res["valide.tar"]
	diff := func(r ResultatPaquet) (retires, ajoutes []EntreeTar, ordre bool) {
		dansV := map[string]int{}
		for _, e := range v.Entrees {
			dansV[cleEntree(e)]++
		}
		dansR := map[string]int{}
		for _, e := range r.Entrees {
			dansR[cleEntree(e)]++
		}
		var communsR []string
		for _, e := range r.Entrees {
			k := cleEntree(e)
			if dansV[k] > 0 {
				dansV[k]--
				communsR = append(communsR, k)
			} else {
				ajoutes = append(ajoutes, e)
			}
		}
		dansV = map[string]int{}
		for _, e := range r.Entrees {
			dansV[cleEntree(e)]++
		}
		var communsV []string
		for _, e := range v.Entrees {
			k := cleEntree(e)
			if dansV[k] > 0 {
				dansV[k]--
				communsV = append(communsV, k)
			} else {
				retires = append(retires, e)
			}
		}
		return retires, ajoutes, strings.Join(communsR, "\x00") == strings.Join(communsV, "\x00")
	}
	noms := func(es []EntreeTar) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.NomComplet())
		}
		return out
	}
	evt := "paquet-reviseur/dossiers/valide-seq-7-complet/evenement.json"
	man := "paquet-reviseur/MANIFESTE.json"
	type attente struct {
		retires, ajoutes []string
		plus             func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string)
	}
	unOctet := func(a, b []byte, de, vers byte) bool {
		if len(a) != len(b) {
			return false
		}
		n := 0
		for i := range a {
			if a[i] != b[i] {
				n++
				if a[i] != de || b[i] != vers {
					return false
				}
			}
		}
		return n == 1
	}
	evtValide, _ := entreeNommee(v, "dossiers/valide-seq-7-complet/evenement.json")
	attentes := map[string]attente{
		"fichier-altere.tar": {[]string{evt}, []string{evt}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			return unOctet(ret[0].Donnees, aj[0].Donnees, '7', '9'), "un seul octet changé, 7 devenu 9 ; manifeste inchangé"
		}},
		"fichier-manquant.tar": {[]string{"paquet-reviseur/dossiers/valide-seq-7-complet/voisins.json"}, nil, nil},
		"fichier-en-trop.tar": {nil, []string{"paquet-reviseur/dossiers/valide-seq-7-complet/note.txt"}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			for k := 1; k < len(r.Entrees); k++ {
				if !(r.Entrees[k-1].NomComplet() < r.Entrees[k].NomComplet()) {
					return false, "à sa place dans l'ordre"
				}
			}
			return true, "à sa place dans l'ordre"
		}},
		"manifeste-altere.tar": {[]string{man}, []string{man}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			m, err := AnalyserJSON(aj[0].Donnees)
			if err != nil {
				return false, err.Error()
			}
			ecarts := 0
			ok := true
			for i, x := range m.Get("files").Arr {
				y := v.Manifeste.Get("files").Arr[i]
				if !Egales(x, y) {
					ecarts++
					ok = ok && x.Get("path").Str == "dossiers/valide-seq-7-complet/evenement.json" && x.Get("sha256").Str != SHA256Hex(evtValide.Donnees)
				}
			}
			return ok && ecarts == 1 && Egales(m.Sans("files"), v.Manifeste.Sans("files")), "seul le SHA-256 déclaré d'evenement.json change ; le fichier est intact"
		}},
		"contrefacon-coherente.tar": {[]string{man, evt}, []string{man, evt}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			fa, ok := res["fichier-altere.tar"]
			if !ok {
				return false, "fichier-altere.tar absent"
			}
			e1, _ := entreeNommee(fa, "dossiers/valide-seq-7-complet/evenement.json")
			e2, _ := entreeNommee(r, "dossiers/valide-seq-7-complet/evenement.json")
			return bytes.Equal(e1.Donnees, e2.Donnees) && r.Etat == "intact", "même octet changé que fichier-altere, manifeste recalculé (paquet intact)"
		}},
		"chemin-hors-archive.tar": {nil, []string{"paquet-reviseur/../../evasion.txt"}, nil},
		"chemin-absolu.tar":       {nil, []string{"/paquet-reviseur/evasion.txt"}, nil},
		"lien-symbolique.tar": {nil, []string{"paquet-reviseur/ancres/raccourci"}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			return aj[0].Typeflag == '2' && aj[0].Linkname == "../../../evasion", "lien symbolique vers ../../../evasion"
		}},
		"lien-physique.tar": {nil, []string{"paquet-reviseur/ancres/double"}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			cible := false
			for _, e := range v.Entrees {
				cible = cible || e.NomComplet() == aj[0].Linkname
			}
			return aj[0].Typeflag == '1' && cible, "lien physique vers un fichier de l'archive"
		}},
		"nom-en-double.tar": {nil, []string{"paquet-reviseur/LISEZMOI.md"}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			l, _ := entreeNommee(v, "LISEZMOI.md")
			return !bytes.Equal(l.Donnees, aj[0].Donnees), "seconde entrée d'un autre contenu"
		}},
		"metadonnees-non-fixees.tar": {[]string{"paquet-reviseur/README.md"}, []string{"paquet-reviseur/README.md"}, func(r ResultatPaquet, ret, aj []EntreeTar) (bool, string) {
			return aj[0].Mode == 0o600 && bytes.Equal(ret[0].Donnees, aj[0].Donnees), "mode 0600, contenu inchangé"
		}},
	}
	var ordre []string
	for nom := range attentes {
		ordre = append(ordre, nom)
	}
	sort.Strings(ordre)
	for _, nom := range ordre {
		at := attentes[nom]
		r, ok := res[nom]
		if !ok {
			c.Rap.Erreur("%s absent", nom)
			continue
		}
		ret, aj, ordre := diff(r)
		c.Rap.Comparer(f, nom, "entrées retirées de valide.tar", Liste(at.retires), Liste(noms(ret)))
		c.Rap.Comparer(f, nom, "entrées ajoutées à valide.tar", Liste(at.ajoutes), Liste(noms(aj)))
		c.Rap.Constater(f, nom, "autres entrées de valide.tar inchangées, dans le même ordre (EX-A.12)", ordre, "")
		if at.plus != nil && len(ret) == len(at.retires) && len(aj) == len(at.ajoutes) {
			okp, quoi := at.plus(r, ret, aj)
			c.Rap.Constater(f, nom, quoi, okp, "")
		}
	}
}
