// Famille « supervision » (CT-8 §10.3 à §10.7, EX-10.6, EX-10.11 SV-1, SV-5
// et SV-6 ; A.6, A.9). Recalcule, sans lire le code JavaScript :
//
//   - SV-5 : l'exposition de l'extracteur rejoué sur supervision/journaux/,
//     d'après la table de 10.3 telle que la révision de l'étape 7 la propose
//     (noms des lignes et des membres du code des paquets : detail de
//     approval_service_unavailable et de alerte_checkpoint_anchor_late,
//     horloge_suspecte lue dans warnings) ; seules les séries et les lignes
//     TYPE sont comparées, les lignes HELP sont libres ;
//   - SV-6 : regles-attendues.yml égale le fichier de référence
//     deploiement/observabilite/regles-noortrace.yml aux seuils près, chaque
//     seuil recalculé depuis configuration-modifiee.json et ancrage-modifie.json
//     selon les tables de 10.4 et 10.5 et EX-10.6 ;
//   - SV-1 (partie) : les règles du fichier de référence sont celles des
//     tables de 10.4 à 10.7, plus celles d'EX-10.9 (proposition PD-28 de
//     CT-9), avec la gravité, l'exigence, le runbook et la clause for de la
//     table.

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var sourcesSupervision = []string{"exploitation", "gel", "acquisitions", "registre", "consultations", "approbation"}
var reValeurSure = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var reHorodatageSV = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z$`)

func sure(v *Value) string {
	s := v.Chaine()
	if reValeurSure.MatchString(s) {
		return s
	}
	return ""
}

// msInstant lit un horodatage UTC ; la fraction est tronquée à la milliseconde.
func msInstant(v *Value) (int64, bool) {
	m := reHorodatageSV.FindStringSubmatch(v.Chaine())
	if m == nil {
		return 0, false
	}
	n := make([]int, 6)
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	if n[1] < 1 || n[1] > 12 || n[2] < 1 || n[3] > 23 || n[4] > 59 || n[5] > 59 {
		return 0, false
	}
	if n[2] > time.Date(n[0], time.Month(n[1])+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return 0, false
	}
	frac := int64(0)
	if m[7] != "" {
		f := (m[7][1:] + "00")[:3]
		x, _ := strconv.Atoi(f)
		frac = int64(x)
	}
	return time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], 0, time.UTC).UnixMilli() + frac, true
}

// secondesTexte écrit des millisecondes en secondes : entier, ou décimales sans zéro final.
func secondesTexte(ms int64) string {
	e := ms / 1000
	r := ms % 1000
	if r < 0 {
		e--
		r += 1000
	}
	if r == 0 {
		return strconv.FormatInt(e, 10)
	}
	return strconv.FormatInt(e, 10) + "." + strings.TrimRight(fmt.Sprintf("%03d", r), "0")
}

func nombrePositif(v *Value) bool {
	if v == nil || v.Kind != KindNumber {
		return false
	}
	f, err := strconv.ParseFloat(v.Num, 64)
	return err == nil && f > 0
}

func contientChaine(v *Value, s string) bool {
	if v == nil || v.Kind != KindArray {
		return false
	}
	for _, x := range v.Arr {
		if x.Kind == KindString && x.Str == s {
			return true
		}
	}
	return false
}

// detailSV est la colonne detail de la table de 10.3 (révision proposée).
func detailSV(source, event string, v *Value) string {
	d := v.Get("data")
	switch source {
	case "exploitation", "gel":
		switch event {
		case "worm_lock_config_check":
			if d.Get("verdict").Chaine() == "conforme" {
				return "conforme"
			}
			return "non_conforme"
		case "worm_lock_check":
			if contientChaine(d.Get("reasons"), "gel_absent") {
				return "gel_absent"
			}
			if d.Get("verdict").Chaine() == "conforme" {
				return "conforme"
			}
			return "non_conforme"
		case "worm_legal_hold_observed":
			if g := d.Get("garde"); g != nil && g.Kind == KindString && g.Str != "respectee" {
				return "garde_violee"
			}
			if d.Get("kind").Chaine() == "levee" {
				return "levee"
			}
			return "autre"
		case "anchoring_queue_rebuilt":
			if nombrePositif(d.Get("recreated")) {
				return "recree"
			}
			return "aucune"
		case "anchor_refused":
			if d.Get("error_code").Chaine() == "empreinte_squattee" {
				return "empreinte_squattee"
			}
			return "autre"
		case "alerte_checkpoint_anchor_late":
			switch d.Get("severity").Chaine() {
			case "majeure":
				return "exterieur"
			case "mineure":
				return "interne"
			}
			return ""
		case "dossier_export_refused":
			return sure(d.Get("raison"))
		case "approval_service_unavailable":
			if d.Get("message").Chaine() == "charger" && d.Get("code").Chaine() == "politique_invalide" {
				return "politique_invalide_au_charger"
			}
		}
		return ""
	case "acquisitions":
		if v.Get("freshness").Chaine() == "horloge_suspecte" || contientChaine(v.Get("warnings"), "horloge_suspecte") {
			return "horloge_suspecte"
		}
		if contientChaine(v.Get("warnings"), "reponse_tardive") && v.Get("promoted") != nil && v.Get("promoted").Kind == KindBool && v.Get("promoted").Bool {
			return "reponse_tardive_promue"
		}
		if r := v.Get("revoked"); r != nil && r.Kind == KindBool && r.Bool {
			return "revoque"
		}
		return sure(v.Get("outcome"))
	case "registre":
		if a := v.Chemin("outputs", "retention", "alert"); a != nil && a.Kind == KindBool && a.Bool {
			return "marge_retention_basse"
		}
		if v.Chemin("error", "code").Chaine() == "examen_requis" {
			return "examen_requis"
		}
		return ""
	case "consultations":
		return sure(v.Get("role"))
	case "approbation":
		if event == "notification_echec" || event == "notification_abandonnee" {
			return sure(v.Get("cause"))
		}
	}
	return ""
}

type extracteurSV struct {
	lignes     map[[4]string]int
	dernieres  map[[2]string]int64
	illisibles map[string]int
	pv         map[string]int64
}

func (x *extracteurSV) valeur(source string, v *Value) {
	if v.Kind != KindObject {
		x.lignes[[4]string{source, "", "", ""}]++
		return
	}
	niveau := v.Get("level").Chaine()
	if !contient([]string{"debug", "info", "warning", "error"}, niveau) {
		niveau = ""
	}
	var event string
	var instant *Value
	switch source {
	case "exploitation", "gel":
		event, instant = sure(v.Get("event")), v.Get("ts")
	case "acquisitions":
		event, instant = "acquisition", v.Get("received_at")
	case "registre":
		event = sure(v.Get("command"))
	case "consultations":
		event, instant = sure(v.Get("action")), v.Get("ts")
	case "approbation":
		event, instant = sure(v.Get("type")), v.Get("ts")
	}
	detail := ""
	if event != "" || source != "exploitation" && source != "gel" {
		detail = detailSV(source, event, v)
	}
	x.lignes[[4]string{source, event, niveau, detail}]++
	if ms, ok := msInstant(instant); ok {
		k := [2]string{source, event}
		if d, vu := x.dernieres[k]; !vu || ms > d {
			x.dernieres[k] = ms
		}
	}
}

func (x *extracteurSV) lire(source string, b []byte) {
	v, err := AnalyserJSON(b)
	if err != nil {
		x.illisibles[source]++
		return
	}
	x.valeur(source, v)
}

// fichiersSV rend les fichiers ordinaires sous rep, récursivement, par ordre d'octets des noms.
func fichiersSV(rep, suffixe string) []string {
	es, err := os.ReadDir(rep)
	if err != nil {
		return nil
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Name() < es[j].Name() })
	var out []string
	for _, e := range es {
		p := filepath.Join(rep, e.Name())
		if e.IsDir() {
			out = append(out, fichiersSV(p, suffixe)...)
		} else if e.Type().IsRegular() && strings.HasSuffix(e.Name(), suffixe) {
			out = append(out, p)
		}
	}
	return out
}

// lignesLF rend les lignes terminées par LF, CR final retiré, lignes vides omises.
func lignesLF(b []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return out
		}
		l := bytes.TrimSuffix(b[:i], []byte("\r"))
		if len(l) > 0 {
			out = append(out, l)
		}
		b = b[i+1:]
	}
}

// ExtraireSV rejoue l'extracteur sur un répertoire journaux/ ; rend les
// lignes TYPE et les séries, dans l'ordre de l'exposition.
func ExtraireSV(c *Contexte, rep string) []string {
	x := &extracteurSV{map[[4]string]int{}, map[[2]string]int64{}, map[string]int{}, map[string]int64{}}
	for _, s := range sourcesSupervision {
		r := filepath.Join(rep, s)
		if _, err := os.Stat(r); err != nil {
			continue
		}
		x.illisibles[s] += 0
		suffixe := ""
		if s == "registre" {
			suffixe = ".json"
		}
		for _, f := range fichiersSV(r, suffixe) {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if s == "registre" {
				x.lire(s, b)
				continue
			}
			for _, l := range lignesLF(b) {
				x.lire(s, l)
			}
		}
	}
	for _, f := range fichiersSV(filepath.Join(rep, "proces-verbaux"), ".json") {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if VerifierPV(c, b, "", nil)["PV-1"] != "reussi" {
			continue
		}
		pv, _ := AnalyserJSON(b)
		kind := sure(pv.Get("kind"))
		if ms, ok := msInstant(pv.Get("finished_at")); ok && kind != "" {
			if d, vu := x.pv[kind]; !vu || ms > d {
				x.pv[kind] = ms
			}
		}
	}
	trie := func(xs []string) []string { sort.Strings(xs); return xs }
	out := []string{"# TYPE noortrace_journal_lignes_total counter"}
	var l []string
	for k, n := range x.lignes {
		l = append(l, fmt.Sprintf("noortrace_journal_lignes_total{source=%q,event=%q,level=%q,detail=%q} %d", k[0], k[1], k[2], k[3], n))
	}
	out = append(out, trie(l)...)
	out = append(out, "# TYPE noortrace_journal_derniere_ligne_s gauge")
	l = nil
	for k, ms := range x.dernieres {
		l = append(l, fmt.Sprintf("noortrace_journal_derniere_ligne_s{source=%q,event=%q} %s", k[0], k[1], secondesTexte(ms)))
	}
	out = append(out, trie(l)...)
	out = append(out, "# TYPE noortrace_journal_illisibles_total counter")
	l = nil
	for s, n := range x.illisibles {
		l = append(l, fmt.Sprintf("noortrace_journal_illisibles_total{source=%q} %d", s, n))
	}
	out = append(out, trie(l)...)
	out = append(out, "# TYPE noortrace_proces_verbal_dernier_s gauge")
	l = nil
	for k, ms := range x.pv {
		l = append(l, fmt.Sprintf("noortrace_proces_verbal_dernier_s{kind=%q} %s", k, secondesTexte(ms)))
	}
	return append(out, trie(l)...)
}

// ---------------------------------------------------------------- règles

// regleYAML est une règle lue dans un fichier de règles écrit en blocs
// réguliers (« - alert: », « expr: », « for: », étiquettes et annotations
// entre apostrophes).
type regleYAML struct {
	Nom    string
	Champs map[string]string
}

func sansApostrophes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

func lireReglesYAML(b []byte) []regleYAML {
	var out []regleYAML
	for _, l := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || t == "" {
			continue
		}
		if strings.HasPrefix(t, "- alert: ") {
			out = append(out, regleYAML{strings.TrimPrefix(t, "- alert: "), map[string]string{}})
			continue
		}
		if len(out) == 0 {
			continue
		}
		i := strings.Index(t, ": ")
		if i < 0 {
			continue
		}
		out[len(out)-1].Champs[t[:i]] = sansApostrophes(t[i+2:])
	}
	return out
}

var reRunbook = regexp.MustCompile(`RB-[0-9]+`)

// reglesTables lit les tables de 10.4 à 10.7 : nom → cellules et section.
func reglesTables(c *Contexte) (map[string][]string, map[string]string, []string) {
	cellules := map[string][]string{}
	sections := map[string]string{}
	var ordre []string
	for _, s := range []string{"### 10.4 ", "### 10.5 ", "### 10.6 ", "### 10.7 "} {
		sec, err := c.Texte.Section(s)
		if err != nil {
			c.Rap.Erreur("%v", err)
			continue
		}
		t, err := TableEntete(sec, "Règle", "Expression")
		if err != nil {
			c.Rap.Erreur("%s : %v", s, err)
			continue
		}
		for _, l := range t.Lignes {
			n := SansCode(l[0])
			cellules[n] = l
			sections[n] = strings.TrimSpace(strings.TrimPrefix(s, "### "))
			ordre = append(ordre, n)
		}
	}
	return cellules, sections, ordre
}

func entier(v *Value, defaut int64) int64 {
	if n, ok := v.Entier(); ok {
		return n
	}
	return defaut
}

func dureeSV(s int64) string {
	if s%3600 == 0 {
		return fmt.Sprintf("%dh", s/3600)
	}
	return fmt.Sprintf("%ds", s)
}

// FamilleSupervision confronte supervision/ et le fichier de règles de référence.
func FamilleSupervision(c *Contexte) {
	const f = "supervision"
	rep := c.Chemin("supervision")
	if _, err := os.Stat(rep); err != nil {
		c.Rap.HorsPerimetre(f, "supervision", "présent", "présent", "famille absente")
		return
	}
	// SV-5
	att, ok := c.LireFichier(filepath.Join(rep, "attendu.prom"))
	if ok {
		var attendu []string
		for _, l := range strings.Split(strings.TrimSuffix(string(att), "\n"), "\n") {
			if !strings.HasPrefix(l, "# HELP ") {
				attendu = append(attendu, l)
			}
		}
		obtenu := ExtraireSV(c, filepath.Join(rep, "journaux"))
		c.Rap.Comparer(f, "journaux", "SV-5 : séries et types de l'extracteur (10.3)", strings.Join(attendu, "\n"), strings.Join(obtenu, "\n"))
	}
	// SV-1 (partie) sur le fichier de référence
	refB, ok := c.LireFichier(filepath.Join(c.Spec, "..", "deploiement", "observabilite", "regles-noortrace.yml"))
	if !ok {
		return
	}
	ref := lireReglesYAML(refB)
	cellules, sections, ordre := reglesTables(c)
	var noms []string
	for _, r := range ref {
		noms = append(noms, r.Nom)
	}
	var ordreFichier []string
	for _, r := range ref {
		if _, ok := cellules[r.Nom]; ok {
			ordreFichier = append(ordreFichier, r.Nom)
		}
	}
	c.Rap.Comparer(f, "regles-noortrace.yml", "SV-1 : règles des tables de 10.4 à 10.7, dans l'ordre", Liste(ordre), Liste(ordreFichier))
	composantSection := map[string]string{"10.4": "enregistreur", "10.5": "ancrage", "10.6": "registre"}
	for _, r := range ref {
		l, ok := cellules[r.Nom]
		if !ok {
			c.Rap.Constater(f, r.Nom, "règle hors des tables : celle d'EX-10.9 (PD-28)", r.Champs["exigence"] == "CT-8 EX-10.9" && r.Champs["severity"] == "critique", r.Champs["exigence"])
			continue
		}
		c.Rap.Comparer(f, r.Nom, "SV-1 : gravité de la table", strings.Fields(l[3])[0], r.Champs["severity"])
		c.Rap.Comparer(f, r.Nom, "SV-1 : exigence de la table", SansCode(l[4]), r.Champs["exigence"])
		rb := reRunbook.FindAllString(l[5], -1)
		runbook := "aucun"
		if len(rb) > 0 {
			runbook = strings.Join(rb, ", ")
		}
		c.Rap.Comparer(f, r.Nom, "SV-1 : runbook de la table", runbook, r.Champs["runbook"])
		pour := strings.Fields(SansCode(l[2]))[0]
		if pour == "—" {
			pour = ""
		}
		c.Rap.Comparer(f, r.Nom, "SV-4 : clause for de la table", pour, r.Champs["for"])
		if cs, ok := composantSection[sections[r.Nom]]; ok {
			c.Rap.Comparer(f, r.Nom, "EX-10.2 : composant de la section", cs, r.Champs["component"])
		} else {
			c.Rap.Constater(f, r.Nom, "EX-10.2 : composant énuméré", contient([]string{"enregistreur", "ancrage", "approbation", "registre", "hote", "exploitation"}, r.Champs["component"]), r.Champs["component"])
		}
	}
	// SV-6
	modB, ok1 := c.LireFichier(filepath.Join(rep, "regles-attendues.yml"))
	conf, _, ok2 := c.LireJSON(filepath.Join(rep, "configuration-modifiee.json"))
	anc, _, ok3 := c.LireJSON(filepath.Join(rep, "ancrage-modifie.json"))
	modele, _, ok4 := c.LireJSON(filepath.Join(c.Spec, "..", "deploiement", "config", "modele-production", "configuration.json"))
	if !(ok1 && ok2 && ok3 && ok4) {
		return
	}
	mod := map[string]regleYAML{}
	for _, r := range lireReglesYAML(modB) {
		mod[r.Nom] = r
	}
	// Défauts d'EX-10.6 et des tables ; racine du modèle de production.
	pending := entier(conf.Chemin("policy", "failure", "pending_max_ms"), 300000)
	skew := entier(conf.Chemin("clock", "warn_skew_ms"), 1000)
	audit := entier(conf.Chemin("storage", "seal", "worm", "lock_audit_interval_days"), 30)
	libre := new(big.Int).Mul(big.NewInt(2), big.NewInt(entier(conf.Chemin("storage", "min_free_bytes"), 1073741824)))
	racine := strings.TrimRight(conf.Chemin("storage", "root").Chaine(), "/")
	racineRef := strings.TrimRight(modele.Chemin("storage", "root").Chaine(), "/")
	alerte := entier(anc.Chemin("queue", "anchor_pending_alert_s"), 7200)
	inclusion := entier(anc.Chemin("registry", "inclusion_alert_s"), 60)
	abandon := entier(anc.Chemin("opentimestamps", "upgrade", "give_up_after_s"), 1209600)
	remplacements := map[string][2]string{
		"noortrace_attente_ancienne":                {"> 150000", fmt.Sprintf("> %d", pending/2)},
		"noortrace_releve_en_retard":                {"> 5184000", fmt.Sprintf("> %d", 2*audit*86400)},
		"noortrace_horloge_ecart":                   {"> 1000", fmt.Sprintf("> %d", skew)},
		"noortrace_disque_espace":                   {fmt.Sprintf("mountpoint=%q} < 2147483648", racineRef), fmt.Sprintf("mountpoint=%q} < %s", racine, libre.String())},
		"noortrace_ancrage_inclusion_lente":         {`le=~"60(`, fmt.Sprintf(`le=~"%d(`, inclusion)},
		"noortrace_ancrage_inclusion_lente_repetee": {`le=~"60(`, fmt.Sprintf(`le=~"%d(`, inclusion)},
		"noortrace_ancrage_ots_abandon":             {"> 1209600", fmt.Sprintf("> %d", abandon)},
	}
	var nomsMod []string
	for _, r := range lireReglesYAML(modB) {
		nomsMod = append(nomsMod, r.Nom)
	}
	c.Rap.Comparer(f, "regles-attendues.yml", "SV-6 : mêmes règles que la référence", Liste(noms), Liste(nomsMod))
	for _, r := range ref {
		m, ok := mod[r.Nom]
		if !ok {
			continue
		}
		attendu := map[string]string{}
		for k, v := range r.Champs {
			attendu[k] = v
		}
		if rp, ok := remplacements[r.Nom]; ok {
			c.Rap.Constater(f, r.Nom, "SV-6 : seuil par défaut dans la référence", strings.Contains(r.Champs["expr"], rp[0]), r.Champs["expr"])
			attendu["expr"] = strings.Replace(r.Champs["expr"], rp[0], rp[1], 1)
		}
		if r.Nom == "noortrace_ancre_en_retard" {
			c.Rap.Comparer(f, r.Nom, "SV-6 : clause for par défaut (7 200 s)", "2h", r.Champs["for"])
			attendu["for"] = dureeSV(alerte)
		}
		var a, b []string
		for _, k := range []string{"expr", "for", "severity", "component", "exigence", "runbook", "summary", "description"} {
			a = append(a, k+"="+attendu[k])
			b = append(b, k+"="+m.Champs[k])
		}
		c.Rap.Comparer(f, r.Nom, "SV-6 : règle régénérée (EX-10.6)", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}
