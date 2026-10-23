// Familles de l'annexe A qui portent sur le langage de règles : constantes
// (A.2), schémas (EX-A.3), politiques et politiques refusées (A.4),
// évaluation (A.4, section 6), candidats (A.4, EX-4.11), épreuve
// d'acceptation (A.5).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Familles, dans l'ordre du rapport.
const (
	FamConstantes  = "constantes"
	FamSchemas     = "schemas"
	FamPolitiques  = "politiques"
	FamInvalides   = "politiques-invalides"
	FamEvaluation  = "evaluation"
	FamCandidats   = "candidats"
	FamAcceptation = "acceptation"
	FamTickets     = "tickets"
	FamDecisions   = "decisions"
	FamSignatures  = "signatures"
)

// RefTicket est le schéma ticket-v0.
const RefTicket = "https://noortrace.example/schemas/v0/ticket.schema.json"

// Contexte porte ce qui est partagé par les familles.
type Contexte struct {
	Racine string
	Sch    *Schemas
	R      *Rapport
	Spec   string // texte de spec/CT-3-approbations.md, s'il est trouvé
	Consts *Constantes
}

// Constantes de l'annexe A.2, recalculées (et non lues dans les vecteurs).
type Constantes struct {
	OrgID, JournalID string
	Registre         string
	Jeux             map[int]string
	Comptes          map[int]string // adresse
	Prives           map[string][]byte
	Demandeur        string
}

func (c *Contexte) lire(rel string) (*Value, bool) {
	src, err := os.ReadFile(filepath.Join(c.Racine, rel))
	if err != nil {
		c.R.Erreur("%s : %v", rel, err)
		return nil, false
	}
	v, err := ParseJSON(src)
	if err != nil {
		c.R.Erreur("%s : %v", rel, err)
		return nil, false
	}
	return v, true
}

func (c *Contexte) fichiers(motif string) []string {
	m, _ := filepath.Glob(filepath.Join(c.Racine, motif))
	sort.Strings(m)
	out := []string{}
	for _, f := range m {
		r, _ := filepath.Rel(c.Racine, f)
		out = append(out, filepath.ToSlash(r))
	}
	return out
}

// ------------------------------------------------------------ constantes

const mnemoniqueHardhat = "test test test test test test test test test test test junk"

// CalculerConstantes recalcule les constantes de l'annexe A.2.
func CalculerConstantes() (*Constantes, error) {
	k := &Constantes{
		OrgID:     Hex0x(Keccak256([]byte("assureur-demo"))),
		JournalID: Hex0x(Keccak256([]byte("journal-approbations"))),
		Registre:  Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/registre")[:20]),
		Jeux:      map[int]string{},
		Comptes:   map[int]string{},
		Prives:    map[string][]byte{},
		Demandeur: "u.martin@assureur-demo.example",
	}
	for n := 1; n <= 2; n++ {
		k.Jeux[n] = Hex0x(SHA256Etiquette(fmt.Sprintf("noortrace/vecteurs/ct3/jeu/%d", n))[:20])
	}
	graine, err := GraineBIP39(mnemoniqueHardhat)
	if err != nil {
		return nil, err
	}
	for i := 1; i <= 4; i++ {
		prive, err := DeriverBIP32(graine, fmt.Sprintf("m/44'/60'/0'/0/%d", i))
		if err != nil {
			return nil, err
		}
		a, err := AdresseDePrivee(prive)
		if err != nil {
			return nil, err
		}
		k.Comptes[i] = Hex0x(a)
		k.Prives[Hex0x(a)] = prive
	}
	return k, nil
}

// adressesA2 sont les adresses que l'annexe A.2 imprime.
var adressesA2 = map[int]string{
	1: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
	2: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
	3: "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
	4: "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
}

func familleConstantes(c *Contexte) {
	const f = FamConstantes
	const v = "constantes.json"
	k := c.Consts
	d, ok := c.lire(v)
	if !ok {
		return
	}
	r := c.R
	a2 := "CT-3 annexe A.2"
	r.Comparer(f, v, "organization.slug", d.Get("organization").Get("slug").S(), "assureur-demo", a2+" : « assureur-demo »")
	r.Comparer(f, v, "organization.org_id", d.Get("organization").Get("org_id").S(), k.OrgID, a2+" : org_id = keccak256(UTF-8(\"assureur-demo\"))")
	r.Comparer(f, v, "journal.name", d.Get("journal").Get("name").S(), "journal-approbations", a2+" : « journal-approbations »")
	r.Comparer(f, v, "journal.journal_id", d.Get("journal").Get("journal_id").S(), k.JournalID, a2+" : journal_id = keccak256(UTF-8(\"journal-approbations\"))")
	r.Comparer(f, v, "policy_versions", Compact(d.Get("policy_versions")), `["vecteurs-ct3-1","vecteurs-ct3-2"]`, a2+" : « vecteurs-ct3-1, puis vecteurs-ct3-2 »")
	r.Comparer(f, v, "chain_id", Compact(d.Get("chain_id")), "2124", a2+" : « chain_id 2124 »")
	r.Comparer(f, v, "registry", d.Get("registry").S(), k.Registre, a2+" : « les 20 premiers octets de SHA-256(UTF-8(\"noortrace/vecteurs/ct3/registre\")) »")
	for n := 1; n <= 2; n++ {
		r.Comparer(f, v, fmt.Sprintf("sets.%d", n), d.Get("sets").Get(fmt.Sprint(n)).S(), k.Jeux[n], a2+" : jeu n = 20 premiers octets de SHA-256(UTF-8(\"noortrace/vecteurs/ct3/jeu/<n>\"))")
	}
	lab := d.Get("labels")
	for _, cv := range [][2]string{{"registry", "noortrace/vecteurs/ct3/registre"}, {"set", "noortrace/vecteurs/ct3/jeu/<n>"}, {"block", "noortrace/vecteurs/ct3/bloc/<h>"}, {"request", "noortrace/vecteurs/ct3/demande/<k>"}, {"event", "noortrace/vecteurs/ct3/evenement/<seq>"}} {
		r.Comparer(f, v, "labels."+cv[0], lab.Get(cv[0]).S(), cv[1], a2)
	}
	r.Comparer(f, v, "mnemonic", d.Get("mnemonic").S(), mnemoniqueHardhat, a2+" : « mnémonique Hardhat (test test … junk) » ; texte complet confirmé par les adresses qu'il dérive")
	comptes := map[int]*Value{}
	for _, a := range d.Get("accounts").Arr {
		if i, ok := EntierJSON(a.Get("index")); ok {
			comptes[int(i)] = a
		}
	}
	for i := 1; i <= 4; i++ {
		a := comptes[i]
		if a == nil {
			r.Erreur("%s : compte %d absent", v, i)
			continue
		}
		g := fmt.Sprintf("accounts[%d]", i)
		r.Comparer(f, v, g+".derivation_path", a.Get("derivation_path").S(), fmt.Sprintf("m/44'/60'/0'/0/%d", i), a2+" : m/44'/60'/0'/0/i")
		r.Comparer(f, v, g+".private_key", a.Get("private_key").S(), Hex0x(k.Prives[k.Comptes[i]]), a2+" : BIP-39 puis BIP-32 sur le mnémonique")
		r.Comparer(f, v, g+".address", a.Get("address").S(), k.Comptes[i], a2+" : adresse de la clé dérivée")
		r.Comparer(f, v, g+".address (texte de A.2)", adressesA2[i], k.Comptes[i], a2+" : adresses imprimées")
	}
	req := d.Get("requester")
	r.Comparer(f, v, "requester.launched_by", req.Get("launched_by").S(), k.Demandeur, a2+" : « u.martin@assureur-demo.example, qui détient le compte 3 »")
	r.Comparer(f, v, "requester.account", Compact(req.Get("account")), "3", a2)
	r.Comparer(f, v, "base_instant", d.Get("base_instant").S(), "2026-11-12T09:00:00.000Z", a2+" : « Instant de base 2026-11-12T09:00:00.000Z »")
	r.Comparer(f, v, "expire_after_ms", Compact(d.Get("expire_after_ms")), "3600000", "CT-3 annexe A.4 : « 3 600 000, sauf pour un cas qui exige une autre valeur »")
}

// ---------------------------------------------------------------- schémas

func (c *Contexte) validerSchema(fichier, ref string, inst *Value, fondement string) bool {
	errs := c.Sch.Valider(ref, inst)
	return c.R.Exiger(FamSchemas, fichier, "conforme à "+raccourcirRef(ref), len(errs) == 0, strings.Join(premiers(errs, 3), " ; "), fondement)
}

func raccourcirRef(ref string) string {
	ref = strings.Replace(ref, "https://noortrace.example/schemas/v0/", "", 1)
	return ref
}

func premiers(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("… (%d erreurs)", len(s)))
	}
	return s
}

func familleSchemas(c *Contexte) {
	ex := "CT-3 EX-A.3"
	for _, fic := range c.fichiers("politiques/*.json") {
		if v, ok := c.lire(fic); ok {
			c.validerSchema(fic, RefPolitique, v, ex)
		}
	}
	if v, ok := c.lire("acceptation/politique.json"); ok {
		c.validerSchema("acceptation/politique.json", RefPolitique, v, "CT-3 A.5 : « une politique : quelques règles sur un même outil (trois dans les vecteurs) et sa règle par défaut (section 4) »")
	}
	if v, ok := c.lire("politiques-invalides/attendu.json"); ok {
		c.validerSchema("politiques-invalides/attendu.json", RefTicket+"#/$defs/attendu_politiques_invalides", v, ex)
	}
	for _, fic := range c.fichiers("evaluation/*.json") {
		if v, ok := c.lire(fic); ok {
			c.validerSchema(fic, RefTicket+"#/$defs/fichier_evaluation", v, ex)
		}
	}
	for _, fic := range c.fichiers("candidats/*.json") {
		if v, ok := c.lire(fic); ok {
			c.validerSchema(fic, RefTicket+"#/$defs/fichier_candidats", v, ex)
		}
	}
	if v, ok := c.lire("acceptation-attendu.json"); ok {
		c.validerSchema("acceptation-attendu.json", RefTicket+"#/$defs/attendu_acceptation", v, ex)
	}
	for _, fic := range c.fichiers("acceptation/cas/*.json") {
		v, ok := c.lire(fic)
		if !ok {
			continue
		}
		cles := []string{}
		for _, m := range v.Obj {
			cles = append(cles, m.Key)
		}
		c.R.Comparer(FamSchemas, fic, "membres", strings.Join(cles, ","), "id,request", "CT-3 A.5 : « { \"id\", \"request\" } : la requête evaluer, sans attendu »")
		c.validerSchema(fic+" (request)", RefTicket+"#/$defs/requete_evaluer", v.Get("request"), "CT-3 A.5, 12.3")
	}
	for _, fic := range c.fichiers("tickets/*.json") {
		v, ok := c.lire(fic)
		if !ok {
			continue
		}
		c.validerSchema(fic, RefTicket+"#/$defs/trace", v, ex+" (les remises et fenêtres attendues comprises : $defs/attendu_pas)")
	}
	for _, fic := range append(c.fichiers("decisions/valides/*.json"), c.fichiers("decisions/invalides/*.json")...) {
		v, ok := c.lire(fic)
		if !ok {
			continue
		}
		c.validerSchema(fic, RefTicket+"#/$defs/cas_remise", v, ex)
		if strings.HasPrefix(fic, "decisions/valides/") {
			c.validerSchema(fic+" (remise)", RefTicket+"#/$defs/remise", v.Get("remise"), ex+" : « leurs remises valides par #/$defs/remise »")
		}
	}
}

// ------------------------------------------------------------- politiques

// politiqueValide lit, valide et modélise une politique (EX-4.2), sous un
// environnement de développement et expire_after_ms de 3 600 000.
func (c *Contexte) politiqueValide(rel string) (*Politique, *Value, bool) {
	v, ok := c.lire(rel)
	if !ok {
		return nil, nil, false
	}
	errs, _ := ValiderPolitique(c.Sch, v, "developpement", 3600000)
	if len(errs) > 0 {
		c.R.Erreur("%s : politique refusée par EX-4.2 : %v", rel, errs)
		return nil, v, false
	}
	return LirePolitique(v), v, true
}

// blocJSON extrait de la spécification le bloc ```json qui suit le
// marqueur donné.
func blocJSON(spec, marqueur string) (*Value, error) {
	i := strings.Index(spec, marqueur)
	if i < 0 {
		return nil, fmt.Errorf("marqueur %q absent de la spécification", marqueur)
	}
	reste := spec[i:]
	d := strings.Index(reste, "```json\n")
	if d < 0 {
		return nil, fmt.Errorf("bloc json absent après %q", marqueur)
	}
	reste = reste[d+len("```json\n"):]
	e := strings.Index(reste, "\n```")
	if e < 0 {
		return nil, fmt.Errorf("bloc json non fermé après %q", marqueur)
	}
	return ParseJSON([]byte(reste[:e]))
}

// ordreInverse dit si chaque objet de b a les membres de l'objet
// correspondant de a en ordre inverse.
func ordreInverse(a, b *Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindArray:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !ordreInverse(a.Arr[i], b.Arr[i]) {
				return false
			}
		}
	case KindObject:
		n := len(a.Obj)
		if n != len(b.Obj) {
			return false
		}
		for i := range a.Obj {
			if a.Obj[i].Key != b.Obj[n-1-i].Key || !ordreInverse(a.Obj[i].Val, b.Obj[n-1-i].Val) {
				return false
			}
		}
	}
	return true
}

func famillePolitiques(c *Contexte) {
	const f = FamPolitiques
	for _, fic := range c.fichiers("politiques/*.json") {
		v, ok := c.lire(fic)
		if !ok {
			continue
		}
		errs, det := ValiderPolitique(c.Sch, v, "developpement", 3600000)
		obt := "aucune erreur"
		if len(errs) > 0 {
			obt = fmt.Sprintf("%v %v", errs, premiers(det, 3))
		}
		c.R.Comparer(f, fic, "validation EX-4.2 (developpement, expire_after_ms 3600000)", "aucune erreur", obt, "CT-3 A.4 : « politiques/<nom>.json : un document valide »")
	}
	if c.Spec != "" {
		ex, err := blocJSON(c.Spec, "<!-- schema: politique-approbation -->")
		if err != nil {
			c.R.Erreur("spécification : %v", err)
		} else if v, ok := c.lire("politiques/assureur.json"); ok {
			c.R.ComparerJSON(f, "politiques/assureur.json", "égale à l'exemple de CT-3 §4.3", ex, v, "INDEX.md et §4.3 : « Exemple complet de CT-3 §4.3, même valeur JSON »")
		}
	} else {
		c.R.HorsPerimetre(f, "politiques/assureur.json", "égale à l'exemple de CT-3 §4.3", "spécification introuvable à côté des vecteurs")
	}
	a, ok1 := c.lire("politiques/assureur.json")
	b, ok2 := c.lire("politiques/assureur-permute.json")
	if ok1 && ok2 {
		c.R.ComparerJSON(f, "politiques/assureur-permute.json", "même valeur que assureur.json", a, b, "CT-3 EX-6.6, AP-17")
		c.R.Exiger(f, "politiques/assureur-permute.json", "membres de chaque objet en ordre inverse", ordreInverse(a, b), "ordre non inversé", "AP-17 : « quel que soit l'ordre des membres des objets […] dans le document »")
	}
}

// --------------------------------------------------- politiques refusées

func erreursJSON(errs []ErreurPolitique) *Value {
	t := Tableau()
	for _, e := range errs {
		p := Nul()
		if e.Pointeur != nil {
			p = Chaine(*e.Pointeur)
		}
		t.Arr = append(t.Arr, Objet("code", Chaine(e.Code), "pointer", p))
	}
	return t
}

func famillePolitiquesInvalides(c *Contexte) {
	const f = FamInvalides
	att, ok := c.lire("politiques-invalides/attendu.json")
	if !ok {
		return
	}
	vus := map[string]bool{}
	for _, cas := range att.Get("cases").Arr {
		fic := "politiques-invalides/" + cas.Get("file").S()
		vus[fic] = true
		v, ok := c.lire(fic)
		if !ok {
			continue
		}
		e, _ := EntierJSON(cas.Get("expire_after_ms"))
		errs, det := ValiderPolitique(c.Sch, v, cas.Get("environment").S(), e)
		if !c.R.ComparerJSON(f, fic, "errors (liste complète, triée par pointer puis code)", cas.Get("errors"), erreursJSON(errs), "CT-3 EX-4.2 et A.4") && len(det) > 0 {
			c.R.Note("%s : non-conformités au schéma relevées : %s", fic, strings.Join(premiers(det, 4), " ; "))
		}
	}
	for _, fic := range c.fichiers("politiques-invalides/*.json") {
		if fic != "politiques-invalides/attendu.json" && !vus[fic] {
			c.R.Erreur("%s : fichier sans attendu dans attendu.json", fic)
		}
	}
	if c.Spec != "" {
		ex, err := blocJSON(c.Spec, "<!-- schema: ticket/attendu_politiques_invalides -->")
		if err == nil {
			for _, ce := range ex.Get("cases").Arr {
				for _, ca := range att.Get("cases").Arr {
					if ca.Get("file").S() == ce.Get("file").S() {
						c.R.ComparerJSON(f, "politiques-invalides/attendu.json", "cas "+ce.Get("file").S()+" égal à l'exemple de CT-3 A.4", ce, ca, "CT-3 A.4, exemple de politiques-invalides/attendu.json")
					}
				}
			}
		}
	}
}

// -------------------------------------------------------------- évaluation

func fenetresJSON(f []*Fenetre) *Value {
	t := Tableau()
	for _, w := range f {
		t.Arr = append(t.Arr, w.JSON())
	}
	return t
}

func familleEvaluation(c *Contexte) {
	const f = FamEvaluation
	for _, fic := range c.fichiers("evaluation/*.json") {
		d, ok := c.lire(fic)
		if !ok {
			continue
		}
		p, _, ok := c.politiqueValide(d.Get("policy").S())
		if !ok {
			continue
		}
		pv := d.Get("policy_version").S()
		for _, cas := range d.Get("cases").Arr {
			id := fic + " " + cas.Get("id").S()
			t, err := LireInstant(cas.Get("t").S())
			if err != nil {
				c.R.Erreur("%s : %v", id, err)
				continue
			}
			var fs []*Fenetre
			for _, w := range cas.Get("windows").Arr {
				fw, err := LireFenetre(w)
				if err != nil {
					c.R.Erreur("%s : %v", id, err)
					continue
				}
				fs = append(fs, fw)
			}
			req := cas.Get("request")
			if cpv := req.Get("code").Get("policy_version").S(); cpv != pv {
				c.R.Note("%s : code.policy_version %q diffère de la version en vigueur du fichier %q", id, cpv, pv)
			}
			s := Evaluer(p, pv, DemandeDe(req), fs, t, nil)
			if s.Consommee >= 0 {
				fs[s.Consommee].Restant--
			}
			exp := cas.Get("expected")
			c.R.Comparer(f, id, "rule", exp.Get("rule").S(), s.Regle, "CT-3 6.2 (EVALUER), EX-6.2, EX-6.4")
			c.R.Comparer(f, id, "decision", exp.Get("decision").S(), s.Decision, "CT-3 6.2 (EVALUER), EX-4.9, EX-6.2")
			c.R.ComparerJSON(f, id, "opening", exp.Get("opening"), s.Ouverture.JSON(), "CT-3 6.2 : « o := si ouvrant : { la portée K de d pour r* (EX-5.2), r*.window.duration_ms, r*.window.max_calls } ; null sinon »")
			c.R.ComparerJSON(f, id, "windows (après)", exp.Get("windows"), fenetresJSON(fs), "CT-3 EX-5.5 : « Si cette issue est celle que l'évaluation retient (6.2), restant diminue de 1 ; sinon la fenêtre n'est pas consommée »")
		}
	}
}

// --------------------------------------------------------------- candidats

func familleCandidats(c *Contexte) {
	const f = FamCandidats
	for _, fic := range c.fichiers("candidats/*.json") {
		d, ok := c.lire(fic)
		if !ok {
			continue
		}
		p, _, ok := c.politiqueValide(d.Get("policy").S())
		if !ok {
			continue
		}
		for _, cas := range d.Get("cases").Arr {
			got := Candidats(p, chaines(cas.Get("tools")))
			c.R.ComparerJSON(f, fic+" "+cas.Get("id").S(), "approval_candidates", cas.Get("approval_candidates"), TableauChaines(got), "CT-3 EX-4.11 (CANDIDATS)")
		}
	}
	// Exemple de 4.12 sur la politique de 4.3, lu dans le texte.
	if c.Spec != "" {
		if p, _, ok := c.politiqueValide("politiques/assureur.json"); ok {
			l := []string{"crm.claims.get", "crm.claims.delete", "documents.search", "mail.send", "sap.payments.create", "sap.payments.list"}
			got := Candidats(p, l)
			c.R.Comparer(f, "CT-3 §4.12 (exemple)", "liste", "crm.claims.delete, mail.send, sap.payments.create, sap.payments.list", strings.Join(got, ", "), "CT-3 4.12 : « la liste est crm.claims.delete, mail.send, sap.payments.create, sap.payments.list »")
		}
	}
}

// ----------------------------------------------------------- acceptation

// couverture relève, pour l'épreuve, les faits qu'EX-A.4 exige.
type couverture struct {
	absent, autreType, egalite bool
}

func (o *couverture) PointeurNonResolu(string)        { o.absent = true }
func (o *couverture) TypeDifferent(string, string)    { o.autreType = true }
func (o *couverture) EgaliteNumerique(string, string) { o.egalite = true }

var reCas = regexp.MustCompile(`^cas-(0[1-9]|10)$`)

func familleAcceptation(c *Contexte) {
	const f = FamAcceptation
	att, ok := c.lire("acceptation-attendu.json")
	if !ok {
		return
	}
	c.R.Comparer(f, "acceptation-attendu.json", "policy", att.Get("policy").S(), "acceptation/politique.json", "CT-3 A.5")
	p, _, ok := c.politiqueValide("acceptation/politique.json")
	if !ok {
		return
	}
	memesOutils := len(p.Regles) >= 1
	for _, r := range p.Regles {
		if listeChaines(r.Outils) != listeChaines(p.Regles[0].Outils) {
			memesOutils = false
		}
	}
	c.R.Exiger(f, "acceptation/politique.json", "des règles qui sélectionnent toutes les mêmes outils", memesOutils, fmt.Sprintf("%d règle(s)", len(p.Regles)), "CT-3 A.5 : « une politique : quelques règles sur un même outil (trois dans les vecteurs) et sa règle par défaut »")
	cov := &couverture{}
	sorties := map[string]int{}
	autreOutil := false
	for _, e := range att.Get("expected").Arr {
		id := e.Get("id").S()
		cas, ok := c.lire("acceptation/cas/" + id + ".json")
		if !ok {
			continue
		}
		req := cas.Get("request")
		d := DemandeDe(req)
		sel := false
		for _, r := range p.Regles {
			if Selectionne(r.Outils, d.Outil) {
				sel = true
			}
		}
		if !sel {
			autreOutil = true
		}
		s := Evaluer(p, req.Get("code").Get("policy_version").S(), d, nil, 0, cov)
		sorties[s.Decision]++
		c.R.Comparer(f, "acceptation/cas/"+id+".json", "rule", e.Get("rule").S(), s.Regle, "CT-3 6.2, A.5 (F vide)")
		c.R.Comparer(f, "acceptation/cas/"+id+".json", "decision", e.Get("decision").S(), s.Decision, "CT-3 6.2, A.5 (F vide)")
	}
	fond := "CT-3 EX-A.4"
	for _, x := range []string{"autorise", "a_approuver", "refuse"} {
		c.R.Exiger(f, "acceptation", "sortie "+x+" au moins deux fois", sorties[x] >= 2, fmt.Sprintf("%d fois", sorties[x]), fond)
	}
	c.R.Exiger(f, "acceptation", "égalité exacte au seuil d'une comparaison", cov.egalite, "aucune", fond)
	c.R.Exiger(f, "acceptation", "argument absent", cov.absent, "aucun", fond)
	c.R.Exiger(f, "acceptation", "argument d'un autre type", cov.autreType, "aucun", fond)
	c.R.Exiger(f, "acceptation", "autre outil que celui des règles", autreOutil, "aucun", fond)
	sansFenetre := true
	for _, r := range p.Regles {
		if r.Niveau == "fenetre" {
			sansFenetre = false
		}
	}
	c.R.Exiger(f, "acceptation/politique.json", "aucune règle fenetre (aucun cas ne dépend d'une fenêtre)", sansFenetre, "règle fenetre présente", fond+" : « Aucun cas ne dépend d'une fenêtre ni d'un ticket »")
	// Fichiers remis aux relecteurs (A.5, EX-A.5).
	fics := c.fichiers("acceptation/cas/*.json")
	ok10 := len(fics) == 10
	for _, fic := range fics {
		if !reCas.MatchString(strings.TrimSuffix(filepath.Base(fic), ".json")) {
			ok10 = false
		}
	}
	c.R.Exiger(f, "acceptation/cas", "dix cas cas-01 à cas-10", ok10, fmt.Sprint(fics), "CT-3 A.5")
	if g, ok := c.lire("acceptation/gabarit-reponse.json"); ok {
		forme := g.Kind == KindObject && len(g.Obj) == 3 && g.Has("role") && g.Has("reviewer") && g.Get("answers").Kind == KindArray
		if forme {
			for _, a := range g.Get("answers").Arr {
				if a.Kind != KindObject || len(a.Obj) != 2 || !a.Has("id") || !a.Has("decision") {
					forme = false
				}
			}
		}
		c.R.Exiger(f, "acceptation/gabarit-reponse.json", "forme { role, reviewer, answers: [ { id, decision } ] }", forme, Compact(g), "CT-3 A.5")
	}
	_, err := os.Stat(filepath.Join(c.Racine, "acceptation", "consigne.md"))
	c.R.Exiger(f, "acceptation/consigne.md", "présent", err == nil, "absent", "CT-3 A.5, EX-A.5")
	_, err = os.Stat(filepath.Join(c.Racine, "acceptation", "acceptation-attendu.json"))
	c.R.Exiger(f, "acceptation/", "attendu hors du répertoire remis", err != nil, "acceptation/acceptation-attendu.json présent", "CT-3 A.5 : « les décisions attendues sont dans un fichier que les relecteurs ne voient pas »")
	c.R.HorsPerimetre(f, "acceptation/consigne.md", "contenu de la consigne (EX-A.5)", "texte libre, non recalculable")
}
