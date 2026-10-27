// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/dossier.go).

// Dossier de preuve v0 (CT-1 §11) : index dossier.json, fichiers compagnons
// et les contrôles D-1, D-2, E-1 à E-11, C-1 à C-3, M-1 à M-3, P-1 à P-5,
// A-1 à A-4, et, révision 0.3, K-1 à K-6 sur la treizième partie facultative
// points-de-controle.json (K-7 à K-9, qui réemploient les vérifications de
// CT-6, sont hors périmètre quand l'ancre n'est pas nulle ; index à douze
// parties ou partie absente avec raison : les neuf sont non exécutées pour une
// raison admise, §11.4), et, révision 0.4, AT-1 à AT-7 sur la quatorzième
// partie facultative attestation-perimetre.json (attestation.go ; sans effet
// sur la validité du dossier). E-9 (EIP-191) est hors périmètre de ce vérificateur ;
// les parties réservées à CT-4 et CT-5 rendent les contrôles 4, 5 et 8 non
// exécutés et bornent le verdict (§11.3).

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Partie est une entrée de l'index.
type Partie struct {
	Name, File, SHA256, Reason string
	Present                    bool
}

// partiesAttendues sont les douze parties, dans l'ordre imposé, puis la
// treizième, facultative (révision 0.3), et la quatorzième, facultative,
// déclarée seulement après la treizième (révision 0.4).
var partiesAttendues = []struct{ name, file string }{
	{"evenement", "evenement.json"},
	{"voisins", "voisins.json"},
	{"chemin", "chemin.json"},
	{"manifeste", "manifeste.json"},
	{"manifeste_sig", "manifeste.sig"},
	{"cles", "cles.json"},
	{"approbations", "approbations.json"},
	{"jeton_rfc3161", "jeton-rfc3161.der"},
	{"preuve_ots", "preuve.ots"},
	{"registre", "registre.json"},
	{"certificat_commit", "certificat-commit.json"},
	{"validateurs", "validateurs.json"},
	{"points_de_controle", "points-de-controle.json"},
	{"attestation_perimetre", "attestation-perimetre.json"},
}

// idsK sont les vérifications de la treizième partie (§11.4, révision 0.3).
var idsK = []string{"K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"}

// Dossier est le résultat de la vérification d'un répertoire.
type Dossier struct {
	Dir          string
	Index        *Value
	Parties      map[string]*Partie
	Evenement    *Value
	Voisins      *Value
	Chemin       *Value
	Manifeste    *Value
	ManifesteSig *Value
	Cles         *JeuCles
	Approbations *Value
	Resultats    *Resultats
	Bornes       []string
	admis        map[string]bool // contrôles non exécutés pour une raison admise (§11.4)
	// Perimetre porte les statuts de AT-1 à AT-7 (révision 0.4), nil quand
	// la quatorzième partie n'est pas déclarée présente ; ils n'entrent ni
	// dans Resultats ni dans la validité du dossier.
	Perimetre []*StatutAT
	// clesExploitable : cles.json lu et conforme à la première partie de
	// E-8 (schéma, org_id et journal_id, unicité, validités), prérequis d'AT-6.
	clesExploitable bool
}

// nonExecuteAdmis marque un contrôle non exécuté pour une raison que §11.4 admet.
func (d *Dossier) nonExecuteAdmis(id, raison string) {
	d.Resultats.NonExecute(id, raison)
	if d.admis == nil {
		d.admis = map[string]bool{}
	}
	d.admis[id] = true
}

// lireJSON lit et analyse un fichier JSON du dossier, qui doit être un objet
// JSON ; toute défaillance (fichier illisible, texte qui n'est pas du JSON,
// littéral null, tableau, nombre) est imputée au contrôle qui porte la partie
// (CT-1 §11.4), sauf la forme canonique impossible, imputée à E-2. La partie
// est alors inexploitable : nil, et les contrôles qui en dépendent sont non
// exécutés sans raison admise.
func (d *Dossier) lireJSON(nom, controle string) *Value {
	octets, err := os.ReadFile(filepath.Join(d.Dir, nom))
	if err != nil {
		d.Resultats.Echec(controle, "%s illisible : %v", nom, err)
		return nil
	}
	v, err := ParseJSON(octets)
	if err != nil {
		var ej *ErreurJSON
		if errors.As(err, &ej) && ej.Canonique {
			d.Resultats.Echec("E-2", "%s : %v", nom, err)
		} else {
			d.Resultats.Echec(controle, "%s : %v", nom, err)
		}
		return nil
	}
	if v.Kind != KindObject {
		d.Resultats.Echec(controle, "%s : objet JSON attendu, reçu %s ; la partie est inexploitable", nom, v.Kind)
		return nil
	}
	return v
}

// NonExecutesNonAdmis rend les contrôles non exécutés qu'un dossier valide ne
// peut pas avoir (CT-1 §11.4) : tous, sauf A-4 (événement de demande hors du
// dossier), sauf A-2 et A-3 quand approbations.json est déclaré absent avec
// raison, sauf les contrôles des parties réservées à CT-4 et CT-5, et sauf,
// révision 0.3, les K- non exécutées pour une raison admise (index à douze
// parties, partie absente avec raison, ancre nulle, événement last_seq hors du
// dossier).
func (d *Dossier) NonExecutesNonAdmis() []string {
	p := d.Parties["approbations"]
	absente := p != nil && !p.Present && strings.TrimSpace(p.Reason) != ""
	var out []string
	for _, c := range d.Resultats.Liste() {
		if c.Etat != EtatNonExecute {
			continue
		}
		switch {
		case c.ID == "A-4":
		case absente && (c.ID == "A-2" || c.ID == "A-3"):
		case strings.HasSuffix(c.ID, "-*"):
		case d.admis[c.ID]:
		default:
			out = append(out, c.ID)
		}
	}
	return out
}

// Valide dit si le dossier est valide au sens de CT-1 §11.4 : aucun contrôle
// en échec et aucun contrôle non exécuté sans raison admise.
func (d *Dossier) Valide() bool {
	return d.Resultats.Valide() && len(d.NonExecutesNonAdmis()) == 0
}

// VerifierDossier exécute tous les contrôles applicables sur un répertoire.
func VerifierDossier(dir string) *Dossier {
	d := &Dossier{Dir: dir, Resultats: NouveauxResultats(), Parties: map[string]*Partie{}}
	r := d.Resultats

	// D-1 : index
	d.Index = d.lireJSON("dossier.json", "D-1")
	if d.Index == nil {
		return d
	}
	d.controlerIndex()

	// D-2 : empreintes des fichiers
	d.controlerEmpreintes()

	// Pièces
	d.Evenement = d.lireJSON("evenement.json", "E-1")
	if d.Evenement == nil {
		return d
	}
	if seq, ok := entierDe(d.Index, "event", "seq"); !ok || seq != Seq(d.Evenement) {
		r.Echec("D-1", "event.seq de l'index ≠ seq de evenement.json (%d)", Seq(d.Evenement))
	}
	if h := chaineDe(d.Index, "event", "hash"); h != chaineDe(d.Evenement, "hash") {
		r.Echec("D-1", "event.hash de l'index ≠ hash de evenement.json")
	}
	for _, k := range []string{"org_id", "journal_id"} {
		if a, b := chaineDe(d.Index, k), chaineDe(d.Evenement, k); a != b {
			r.Echec("D-1", "%s de l'index ≠ %s de evenement.json", k, k)
		}
	}
	r.Passe("D-1")

	if cv := d.lireJSON("cles.json", "E-8"); cv != nil {
		jeu, mq := ChargerCles(cv)
		for _, m := range mq {
			r.Echec("E-8", "cles.json : %s", m)
		}
		d.Cles = jeu
		d.clesExploitable = jeu != nil && len(mq) == 0
		if jeu != nil && (jeu.OrgID != chaineDe(d.Evenement, "org_id") || jeu.JournalID != chaineDe(d.Evenement, "journal_id")) {
			r.Echec("E-8", "cles.json : org_id ou journal_id différents de ceux de l'événement")
			d.clesExploitable = false
		}
	}

	// E-1 à E-11 sur l'événement prouvé
	r.Fusionner(ControlerEvenement(d.Evenement, d.Cles), "evenement.json")

	// Voisins : C-1 à C-3, P-3
	d.Voisins = d.lireJSON("voisins.json", "C-1")
	d.controlerVoisins()

	// Manifeste et signature : P-1 à P-5
	d.Manifeste = d.lireJSON("manifeste.json", "P-1")
	d.ManifesteSig = d.lireJSON("manifeste.sig", "P-5")
	d.controlerManifeste()

	// Chemin : M-1 à M-3
	d.Chemin = d.lireJSON("chemin.json", "M-2")
	d.controlerChemin()

	// Approbations : A-1 à A-4
	d.controlerApprobations()

	// Treizième partie (révision 0.3) : K-1 à K-9
	d.controlerPointsDeControle()

	// Quatorzième partie (révision 0.4) : AT-1 à AT-7, sans effet sur le verdict
	d.controlerAttestation()

	// Borne du verdict (§11.3)
	d.enoncerBornes()
	return d
}

func (d *Dossier) controlerIndex() {
	r := d.Resultats
	idx := d.Index
	m := &manquements{}
	if !m.clesExactes(idx, "dossier", []string{"version", "event", "org_id", "journal_id", "generated_at", "parts"}) {
		for _, x := range m.liste {
			r.Echec("D-1", "%s", x)
		}
		return
	}
	if ver := idx.Get("version"); ver.Kind != KindNumber {
		m.add("dossier.version", "constante 0 attendue")
	} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
		m.add("dossier.version", "constante 0 attendue, reçu %s", ver.Num)
	}
	if ev := idx.Get("event"); m.clesExactes(ev, "dossier.event", []string{"seq", "hash"}) {
		m.entier(ev.Get("seq"), "dossier.event.seq", 1, EntierSurMax)
		m.hex(ev.Get("hash"), "dossier.event.hash", 32, false)
	}
	m.hex(idx.Get("org_id"), "dossier.org_id", 32, false)
	m.hex(idx.Get("journal_id"), "dossier.journal_id", 32, false)
	m.horodatage(idx.Get("generated_at"), "dossier.generated_at")
	parts := idx.Get("parts")
	if parts.Kind != KindArray {
		m.add("dossier.parts", "tableau attendu")
	} else {
		if len(parts.Arr) < 12 || len(parts.Arr) > 14 {
			m.add("dossier.parts", "douze parties attendues (treize avec points-de-controle.json, révision 0.3 ; quatorze avec attestation-perimetre.json, révision 0.4), %d déclarées", len(parts.Arr))
		}
		for i, p := range parts.Arr {
			ch := fmt.Sprintf("dossier.parts[%d]", i)
			if !m.clesExactes(p, ch, []string{"name", "file", "sha256", "present", "reason_if_absent"}) {
				continue
			}
			pa := &Partie{Name: chaineDe(p, "name"), File: chaineDe(p, "file")}
			if i < len(partiesAttendues) {
				if pa.Name != partiesAttendues[i].name || pa.File != partiesAttendues[i].file {
					m.add(ch, "partie %q (%s) attendue à cette position, reçu %q (%s)", partiesAttendues[i].name, partiesAttendues[i].file, pa.Name, pa.File)
				}
			}
			pr := p.Get("present")
			if pr.Kind != KindBool {
				m.add(ch+".present", "booléen attendu")
				continue
			}
			pa.Present = pr.Bool
			sh, rs := p.Get("sha256"), p.Get("reason_if_absent")
			if pa.Present {
				if s, ok := m.hex(sh, ch+".sha256", 32, false); ok {
					pa.SHA256 = s
				}
				if !rs.IsNull() {
					m.add(ch+".reason_if_absent", "null attendu pour une partie présente")
				}
				if i >= 7 && i <= 11 {
					r.NonExecute(controleDePartie(pa.Name), fmt.Sprintf("partie %s présente mais spécifiée par CT-4/CT-5 : non vérifiée ici", pa.Name))
				}
			} else {
				if !sh.IsNull() {
					m.add(ch+".sha256", "null attendu pour une partie absente")
				}
				if s, ok := m.chaine(rs, ch+".reason_if_absent", 1, 256, false); ok {
					pa.Reason = s
				}
				if i < 6 {
					m.add(ch, "les six premières parties sont toujours présentes")
				}
			}
			d.Parties[pa.Name] = pa
		}
	}
	for _, x := range m.liste {
		r.Echec("D-1", "%s", x)
	}
}

// controleDePartie rend l'identifiant de contrôle qu'une partie réservée
// alimente (numérotations T-, O-, R- annoncées par CT-5 et CT-4).
func controleDePartie(nom string) string {
	switch nom {
	case "jeton_rfc3161":
		return "T-*"
	case "preuve_ots":
		return "O-*"
	}
	return "R-*"
}

func (d *Dossier) controlerEmpreintes() {
	r := d.Resultats
	for _, pa := range partiesAttendues {
		p := d.Parties[pa.name]
		if p == nil {
			continue
		}
		chemin := filepath.Join(d.Dir, p.File)
		octets, err := os.ReadFile(chemin)
		if p.Present {
			if err != nil {
				r.Echec("D-2", "%s déclaré présent mais illisible : %v", p.File, err)
				continue
			}
			if got := Hex0x(SHA256(octets)); p.SHA256 != "" && got != p.SHA256 {
				r.Echec("D-2", "%s : SHA-256 du fichier %s ≠ %s déclaré", p.File, got, p.SHA256)
			}
		} else {
			if err == nil {
				r.Echec("D-2", "%s déclaré absent mais présent dans le répertoire", p.File)
			}
			if strings.TrimSpace(p.Reason) == "" {
				r.Echec("D-2", "%s absent sans raison", p.File)
			}
		}
	}
	r.Passe("D-2")
}

func (d *Dossier) controlerVoisins() {
	r := d.Resultats
	ev := d.Evenement
	seq := Seq(ev)
	etiquetteEv := fmt.Sprintf("evenement.json (seq %d)", seq)
	if d.Voisins == nil {
		r.NonExecute("C-1", "voisins.json illisible")
		r.NonExecute("C-2", "voisins.json illisible")
		r.NonExecute("C-3", "voisins.json illisible")
		return
	}
	m := &manquements{}
	if !m.clesExactes(d.Voisins, "voisins", []string{"version", "previous", "next"}) {
		for _, x := range m.liste {
			r.Echec("C-1", "%s", x)
		}
		return
	}
	if ver := d.Voisins.Get("version"); ver.Kind != KindNumber || ver.Num != "0" {
		r.Echec("C-1", "voisins.version : constante 0 attendue")
	}
	prev, next := d.Voisins.Get("previous"), d.Voisins.Get("next")
	if prev.IsNull() != (seq == 1) {
		r.Echec("C-1", "previous %s pour seq %d (null si et seulement si seq = 1)", sorteNulle(prev), seq)
	}
	if !prev.IsNull() {
		r.Fusionner(ControlerEvenement(prev, d.Cles), "voisins.previous")
		ControlerPaire(r, prev, ev, fmt.Sprintf("previous (seq %d) → %s", Seq(prev), etiquetteEv))
	} else {
		ControlerPremier(r, ev, etiquetteEv)
	}
	if !next.IsNull() {
		r.Fusionner(ControlerEvenement(next, d.Cles), "voisins.next")
		ControlerPaire(r, ev, next, fmt.Sprintf("%s → next (seq %d)", etiquetteEv, Seq(next)))
	}
	r.Passe("C-1")
	r.Passe("C-2")
	r.Passe("C-3")
}

func sorteNulle(v *Value) string {
	if v.IsNull() {
		return "null"
	}
	return "non null"
}

func (d *Dossier) controlerManifeste() {
	r := d.Resultats
	ev := d.Evenement
	if d.Manifeste == nil {
		for _, id := range []string{"P-1", "P-2", "P-3", "P-4", "P-5", "M-3"} {
			r.NonExecute(id, "manifeste.json illisible")
		}
		return
	}
	r.Fusionner(ControlerManifeste(d.Manifeste, d.ManifesteSig, d.Cles), "")
	m := LireManifeste(d.Manifeste)
	if m.OrgID != chaineDe(ev, "org_id") || m.JournalID != chaineDe(ev, "journal_id") {
		r.Echec("P-1", "org_id ou journal_id du manifeste différents de ceux de l'événement")
	}
	// P-2
	seq := Seq(ev)
	if seq < m.FirstSeq || seq > m.LastSeq {
		r.Echec("P-2", "seq %d hors de [first_seq %d, last_seq %d]", seq, m.FirstSeq, m.LastSeq)
	}
	if ts, ok := Ts(ev); ok && !m.Contient(ts) {
		r.Echec("P-2", "ts %s hors de [period_start %d, period_end %d)", FormaterHorodatage(ts), m.PeriodStart, m.PeriodEnd)
	}
	r.Passe("P-2")
	// P-3 : un voisin dans la période par seq y est aussi par ts ; un voisin hors
	// période est adjacent, avant period_start (previous) ou à partir de
	// period_end (next) ; sinon le manifeste a tronqué sa période (§7.2).
	if d.Voisins != nil {
		debut := time.UnixMilli(m.PeriodStart * 1000).UTC()
		fin := time.UnixMilli(m.PeriodEnd * 1000).UTC()
		for _, nom := range []string{"previous", "next"} {
			v := d.Voisins.Get(nom)
			if v == nil || v.IsNull() {
				continue
			}
			vs := Seq(v)
			ts, ok := Ts(v)
			if vs >= m.FirstSeq && vs <= m.LastSeq {
				if ok && !m.Contient(ts) {
					r.Echec("P-3", "voisin %s (seq %d) dans la période par seq mais ts %s hors de la période", nom, vs, FormaterHorodatage(ts))
				}
			} else if vs != m.FirstSeq-1 && vs != m.LastSeq+1 {
				r.Echec("P-3", "voisin %s (seq %d) hors période sans être first_seq - 1 ni last_seq + 1", nom, vs)
			} else if ok && ((nom == "previous" && !ts.Before(debut)) || (nom == "next" && ts.Before(fin))) {
				r.Echec("P-3", "voisin %s (seq %d) hors de l'intervalle de seq du manifeste mais horodaté %s, dans la période : manifeste tronqué", nom, vs, FormaterHorodatage(ts))
			}
		}
		r.Passe("P-3")
	} else {
		r.NonExecute("P-3", "voisins.json inexploitable")
	}
	// P-4 : un dossier contient un événement
	if m.Count < 1 {
		r.Echec("P-4", "count = %d dans un dossier (il contient un événement)", m.Count)
	}
	r.Passe("P-4")
}

func (d *Dossier) controlerChemin() {
	r := d.Resultats
	if d.Chemin == nil {
		for _, id := range []string{"M-1", "M-2", "M-3"} {
			r.NonExecute(id, "chemin.json illisible")
		}
		return
	}
	m := &manquements{}
	ok := m.clesExactes(d.Chemin, "chemin", []string{"version", "tree_size", "leaf_index", "leaf_hash", "path", "root"})
	var treeSize, leafIndex int64
	var leafHash, root []byte
	var path [][]byte
	if ok {
		if ver := d.Chemin.Get("version"); ver.Kind != KindNumber || ver.Num != "0" {
			m.add("chemin.version", "constante 0 attendue")
		}
		treeSize, _ = m.entier(d.Chemin.Get("tree_size"), "chemin.tree_size", 1, EntierSurMax)
		leafIndex, _ = m.entier(d.Chemin.Get("leaf_index"), "chemin.leaf_index", 0, EntierSurMax-1)
		if s, okh := m.hex(d.Chemin.Get("leaf_hash"), "chemin.leaf_hash", 32, false); okh {
			leafHash, _ = OctetsHex(s, 32)
		}
		if s, okh := m.hex(d.Chemin.Get("root"), "chemin.root", 32, false); okh {
			root, _ = OctetsHex(s, 32)
		}
		if p := d.Chemin.Get("path"); p.Kind != KindArray {
			m.add("chemin.path", "tableau attendu")
		} else {
			if len(p.Arr) > 64 {
				m.add("chemin.path", "plus de 64 éléments")
			}
			for i, x := range p.Arr {
				if s, okh := m.hex(x, fmt.Sprintf("chemin.path[%d]", i), 32, false); okh {
					b, _ := OctetsHex(s, 32)
					path = append(path, b)
				} else {
					ok = false
				}
			}
		}
	}
	for _, x := range m.liste {
		r.Echec("M-2", "%s", x)
	}
	if !ok || leafHash == nil || root == nil {
		r.NonExecute("M-1", "chemin.json mal formé")
		r.NonExecute("M-3", "chemin.json mal formé")
		return
	}
	// M-1
	hash, _, err := HashEvenement(d.Evenement)
	if err != nil {
		r.NonExecute("M-1", "hash de l'événement non calculable")
	} else if got := Feuille(hash); Hex0x(got) != Hex0x(leafHash) {
		r.Echec("M-1", "leaf_hash %s ≠ SHA-256(0x00 || hash recalculé) = %s", Hex0x(leafHash), Hex0x(got))
	}
	r.Passe("M-1")
	// M-2
	if err := VerifierInclusion(leafHash, uint64(leafIndex), uint64(treeSize), path, root); err != nil {
		r.Echec("M-2", "%v", err)
	}
	r.Passe("M-2")
	// M-3
	if d.Manifeste != nil {
		mf := LireManifeste(d.Manifeste)
		if Hex0x(root) != mf.Root {
			r.Echec("M-3", "chemin.root %s ≠ manifeste.root %s", Hex0x(root), mf.Root)
		}
		if treeSize != mf.Count {
			r.Echec("M-3", "chemin.tree_size %d ≠ manifeste.count %d", treeSize, mf.Count)
		}
		if attendu := Seq(d.Evenement) - mf.FirstSeq; leafIndex != attendu {
			r.Echec("M-3", "chemin.leaf_index %d ≠ seq - first_seq = %d", leafIndex, attendu)
		}
		r.Passe("M-3")
	} else {
		r.NonExecute("M-3", "manifeste.json illisible")
	}
}

func (d *Dossier) controlerApprobations() {
	r := d.Resultats
	ev := d.Evenement
	approval := ev.Get("approval")
	aApproval := approval != nil && approval.Kind != KindNull
	p := d.Parties["approbations"]
	present := p != nil && p.Present
	if present != aApproval {
		r.Echec("A-1", "approbations.json %s alors que approval est %s", presence(present), sorteNulle(approval))
	}
	if !aApproval {
		if p != nil && !p.Present && p.Reason != "aucune approbation liée" {
			r.Echec("A-1", "raison d'absence %q, attendu « aucune approbation liée »", p.Reason)
		}
		for _, id := range []string{"A-2", "A-3", "A-4"} {
			r.NonExecute(id, "aucune approbation liée")
		}
		r.Passe("A-1")
		return
	}
	if !present {
		for _, id := range []string{"A-2", "A-3", "A-4"} {
			r.NonExecute(id, "approbations.json absent")
		}
		return
	}
	d.Approbations = d.lireJSON("approbations.json", "A-1")
	if d.Approbations == nil {
		return
	}
	ap := d.Approbations
	m := &manquements{}
	if !m.clesExactes(ap, "approbations", []string{"version", "ticket", "request_hash", "approver_set", "events"}) {
		for _, x := range m.liste {
			r.Echec("A-1", "%s", x)
		}
		return
	}
	if ver := ap.Get("version"); ver.Kind != KindNumber || ver.Num != "0" {
		m.add("approbations.version", "constante 0 attendue")
	}
	m.chaine(ap.Get("ticket"), "approbations.ticket", 1, 128, false)
	m.hex(ap.Get("request_hash"), "approbations.request_hash", 32, false)
	var members []string
	var required, size int64
	if as := ap.Get("approver_set"); m.clesExactes(as, "approbations.approver_set", []string{"threshold", "members", "source"}) {
		if th := as.Get("threshold"); m.clesExactes(th, "approbations.approver_set.threshold", []string{"required", "size"}) {
			required, _ = m.entier(th.Get("required"), "approbations.approver_set.threshold.required", 1, 65535)
			size, _ = m.entier(th.Get("size"), "approbations.approver_set.threshold.size", 1, 65535)
		}
		if mb := as.Get("members"); mb.Kind != KindArray || len(mb.Arr) < 1 {
			m.add("approbations.approver_set.members", "tableau non vide attendu")
		} else {
			vus := map[string]bool{}
			for i, x := range mb.Arr {
				if s, ok := m.hex(x, fmt.Sprintf("approbations.approver_set.members[%d]", i), 20, false); ok {
					if vus[s] {
						m.add("approbations.approver_set.members", "adresse %s en double", s)
					}
					vus[s] = true
					members = append(members, s)
				}
			}
		}
		m.chaine(as.Get("source"), "approbations.approver_set.source", 1, 256, false)
	}
	events := ap.Get("events")
	if events.Kind != KindArray || len(events.Arr) < 1 {
		m.add("approbations.events", "tableau non vide attendu")
	}
	for _, x := range m.liste {
		r.Echec("A-1", "%s", x)
	}
	if t1, t2 := chaineDe(ap, "ticket"), chaineDe(approval, "ticket"); t1 != t2 {
		r.Echec("A-1", "ticket %q ≠ approval.ticket %q", t1, t2)
	}
	if h1, h2 := chaineDe(ap, "request_hash"), chaineDe(approval, "request_hash"); h1 != h2 {
		r.Echec("A-1", "request_hash ≠ approval.request_hash")
	}
	r.Passe("A-1")

	// A-2 : chaque décision est une décision du même ticket (E-1 à E-11, approval
	// et A égaux) ; une décision précède l'appel relayé qu'elle autorise (seq,
	// approval.at ≤ ts) ; le dossier d'une décision la contient dans events.
	evEstDecision := Outil(ev) == OutilApprobation
	hashEv, _, errHashEv := HashEvenement(ev)
	prouveDansEvents := false
	if events.Kind == KindArray {
		for i, e := range events.Arr {
			etiq := fmt.Sprintf("approbations.events[%d]", i)
			r.Fusionner(ControlerEvenement(e, d.Cles), etiq)
			if Outil(e) != OutilApprobation {
				r.Echec("A-2", "%s : execution.tool %q, attendu %s", etiq, Outil(e), OutilApprobation)
			}
			if !memeCanonique(e.Get("approval"), approval) {
				r.Echec("A-2", "%s : approval différent, clé pour clé, de celui de l'événement prouvé", etiq)
			}
			val := e.Get("execution").Get("arguments").Get("value")
			if val == nil || !memeCanonique(val, ObjetSigneApprobation(ev)) {
				r.Echec("A-2", "%s : execution.arguments.value ≠ A = {decision, journal_id, org_id, request_hash, ticket}", etiq)
			}
			if !evEstDecision && Seq(e) >= Seq(ev) {
				r.Echec("A-2", "%s : seq %d n'est pas antérieur à celui de l'appel relayé (%d)", etiq, Seq(e), Seq(ev))
			}
			if h, _, err := HashEvenement(e); err == nil && errHashEv == nil && Hex0x(h) == Hex0x(hashEv) {
				prouveDansEvents = true
			}
		}
	}
	if !evEstDecision {
		if at, okAt := ParseHorodatage(chaineDe(approval, "at")); okAt {
			if ts, okTs := Ts(ev); okTs && at.After(ts) {
				r.Echec("A-2", "approval.at %s postérieur au ts de l'appel relayé %s", FormaterHorodatage(at), FormaterHorodatage(ts))
			}
		}
	} else if errHashEv == nil && !prouveDansEvents {
		r.Echec("A-2", "l'événement prouvé est une décision mais ne figure pas dans events")
	}
	r.Passe("A-2")

	// A-3
	decision := chaineDe(approval, "decision")
	approvers := approval.Get("approvers")
	var adresses []string
	if approvers != nil && approvers.Kind == KindArray {
		vus := map[string]bool{}
		for _, a := range approvers.Arr {
			if a.Kind == KindString {
				if vus[a.Str] {
					r.Echec("A-3", "approbateur %s en double", a.Str)
				}
				vus[a.Str] = true
				adresses = append(adresses, a.Str)
				if !dansEnum(a.Str, members) {
					r.Echec("A-3", "approbateur %s hors du jeu déclaré approver_set.members", a.Str)
				}
			}
		}
	}
	evReq, _ := entierDe(approval, "threshold", "required")
	evSize, _ := entierDe(approval, "threshold", "size")
	if evReq != required || evSize != size {
		r.Echec("A-3", "threshold de l'événement {%d, %d} ≠ approver_set.threshold {%d, %d}", evReq, evSize, required, size)
	}
	if required > size {
		r.Echec("A-3", "required %d > size %d", required, size)
	}
	if int64(len(members)) != size {
		r.Echec("A-3", "size %d ≠ nombre de membres déclarés %d", size, len(members))
	}
	switch decision {
	case "expire":
		if len(adresses) != 0 {
			r.Echec("A-3", "decision expire avec %d approbateur(s)", len(adresses))
		}
	default:
		if int64(len(adresses)) < required {
			r.Echec("A-3", "%d approbateur(s) pour un seuil de %d", len(adresses), required)
		}
	}
	r.Passe("A-3")
	r.HorsPerimetre("E-9", "signatures EIP-191 des approbateurs non vérifiées (secp256k1 et keccak256 hors périmètre de ce vérificateur) ; structure contrôlée par E-5 et A-3")

	// A-4
	requestHash := chaineDe(approval, "request_hash")
	trouve := false
	if d.Voisins != nil {
		for _, nom := range []string{"previous", "next"} {
			v := d.Voisins.Get(nom)
			if v == nil || v.IsNull() {
				continue
			}
			h, _, err := HashEvenement(v)
			if err != nil || Hex0x(h) != requestHash {
				continue
			}
			trouve = true
			if st := chaineDe(v, "execution", "status"); st != "retenue" {
				r.Echec("A-4", "événement de demande (voisin %s, seq %d) : status %q, attendu retenue", nom, Seq(v), st)
			}
			if a, b := chaineDe(v, "policy", "ticket"), chaineDe(approval, "ticket"); a != b {
				r.Echec("A-4", "événement de demande : policy.ticket %q ≠ approval.ticket %q", a, b)
			}
		}
	}
	if !trouve {
		r.NonExecute("A-4", "événement de demande (request_hash) absent du dossier : non vérifiable")
	}
	r.Passe("A-4")
}

func presence(b bool) string {
	if b {
		return "présent"
	}
	return "absent"
}

func (d *Dossier) enoncerBornes() {
	var absentes []string
	for _, pa := range partiesAttendues[7:12] {
		if p := d.Parties[pa.name]; p == nil || !p.Present {
			absentes = append(absentes, pa.file)
		}
	}
	if len(absentes) == 0 {
		return
	}
	d.Bornes = append(d.Bornes,
		"verdict borné (CT-1 §11.3) : les contrôles 4 et 5 (jeton RFC 3161, preuve OpenTimestamps ; CT-5) et 8 (registre, certificat de commit, validateurs ; CT-4) ne sont pas exécutables, parties absentes : "+strings.Join(absentes, ", "),
		"ce que le dossier établit au mieux : l'événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste signé par cette clé ; les adresses d'approbation sont déclarées mais leurs signatures EIP-191 (contrôle 7, E-9) ne sont pas vérifiées par ce vérificateur ; rien n'est établi sur la date ni sur l'ancre")
}

// controlerPointsDeControle exécute K-1 à K-6 (révision 0.3) sur la treizième
// partie quand l'index la déclare présente ; K-7 à K-9 sont non exécutées,
// raison admise, quand l'ancre vaut null, et hors périmètre de ce vérificateur
// sinon (vérifications T-, R- et O- de CT-6). Index à douze parties ou partie
// absente avec raison (§11.1, §11.4, alignés sur CT-6 EX-5.7) : les neuf ne
// sont pas exécutées et ne figurent pas au rapport, et le verdict ne change
// pas. Partie présente mais inexploitable, ou K-1 en échec : K-2 à K-9 non
// exécutées sans raison admise.
func (d *Dossier) controlerPointsDeControle() {
	r := d.Resultats
	pa := d.Parties["points_de_controle"]
	if pa == nil || !pa.Present {
		// Index à douze parties (format v0 d'origine, antérieur à la révision
		// 0.3), ou treizième partie déclarée absente avec une raison : aucune K-.
		return
	}
	v := d.lireJSON("points-de-controle.json", "K-1")
	if v == nil {
		for _, id := range idsK[1:] {
			r.NonExecute(id, "points-de-controle.json inexploitable (K-1 en échec)")
		}
		return
	}
	m := &manquements{}
	var point *Value
	var consistency *Value
	var anchors *Value
	if m.clesExactes(v, "points_de_controle", []string{"version", "checkpoint", "checkpoint_hash", "consistency", "anchors"}) {
		if ver := v.Get("version"); ver.Kind != KindNumber {
			m.add("points_de_controle.version", "constante 0 attendue")
		} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
			m.add("points_de_controle.version", "constante 0 attendue, reçu %s", ver.Num)
		}
		point = v.Get("checkpoint")
		for _, x := range ValiderSchemaPoint(point) {
			m.add("points_de_controle.checkpoint", "%s", x)
		}
		m.hex(v.Get("checkpoint_hash"), "points_de_controle.checkpoint_hash", 32, false)
		consistency = v.Get("consistency")
		if m.clesExactes(consistency, "points_de_controle.consistency", []string{"version", "first_size", "second_size", "first_root", "second_root", "path"}) {
			if ver := consistency.Get("version"); ver.Kind != KindNumber {
				m.add("points_de_controle.consistency.version", "constante 0 attendue")
			} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
				m.add("points_de_controle.consistency.version", "constante 0 attendue, reçu %s", ver.Num)
			}
			m.entier(consistency.Get("first_size"), "points_de_controle.consistency.first_size", 1, EntierSurMax)
			m.entier(consistency.Get("second_size"), "points_de_controle.consistency.second_size", 1, EntierSurMax)
			m.hex(consistency.Get("first_root"), "points_de_controle.consistency.first_root", 32, false)
			m.hex(consistency.Get("second_root"), "points_de_controle.consistency.second_root", 32, false)
			if p := consistency.Get("path"); p.Kind != KindArray {
				m.add("points_de_controle.consistency.path", "tableau attendu")
			} else {
				if len(p.Arr) > 64 {
					m.add("points_de_controle.consistency.path", "plus de 64 éléments")
				}
				for i, x := range p.Arr {
					m.hex(x, fmt.Sprintf("points_de_controle.consistency.path[%d]", i), 32, false)
				}
			}
		}
		anchors = v.Get("anchors")
		if m.clesExactes(anchors, "points_de_controle.anchors", []string{"rfc3161", "registry", "ots"}) {
			if a := anchors.Get("rfc3161"); !a.IsNull() && m.clesExactes(a, "points_de_controle.anchors.rfc3161", []string{"token"}) {
				m.base64(a.Get("token"), "points_de_controle.anchors.rfc3161.token")
			}
			if a := anchors.Get("ots"); !a.IsNull() && m.clesExactes(a, "points_de_controle.anchors.ots", []string{"proof"}) {
				m.base64(a.Get("proof"), "points_de_controle.anchors.ots.proof")
			}
			if a := anchors.Get("registry"); !a.IsNull() && m.clesExactes(a, "points_de_controle.anchors.registry", []string{"chain_id", "contract", "fingerprint", "doc_type", "block_number", "block_hash", "transaction_hash", "log_index"}) {
				// $defs/ancre_registre_point : entiers de la section 3 (chain_id ≥ 1,
				// log_index ≤ 255), adresse de 20 octets, empreintes de 32 octets.
				m.entier(a.Get("chain_id"), "points_de_controle.anchors.registry.chain_id", 1, EntierSurMax)
				m.hex(a.Get("contract"), "points_de_controle.anchors.registry.contract", 20, false)
				m.hex(a.Get("fingerprint"), "points_de_controle.anchors.registry.fingerprint", 32, false)
				m.hex(a.Get("doc_type"), "points_de_controle.anchors.registry.doc_type", 32, false)
				m.entier(a.Get("block_number"), "points_de_controle.anchors.registry.block_number", 0, EntierSurMax)
				m.hex(a.Get("block_hash"), "points_de_controle.anchors.registry.block_hash", 32, false)
				m.hex(a.Get("transaction_hash"), "points_de_controle.anchors.registry.transaction_hash", 32, false)
				m.entier(a.Get("log_index"), "points_de_controle.anchors.registry.log_index", 0, 255)
			}
		}
	}
	ev := d.Evenement
	var pt *Point
	if len(m.liste) == 0 {
		pt = LirePoint(point)
		if pt.OrgID != chaineDe(ev, "org_id") || pt.JournalID != chaineDe(ev, "journal_id") {
			m.add("points_de_controle.checkpoint", "org_id ou journal_id différents de ceux de l'événement")
		}
		if d.Manifeste == nil {
			for _, x := range m.liste {
				r.Echec("K-1", "%s", x)
			}
			r.NonExecute("K-1", "manifeste.json inexploitable : relations au manifeste non vérifiables")
			for _, id := range idsK[1:] {
				r.NonExecute(id, "manifeste.json inexploitable")
			}
			return
		}
		mf := LireManifeste(d.Manifeste)
		if pt.PeriodStart != mf.PeriodStart {
			m.add("points_de_controle.checkpoint.period_start", "%d différent de celui du manifeste %d", pt.PeriodStart, mf.PeriodStart)
		}
		if pt.TreeSize < 1 || pt.TreeSize > mf.Count {
			m.add("points_de_controle.checkpoint.tree_size", "%d hors de [1, count = %d]", pt.TreeSize, mf.Count)
		}
		if pt.LastSeq != mf.FirstSeq+pt.TreeSize-1 {
			m.add("points_de_controle.checkpoint.last_seq", "%d différent de first_seq + tree_size - 1 (%d)", pt.LastSeq, mf.FirstSeq+pt.TreeSize-1)
		}
		if pt.Root == Zero32 {
			m.add("points_de_controle.checkpoint.root", "racine nulle")
		}
		if pt.TsOK && pt.CheckpointTs.UnixMilli() < pt.PeriodStart*1000 {
			m.add("points_de_controle.checkpoint.checkpoint_ts", "%s antérieur à period_start", FormaterHorodatage(pt.CheckpointTs))
		}
	}
	for _, x := range m.liste {
		r.Echec("K-1", "%s", x)
	}
	if len(m.liste) > 0 {
		// §11.4 : K-2 à K-9 non exécutées sans raison admise.
		for _, id := range idsK[1:] {
			r.NonExecute(id, "K-1 en échec")
		}
		return
	}
	r.Passe("K-1")
	mf := LireManifeste(d.Manifeste)

	// K-2 : checkpointHash recalculé
	hash, _, err := CheckpointHash(point)
	if err != nil {
		r.Echec("K-2", "point non canonisable : %v", err)
	} else if got, att := Hex0x(hash), chaineDe(v, "checkpoint_hash"); got != att {
		r.Echec("K-2", "checkpointHash recalculé %s ≠ checkpoint_hash déclaré %s", got, att)
	}
	r.Passe("K-2")

	// K-3 : signature sous la clé key_id de cles.json et validité annoncée
	if d.Cles == nil {
		r.NonExecute("K-3", "cles.json inexploitable (échec porté par E-8)")
	} else if cle := d.Cles.Trouver(pt.KeyID); cle == nil {
		r.Echec("K-3", "clé %q absente de cles.json", pt.KeyID)
	} else {
		if err := VerifierSignaturePoint(point, cle); err != nil {
			r.Echec("K-3", "signature du point sous %s : %v", pt.KeyID, err)
		}
		if pt.TsOK && !cle.Couvre(pt.CheckpointTs) {
			r.Echec("K-3", "checkpoint_ts %s hors de la validité annoncée %s de la clé %s", FormaterHorodatage(pt.CheckpointTs), cle.Intervalle(), pt.KeyID)
		}
		r.Passe("K-3")
	}

	// K-4 : couverture de l'événement prouvé
	if d.Chemin == nil {
		r.NonExecute("K-4", "chemin.json inexploitable")
	} else {
		if li, ok := entierDe(d.Chemin, "leaf_index"); !ok {
			r.NonExecute("K-4", "chemin.leaf_index illisible")
		} else if li >= pt.TreeSize {
			r.Echec("K-4", "leaf_index %d n'est pas strictement inférieur à tree_size %d : le point ne couvre pas l'événement", li, pt.TreeSize)
		}
		if ts, ok := Ts(ev); ok && pt.TsOK && ts.After(pt.CheckpointTs) {
			r.Echec("K-4", "ts de l'événement %s postérieur à checkpoint_ts %s", FormaterHorodatage(ts), FormaterHorodatage(pt.CheckpointTs))
		}
		r.Passe("K-4")
	}

	// K-5 : preuve de cohérence vers la racine du manifeste
	fs, _ := entierDe(consistency, "first_size")
	ss, _ := entierDe(consistency, "second_size")
	fr := chaineDe(consistency, "first_root")
	sr := chaineDe(consistency, "second_root")
	if fs != pt.TreeSize {
		r.Echec("K-5", "consistency.first_size %d ≠ tree_size %d", fs, pt.TreeSize)
	}
	if ss != mf.Count {
		r.Echec("K-5", "consistency.second_size %d ≠ manifeste.count %d", ss, mf.Count)
	}
	if fr != pt.Root {
		r.Echec("K-5", "consistency.first_root ≠ checkpoint.root")
	}
	if sr != mf.Root {
		r.Echec("K-5", "consistency.second_root ≠ manifeste.root")
	}
	var path [][]byte
	for _, x := range consistency.Get("path").Arr {
		b, _ := OctetsHex(chaineDe(x, ""), 32)
		path = append(path, b)
	}
	frO, _ := OctetsHex(fr, 32)
	srO, _ := OctetsHex(sr, 32)
	if err := VerifierCoherence(uint64(fs), uint64(ss), frO, srO, path); err != nil {
		r.Echec("K-5", "preuve de cohérence (%d, %d) refusée : %v", fs, ss, err)
	}
	r.Passe("K-5")

	// K-6 : last_hash contre l'événement last_seq quand il est dans le dossier
	trouve := false
	candidats := []*Value{ev}
	if d.Voisins != nil {
		for _, nom := range []string{"previous", "next"} {
			if x := d.Voisins.Get(nom); x != nil && !x.IsNull() {
				candidats = append(candidats, x)
			}
		}
	}
	for _, c := range candidats {
		if Seq(c) != pt.LastSeq {
			continue
		}
		trouve = true
		if h, _, err := HashEvenement(c); err != nil {
			r.NonExecute("K-6", "hash de l'événement last_seq non calculable")
		} else if Hex0x(h) != pt.LastHash {
			r.Echec("K-6", "last_hash %s ≠ hash recalculé %s de l'événement seq %d", pt.LastHash, Hex0x(h), pt.LastSeq)
		}
		break
	}
	if !trouve {
		d.nonExecuteAdmis("K-6", fmt.Sprintf("événement last_seq (seq %d) hors du dossier : non vérifiable", pt.LastSeq))
	} else {
		r.Passe("K-6")
	}

	d.controlerAncresPoint(anchors)
}

// base64 transcrit #/$defs/base64 du schéma de dossier (révision 0.3) :
// alphabet standard de la RFC 4648 §4, groupes de quatre caractères,
// remplissage exact, sans saut de ligne, 4 à 131072 caractères. Le décodage
// et la vérification de l'ancre relèvent de K-7 et K-9 (CT-6).
func (m *manquements) base64(v *Value, chemin string) (string, bool) {
	s, ok := m.chaine(v, chemin, 4, 131072, false)
	if !ok {
		return "", false
	}
	if !estBase64(s) {
		m.add(chemin, "base64 standard avec remplissage exact attendu (RFC 4648 §4)")
		return "", false
	}
	return s, true
}

// estBase64 reconnaît ^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$
// pour une chaîne non vide.
func estBase64(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		case c == '=' && (i == len(s)-1 || (i == len(s)-2 && s[len(s)-1] == '=')):
		default:
			return false
		}
	}
	return true
}

// controlerAncresPoint fixe l'état de K-7 à K-9 quand K-1 est passée : non
// exécutée, raison admise, pour une ancre nulle ; hors périmètre
// (vérifications T-, R- et O- de CT-6) pour une ancre fournie.
func (d *Dossier) controlerAncresPoint(anchors *Value) {
	r := d.Resultats
	for _, x := range []struct{ id, nom, quoi string }{{"K-7", "rfc3161", "jeton RFC 3161 (T-1 à T-11 de CT-6)"}, {"K-8", "registry", "ancre au registre (R- de CT-6)"}, {"K-9", "ots", "preuve OpenTimestamps (O-1 à O-7 de CT-6)"}} {
		if anchors == nil || anchors.Kind != KindObject {
			r.NonExecute(x.id, "anchors inexploitable")
			continue
		}
		a := anchors.Get(x.nom)
		if a == nil || a.IsNull() {
			d.nonExecuteAdmis(x.id, "ancre "+x.nom+" nulle : partie absente")
			continue
		}
		r.HorsPerimetre(x.id, x.quoi+" : hors périmètre de ce vérificateur")
	}
}
