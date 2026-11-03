// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/dossier.go).

// Dossier de preuve v0 (CT-1 §11) : index dossier.json, fichiers compagnons
// et les contrôles D-1, D-2, E-1 à E-11, C-1 à C-3, M-1 à M-3, P-1 à P-5,
// A-1 à A-4, et, révision 0.3, K-1 à K-9 sur la treizième partie facultative
// points-de-controle.json, et, révision 0.4, AT-1 à AT-7 sur la quatorzième
// partie facultative attestation-perimetre.json (attestation.go ; sans effet
// sur la validité du dossier).
//
// Révision 0.5 (CT-1 §11.4) : chaque partie a un contrôle porteur ; une
// partie déclarée présente est inexploitable dans cinq cas (a) à (e), et
// tout contrôle qui la lit est alors non exécuté sans raison admise, sauf
// s'il échoue sur ce qu'il lit des autres parties ; une partie contraire à
// son schéma reste exploitable, et les relations portent sur les valeurs
// lues (un terme absent, mal typé ou incalculable met en échec le contrôle
// qui l'évalue). Les parties réservées à CT-4 et CT-5 (contrôles 4, 5 et 8)
// et les ancres non nulles d'un point de contrôle ne sont pas vérifiées par
// ce vérificateur de CT-1 seul : déclarées présentes, elles rendent le
// dossier invalide pour lui, sans raison admise.

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// idsE sont les contrôles d'un événement.
var idsE = []string{"E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"}

// Limites de taille (CT-1 §11.4, révision 0.5 ; CT-6 EX-4.13 à EX-4.15). Un
// fichier de taille égale à sa limite est lu ; un fichier plus grand ne l'est
// pas.
const (
	Mio                    = 1 << 20
	LimiteIndex            = 1 * Mio
	LimitePartieJSON       = 16 * Mio
	LimitePointsDeControle = 1 * Mio
	PlafondAttestation     = 64 * Mio
)

// limitesParties donne la limite de chaque partie qui n'est pas l'une des
// sept parties JSON v0 (16 Mio) ; les parties réservées ont les limites de
// CT-6 EX-4.13.
var limitesParties = map[string]int64{
	"points-de-controle.json":    LimitePointsDeControle,
	"attestation-perimetre.json": TailleMaxPartieAttestation,
	"jeton-rfc3161.der":          64 << 10,
	"preuve.ots":                 256 << 10,
	"registre.json":              64 * Mio,
	"certificat-commit.json":     64 * Mio,
	"validateurs.json":           1 * Mio,
}

func limiteDe(fichier string) int64 {
	if l, ok := limitesParties[fichier]; ok {
		return l
	}
	return LimitePartieJSON
}

// Raisons de non-exécution (vocabulaire de CT-6, table 6.2).
const (
	RaisonNEPrerequis    = "prerequis_en_echec"
	RaisonNEPartieAbsent = "partie_absente"
	RaisonNEHorsDossier  = "piece_hors_dossier"
)

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
	// Illisible est non vide quand l'entrée est inutilisable (code 2, sans
	// verdict) : dossier.json absent, qui n'est pas un fichier ordinaire ou
	// qui n'est pas un texte JSON (§11.4 révision 0.5, CT-6 EX-4.12) ;
	// attestation-perimetre.json au-delà de 64 Mio (CT-6 EX-4.15).
	Illisible string
	// TypeErreur est le type d'erreur de CT-6 §8 d'une entrée inutilisable
	// (dossier_illisible, taille_depassee), quand Illisible n'est pas vide.
	TypeErreur string
	// admis : contrôles non exécutés pour une raison admise (§11.4) ; refus :
	// contrôles non exécutés pour une autre raison au moins une fois. Un
	// contrôle non exécuté qui n'est pas dans admis est non admis.
	admis   map[string]bool
	refus   map[string]bool
	raisons map[string]string
	// Perimetre porte les statuts de AT-1 à AT-7 (révision 0.4), nil quand
	// la quatorzième partie n'est pas déclarée présente ; ils n'entrent ni
	// dans Resultats ni dans la validité du dossier.
	Perimetre []*StatutAT
	// clesExploitable : cles.json exploitable, c'est-à-dire la première partie
	// de E-8 réussie (schéma, org_id et journal_id égaux à ceux de
	// l'événement, dates, unicité, validités), prérequis de E-10 (pour ses
	// comparaisons à cles.json), E-11, P-5, K-3 et AT-6 (§11.4).
	clesExploitable bool
	// evE1E2 : E-1 et E-2 réussies pour l'événement prouvé (prérequis
	// d'AT-5 et d'AT-6, §11.4 révision 0.5).
	evE1E2 bool
	// checkpointHash recalculé (K-2), pour K-8.
	checkpointHash []byte
}

func (d *Dossier) initRaisons() {
	if d.admis == nil {
		d.admis, d.refus, d.raisons = map[string]bool{}, map[string]bool{}, map[string]string{}
	}
}

// nonExecuteAdmis marque un contrôle non exécuté pour une raison que §11.4
// admet (code : partie_absente ou piece_hors_dossier).
func (d *Dossier) nonExecuteAdmis(id, raison string, code ...string) {
	d.initRaisons()
	d.Resultats.NonExecute(id, raison)
	d.admis[id] = true
	if len(code) > 0 && d.raisons[id] == "" {
		d.raisons[id] = code[0]
	}
}

// nonExecute marque un contrôle non exécuté sans raison admise
// (prerequis_en_echec), sauf s'il a déjà échoué.
func (d *Dossier) nonExecute(id, raison string) {
	d.initRaisons()
	d.Resultats.NonExecute(id, raison)
	d.refus[id] = true
	d.raisons[id] = RaisonNEPrerequis
}

// RaisonNonExecution rend la raison de non-exécution d'un contrôle :
// prerequis_en_echec dès qu'une raison non admise s'applique, sinon la
// raison admise.
func (d *Dossier) RaisonNonExecution(id string) string {
	c := d.Resultats.parID[id]
	if c == nil || c.Etat != EtatNonExecute {
		return ""
	}
	if d.admis[id] && !d.refus[id] {
		if r := d.raisons[id]; r != "" {
			return r
		}
		return RaisonNEPartieAbsent
	}
	return RaisonNEPrerequis
}

// reussi dit si un contrôle a été exécuté et a réussi.
func (d *Dossier) reussi(id string) bool {
	c := d.Resultats.parID[id]
	return c != nil && c.Etat == EtatPasse
}

// NonExecutesNonAdmis rend les contrôles non exécutés qu'un dossier valide ne
// peut pas avoir (CT-1 §11.4) : tous ceux qui ne le sont pas pour une raison
// admise (A-2 à A-4 avec approval nul et la partie déclarée absente avec la
// raison « aucune approbation liée » ; A-4 quand aucun voisin n'est la
// demande ; K-6 quand l'événement last_seq est hors du dossier ; K-7 à K-9
// pour une ancre nulle).
func (d *Dossier) NonExecutesNonAdmis() []string {
	var out []string
	for _, c := range d.Resultats.Liste() {
		if c.Etat != EtatNonExecute {
			continue
		}
		if d.admis[c.ID] && !d.refus[c.ID] {
			continue
		}
		out = append(out, c.ID)
	}
	return out
}

// Valide dit si le dossier est valide au sens de CT-1 §11.4 : une entrée
// lisible, aucun contrôle en échec et aucun contrôle non exécuté sans raison
// admise.
func (d *Dossier) Valide() bool {
	return d.Illisible == "" && d.Resultats.Valide() && len(d.NonExecutesNonAdmis()) == 0
}

// ---------------------------------------------------------------- lecture

// defautPartie classe une partie déclarée présente (§11.4, révision 0.5).
type defautPartie int

const (
	partieExploitable  defautPartie = iota
	partieManquante                 // (a) pas de fichier ordinaire de ce nom
	partieTropGrande                // (b) au-delà de sa limite
	partiePasJSON                   // (c) pas un texte JSON, ou trop profond
	partieNonCanonique              // (d) sans forme canonique
	partiePasObjet                  // (e) pas un objet
)

// fichierOrdinaire examine le chemin sans suivre de lien (lstat) : un lien
// symbolique, un répertoire, un tube ou un périphérique n'est pas un fichier
// ordinaire, et n'est jamais ouvert (CT-6 EX-4.17).
func fichierOrdinaire(chemin string) (os.FileInfo, bool) {
	info, err := os.Lstat(chemin)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	return info, true
}

// lireBorne lit un fichier ordinaire sans dépasser limite octets. Rend le
// défaut (a) ou (b) le cas échéant.
func lireBorne(chemin string, limite int64) ([]byte, defautPartie, string) {
	info, ok := fichierOrdinaire(chemin)
	if !ok {
		return nil, partieManquante, "absent du répertoire ou qui n'est pas un fichier ordinaire"
	}
	if info.Size() > limite {
		return nil, partieTropGrande, fmt.Sprintf("%d octets, au-delà de la limite de %d : non lu", info.Size(), limite)
	}
	f, err := os.Open(chemin)
	if err != nil {
		return nil, partieManquante, fmt.Sprintf("illisible : %v", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || !os.SameFile(info, fi) {
		return nil, partieManquante, "le fichier ouvert n'est pas celui que lstat a vu"
	}
	octets, err := io.ReadAll(io.LimitReader(f, limite+1))
	if err != nil {
		return nil, partieManquante, fmt.Sprintf("illisible : %v", err)
	}
	if int64(len(octets)) > limite {
		return nil, partieTropGrande, fmt.Sprintf("plus de %d octets : non lu au-delà", limite)
	}
	return octets, partieExploitable, ""
}

// analyserPartie applique les cas (c), (d) et (e) à des octets lus.
func analyserPartie(octets []byte) (*Value, defautPartie, string) {
	v, err := ParseJSONV0(octets)
	if err != nil {
		if ej, ok := err.(*ErreurJSON); ok && ej.Canonique {
			return nil, partieNonCanonique, err.Error()
		}
		return nil, partiePasJSON, err.Error()
	}
	if _, err := Canonique(v); err != nil {
		return nil, partieNonCanonique, err.Error()
	}
	if v.Kind != KindObject {
		return nil, partiePasObjet, fmt.Sprintf("objet JSON attendu, reçu %s", v.Kind)
	}
	return v, partieExploitable, ""
}

// lirePartie lit une partie de CT-1 déclarée présente et applique la règle
// des cinq cas (§11.4, révision 0.5) : (a) D-2 échoue (controlerEmpreintes)
// et le contrôle porteur n'est pas exécuté ; (b), (c), (e) le contrôle
// porteur échoue ; (d) E-2 échoue et le contrôle porteur n'est pas exécuté.
// Rend nil quand la partie est inexploitable.
func (d *Dossier) lirePartie(nom, porteur string) *Value {
	p := d.Parties[nom]
	if p == nil || !p.Present {
		return nil
	}
	octets, def, msg := lireBorne(filepath.Join(d.Dir, p.File), limiteDe(p.File))
	var v *Value
	if def == partieExploitable {
		v, def, msg = analyserPartie(octets)
	}
	switch def {
	case partieManquante:
		d.nonExecute(porteur, p.File+" "+msg+" : échec porté par D-2")
	case partieTropGrande, partiePasJSON, partiePasObjet:
		d.Resultats.Echec(porteur, "%s : %s ; la partie est inexploitable", p.File, msg)
	case partieNonCanonique:
		d.Resultats.Echec("E-2", "%s : %s ; la partie est inexploitable", p.File, msg)
		d.nonExecute(porteur, p.File+" sans forme canonique (échec porté par E-2)")
	}
	return v
}

// ---------------------------------------------------------------- dossier

// VerifierDossier exécute tous les contrôles applicables sur un répertoire.
func VerifierDossier(dir string) *Dossier {
	d := &Dossier{Dir: dir, Resultats: NouveauxResultats(), Parties: map[string]*Partie{}}
	d.initRaisons()
	r := d.Resultats

	// dossier.json (§11.4, révision 0.5) : absent, pas un fichier ordinaire
	// ou pas un texte JSON : entrée inutilisable, code 2 ; au-delà de 1 Mio,
	// pas un objet ou contraire à son schéma : D-1 ; sans forme canonique :
	// E-2 ; aucun autre contrôle n'est alors exécuté.
	octets, def, msg := lireBorne(filepath.Join(dir, "dossier.json"), LimiteIndex)
	var idx *Value
	if def == partieExploitable {
		idx, def, msg = analyserPartie(octets)
	}
	switch def {
	case partieManquante, partiePasJSON:
		d.Illisible, d.TypeErreur = "dossier.json "+msg, "dossier_illisible"
		return d
	case partieTropGrande, partiePasObjet:
		r.Echec("D-1", "dossier.json : %s ; rien n'est lu de l'index", msg)
		return d
	case partieNonCanonique:
		r.Echec("E-2", "dossier.json : %s ; rien n'est lu de l'index", msg)
		d.nonExecute("D-1", "dossier.json sans forme canonique (échec porté par E-2)")
		return d
	}
	d.Index = idx
	if !d.controlerIndex() {
		return d
	}

	// D-2 : empreintes et présence des fichiers
	d.controlerEmpreintes()
	if d.Illisible != "" {
		return d
	}

	// evenement.json → E-1 ; D-1 compare seq, hash, org_id et journal_id.
	d.Evenement = d.lirePartie("evenement", "E-1")
	ev := d.Evenement
	if ev == nil {
		d.nonExecute("D-1", "evenement.json inexploitable : seq, hash, org_id et journal_id non comparables")
	} else {
		if a, okA := entierTypee(d.Index, "event", "seq"); !func() bool { b, okB := SeqTypee(ev); return okA && okB && a == b }() {
			r.Echec("D-1", "event.seq de l'index ≠ seq de evenement.json (%s)", texteTerme(ev, "seq"))
		}
		for _, k := range [][2]string{{"event.hash", "hash"}, {"org_id", "org_id"}, {"journal_id", "journal_id"}} {
			chemin := strings.Split(k[0], ".")
			a, okA := chaineTypee(d.Index, chemin...)
			b, okB := chaineTypee(ev, k[1])
			if !okA || !okB || a != b {
				r.Echec("D-1", "%s de l'index ≠ %s de evenement.json", k[0], k[1])
			}
		}
		r.Passe("D-1")
	}

	// cles.json → E-8 (première partie) ; exploitable si elle réussit.
	d.controlerCles()

	// E-1 à E-11 sur l'événement prouvé
	if ev != nil {
		res := ControlerEvenement(ev, d.Cles)
		d.evE1E2 = res.parID["E-1"].Etat == EtatPasse && res.parID["E-2"].Etat == EtatPasse
		r.Fusionner(res, "evenement.json")
	} else {
		for _, id := range idsE {
			d.nonExecute(id, "evenement.json inexploitable")
		}
	}

	// Voisins : enveloppe (C-1), événements (E-1 à E-11), C-1 à C-3
	d.controlerVoisins()

	// Manifeste et signature : P-1 à P-5
	d.controlerManifeste()

	// Chemin : M-1 à M-3
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

// controlerIndex valide l'index contre son schéma (D-1) et lit ses parties.
// Rend false quand l'index est contraire à son schéma : D-1 échoue et aucun
// autre contrôle n'est exécuté (§11.4, révision 0.5).
func (d *Dossier) controlerIndex() bool {
	r := d.Resultats
	idx := d.Index
	m := &manquements{}
	if !m.clesExactes(idx, "dossier", []string{"version", "event", "org_id", "journal_id", "generated_at", "parts"}) {
		for _, x := range m.liste {
			r.Echec("D-1", "%s", x)
		}
		return false
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
	parties := map[string]*Partie{}
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
			parties[pa.Name] = pa
		}
	}
	for _, x := range m.liste {
		r.Echec("D-1", "%s", x)
	}
	if len(m.liste) > 0 {
		return false
	}
	d.Parties = parties
	return true
}

// controleDePartie rend l'identifiant de contrôle qu'une partie réservée
// alimente (numérotations T-, O-, R- de CT-6).
func controleDePartie(nom string) string {
	switch nom {
	case "jeton_rfc3161":
		return "T-*"
	case "preuve_ots":
		return "O-*"
	}
	return "R-*"
}

// controlerEmpreintes applique D-2 (§11.4, révision 0.5) : pour chaque partie
// présente, un fichier ordinaire de ce nom et son SHA-256 égal à celui que
// l'index déclare (au-delà de sa limite, le SHA-256 n'est pas comparé, sauf
// pour attestation-perimetre.json, calculé jusqu'à 64 Mio) ; pour chaque
// partie absente, aucun fichier ordinaire de ce nom et une raison qui est
// une chaîne non vide (§3). Une partie réservée présente n'est pas vérifiée
// par ce vérificateur : non exécutée, sans raison admise.
func (d *Dossier) controlerEmpreintes() {
	r := d.Resultats
	for i, pa := range partiesAttendues {
		p := d.Parties[pa.name]
		if p == nil {
			continue
		}
		chemin := filepath.Join(d.Dir, p.File)
		if !p.Present {
			if _, ok := fichierOrdinaire(chemin); ok {
				r.Echec("D-2", "%s déclaré absent mais présent dans le répertoire", p.File)
			}
			if !ChaineNonVide(p.Reason) {
				r.Echec("D-2", "%s absent sans raison qui soit une chaîne non vide (%q)", p.File, p.Reason)
			}
			continue
		}
		if i >= 7 && i <= 11 {
			d.nonExecute(controleDePartie(p.Name), fmt.Sprintf("partie %s présente : vérification de CT-6 non exécutée par ce vérificateur (§11.4, révision 0.5 ; quelle que soit sa taille)", p.Name))
		}
		limite := limiteDe(p.File)
		if p.Name == "attestation_perimetre" {
			limite = PlafondAttestation
		}
		octets, def, msg := lireBorne(chemin, limite)
		switch def {
		case partieManquante:
			r.Echec("D-2", "%s déclaré présent : %s", p.File, msg)
			continue
		case partieTropGrande:
			if p.Name == "attestation_perimetre" {
				d.Illisible, d.TypeErreur = p.File+" "+msg+" : au-delà du plafond de lecture de 64 Mio (CT-6 EX-4.15)", "taille_depassee"
				return
			}
			// SHA-256 non comparé : l'échec est porté par le contrôle de la partie.
			continue
		}
		if got := Hex0x(SHA256(octets)); p.SHA256 != "" && got != p.SHA256 {
			r.Echec("D-2", "%s : SHA-256 du fichier %s ≠ %s déclaré", p.File, got, p.SHA256)
		}
	}
	r.Passe("D-2")
}

// controlerCles lit cles.json (contrôle porteur E-8) et applique la première
// partie de E-8 : schéma, dates, unicité, validités, org_id et journal_id
// égaux à ceux de l'événement prouvé. cles.json n'est exploitable pour les
// autres contrôles qui le lisent que si elle réussit (§11.4, révision 0.5).
func (d *Dossier) controlerCles() {
	r := d.Resultats
	cv := d.lirePartie("cles", "E-8")
	if cv == nil {
		return
	}
	jeu, mq := ChargerClesDossier(cv)
	for _, m := range mq {
		r.Echec("E-8", "cles.json : %s", m)
	}
	exploitable := jeu != nil && len(mq) == 0
	if ev := d.Evenement; ev != nil && jeu != nil {
		for _, k := range []string{"org_id", "journal_id"} {
			attendu := jeu.OrgID
			if k == "journal_id" {
				attendu = jeu.JournalID
			}
			if s, ok := chaineTypee(ev, k); !ok || s != attendu {
				r.Echec("E-8", "cles.json : %s différent de celui de l'événement", k)
				exploitable = false
			}
		}
	} else {
		exploitable = false
	}
	d.clesExploitable = exploitable
	if exploitable {
		d.Cles = jeu
	}
}

func (d *Dossier) controlerVoisins() {
	r := d.Resultats
	ev := d.Evenement
	vo := d.lirePartie("voisins", "C-1")
	d.Voisins = vo
	if vo == nil {
		for _, id := range []string{"C-1", "C-2", "C-3"} {
			d.nonExecute(id, "voisins.json inexploitable")
		}
		return
	}
	// Enveloppe contraire au schéma : C-1 échoue, la partie reste exploitable.
	m := &manquements{}
	m.clesExactes(vo, "voisins", []string{"version", "previous", "next"})
	if ver := vo.Get("version"); ver != nil && (ver.Kind != KindNumber || ver.Num != "0") {
		m.add("voisins.version", "constante 0 attendue")
	}
	for _, x := range m.liste {
		r.Echec("C-1", "%s", x)
	}
	prev, next := vo.Get("previous"), vo.Get("next")
	// Les deux voisins sont des événements du dossier, soumis à E-1 à E-11 ;
	// un voisin qui n'est ni un objet ni null est un événement qui n'est pas
	// un objet : E-1 échoue pour lui.
	for _, x := range []struct {
		nom string
		v   *Value
	}{{"previous", prev}, {"next", next}} {
		if x.v != nil && !x.v.IsNull() {
			r.Fusionner(ControlerEvenement(x.v, d.Cles), "voisins."+x.nom)
			// Règle d'origine de C-2 sur chaque événement du dossier, voisins
			// compris (§11.4, révision 0.5).
			if estObjet(x.v) {
				if m, faux := origineFausse(x.v); faux {
					r.Echec("C-2", "voisins.%s : %s", x.nom, m)
				}
			}
		}
	}
	if ev == nil {
		for _, id := range []string{"C-1", "C-2", "C-3"} {
			d.nonExecute(id, "evenement.json inexploitable : couples non évaluables")
		}
		return
	}
	etiquetteEv := fmt.Sprintf("evenement.json (seq %s)", texteTerme(ev, "seq"))
	seq, okSeq := SeqTypee(ev)
	switch {
	case prev == nil:
		r.Echec("C-1", "previous absent : « null si et seulement si seq = 1 » non évaluable")
	case !okSeq:
		r.Echec("C-1", "seq de l'événement %s n'est pas un entier : « previous null si et seulement si seq = 1 » non tenue", texteTerme(ev, "seq"))
	case prev.IsNull() != (seq == 1):
		r.Echec("C-1", "previous %s pour seq %d (null si et seulement si seq = 1)", sorteNulle(prev), seq)
	}
	ControlerPremier(r, ev, etiquetteEv)
	if prev != nil && !prev.IsNull() {
		ControlerPaire(r, prev, ev, fmt.Sprintf("previous (seq %s) → %s", texteTerme(prev, "seq"), etiquetteEv))
	}
	if next != nil && !next.IsNull() {
		ControlerPaire(r, ev, next, fmt.Sprintf("%s → next (seq %s)", etiquetteEv, texteTerme(next, "seq")))
	}
	// Membre previous ou next absent : voisin qui n'est pas un objet (§11.4,
	// révision 0.5, règle unique) : C-1 (enveloppe), C-2 et C-3, dont une
	// relation l'a pour terme, échouent ; E-1 ne le concerne pas.
	for _, x := range []struct {
		nom string
		v   *Value
	}{{"previous", prev}, {"next", next}} {
		if x.v == nil {
			r.Echec("C-1", "voisins.%s absent : relation de seq non tenue", x.nom)
			r.Echec("C-2", "voisins.%s absent : relation de hash non tenue", x.nom)
			r.Echec("C-3", "voisins.%s absent : relation de clé non tenue", x.nom)
		}
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
	d.Manifeste = d.lirePartie("manifeste", "P-1")
	d.ManifesteSig = d.lirePartie("manifeste_sig", "P-5")
	mf := d.Manifeste
	if mf == nil {
		for _, id := range []string{"P-1", "P-2", "P-3", "P-4", "P-5"} {
			d.nonExecute(id, "manifeste.json inexploitable")
		}
		return
	}
	// P-1 (schéma, arithmétique, identifiants non nuls), P-4, P-5 ; P-5 lit
	// manifeste.sig et cles.json : l'un inexploitable, elle n'est pas exécutée,
	// sauf échec sur ce qu'elle lit des autres parties.
	if d.ManifesteSig == nil {
		d.nonExecute("P-5", "manifeste.sig inexploitable")
	} else if d.Cles == nil {
		d.nonExecute("P-5", "cles.json inexploitable (première partie de E-8 en échec ou non exécutée)")
	}
	r.Fusionner(ControlerManifeste(mf, d.ManifesteSig, d.Cles), "")
	// P-1 : org_id et journal_id égaux à ceux de l'événement.
	if ev == nil {
		d.nonExecute("P-1", "evenement.json inexploitable : org_id et journal_id non comparables")
	} else {
		for _, k := range []string{"org_id", "journal_id"} {
			a, okA := chaineTypee(mf, k)
			b, okB := chaineTypee(ev, k)
			if !okA || !okB || a != b {
				r.Echec("P-1", "%s du manifeste différent de celui de l'événement", k)
			}
		}
	}
	fs, okFs := entierTypee(mf, "first_seq")
	ls, okLs := entierTypee(mf, "last_seq")
	ps, okPs := entierTypee(mf, "period_start")
	pe, okPe := entierTypee(mf, "period_end")
	// P-2
	if ev == nil {
		d.nonExecute("P-2", "evenement.json inexploitable")
	} else {
		seq, okSeq := SeqTypee(ev)
		switch {
		case !okSeq || !okFs || !okLs:
			r.Echec("P-2", "seq %s, first_seq ou last_seq qui n'est pas un entier : relation non tenue", texteTerme(ev, "seq"))
		case seq < fs || seq > ls:
			r.Echec("P-2", "seq %d hors de [first_seq %d, last_seq %d]", seq, fs, ls)
		}
		ts, okTs := TsTypee(ev)
		switch {
		case !okTs || !okPs || !okPe:
			r.Echec("P-2", "ts %s, period_start ou period_end incalculable : relation non tenue", texteTerme(ev, "ts"))
		case ts.UnixMilli() < ps*1000 || ts.UnixMilli() >= pe*1000:
			r.Echec("P-2", "ts %s hors de [period_start %d, period_end %d)", FormaterHorodatage(ts), ps, pe)
		}
		r.Passe("P-2")
	}
	// P-3 : un voisin dans la période par seq y est aussi par ts ; un voisin hors
	// période est adjacent, avant period_start (previous) ou à partir de
	// period_end (next) ; sinon le manifeste a tronqué sa période (§7.2).
	if d.Voisins == nil {
		d.nonExecute("P-3", "voisins.json inexploitable")
		return
	}
	for _, nom := range []string{"previous", "next"} {
		v := d.Voisins.Get(nom)
		if v == nil {
			r.Echec("P-3", "voisin %s absent : relation non tenue", nom)
			continue
		}
		if v.IsNull() {
			continue
		}
		vs, okVs := SeqTypee(v)
		ts, okTs := TsTypee(v)
		if !okVs || !okTs || !okFs || !okLs || !okPs || !okPe {
			r.Echec("P-3", "voisin %s : seq, ts ou bornes du manifeste incalculables : relation non tenue", nom)
			continue
		}
		dans := ts.UnixMilli() >= ps*1000 && ts.UnixMilli() < pe*1000
		switch {
		case vs >= fs && vs <= ls:
			if !dans {
				r.Echec("P-3", "voisin %s (seq %d) dans la période par seq mais ts %s hors de la période", nom, vs, FormaterHorodatage(ts))
			}
		case vs != fs-1 && vs != ls+1:
			r.Echec("P-3", "voisin %s (seq %d) hors période sans être first_seq - 1 ni last_seq + 1", nom, vs)
		case (nom == "previous" && ts.UnixMilli() >= ps*1000) || (nom == "next" && ts.UnixMilli() < pe*1000):
			r.Echec("P-3", "voisin %s (seq %d) hors de l'intervalle de seq du manifeste mais horodaté %s, dans la période : manifeste tronqué", nom, vs, FormaterHorodatage(ts))
		}
	}
	r.Passe("P-3")
}

func (d *Dossier) controlerChemin() {
	r := d.Resultats
	d.Chemin = d.lirePartie("chemin", "M-2")
	ch := d.Chemin
	if ch == nil {
		d.nonExecute("M-1", "chemin.json inexploitable")
		d.nonExecute("M-3", "chemin.json inexploitable")
		return
	}
	// Schéma (M-2) ; la partie contraire à son schéma reste exploitable : M-1 et
	// M-3 s'exécutent sur les valeurs lues (révision 0.5).
	m := &manquements{}
	m.clesExactes(ch, "chemin", []string{"version", "tree_size", "leaf_index", "leaf_hash", "path", "root"})
	if ver := ch.Get("version"); ver == nil || ver.Kind != KindNumber || ver.Num != "0" {
		m.add("chemin.version", "constante 0 attendue")
	}
	treeSize, okTs := m.entier(ch.Get("tree_size"), "chemin.tree_size", 1, EntierSurMax)
	leafIndex, okLi := m.entier(ch.Get("leaf_index"), "chemin.leaf_index", 0, EntierSurMax-1)
	var leafHash, root []byte
	if s, ok := m.hex(ch.Get("leaf_hash"), "chemin.leaf_hash", 32, false); ok {
		leafHash, _ = OctetsHex(s, 32)
	}
	if s, ok := m.hex(ch.Get("root"), "chemin.root", 32, false); ok {
		root, _ = OctetsHex(s, 32)
	}
	var path [][]byte
	okPath := false
	if p := ch.Get("path"); p == nil || p.Kind != KindArray {
		m.add("chemin.path", "tableau attendu")
	} else {
		okPath = true
		if len(p.Arr) > 64 {
			m.add("chemin.path", "plus de 64 éléments")
		}
		for i, x := range p.Arr {
			if s, okh := m.hex(x, fmt.Sprintf("chemin.path[%d]", i), 32, false); okh {
				b, _ := OctetsHex(s, 32)
				path = append(path, b)
			} else {
				okPath = false
			}
		}
	}
	for _, x := range m.liste {
		r.Echec("M-2", "%s", x)
	}
	// M-2 : algorithme de la section 9.3 (un terme mal typé l'a déjà mise en échec).
	if okTs && okLi && okPath && leafHash != nil && root != nil {
		if err := VerifierInclusion(leafHash, uint64(leafIndex), uint64(treeSize), path, root); err != nil {
			r.Echec("M-2", "%v", err)
		}
	}
	r.Passe("M-2")
	// M-1
	switch {
	case d.Evenement == nil:
		d.nonExecute("M-1", "evenement.json inexploitable")
	case leafHash == nil:
		r.Echec("M-1", "leaf_hash absent ou mal typé : relation non tenue")
	default:
		if hash, ok := HashCalculable(d.Evenement); !ok {
			r.Echec("M-1", "hash de l'événement non calculable")
		} else if got := Feuille(hash); Hex0x(got) != Hex0x(leafHash) {
			r.Echec("M-1", "leaf_hash %s ≠ SHA-256(0x00 || hash recalculé) = %s", Hex0x(leafHash), Hex0x(got))
		}
		r.Passe("M-1")
	}
	// M-3
	mf := d.Manifeste
	if mf == nil {
		d.nonExecute("M-3", "manifeste.json inexploitable")
		return
	}
	if mr, ok := chaineTypee(mf, "root"); root == nil || !ok || Hex0x(root) != mr {
		r.Echec("M-3", "chemin.root %s ≠ manifeste.root %s", texteTerme(ch, "root"), texteTerme(mf, "root"))
	}
	if ct, ok := entierTypee(mf, "count"); !okTs || !ok || treeSize != ct {
		r.Echec("M-3", "chemin.tree_size %s ≠ manifeste.count %s", texteTerme(ch, "tree_size"), texteTerme(mf, "count"))
	}
	if d.Evenement == nil {
		d.nonExecute("M-3", "evenement.json inexploitable : leaf_index = seq − first_seq non comparable")
		return
	}
	seq, okSeq := SeqTypee(d.Evenement)
	fs, okFs := entierTypee(mf, "first_seq")
	if !okSeq || !okFs || !okLi || leafIndex != seq-fs {
		r.Echec("M-3", "chemin.leaf_index %s ≠ seq − first_seq (seq %s, first_seq %s)", texteTerme(ch, "leaf_index"), texteTerme(d.Evenement, "seq"), texteTerme(mf, "first_seq"))
	}
	r.Passe("M-3")
}

// RaisonAucuneApprobation est la raison d'absence exacte de
// approbations.json quand approval vaut null (§11.1, A-1, révision 0.5).
const RaisonAucuneApprobation = "aucune approbation liée"

func (d *Dossier) controlerApprobations() {
	r := d.Resultats
	ev := d.Evenement
	p := d.Parties["approbations"]
	present := p != nil && p.Present
	if ev == nil {
		for _, id := range []string{"A-1", "A-2", "A-3", "A-4"} {
			d.nonExecute(id, "evenement.json inexploitable")
		}
		// Les événements d'une partie exploitable restent soumis à E-1 à E-11.
		if present {
			if ap := d.lirePartie("approbations", "A-1"); ap != nil {
				d.Approbations = ap
				d.controlerEvenementsApprobations(ap)
			}
		}
		return
	}
	approval := ev.Get("approval")
	switch {
	case approval == nil || (approval.Kind != KindNull && approval.Kind != KindObject):
		// §11.4, « Autres termes mal typés » (révision 0.5) : A-1 à A-4, dont
		// les relations lisent approval, échouent ; pour A-4, request_hash ne
		// se lit pas.
		for _, id := range []string{"A-1", "A-2", "A-3", "A-4"} {
			r.Echec(id, "approval absent, ou ni null ni objet : relation non tenue")
		}
		if present {
			if ap := d.lirePartie("approbations", "A-1"); ap != nil {
				d.Approbations = ap
				d.controlerEvenementsApprobations(ap)
			}
		}
		return
	case approval.IsNull():
		// A-1 : la partie déclarée absente avec la raison exacte.
		if !present && p != nil && p.Reason == RaisonAucuneApprobation {
			r.Passe("A-1")
			for _, id := range []string{"A-2", "A-3", "A-4"} {
				d.nonExecuteAdmis(id, "aucune approbation liée : partie absente", RaisonNEPartieAbsent)
			}
			return
		}
		if present {
			r.Echec("A-1", "approbations.json présent alors que approval est null")
			if ap := d.lirePartie("approbations", "A-1"); ap != nil {
				d.Approbations = ap
				d.controlerEvenementsApprobations(ap)
			}
		} else if p != nil {
			r.Echec("A-1", "raison d'absence %q, attendu « %s »", p.Reason, RaisonAucuneApprobation)
		}
		for _, id := range []string{"A-2", "A-3", "A-4"} {
			d.nonExecute(id, "A-1 en échec (approval null)")
		}
		return
	}

	// approval est un objet.
	var ap *Value
	if !present {
		r.Echec("A-1", "approbations.json déclaré absent alors que approval n'est pas null")
		d.nonExecute("A-2", "approbations.json absent")
		d.nonExecute("A-3", "approbations.json absent")
	} else {
		ap = d.lirePartie("approbations", "A-1")
		if ap == nil {
			d.nonExecute("A-2", "approbations.json inexploitable")
			d.nonExecute("A-3", "approbations.json inexploitable")
		}
	}
	if ap != nil {
		d.Approbations = ap
		d.controlerEnveloppeApprobations(ap, approval)
	}
	// A-4 : lit evenement.json et voisins.json seulement.
	d.controlerDemande(approval)
}

// controlerEvenementsApprobations soumet chaque événement de events à E-1 à
// E-11 (§11.4 : les événements d'une partie exploitable).
func (d *Dossier) controlerEvenementsApprobations(ap *Value) {
	if events := ap.Get("events"); events != nil && events.Kind == KindArray {
		for i, e := range events.Arr {
			d.Resultats.Fusionner(ControlerEvenement(e, d.Cles), fmt.Sprintf("approbations.events[%d]", i))
		}
	}
}

// controlerEnveloppeApprobations applique A-1 (enveloppe, ticket,
// request_hash), A-2 et A-3 à une partie exploitable ; une enveloppe
// contraire au schéma met A-1 en échec et A-2, A-3 s'exécutent sur les
// valeurs lues (CT-6 EX-5.16).
func (d *Dossier) controlerEnveloppeApprobations(ap, approval *Value) {
	r := d.Resultats
	ev := d.Evenement
	m := &manquements{}
	m.clesExactes(ap, "approbations", []string{"version", "ticket", "request_hash", "approver_set", "events"})
	if ver := ap.Get("version"); ver == nil || ver.Kind != KindNumber || ver.Num != "0" {
		m.add("approbations.version", "constante 0 attendue")
	}
	m.chaine(ap.Get("ticket"), "approbations.ticket", 1, 128, false)
	m.hex(ap.Get("request_hash"), "approbations.request_hash", 32, false)
	as := ap.Get("approver_set")
	m.clesExactes(as, "approbations.approver_set", []string{"threshold", "members", "source"})
	th := as.Get("threshold")
	m.clesExactes(th, "approbations.approver_set.threshold", []string{"required", "size"})
	required, okReq := m.entier(th.Get("required"), "approbations.approver_set.threshold.required", 1, 65535)
	size, okSize := m.entier(th.Get("size"), "approbations.approver_set.threshold.size", 1, 65535)
	var members []string
	okMembers := false
	if mb := as.Get("members"); mb == nil || mb.Kind != KindArray || len(mb.Arr) < 1 {
		m.add("approbations.approver_set.members", "tableau non vide attendu")
	} else {
		okMembers = true
		vus := map[string]bool{}
		for i, x := range mb.Arr {
			if s, ok := m.hex(x, fmt.Sprintf("approbations.approver_set.members[%d]", i), 20, false); ok {
				if vus[s] {
					m.add("approbations.approver_set.members", "adresse %s en double", s)
				}
				vus[s] = true
				members = append(members, s)
			} else {
				okMembers = false
			}
		}
	}
	m.chaine(as.Get("source"), "approbations.approver_set.source", 1, 256, false)
	events := ap.Get("events")
	if events == nil || events.Kind != KindArray || len(events.Arr) < 1 {
		m.add("approbations.events", "tableau non vide attendu")
	}
	for _, x := range m.liste {
		r.Echec("A-1", "%s", x)
	}
	for _, k := range []string{"ticket", "request_hash"} {
		a, okA := chaineTypee(ap, k)
		b, okB := chaineTypee(approval, k)
		if !okA || !okB || a != b {
			r.Echec("A-1", "%s %q ≠ approval.%s %q", k, a, k, b)
		}
	}
	r.Passe("A-1")

	// A-2 : chaque décision est soumise à E-1 à E-11 (l'échec est porté par
	// la vérification E- concernée, CT-6 EX-5.16), est une décision du même
	// ticket (approval et A égaux) ; une décision précède l'appel relayé
	// qu'elle autorise (seq, approval.at ≤ ts) ; le dossier d'une décision la
	// contient dans events.
	evEstDecision := Outil(ev) == OutilApprobation
	hashEv, okHashEv := HashCalculable(ev)
	seqEv, okSeqEv := SeqTypee(ev)
	tsEv, okTsEv := TsTypee(ev)
	prouveDansEvents := false
	if events != nil && events.Kind == KindArray {
		for i, e := range events.Arr {
			etiq := fmt.Sprintf("approbations.events[%d]", i)
			r.Fusionner(ControlerEvenement(e, d.Cles), etiq)
			if t, ok := chaineTypee(e, "execution", "tool"); !ok || t != OutilApprobation {
				r.Echec("A-2", "%s : execution.tool %q, attendu %s", etiq, t, OutilApprobation)
			}
			if !memeCanonique(e.Get("approval"), approval) {
				r.Echec("A-2", "%s : approval différent, clé pour clé, de celui de l'événement prouvé", etiq)
			}
			val := valeurAu(e, "execution", "arguments", "value")
			if a, ok := ObjetA(ev); val == nil || !ok || !memeCanonique(val, a) {
				r.Echec("A-2", "%s : execution.arguments.value ≠ A = {decision, journal_id, org_id, request_hash, ticket}", etiq)
			}
			if !evEstDecision {
				if s, ok := SeqTypee(e); !ok || !okSeqEv || s >= seqEv {
					r.Echec("A-2", "%s : seq %s n'est pas antérieur à celui de l'appel relayé (%s)", etiq, texteTerme(e, "seq"), texteTerme(ev, "seq"))
				}
			}
			if h, ok := HashCalculable(e); ok && okHashEv && Hex0x(h) == Hex0x(hashEv) {
				prouveDansEvents = true
			}
		}
	}
	if !evEstDecision {
		at, okAt := chaineTypee(approval, "at")
		tAt, okDate := ParseHorodatage(at)
		switch {
		case !okAt || !okDate || !okTsEv:
			r.Echec("A-2", "approval.at ou ts de l'appel relayé qui n'est pas une date existante : relation non tenue")
		case tAt.After(tsEv):
			r.Echec("A-2", "approval.at %s postérieur au ts de l'appel relayé %s", FormaterHorodatage(tAt), FormaterHorodatage(tsEv))
		}
	} else if !prouveDansEvents {
		r.Echec("A-2", "l'événement prouvé est une décision mais ne figure pas dans events")
	}
	r.Passe("A-2")

	// A-3 : approbateurs distincts, membres du jeu déclaré, au seuil ; seuil
	// de l'événement = seuil du jeu ; required ≤ size = nombre de membres ;
	// pour expire, aucune signature.
	decision, _ := chaineTypee(approval, "decision")
	approvers := approval.Get("approvers")
	var adresses []string
	if approvers == nil || approvers.Kind != KindArray {
		r.Echec("A-3", "approval.approvers n'est pas un tableau")
	} else {
		vus := map[string]bool{}
		for i, a := range approvers.Arr {
			s, ok := chaineTypee(a)
			if !ok {
				r.Echec("A-3", "approval.approvers[%d] n'est pas une chaîne", i)
				continue
			}
			if vus[s] {
				r.Echec("A-3", "approbateur %s en double", s)
			}
			vus[s] = true
			adresses = append(adresses, s)
			if !okMembers || !dansEnum(s, members) {
				r.Echec("A-3", "approbateur %s hors du jeu déclaré approver_set.members", s)
			}
		}
	}
	evReq, okER := entierTypee(approval, "threshold", "required")
	evSize, okES := entierTypee(approval, "threshold", "size")
	if !okER || !okES || !okReq || !okSize || evReq != required || evSize != size {
		r.Echec("A-3", "threshold de l'événement {%s, %s} ≠ approver_set.threshold {%s, %s}", texteTerme(approval.Get("threshold"), "required"), texteTerme(approval.Get("threshold"), "size"), texteTerme(th, "required"), texteTerme(th, "size"))
	}
	if !okReq || !okSize || required > size {
		r.Echec("A-3", "required %s > size %s, ou incalculable", texteTerme(th, "required"), texteTerme(th, "size"))
	}
	if !okSize || !okMembers || int64(len(members)) != size {
		r.Echec("A-3", "size %s ≠ nombre de membres déclarés %d", texteTerme(th, "size"), len(members))
	}
	switch decision {
	case "expire":
		if sg := approval.Get("signatures"); sg == nil || sg.Kind != KindArray || len(sg.Arr) != 0 {
			r.Echec("A-3", "decision expire avec des signatures")
		}
	default:
		if !okReq || int64(len(adresses)) < required {
			r.Echec("A-3", "%d approbateur(s) pour un seuil de %s", len(adresses), texteTerme(th, "required"))
		}
	}
	r.Passe("A-3")
}

// controlerDemande applique A-4 (§11.4, révision 0.5 ; CT-6 EX-5.18) : la
// demande est le voisin dont le hash recalculé égale request_hash ; s'il y en
// a un, son status vaut retenue. Aucun voisin ne l'étant : non exécutée,
// raison admise ; voisins.json inexploitable : non exécutée, sans raison
// admise.
func (d *Dossier) controlerDemande(approval *Value) {
	r := d.Resultats
	if d.Voisins == nil {
		d.nonExecute("A-4", "voisins.json inexploitable : demande non recherchée")
		return
	}
	requestHash, okRH := chaineTypee(approval, "request_hash")
	if !okRH {
		r.Echec("A-4", "approval.request_hash absent ou mal typé : demande non désignée")
		return
	}
	trouve := false
	for _, nom := range []string{"previous", "next"} {
		v := d.Voisins.Get(nom)
		h, ok := HashCalculable(v)
		if !ok || Hex0x(h) != requestHash {
			continue
		}
		trouve = true
		if st, ok := chaineTypee(v, "execution", "status"); !ok || st != "retenue" {
			r.Echec("A-4", "événement de demande (voisin %s, seq %s) : status %q, attendu retenue", nom, texteTerme(v, "seq"), st)
		}
	}
	if !trouve {
		d.nonExecuteAdmis("A-4", "événement de demande (request_hash) hors du dossier : non vérifiable", RaisonNEHorsDossier)
		return
	}
	r.Passe("A-4")
}

func (d *Dossier) enoncerBornes() {
	var absentes, presentes []string
	for _, pa := range partiesAttendues[7:12] {
		if p := d.Parties[pa.name]; p == nil || !p.Present {
			absentes = append(absentes, pa.file)
		} else {
			presentes = append(presentes, pa.file)
		}
	}
	if len(presentes) > 0 {
		d.Bornes = append(d.Bornes,
			"parties réservées présentes ("+strings.Join(presentes, ", ")+") : vérifiées par CT-6 (contrôles 4, 5, 8), non par ce vérificateur de CT-1 seul, qui ne rend donc pas ce dossier valide (§11.4, révision 0.5)")
	}
	if len(absentes) == 0 {
		return
	}
	d.Bornes = append(d.Bornes,
		"verdict borné (CT-1 §11.3) : les contrôles 4 et 5 (jeton RFC 3161, preuve OpenTimestamps ; CT-5) et 8 (registre, certificat de commit, validateurs ; CT-4) ne sont pas exécutables, parties absentes : "+strings.Join(absentes, ", "),
		"ce que le dossier établit au mieux : l'événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste signé par cette clé, approuvé par les signatures EIP-191 recouvrées (contrôle 7) ; rien n'est établi sur la date ni sur l'ancre")
}

// ---------------------------------------------------------------- K-1 à K-9

// validerPartiePoints transcrit #/$defs/points_de_controle (K-1, schéma).
func validerPartiePoints(v *Value) (point, consistency, anchors *Value, liste []string) {
	m := &manquements{}
	if !m.clesExactes(v, "points_de_controle", []string{"version", "checkpoint", "checkpoint_hash", "consistency", "anchors"}) {
		return nil, nil, nil, m.liste
	}
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
	return point, consistency, anchors, m.liste
}

// controlerPointsDeControle exécute K-1 à K-9 (révision 0.3 ; précisions de
// la révision 0.5) sur la treizième partie quand l'index la déclare
// présente. Index à douze parties ou partie absente avec raison : les neuf
// ne sont pas exécutées et ne figurent pas au rapport (§11.4, CT-6 EX-5.7).
// Partie inexploitable : K-1 en échec (cas b, c, e) ou non exécutée (cas a :
// D-2 ; cas d : E-2) ; K-1 contrôle le schéma de la partie même quand P-1 n'a
// pas réussi ou que evenement.json est inexploitable, et n'est sinon pas
// exécutée ; K-1 sans réussite : K-2 à K-9 non exécutées, sans raison admise.
func (d *Dossier) controlerPointsDeControle() {
	r := d.Resultats
	pa := d.Parties["points_de_controle"]
	if pa == nil || !pa.Present {
		return
	}
	prerequis := func(raison string) {
		for _, id := range idsK[1:] {
			d.nonExecute(id, raison)
		}
	}
	v := d.lirePartie("points_de_controle", "K-1")
	if v == nil {
		prerequis("points-de-controle.json inexploitable")
		return
	}
	point, consistency, anchors, defauts := validerPartiePoints(v)
	for _, x := range defauts {
		r.Echec("K-1", "%s", x)
	}
	if len(defauts) > 0 {
		prerequis("K-1 en échec")
		return
	}
	ev := d.Evenement
	if ev == nil || !d.reussi("P-1") {
		d.nonExecute("K-1", "P-1 n'a pas réussi ou evenement.json est inexploitable : relations au manifeste et à l'événement non comparables")
		prerequis("K-1 non exécutée")
		return
	}
	mf := d.Manifeste
	pt := LirePoint(point)
	m := &manquements{}
	for _, k := range []string{"org_id", "journal_id"} {
		if a, ok := chaineTypee(ev, k); !ok || a != chaineDe(point, k) {
			m.add("points_de_controle.checkpoint."+k, "différent de celui de l'événement")
		}
	}
	mps, _ := entierTypee(mf, "period_start")
	mcount, _ := entierTypee(mf, "count")
	mfs, _ := entierTypee(mf, "first_seq")
	if pt.PeriodStart != mps {
		m.add("points_de_controle.checkpoint.period_start", "%d différent de celui du manifeste %d", pt.PeriodStart, mps)
	}
	if pt.TreeSize < 1 || pt.TreeSize > mcount {
		m.add("points_de_controle.checkpoint.tree_size", "%d hors de [1, count = %d]", pt.TreeSize, mcount)
	}
	if pt.LastSeq != mfs+pt.TreeSize-1 {
		m.add("points_de_controle.checkpoint.last_seq", "%d différent de first_seq + tree_size - 1 (%d)", pt.LastSeq, mfs+pt.TreeSize-1)
	}
	if pt.Root == Zero32 {
		m.add("points_de_controle.checkpoint.root", "racine nulle")
	}
	if pt.TsOK && pt.CheckpointTs.UnixMilli() < pt.PeriodStart*1000 {
		m.add("points_de_controle.checkpoint.checkpoint_ts", "%s antérieur à period_start", FormaterHorodatage(pt.CheckpointTs))
	}
	for _, x := range m.liste {
		r.Echec("K-1", "%s", x)
	}
	if len(m.liste) > 0 {
		prerequis("K-1 en échec")
		return
	}
	r.Passe("K-1")
	mroot, _ := chaineTypee(mf, "root")

	// K-2 : checkpointHash recalculé
	if hash, _, err := CheckpointHash(point); err != nil {
		r.Echec("K-2", "point non canonisable : %v", err)
	} else {
		d.checkpointHash = hash
		if got, att := Hex0x(hash), chaineDe(v, "checkpoint_hash"); got != att {
			r.Echec("K-2", "checkpointHash recalculé %s ≠ checkpoint_hash déclaré %s", got, att)
		}
	}
	r.Passe("K-2")

	// K-3 : signature sous la clé key_id de cles.json et validité annoncée
	if d.Cles == nil {
		d.nonExecute("K-3", "cles.json inexploitable (première partie de E-8)")
	} else if cle := d.Cles.Trouver(pt.KeyID); cle == nil {
		r.Echec("K-3", "clé %q absente de cles.json", pt.KeyID)
	} else {
		if err := VerifierSignaturePoint(point, cle); err != nil {
			r.Echec("K-3", "signature du point sous %s : %v", pt.KeyID, err)
		}
		if !cle.Couvre(pt.CheckpointTs) {
			r.Echec("K-3", "checkpoint_ts %s hors de la validité annoncée %s de la clé %s", FormaterHorodatage(pt.CheckpointTs), cle.Intervalle(), pt.KeyID)
		}
		r.Passe("K-3")
	}

	// K-4 : couverture de l'événement prouvé ; non exécutée quand M-3 n'a pas réussi.
	if d.Chemin == nil || !d.reussi("M-3") {
		d.nonExecute("K-4", "chemin.json inexploitable ou M-3 sans réussite")
	} else {
		if li, ok := entierTypee(d.Chemin, "leaf_index"); !ok || li >= pt.TreeSize {
			r.Echec("K-4", "leaf_index %s n'est pas strictement inférieur à tree_size %d : le point ne couvre pas l'événement", texteTerme(d.Chemin, "leaf_index"), pt.TreeSize)
		}
		if ts, ok := TsTypee(ev); !ok || ts.After(pt.CheckpointTs) {
			r.Echec("K-4", "ts de l'événement %s postérieur à checkpoint_ts %s, ou incalculable", texteTerme(ev, "ts"), FormaterHorodatage(pt.CheckpointTs))
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
	if ss != mcount {
		r.Echec("K-5", "consistency.second_size %d ≠ manifeste.count %d", ss, mcount)
	}
	if fr != pt.Root {
		r.Echec("K-5", "consistency.first_root ≠ checkpoint.root")
	}
	if sr != mroot {
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
	// (événement prouvé ou voisin) ; hors du dossier : raison admise ;
	// voisins.json inexploitable : sans raison admise (révision 0.5).
	candidats := []*Value{ev}
	if d.Voisins != nil {
		for _, nom := range []string{"previous", "next"} {
			if x := d.Voisins.Get(nom); x != nil && !x.IsNull() {
				candidats = append(candidats, x)
			}
		}
	}
	var trouve *Value
	for _, c := range candidats {
		if s, ok := SeqTypee(c); ok && s == pt.LastSeq {
			trouve = c
			break
		}
	}
	switch {
	case trouve != nil:
		if h, ok := HashCalculable(trouve); !ok {
			d.nonExecute("K-6", "hash de l'événement last_seq non calculable")
		} else if Hex0x(h) != pt.LastHash {
			r.Echec("K-6", "last_hash %s ≠ hash recalculé %s de l'événement seq %d", pt.LastHash, Hex0x(h), pt.LastSeq)
		} else {
			r.Passe("K-6")
		}
	case d.Voisins == nil:
		d.nonExecute("K-6", "voisins.json inexploitable : événement last_seq non recherché")
	default:
		d.nonExecuteAdmis("K-6", fmt.Sprintf("événement last_seq (seq %d) hors du dossier : non vérifiable", pt.LastSeq), RaisonNEHorsDossier)
	}

	d.controlerAncresPoint(pt, anchors)
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

// LibelleDocTypePoint est le libellé du docType d'une ancre de point de
// contrôle (CT-4 §6.4) ; docType = keccak256(utf8(libellé)).
const LibelleDocTypePoint = "noortrace/point-de-controle/v0"

// controlerAncresPoint fixe l'état de K-7 à K-9 quand K-1 a réussi (§11.4,
// révision 0.5) : K-2 sans réussite, non exécutées sans raison admise ; ancre
// nulle : non exécutée, raison admise (partie absente) ; ancre non nulle :
// K-7 et K-9 non exécutées sans raison admise (vérifications T- et O- de
// CT-6, que ce vérificateur de CT-1 seul n'exécute pas) ; K-8 recalcule
// fingerprint = keccak256(org_id ‖ journal_id ‖ checkpointHash) et compare
// doc_type (un écart la met en échec), et n'est sinon pas exécutée, sans
// raison admise (fichier d'ancres et vérifications R- de CT-6).
func (d *Dossier) controlerAncresPoint(pt *Point, anchors *Value) {
	r := d.Resultats
	for _, x := range []struct{ id, nom, quoi string }{{"K-7", "rfc3161", "jeton RFC 3161 (T-1 à T-11 de CT-6)"}, {"K-8", "registry", "ancre au registre (R- de CT-6)"}, {"K-9", "ots", "preuve OpenTimestamps (O-1 à O-7 de CT-6)"}} {
		if !d.reussi("K-2") {
			d.nonExecute(x.id, "K-2 sans réussite")
			continue
		}
		a := anchors.Get(x.nom)
		if a == nil || a.IsNull() {
			d.nonExecuteAdmis(x.id, "ancre "+x.nom+" nulle : partie absente", RaisonNEPartieAbsent)
			continue
		}
		if x.id == "K-8" {
			org, err1 := OctetsHex(pt.OrgID, 32)
			jr, err2 := OctetsHex(pt.JournalID, 32)
			if err1 == nil && err2 == nil && d.checkpointHash != nil {
				attendue := Hex0x(Keccak256(append(append(append([]byte{}, org...), jr...), d.checkpointHash...)))
				if got := chaineDe(a, "fingerprint"); got != attendue {
					r.Echec("K-8", "anchors.registry.fingerprint %s ≠ keccak256(org_id ‖ journal_id ‖ checkpointHash) = %s", got, attendue)
				}
			}
			if got, att := chaineDe(a, "doc_type"), Hex0x(Keccak256([]byte(LibelleDocTypePoint))); got != att {
				r.Echec("K-8", "anchors.registry.doc_type %s ≠ docType de %s (CT-4 §6.4) %s", got, LibelleDocTypePoint, att)
			}
		}
		d.nonExecute(x.id, x.quoi+" : vérification de CT-6 non exécutée par ce vérificateur (§11.4, révision 0.5)")
	}
}
