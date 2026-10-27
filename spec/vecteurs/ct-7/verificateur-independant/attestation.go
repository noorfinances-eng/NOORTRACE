// Attestation de périmètre (CT-7 section 7) : condensé D_P =
// keccak256(P_P ‖ JCS(P)) (EX-7.6), signature EIP-191 de CT-1 §6.3 avec D_P
// à la place de D_A, et vérifications AT-1 à AT-4 hors dossier (EX-7.16 :
// une attestation signée et un jeu, avant de la joindre), dans la forme des
// cas de ct-7/attestations (#/$defs/cas_attestation).
//
// Prérequis (CT-1 §11.4, révision 0.4, repris par EX-7.16) : AT-2 et AT-3
// exigent AT-1 réussie, AT-4 exige AT-3 réussie ; une AT- non exécutée faute
// de prérequis porte la raison prerequis_en_echec.

package main

import (
	"fmt"
	"time"
)

// PrefixeAttestation est P_P (7.2) : 35 octets.
const PrefixeAttestation = "noortrace/attestation-perimetre/v0\n"

// CondenseAttestation rend D_P d'une attestation P.
func CondenseAttestation(p *Value) ([]byte, error) {
	c, err := Canonique(p)
	if err != nil {
		return nil, err
	}
	return Keccak256(append([]byte(PrefixeAttestation), c...)), nil
}

// StatutAT est le statut d'une vérification AT-.
type StatutAT struct {
	ID, Statut, Raison string // Raison "" : null
}

// ResultatAttestation est ce que rejouent les cas hors dossier.
type ResultatAttestation struct {
	Statuts   []StatutAT
	Details   map[string][]string
	Digest    string    // "" : null (AT-1 en échec)
	Recouvres []*string // nil : null (AT-1 en échec) ; élément nil : non recouvrée
	Retenue   bool
}

// Statut rend le statut d'une vérification.
func (r *ResultatAttestation) Statut(id string) string {
	for _, s := range r.Statuts {
		if s.ID == id {
			return s.Statut
		}
	}
	return ""
}

func (r *ResultatAttestation) poser(id, statut, raison string) {
	for i := range r.Statuts {
		if r.Statuts[i].ID == id {
			r.Statuts[i] = StatutAT{id, statut, raison}
			return
		}
	}
	r.Statuts = append(r.Statuts, StatutAT{id, statut, raison})
}

func (r *ResultatAttestation) echec(id, format string, args ...any) {
	r.poser(id, Echoue, "")
	r.Details[id] = append(r.Details[id], fmt.Sprintf(format, args...))
}

// RelationsAttestation applique les relations d'EX-7.2 que le schéma
// n'exprime pas (AT-1) : dates existantes, from ≤ until, journal_id
// distincts, journal_id de chaque agent dans journals, agent_id distincts,
// adresses de signatories distinctes.
func RelationsAttestation(p *Value) []string {
	var out []string
	de, okDe := AnalyserInstant(p.Chemin("validity", "from").Chaine())
	a, okA := AnalyserInstant(p.Chemin("validity", "until").Chaine())
	if !okDe || !okA {
		out = append(out, "validity : instant qui n'existe pas dans le calendrier (CT-1 §3)")
	} else if de.After(a) {
		out = append(out, "validity.from postérieur à validity.until")
	} else if a.Sub(de) > 366*24*time.Hour {
		out = append(out, "validity : plus de 366 jours entre from et until (EX-7.2)")
	}
	if _, ok := AnalyserInstant(p.Get("issued_at").Chaine()); !ok {
		out = append(out, "issued_at : instant qui n'existe pas dans le calendrier")
	}
	journaux := map[string]bool{}
	for _, j := range p.Get("journals").Arr {
		id := j.Get("journal_id").Chaine()
		if journaux[id] {
			out = append(out, "journal_id "+id+" en double dans journals")
		}
		journaux[id] = true
	}
	agents := map[string]bool{}
	for _, ag := range p.Get("agents").Arr {
		id := ag.Get("agent_id").Chaine()
		if agents[id] {
			out = append(out, "agent_id "+id+" en double")
		}
		agents[id] = true
		if !journaux[ag.Get("journal_id").Chaine()] {
			out = append(out, "agent "+id+" : journal_id absent de journals")
		}
	}
	adresses := map[string]bool{}
	for _, s := range p.Get("signatories").Arr {
		ad := s.Get("address").Chaine()
		if adresses[ad] {
			out = append(out, "adresse "+ad+" en double dans signatories")
		}
		adresses[ad] = true
	}
	return out
}

// VerifierAttestation exécute AT-1 à AT-4 sur une attestation signée (une
// valeur analysée, ou le texte JSON d'un cas) et un jeu d'approbateurs.
func VerifierAttestation(signee *Value, jeu *Value, sch *Schema) *ResultatAttestation {
	r := &ResultatAttestation{Details: map[string][]string{}}
	for _, id := range []string{"AT-1", "AT-2", "AT-3", "AT-4"} {
		r.poser(id, Reussi, "")
	}
	prerequis := func(ids ...string) {
		for _, id := range ids {
			r.poser(id, NonExecute, "prerequis_en_echec")
		}
	}

	// AT-1 : forme.
	if signee.Kind == KindString {
		v, err := AnalyserJSONStrict([]byte(signee.Str))
		if err != nil {
			r.echec("AT-1", "texte de l'attestation signée : %v", err)
			prerequis("AT-2", "AT-3", "AT-4")
			return r
		}
		signee = v
	}
	if err := VerifierEntiers(signee, "signed"); err != nil {
		r.echec("AT-1", "%v", err)
	}
	defSignee, _ := sch.Sous("#/$defs/attestation_signee")
	defJeu, _ := sch.Sous("#/$defs/jeu_approbateurs")
	for _, m := range sch.ValiderContre(defSignee, signee) {
		r.echec("AT-1", "attestation_signee : %s", m)
	}
	for _, m := range sch.ValiderContre(defJeu, jeu) {
		r.echec("AT-1", "jeu_approbateurs : %s", m)
	}
	p := signee.Get("attestation")
	var dp []byte
	if r.Statut("AT-1") == Reussi {
		for _, m := range RelationsAttestation(p) {
			r.echec("AT-1", "EX-7.2 : %s", m)
		}
		d, err := CondenseAttestation(p)
		if err != nil {
			r.echec("AT-1", "JCS(P) non calculable : %v", err)
		}
		dp = d
	}
	if r.Statut("AT-1") != Reussi {
		prerequis("AT-2", "AT-3", "AT-4")
		return r
	}
	r.Digest = Hex0x(dp)

	// AT-2 : condensé déclaré.
	if dec := signee.Get("digest").Str; dec != r.Digest {
		r.echec("AT-2", "digest déclaré %s ≠ D_P recalculé %s", dec, r.Digest)
	}

	// AT-3 : signatures canoniques, recouvrées sur M = EIP-191(D_P).
	m := MessageEIP191(dp)
	r.Recouvres = []*string{}
	for i, s := range signee.Get("signatures").Arr {
		dec := s.Get("address").Str
		rec, err := RecouvrerAdresse(m, s.Get("signature").Str)
		if err != nil {
			r.Recouvres = append(r.Recouvres, nil)
			r.echec("AT-3", "signatures[%d] : %v", i, err)
			continue
		}
		r.Recouvres = append(r.Recouvres, &rec)
		if rec != dec {
			r.echec("AT-3", "signatures[%d] : adresse recouvrée %s ≠ adresse déclarée %s", i, rec, dec)
		}
	}
	if r.Statut("AT-3") != Reussi {
		prerequis("AT-4")
		return r
	}

	// AT-4 : adresses distinctes, dans signatories et dans le jeu, au seuil.
	nommes := map[string]bool{}
	for _, s := range p.Get("signatories").Arr {
		nommes[s.Get("address").Str] = true
	}
	membres := map[string]bool{}
	for _, x := range jeu.Get("members").Arr {
		membres[x.Str] = true
	}
	vus := map[string]bool{}
	for i, s := range signee.Get("signatures").Arr {
		a := s.Get("address").Str
		if vus[a] {
			r.echec("AT-4", "signatures[%d] : adresse %s en double", i, a)
		}
		vus[a] = true
		if !nommes[a] {
			r.echec("AT-4", "signatures[%d] : %s absente de signatories", i, a)
		}
		if !membres[a] {
			r.echec("AT-4", "signatures[%d] : %s absente de approver_set.members", i, a)
		}
	}
	requis, _ := jeu.Chemin("threshold", "required").Entier()
	taille, _ := jeu.Chemin("threshold", "size").Entier()
	if int64(len(vus)) < requis {
		r.echec("AT-4", "%d signataire(s) distinct(s) pour un seuil de %d", len(vus), requis)
	}
	if requis > taille {
		r.echec("AT-4", "required %d > size %d", requis, taille)
	}
	if taille != int64(len(jeu.Get("members").Arr)) {
		r.echec("AT-4", "size %d ≠ nombre de membres %d", taille, len(jeu.Get("members").Arr))
	}
	r.Retenue = r.Statut("AT-1") == Reussi && r.Statut("AT-2") == Reussi && r.Statut("AT-3") == Reussi && r.Statut("AT-4") == Reussi
	return r
}
