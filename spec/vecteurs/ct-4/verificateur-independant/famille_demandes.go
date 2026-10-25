// Famille « demandes » : demandes de signature (7.7) ; schéma, OP-6, OP-7.
//
// Lectures retenues :
//   - une demande non conforme à demande_signature est une entrée illisible
//     (entree_illisible, 7.11) ; les vecteurs la rattachent à la première
//     vérification du cas (INDEX.md : « refusé en tête d'OP-6 ») ;
//   - OP-7 s'exécute dans l'ordre de son texte : forme canonique de chaque
//     signature, recouvrement du signataire déclaré, signataires distincts,
//     rangement par adresse croissante, appartenance au jeu, seuil, émetteur
//     d'une ancre. La table 7.11 ne nomme le code que pour une signature à s
//     haut (signature_non_canonique), un non-membre (signataire_hors_jeu) et
//     un seuil non atteint (signatures_insuffisantes) : pour les autres
//     défauts, le code n'est pas confronté.

package main

import (
	"fmt"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
)

// condenseDemande recalcule le condensé d'une demande (OP-6, RG-6 à RG-11).
func condenseDemande(d *Value) ([]byte, *Echec) {
	chain, ok := EntierLitteral(d.Get("evm_chain_id").Num)
	if !ok {
		return nil, echecCode("OP-6", "condense_different", true, "evm_chain_id illisible")
	}
	contrat, err := DecoderHexN(d.Get("contract").S(), 20)
	if err != nil {
		return nil, echecCode("OP-6", "condense_different", true, "contract illisible")
	}
	fl := d.Get("fields")
	h := func(k string, n int) []byte {
		b, _ := DecoderHexN(fl.Get(k).S(), n)
		return b
	}
	var pre []byte
	var e *Echec
	switch d.Get("operation").S() {
	case "inscription":
		pre, e = PreimageInscription(chain, contrat, h("org_id", 32), h("journal_id", 32), h("chain_key", 20), h("ed25519_public_key", 32))
	case "revocation":
		reg, err := Decimal(fl.Get("registered_at").S())
		if err != nil {
			return nil, echecCode("OP-6", "condense_different", true, "registered_at illisible")
		}
		pre, e = PreimageRevocation(chain, contrat, h("org_id", 32), h("chain_key", 20), reg)
	case "cloture":
		m, err := LireMeta(fl.Get("period_meta"))
		if err != nil {
			return nil, echecCode("OP-6", "condense_different", true, "period_meta : %v", err)
		}
		if ee := RG5(m, nil, "", ""); ee != nil {
			return nil, echecCode("OP-6", "condense_different", false, "PeriodMeta refusé par RG-5 : %s", ee.Raison)
		}
		pre = PreimagePeriode(chain, contrat, m)
	case "ancre":
		pre = PreimageAncre(chain, contrat, h("fingerprint", 32), h("doc_type", 32))
	case "administration_jeu":
		n, err := Decimal(fl.Get("nonce").S())
		if err != nil {
			return nil, echecCode("OP-6", "condense_different", true, "nonce illisible")
		}
		pre, e = PreimageAdmin(chain, contrat, fl.Get("op").S(), h("arg", 32), n)
	default:
		return nil, echecCode("OP-6", "condense_different", true, "opération inconnue")
	}
	if e != nil {
		return nil, echecCode("OP-6", "condense_different", false, "%s", e.Raison)
	}
	return Keccak256(pre), nil
}

// VerifierDemande applique le schéma, OP-6 et OP-7 à une demande.
func (c *Ctx) VerifierDemande(d *Value, premier string, membres []string, admin string, complete bool) ([]byte, []string, *Echec) {
	if errs := c.Schemas.Valider("operations-registre-v0.schema.json#/$defs/demande_signature", d); len(errs) > 0 {
		return nil, nil, echecCode(premier, "entree_illisible", true, "demande non conforme à demande_signature : %s", strings.Join(errs, " ; "))
	}
	dg, e := condenseDemande(d)
	if e != nil {
		return nil, nil, e
	}
	if d.Get("digest").S() != Hex0x(dg) {
		return dg, nil, echecCode("OP-6", "condense_different", true, "digest %s au lieu de %s recalculé", d.Get("digest").S(), Hex0x(dg))
	}
	h := HachageSigne(dg)
	if d.Get("eip191_digest").S() != Hex0x(h) {
		return dg, nil, echecCode("OP-6", "condense_different", true, "eip191_digest %s au lieu de %s", d.Get("eip191_digest").S(), Hex0x(h))
	}
	// OP-7.
	var signataires []string
	var sigs []SignatureEVM
	for _, o := range d.Get("signatures").Arr {
		s, signer, err := LireSignature(o)
		if err != nil {
			return dg, nil, echecCode("OP-7", "signature_non_canonique", false, "%v", err)
		}
		signataires = append(signataires, signer)
		sigs = append(sigs, s)
	}
	for i, s := range sigs {
		if !s.Canonique() {
			return dg, nil, echecCode("OP-7", "signature_non_canonique", true, "signature %d non canonique", i)
		}
	}
	for i, s := range sigs {
		adr, err := s.Recouvrir(h)
		if err != nil || adr != signataires[i] {
			return dg, nil, echecCode("OP-7", "signataire_hors_jeu", false, "la signature %d ne recouvre pas son signer %s (recouvrée : %s)", i, signataires[i], adr)
		}
	}
	vus := map[string]bool{}
	for _, s := range signataires {
		if vus[s] {
			return dg, nil, echecCode("OP-7", "signature_non_canonique", false, "signataire %s en double", s)
		}
		vus[s] = true
	}
	if !sort.StringsAreSorted(signataires) {
		return dg, nil, echecCode("OP-7", "signature_non_canonique", false, "signataires non rangés par adresse croissante")
	}
	op := d.Get("operation").S()
	switch op {
	case "inscription", "revocation", "cloture":
		if membres != nil {
			m := map[string]bool{}
			for _, x := range membres {
				m[x] = true
			}
			for _, s := range signataires {
				if !m[s] {
					return dg, nil, echecCode("OP-7", "signataire_hors_jeu", true, "signataire %s hors du jeu", s)
				}
			}
		}
		t, _ := EntierLitteral(d.Get("signer_set").Get("threshold").Num)
		if complete && big.NewInt(int64(len(signataires))).Cmp(t) < 0 {
			return dg, nil, echecCode("OP-7", "signatures_insuffisantes", true, "%d signatures pour un seuil de %s", len(signataires), t)
		}
	case "ancre":
		for _, s := range signataires {
			if s != d.Get("fields").Get("issuer").S() {
				return dg, nil, echecCode("OP-7", "signataire_hors_jeu", false, "signataire %s autre que l'émetteur %s", s, d.Get("fields").Get("issuer").S())
			}
		}
		if complete && len(signataires) != 1 {
			return dg, nil, echecCode("OP-7", "signatures_insuffisantes", false, "une signature de l'émetteur attendue")
		}
	case "administration_jeu":
		for _, s := range signataires {
			if admin != "" && s != admin {
				return dg, nil, echecCode("OP-7", "signataire_hors_jeu", false, "signataire %s autre que l'administrateur du jeu", s)
			}
		}
		if complete && len(signataires) != 1 {
			return dg, nil, echecCode("OP-7", "signatures_insuffisantes", false, "une signature de l'administrateur attendue")
		}
	}
	return dg, signataires, nil
}

// FamilleDemandes vérifie demandes/demandes.json.
func (c *Ctx) FamilleDemandes() {
	f := c.R.F("demandes")
	for _, cs := range c.lireFamille(f, "demandes/demandes.json", "demandes") {
		in := cs.Input
		d, _, err := LireJSON(filepath.Join(c.Racine, filepath.FromSlash(in.Get("file").S())))
		if err != nil {
			f.Erreur(cs.ID, "demande", err, "OP-6")
			continue
		}
		var membres []string
		if m := in.Get("members"); m != nil && !m.IsNull() {
			membres = []string{}
			for _, x := range m.Arr {
				membres = append(membres, x.S())
			}
		}
		admin := ""
		if a := in.Get("administrator"); a != nil && !a.IsNull() {
			admin = a.S()
		}
		complete := in.Get("complete") != nil && in.Get("complete").Bool
		dg, signataires, e := c.VerifierDemande(d, firstCheck(cs), membres, admin, complete)
		if e != nil && e.Code == "entree_illisible" {
			f.Hors(cs.ID, "rattachement du refus de schéma à "+e.Check, "convention des vecteurs (INDEX.md) : la table 7.11 ne rattache entree_illisible à aucune vérification")
		}
		if !c.confronterIssue(f, cs, e) {
			continue
		}
		f.Comparer(cs.ID, "result", cs.Expected.Get("result").S(), "valide", "OP-7")
		f.Comparer(cs.ID, "digest", cs.Expected.Get("digest").S(), Hex0x(dg), "OP-6")
		f.Comparer(cs.ID, "signers", Compact(cs.Expected.Get("signers")), Compact(TableauChaines(signataires)), "OP-7")
		for i, o := range d.Get("signatures").Arr {
			s, signer, _ := LireSignature(o)
			c.reproduire(f, cs.ID, fmt.Sprintf("signatures[%d]", i), signer, HachageSigne(dg), s)
		}
		c.valeursSynthetiquesDemande(f, cs.ID, d)
	}
}

// valeursSynthetiquesDemande recalcule les valeurs synthétiques de signer_set
// de l'exemple de 7.7 (« l'adresse du jeu, la hauteur et le hachage de bloc
// de signer_set sont synthétiques (7.10) »).
func (c *Ctx) valeursSynthetiquesDemande(f *Famille, cas string, d *Value) {
	ss := d.Get("signer_set")
	if ss == nil || ss.IsNull() {
		return
	}
	if ss.Get("curator_set").S() == c.Constantes.Get("example").Get("curator_set").S() {
		h := ss.Get("height").Num
		f.Comparer(cas, "signer_set.block_hash = SHA-256(UTF-8(noortrace/exemple/ct4/bloc/"+h+"))", Hex0x(Sha256([]byte("noortrace/exemple/ct4/bloc/"+h))), ss.Get("block_hash").S(), "7.10")
		return
	}
	f.Hors(cas, "signer_set.height, signer_set.block_hash", "lecture du jeu à la tête (état de la chaîne, bloc non capturé) : non recalculable hors ligne")
}
