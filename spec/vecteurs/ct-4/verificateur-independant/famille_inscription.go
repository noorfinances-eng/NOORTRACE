// Famille « inscription » : dossiers d'inscription (7.5 à 7.10) ; schéma et
// OP-4, puis les valeurs que le dossier tire de l'instance et de A.2.
//
// Lecture retenue : OP-4 n'a, hors lecture d'état, que le code jeu_invalide
// (organisation_existante exige isRegistered) ; tout défaut du dossier
// relevé par OP-4 rend donc jeu_invalide.

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VerifierDossier applique le schéma et OP-4 à un dossier.
func (c *Ctx) VerifierDossier(d *Value, premier string, production bool, comptes []string) *Echec {
	if errs := c.Schemas.Valider("inscription-client-v0.schema.json", d); len(errs) > 0 {
		return echecCode(premier, "entree_illisible", true, "dossier non conforme à inscription-client-v0 : %s", strings.Join(errs, " ; "))
	}
	ji := func(format string, a ...any) *Echec { return echecCode("OP-4", "jeu_invalide", true, format, a...) }
	org := d.Get("organisation")
	id, e := RG1(org.Get("slug").S(), production)
	if e != nil {
		return ji("slug refusé par RG-1 : %s", e.Raison)
	}
	if Hex0x(id) != org.Get("org_id").S() {
		return ji("org_id %s différent de keccak256(slug) %s", org.Get("org_id").S(), Hex0x(id))
	}
	for _, j := range d.Get("journals").Arr {
		jid, e := RG2(j.Get("name").S())
		if e != nil {
			return ji("nom de journal refusé par RG-2 : %s", e.Raison)
		}
		if Hex0x(jid) != j.Get("journal_id").S() {
			return ji("journal_id de %q différent de keccak256(nom)", j.Get("name").S())
		}
	}
	ap := d.Get("approvers")
	var membres []string
	nul := "0x0000000000000000000000000000000000000000"
	for _, m := range ap.Get("members").Arr {
		if m.S() == nul {
			return ji("membre nul")
		}
		if m.S() != strings.ToLower(m.S()) {
			return ji("membre %s hors minuscules", m.S())
		}
		membres = append(membres, m.S())
	}
	vus := map[string]bool{}
	for _, m := range membres {
		if vus[m] {
			return ji("membre %s en double", m)
		}
		vus[m] = true
	}
	if !sort.StringsAreSorted(membres) {
		return ji("membres non triés")
	}
	t, _ := EntierLitteral(ap.Get("threshold").Num)
	if t.Sign() < 1 || t.Cmp(big.NewInt(int64(len(membres)))) > 0 {
		return ji("seuil %s hors de [1, %d]", t, len(membres))
	}
	adm := ap.Get("set_admin").S()
	if adm == nul {
		return ji("administrateur du jeu nul")
	}
	if production {
		for _, k := range comptes {
			if k == adm {
				return ji("administrateur du jeu %s : compte de l'exploitant (EX-5.6)", adm)
			}
		}
		// 7.3, OP-4 : la classe de garde D (CT-2 §11.2) n'est pas admise en production.
		for _, r := range d.Get("recorders").Arr {
			if r.Get("custody_class").S() == "D" || r.Get("chain_key_class").S() == "D" {
				return echecCode("OP-4", "cle_invalide", true, "clé %s : classe de garde D refusée en production (CT-2 §11.2, EX-11.19)", r.Get("key_id").S())
			}
		}
	}
	return nil
}

// FamilleInscription vérifie inscription/inscription.json.
func (c *Ctx) FamilleInscription() {
	f := c.R.F("inscription")
	for _, cs := range c.lireFamille(f, "inscription/inscription.json", "inscription") {
		in := cs.Input
		d, _, err := LireJSON(filepath.Join(c.Racine, filepath.FromSlash(in.Get("file").S())))
		if err != nil {
			f.Erreur(cs.ID, "dossier", err, "OP-4")
			continue
		}
		var comptes []string
		for _, a := range in.Get("operator_accounts").Arr {
			comptes = append(comptes, a.S())
		}
		e := c.VerifierDossier(d, firstCheck(cs), in.Get("nature").S() == "production", comptes)
		if e != nil && e.Code == "entree_illisible" {
			f.Hors(cs.ID, "rattachement du refus de schéma à "+e.Check, "convention des vecteurs (INDEX.md) : la table 7.11 ne rattache entree_illisible à aucune vérification")
		}
		if !c.confronterIssue(f, cs, e) {
			continue
		}
		f.Comparer(cs.ID, "result", cs.Expected.Get("result").S(), "valide", "OP-4")
		f.Comparer(cs.ID, "org_id", cs.Expected.Get("org_id").S(), d.Get("organisation").Get("org_id").S(), "OP-4")
		c.valeursDossier(f, cs.ID, d)
	}
}

// valeursDossier recalcule les valeurs qu'un dossier du réseau de
// développement tire de l'instance (EX-7.2), de la provision (EX-4.19) et,
// pour l'exemple de 7.10, des étiquettes synthétiques.
func (c *Ctx) valeursDossier(f *Famille, cas string, d *Value) {
	ins := d.Get("instance")
	f.Comparer(cas, "instance.evm_chain_id", "2124", ins.Get("evm_chain_id").Num, "EX-7.2")
	f.Comparer(cas, "instance.bft_chain_id", "noortrace-2124-dev", ins.Get("bft_chain_id").S(), "EX-7.2")
	if b, err := os.ReadFile(filepath.Join(c.Depot, "chain", "config", "alloc-dev.json")); err == nil {
		f.Comparer(cas, "instance.genesis_sha256 = SHA-256 de chain/config/alloc-dev.json", Hex0x(Sha256(b)), ins.Get("genesis_sha256").S(), "EX-7.2")
	}
	f.Comparer(cas, "instance.manifest_sha256 (sans manifeste, EX-7.2)", "null", Compact(ins.Get("manifest_sha256")), "EX-7.2")
	if c.JeuDev != nil {
		f.Comparer(cas, "instance.validator_set_hash", Hex0x(c.JeuDev.Hachage()), ins.Get("validator_set_hash").S(), "CT-6 EX-11.8")
	}
	ct := c.Constantes.Get("contracts")
	for _, k := range []string{"curator_set_registry", "recorder_registry", "period_registry", "attestation_registry"} {
		f.Comparer(cas, "instance.contracts."+k, ct.Get(k).S(), ins.Get("contracts").Get(k).S(), "EX-7.2")
	}
	fu := d.Get("funding")
	b, _ := EntierLitteral(fu.Get("daily_budget_gas").Num)
	pk := new(big.Int).Add(new(big.Int).Mul(big.NewInt(30), b), big.NewInt(3000000))
	f.Comparer(cas, "funding.amount_wei = 30 × b + 3 000 000", pk.String(), fu.Get("amount_wei").S(), "EX-4.19")
	f.Comparer(cas, "funding.daily_budget_gas (journal horaire, 7.5)", "10800000", fu.Get("daily_budget_gas").Num, "EX-4.19")
	f.Comparer(cas, "funding.funder (compte Hardhat 0, EX-7.3)", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", fu.Get("funder").S(), "EX-7.3")

	ex := c.Constantes.Get("example")
	if d.Get("organisation").Get("slug").S() != ex.Get("slug").S() {
		return
	}
	// Exemple de 7.10 : étiquettes synthétiques.
	for _, st := range d.Get("steps").Arr {
		nom := st.Get("step").S()
		if bn := st.Get("block_number"); bn != nil && !bn.IsNull() {
			f.Comparer(cas, nom+".block_hash = SHA-256(…/bloc/"+bn.Num+")", Hex0x(Sha256([]byte("noortrace/exemple/ct4/bloc/"+bn.Num))), st.Get("block_hash").S(), "7.10")
		}
		if th := st.Get("transaction_hash"); th != nil && !th.IsNull() {
			v := Hex0x(Sha256([]byte("noortrace/exemple/ct4/transaction/" + nom)))
			if v == th.S() {
				f.Comparer(cas, nom+".transaction_hash = SHA-256(…/transaction/"+nom+")", v, th.S(), "7.10")
			} else {
				f.Hors(cas, nom+".transaction_hash", "étiquette <étape> de 7.10 non fixée : SHA-256(UTF-8(noortrace/exemple/ct4/transaction/"+nom+")) ne redonne pas la valeur")
			}
		}
		if cp := st.Get("capture"); cp != nil && !cp.IsNull() && !st.Get("block_number").IsNull() {
			f.Comparer(cas, nom+".capture (nom de CP-6)", fmt.Sprintf("capture-%s-0-%s.json", st.Get("block_number").Num, roleEtape(nom)), cp.S(), "CP-6")
		}
	}
	r := d.Get("result")
	if r == nil || r.IsNull() {
		return
	}
	f.Comparer(cas, "result.curator_set (20 premiers octets de SHA-256)", ex.Get("curator_set").S(), r.Get("curator_set").S(), "7.10")
	as := r.Get("approver_set")
	f.Comparer(cas, "result.approver_set.registry", ins.Get("contracts").Get("curator_set_registry").S(), as.Get("registry").S(), "7.10")
	f.Comparer(cas, "result.approver_set.set", r.Get("curator_set").S(), as.Get("set").S(), "7.10")
	f.Comparer(cas, "result.approver_set.chain_id", ins.Get("evm_chain_id").Num, as.Get("chain_id").Num, "7.10")
	sr := r.Get("set_read")
	f.Comparer(cas, "result.set_read.members = approvers.members", Compact(d.Get("approvers").Get("members")), Compact(sr.Get("members")), "7.10")
	f.Comparer(cas, "result.set_read.threshold = approvers.threshold", d.Get("approvers").Get("threshold").Num, sr.Get("threshold").Num, "7.10")
	f.Comparer(cas, "result.set_read.size", fmt.Sprint(len(d.Get("approvers").Get("members").Arr)), sr.Get("size").Num, "7.10")
	etape := func(nom string) *Value {
		for _, st := range d.Get("steps").Arr {
			if st.Get("step").S() == nom {
				return st
			}
		}
		return nil
	}
	ref := func(st *Value) string {
		if st == nil {
			return "absente"
		}
		return Compact(Objet("transaction_hash", Copier(st.Get("transaction_hash")), "block_number", Copier(st.Get("block_number")), "block_hash", Copier(st.Get("block_hash")), "capture", Copier(st.Get("capture"))))
	}
	f.Comparer(cas, "result.set_deployment = étape jeu_approbateurs", ref(etape("jeu_approbateurs")), Compact(r.Get("set_deployment")), "7.10")
	f.Comparer(cas, "result.assignment = étape assignation", ref(etape("assignation")), Compact(r.Get("assignment")), "7.10")
	lj := etape("lecture_jeu")
	f.Comparer(cas, "result.set_read.height = étape lecture_jeu", lj.Get("block_number").Num, sr.Get("height").Num, "7.10")
	for _, rc := range r.Get("recorders").Arr {
		f.Comparer(cas, "result.recorders.funding = étape approvisionnement", ref(etape("approvisionnement")), Compact(rc.Get("funding")), "7.10")
		f.Comparer(cas, "result.recorders.registration = étape inscription", ref(etape("inscription")), Compact(rc.Get("registration")), "7.10")
		f.Comparer(cas, "result.recorders.chain_key", ex.Get("chain_key").Get("address").S(), rc.Get("chain_key").S(), "7.10")
	}
	for _, rc := range d.Get("recorders").Arr {
		f.Comparer(cas, "recorders.public_key (Ed25519 de A.2)", ex.Get("ed25519").Get("public_key").S(), rc.Get("public_key").S(), "A.2")
		f.Comparer(cas, "recorders.chain_key", ex.Get("chain_key").Get("address").S(), rc.Get("chain_key").S(), "A.2")
	}
	for _, nom := range []string{"premiere_ancre", "premiere_cloture"} {
		if st := etape(nom); st != nil {
			f.Comparer(cas, nom+".subject = periodHash du manifeste d'exemple de A.2", ex.Get("period_hash").S(), st.Get("subject").S(), "7.10")
		}
	}
}

// roleEtape rend le rôle de capture d'une étape du dossier (9.4).
func roleEtape(nom string) string {
	switch nom {
	case "premiere_ancre":
		return "ancre"
	case "premiere_cloture":
		return "cloture"
	}
	return nom
}
