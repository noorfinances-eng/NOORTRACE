// Manifeste d'instance (CT-4 4.8, 6.8) : RG-16 à RG-20.
//
// Lectures retenues : un document non conforme au schéma instance-registre-v0
// n'est pas un manifeste ; RG-17 à RG-20, qui portent sur « le manifeste »,
// échouent alors avec RG-16. L'ancre registry dérivée n'est rendue que si
// RG-20 réussit ; avec une ancre fournie (input.registry), RG-20 compare
// l'ancre dérivée à celle-ci, membres source exceptés (« source à la
// discrétion du réviseur »).

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ResultatManifeste porte les verdicts RG-16 à RG-20 et l'ancre dérivée.
type ResultatManifeste struct {
	Verdicts map[string]*Echec
	Registre *Value
}

var ordreRGManifeste = []string{"RG-16", "RG-17", "RG-18", "RG-19", "RG-20"}

func horodatageExiste(s string) bool {
	_, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	return err == nil
}

// LigneRegles recalcule la ligne de règles d'un document de genèse (EX-4.3).
func LigneRegles(g *Value) (string, error) {
	r := g.Get("rules")
	if r == nil || r.Kind != KindObject {
		return "", fmt.Errorf("section rules absente")
	}
	val := func(v *Value) (string, error) {
		if v == nil {
			return "", fmt.Errorf("champ absent")
		}
		switch v.Kind {
		case KindBool:
			return strconv.FormatBool(v.Bool), nil
		case KindString:
			return v.Str, nil
		case KindNumber:
			n, ok := EntierLitteral(v.Num)
			if !ok {
				return "", fmt.Errorf("entier attendu")
			}
			return n.String(), nil
		}
		return "", fmt.Errorf("type inattendu")
	}
	parts := []struct {
		nom string
		v   *Value
	}{{"chainId", r.Get("chainId")}, {"evmChainId", g.Get("chainId")}, {"possEnabled", r.Get("possEnabled")},
		{"possRewards", r.Get("possRewards")}, {"possCapWei", r.Get("possCapWei")}, {"possGenesisUnix", r.Get("possGenesisUnix")},
		{"possHalvingSec", r.Get("possHalvingSec")}, {"possSubperiodSec", r.Get("possSubperiodSec")}, {"possEmissionModel", r.Get("possEmissionModel")}}
	var out []string
	for _, p := range parts {
		s, err := val(p.v)
		if err != nil {
			return "", fmt.Errorf("%s : %v", p.nom, err)
		}
		out = append(out, p.nom+"="+s)
	}
	return strings.Join(out, " "), nil
}

// rg17 vérifie la genèse et les identifiants.
func rg17(m *Value, octetsGenese []byte) *Echec {
	gm := m.Get("genesis")
	if Hex0x(Sha256(octetsGenese)) != gm.Get("sha256").S() {
		return echec("RG-17", "SHA-256 du document de genèse %s différent de genesis.sha256", Hex0x(Sha256(octetsGenese)))
	}
	g, err := ParseJSON(octetsGenese)
	if err != nil || g.Kind != KindObject {
		return echec("RG-17", "document de genèse illisible")
	}
	// Forme de 4.2.
	for _, mb := range g.Obj {
		if mb.Key != "chainId" && mb.Key != "alloc" && mb.Key != "rules" {
			return echec("RG-17", "membre %q hors de la forme de 4.2", mb.Key)
		}
	}
	chain, err := EntierChamp(g, "chainId")
	if err != nil || chain.Sign() <= 0 {
		return echec("RG-17", "chainId de tête : entier EVM non nul attendu")
	}
	al := g.Get("alloc")
	if al == nil || al.Kind != KindArray || len(al.Arr) == 0 {
		return echec("RG-17", "alloc vide ou absent")
	}
	total := new(big.Int)
	vues := map[string]bool{}
	for _, a := range al.Arr {
		ad, err := Champ(a, "address")
		if err != nil {
			return echec("RG-17", "alloc : %v", err)
		}
		b, err := DecoderHexLibre(ad)
		if err != nil || len(b) != 20 {
			return echec("RG-17", "alloc : adresse %q invalide", ad)
		}
		if vues[string(b)] {
			return echec("RG-17", "alloc : adresse %q en double", ad)
		}
		vues[string(b)] = true
		bw, err := Champ(a, "balanceWei")
		if err != nil {
			return echec("RG-17", "alloc : %v", err)
		}
		n, err := Decimal(bw)
		if err != nil {
			return echec("RG-17", "alloc : balanceWei %q non décimal", bw)
		}
		total.Add(total, n)
	}
	// Section rules d'EX-4.2.
	r := g.Get("rules")
	if r == nil || r.Kind != KindObject {
		return echec("RG-17", "section rules absente (EX-4.2 : un tel document n'est pas admis)")
	}
	attendu := []Member{
		{"chainId", Chaine(m.Get("bft_chain_id").S())}, {"possEnabled", Booleen(false)},
		{"possRewards", Chaine("0x0000000000000000000000000000000000000000")}, {"possCapWei", Chaine("0")},
		{"possGenesisUnix", Entier(0)}, {"possHalvingSec", Entier(0)}, {"possSubperiodSec", Entier(0)},
		{"possEmissionModel", Chaine("noormint/v1")},
	}
	if len(r.Obj) != len(attendu) {
		return echec("RG-17", "section rules de %d membres au lieu des %d d'EX-4.2", len(r.Obj), len(attendu))
	}
	for _, kv := range attendu {
		if !EgalJSON(r.Get(kv.Key), kv.Val) {
			return echec("RG-17", "rules.%s différent de la valeur d'EX-4.2 ou de bft_chain_id", kv.Key)
		}
	}
	ligne, err := LigneRegles(g)
	if err != nil {
		return echec("RG-17", "ligne de règles : %v", err)
	}
	if ligne != gm.Get("rules_line").S() {
		return echec("RG-17", "ligne de règles recalculée %q différente de genesis.rules_line", ligne)
	}
	evm, _ := EntierChamp(m, "evm_chain_id")
	if evm == nil || chain.Cmp(evm) != 0 {
		return echec("RG-17", "chainId de tête %s différent de evm_chain_id", chain)
	}
	if n, ok := nombreBFT(m.Get("bft_chain_id").S()); !ok || n != evm.String() {
		return echec("RG-17", "le nombre de bft_chain_id n'est pas evm_chain_id")
	}
	if total.String() != gm.Get("alloc_total_wei").S() {
		return echec("RG-17", "somme des balanceWei %s différente de alloc_total_wei", total)
	}
	return nil
}

// jeuxDuManifeste charge les jeux de validator_sets.
func jeuxDuManifeste(m *Value) ([]JeuValidateurs, error) {
	var out []JeuValidateurs
	for _, s := range m.Get("validator_sets").Arr {
		j, err := ChargerJeu(s.Get("validators"))
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

// rg18 vérifie les jeux de validateurs.
func rg18(m *Value) *Echec {
	sets := m.Get("validator_sets").Arr
	production := m.Get("nature").S() == "production"
	type intervalle struct{ de, a *big.Int }
	var iv []intervalle
	for i, s := range sets {
		j, err := ChargerJeu(s.Get("validators"))
		if err != nil {
			return echec("RG-18", "jeu %d : %v", i, err)
		}
		if len(j.Valideurs) < 4 {
			return echec("RG-18", "jeu %d : %d validateurs, au moins quatre exigés", i, len(j.Valideurs))
		}
		if Hex0x(j.Hachage()) != s.Get("valset_hash").S() {
			return echec("RG-18", "jeu %d : valset_hash recalculé %s différent de %s", i, Hex0x(j.Hachage()), s.Get("valset_hash").S())
		}
		nomme := map[string]int{}
		for _, o := range s.Get("operators").Arr {
			nomme[o.Get("validator").S()]++
		}
		for _, v := range j.Valideurs {
			if nomme[v.ID] != 1 {
				return echec("RG-18", "jeu %d : operators nomme %q %d fois", i, v.ID, nomme[v.ID])
			}
		}
		if len(nomme) != len(j.Valideurs) {
			return echec("RG-18", "jeu %d : operators nomme un validateur hors du jeu", i)
		}
		de, _ := EntierChamp(s, "from_height")
		var a *big.Int
		if t := s.Get("to_height"); t != nil && !t.IsNull() {
			a, _ = EntierLitteral(t.Num)
			if a.Cmp(de) < 0 {
				return echec("RG-18", "jeu %d : from_height > to_height", i)
			}
		}
		iv = append(iv, intervalle{de, a})
		if production {
			f := Fautes(len(j.Valideurs))
			parOp, parSite := map[string]int{}, map[string]int{}
			for _, o := range s.Get("operators").Arr {
				parOp[o.Get("operator").S()]++
				parSite[o.Get("site").S()]++
			}
			for k, n := range parOp {
				if n > f {
					return echec("RG-18", "jeu %d : l'opérateur %q porte %d validateurs, plus que f = %d", i, k, n, f)
				}
			}
			for k, n := range parSite {
				if n > f {
					return echec("RG-18", "jeu %d : le site %q porte %d validateurs, plus que f = %d", i, k, n, f)
				}
			}
		}
	}
	sort.Slice(iv, func(x, y int) bool { return iv[x].de.Cmp(iv[y].de) < 0 })
	if len(iv) == 0 || iv[0].de.Cmp(big.NewInt(1)) != 0 {
		return echec("RG-18", "le premier intervalle ne commence pas à 1")
	}
	for k := 1; k < len(iv); k++ {
		if iv[k-1].a == nil || iv[k-1].a.Cmp(iv[k].de) >= 0 {
			return echec("RG-18", "intervalles de hauteurs qui se recouvrent")
		}
	}
	return nil
}

// jeuPour rend le jeu du manifeste dont l'intervalle contient h.
func jeuPour(m *Value, h *big.Int) *JeuValidateurs {
	for _, s := range m.Get("validator_sets").Arr {
		de, _ := EntierChamp(s, "from_height")
		if de == nil || h.Cmp(de) < 0 {
			continue
		}
		if t := s.Get("to_height"); t != nil && !t.IsNull() {
			a, _ := EntierLitteral(t.Num)
			if h.Cmp(a) > 0 {
				continue
			}
		}
		j, err := ChargerJeu(s.Get("validators"))
		if err != nil {
			return nil
		}
		return &j
	}
	return nil
}

// enService rend les contrats de to_height nul, par nom.
func enService(m *Value) map[string][]*Value {
	out := map[string][]*Value{}
	for _, ct := range m.Get("contracts").Arr {
		if t := ct.Get("to_height"); t == nil || t.IsNull() {
			out[ct.Get("name").S()] = append(out[ct.Get("name").S()], ct)
		}
	}
	return out
}

// rg19 vérifie les contrats.
func (c *Ctx) rg19(m *Value, rep string) *Echec {
	production := m.Get("nature").S() == "production"
	es := enService(m)
	for _, nom := range []string{"AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"} {
		if len(es[nom]) != 1 {
			return echec("RG-19", "%d contrats %s de to_height nul au lieu d'un", len(es[nom]), nom)
		}
	}
	csr := es["CuratorSetRegistry"][0].Get("address").S()
	for _, ct := range m.Get("contracts").Arr {
		nom := ct.Get("name").S()
		dep, err := DecoderHexN(ct.Get("deployer").S(), 20)
		if err != nil {
			return echec("RG-19", "%s : déployeur illisible", nom)
		}
		nonce, _ := EntierChamp(ct, "nonce")
		bn, _ := EntierChamp(ct, "block_number")
		if Hex0x(AdresseCreation(dep, nonce)) != ct.Get("address").S() {
			return echec("RG-19", "%s : address %s différente de CREATE(deployer, nonce) = %s", nom, ct.Get("address").S(), Hex0x(AdresseCreation(dep, nonce)))
		}
		var args []string
		for _, a := range ct.Get("constructor_args").Arr {
			args = append(args, a.S())
		}
		var attendus []string
		switch nom {
		case "CuratorSetRegistry":
			admin := ""
			for _, a := range m.Get("accounts").Arr {
				if a.Get("role").S() != "administrateur_registre" {
					continue
				}
				de, _ := EntierChamp(a, "from_height")
				ok := de != nil && de.Cmp(bn) <= 0
				if t := a.Get("to_height"); ok && t != nil && !t.IsNull() {
					x, _ := EntierLitteral(t.Num)
					ok = bn.Cmp(x) <= 0
				}
				if ok {
					admin = a.Get("address").S()
				}
			}
			attendus = []string{admin}
		case "PeriodRegistry", "RecorderRegistry":
			attendus = []string{csr}
		}
		if strings.Join(args, ",") != strings.Join(attendus, ",") {
			return echec("RG-19", "%s : arguments du constructeur [%s] au lieu de [%s] (EX-5.2)", nom, strings.Join(args, ","), strings.Join(attendus, ","))
		}
		ev := ct.Get("evidence")
		bh := ct.Get("block_hash")
		if production && (ev == nil || ev.IsNull() || bh == nil || bh.IsNull()) {
			return echec("RG-19", "%s : block_hash ou evidence nul sur une instance de production", nom)
		}
		if ev == nil || ev.IsNull() {
			continue
		}
		if e := c.preuveDeploiement(m, ct, rep); e != nil {
			return e
		}
	}
	return nil
}

// preuveDeploiement vérifie la capture du bloc de déploiement d'un contrat.
func (c *Ctx) preuveDeploiement(m, ct *Value, rep string) *Echec {
	nom := ct.Get("name").S()
	cap := ct.Get("evidence").Get("capture")
	chemin := filepath.Join(rep, filepath.FromSlash(cap.Get("file").S()))
	b, err := os.ReadFile(chemin)
	if err != nil {
		return echec("RG-19", "%s : index de capture absent", nom)
	}
	if Hex0x(Sha256(b)) != cap.Get("sha256").S() {
		return echec("RG-19", "%s : SHA-256 de l'index de capture différent de celui déclaré", nom)
	}
	idx, err := ParseJSON(b)
	if err != nil {
		return echec("RG-19", "%s : index illisible", nom)
	}
	if idx.Get("role").S() != "deploiement" {
		return echec("RG-19", "%s : index de rôle %q au lieu de deploiement", nom, idx.Get("role").S())
	}
	for _, k := range [][2]string{{"contract", "address"}, {"transaction_hash", "transaction_hash"}, {"block_hash", "block_hash"}} {
		if idx.Get(k[0]).S() != ct.Get(k[1]).S() {
			return echec("RG-19", "%s : %s de l'index différent de %s du contrat", nom, k[0], k[1])
		}
	}
	if idx.Get("block_number").Num != ct.Get("block_number").Num {
		return echec("RG-19", "%s : block_number de l'index différent", nom)
	}
	h, _ := EntierChamp(ct, "block_number")
	jeu := jeuPour(m, h)
	res := c.VerifierCapture(filepath.Dir(chemin), filepath.Base(chemin), jeu, m.Get("bft_chain_id").S())
	for _, cp := range []string{"CP-2", "CP-3", "CP-6", "CP-4"} {
		if e := res.Verdicts[cp]; e != nil {
			return echec("RG-19", "%s : %s en échec (%s)", nom, cp, e.Raison)
		}
	}
	ti, _ := strconv.Atoi(idx.Get("transaction_index").Num)
	if ti >= len(res.Recus) || res.Recus[ti].Statut != 1 {
		return echec("RG-19", "%s : reçu de la transaction de déploiement sans status 0x1", nom)
	}
	if ti >= len(res.Txs) {
		return echec("RG-19", "%s : transaction absente du corps signé de la proposition", nom)
	}
	raw := res.Txs[ti]
	tx, err := DecoderTx2(raw)
	if err != nil {
		return echec("RG-19", "%s : transaction de déploiement illisible : %v", nom, err)
	}
	if tx.Dest != nil {
		return echec("RG-19", "%s : la transaction de déploiement a un destinataire %s", nom, Hex0x(tx.Dest))
	}
	exp, err := Expediteur(raw, tx)
	if err != nil || exp != ct.Get("deployer").S() {
		return echec("RG-19", "%s : transaction signée par %s et non par deployer", nom, exp)
	}
	if tx.Nonce.String() != ct.Get("nonce").Num {
		return echec("RG-19", "%s : transaction au nonce %s au lieu de %s", nom, tx.Nonce, ct.Get("nonce").Num)
	}
	return nil
}

// DeriverRegistre dérive l'ancre registry du manifeste (RG-20).
func DeriverRegistre(m *Value) *Value {
	es := enService(m)
	adr := func(nom string) *Value {
		if len(es[nom]) == 0 {
			return Nul()
		}
		return Chaine(es[nom][0].Get("address").S())
	}
	sets := Tableau()
	for _, s := range m.Get("validator_sets").Arr {
		sets.Arr = append(sets.Arr, Objet("from_height", Copier(s.Get("from_height")), "to_height", Copier(s.Get("to_height")),
			"validators", Copier(s.Get("validators")), "source", Copier(s.Get("source"))))
	}
	return Objet("chain_id", Chaine(m.Get("bft_chain_id").S()),
		"contracts", Objet("period_registry", adr("PeriodRegistry"), "attestation_registry", adr("AttestationRegistry"), "recorder_registry", adr("RecorderRegistry")),
		"validator_sets", sets,
		"source", Chaine(fmt.Sprintf("dérivée du manifeste d'instance %s, révision %s (CT-4 RG-20) : à recouper (CT-6 §12.5)", m.Get("bft_chain_id").S(), m.Get("revision").Num)))
}

// VerifierManifeste recalcule RG-16 à RG-20.
func (c *Ctx) VerifierManifeste(rep, nomManifeste string, nomPrecedent *Value, nomGenese string, registre *Value) ResultatManifeste {
	res := ResultatManifeste{Verdicts: map[string]*Echec{}}
	tous := func(e *Echec) {
		for _, rg := range ordreRGManifeste {
			res.Verdicts[rg] = &Echec{Check: rg, Raison: e.Raison}
		}
	}
	m, _, err := LireJSON(filepath.Join(rep, nomManifeste))
	if err != nil {
		tous(echec("RG-16", "manifeste illisible : %v", err))
		return res
	}
	// RG-16 : schéma, horodatages existants, révisions.
	if errs := c.Schemas.Valider("instance-registre-v0.schema.json", m); len(errs) > 0 {
		tous(echec("RG-16", "manifeste non conforme à instance-registre-v0 : %s", strings.Join(errs, " ; ")))
		return res
	}
	var e16 *Echec
	for _, ts := range []string{m.Get("published_at").S(), m.Get("evm_chain_id_registration").Get("checked_at").S()} {
		if !horodatageExiste(ts) {
			e16 = echec("RG-16", "horodatage %q inexistant", ts)
		}
	}
	rev, _ := EntierChamp(m, "revision")
	prevSha := m.Get("previous_sha256")
	if e16 == nil {
		if nomPrecedent == nil || nomPrecedent.IsNull() {
			if rev.Cmp(big.NewInt(1)) != 0 || !prevSha.IsNull() {
				e16 = echec("RG-16", "révision %s sans révision précédente fournie (revision 1 et previous_sha256 nul attendus)", rev)
			}
		} else {
			pb, err := os.ReadFile(filepath.Join(rep, nomPrecedent.S()))
			var pm *Value
			if err == nil {
				pm, err = ParseJSON(pb)
			}
			switch {
			case err != nil:
				e16 = echec("RG-16", "révision précédente illisible")
			case prevSha.IsNull() || prevSha.S() != Hex0x(Sha256(pb)):
				e16 = echec("RG-16", "previous_sha256 %s différent du SHA-256 %s des octets de la révision précédente", prevSha.S(), Hex0x(Sha256(pb)))
			default:
				pr, _ := EntierChamp(pm, "revision")
				if pr == nil || new(big.Int).Add(pr, big.NewInt(1)).Cmp(rev) != 0 {
					e16 = echec("RG-16", "revision %s au lieu de %v + 1", rev, pr)
				} else if m.Get("published_at").S() < pm.Get("published_at").S() {
					e16 = echec("RG-16", "published_at antérieur à celui de la révision précédente")
				}
			}
		}
	}
	res.Verdicts["RG-16"] = e16
	// RG-17.
	gb, err := os.ReadFile(filepath.Join(rep, filepath.FromSlash(nomGenese)))
	if err != nil {
		res.Verdicts["RG-17"] = echec("RG-17", "document de genèse illisible")
	} else {
		res.Verdicts["RG-17"] = rg17(m, gb)
	}
	res.Verdicts["RG-18"] = rg18(m)
	res.Verdicts["RG-19"] = c.rg19(m, rep)
	// RG-20. EX-6.23 : « adresses des contrats de ces noms en service » ; un
	// nom qui n'a pas exactement un contrat en service rend la dérivation
	// impossible (6.9, motif derivation_impossible).
	res.Registre = DeriverRegistre(m)
	es := enService(m)
	for _, nom := range []string{"PeriodRegistry", "AttestationRegistry", "RecorderRegistry"} {
		if len(es[nom]) != 1 {
			res.Verdicts["RG-20"] = echec("RG-20", "%d contrat(s) %s en service au lieu d'un : dérivation impossible", len(es[nom]), nom)
			return res
		}
	}
	if registre != nil {
		a, b := SansMembre(res.Registre, "source", true), SansMembre(registre, "source", true)
		if !EgalJSON(a, b) {
			res.Verdicts["RG-20"] = echec("RG-20", "ancre registry différente de celle dérivée du manifeste")
		}
	}
	return res
}

// FamilleManifestes vérifie manifestes/manifestes.json.
func (c *Ctx) FamilleManifestes() {
	f := c.R.F("manifestes")
	for _, cs := range c.lireFamille(f, "manifestes/manifestes.json", "manifestes") {
		in := cs.Input
		rep := filepath.Join(c.Racine, filepath.FromSlash(in.Get("directory").S()))
		res := c.VerifierManifeste(rep, in.Get("manifest").S(), in.Get("previous"), in.Get("genesis").S(), in.Get("registry"))
		verd := map[string]bool{}
		var premier *Echec
		for _, rg := range ordreRGManifeste {
			e := res.Verdicts[rg]
			verd[rg] = e == nil
			if e != nil && premier == nil {
				premier = e
			}
			rec := "reussi"
			if e != nil {
				rec = "echoue"
				if cs.Expected.Get("verdicts").Get(rg).S() != "echoue" {
					rec += " (" + e.Raison + ")"
				}
			}
			f.Comparer(cs.ID, "verdict "+rg, cs.Expected.Get("verdicts").Get(rg).S(), rec, rg)
		}
		premierID := ""
		if premier != nil {
			premierID = premier.Check
		}
		c.issueVerdicts(cs, verd, premierID)
		chk, code := refusAttendu(cs)
		switch {
		case chk == "" && premier == nil:
		case chk == "":
			f.Comparer(cs.ID, "refusal", "null", premier.Check, premier.Check)
		case premier == nil:
			f.Comparer(cs.ID, "refusal.check", chk, "aucune vérification en échec", chk)
		default:
			f.Comparer(cs.ID, "refusal.check", chk, premier.Check, chk)
			f.Hors(cs.ID, "refusal.code "+code, raisonMotifRG)
		}
		// Ancre registry dérivée (hors source, texte libre de RG-20).
		// Lecture retenue : l'ancre dérivée n'est rendue que si RG-20 réussit.
		att := cs.Expected.Get("registry")
		if res.Verdicts["RG-20"] != nil {
			f.Comparer(cs.ID, "registry (RG-20 en échec : aucune ancre rendue)", Compact(att), "null", "RG-20")
			continue
		}
		f.Vrai(cs.ID, "registry dérivée (hors source)", EgalJSON(SansMembre(att, "source", false), SansMembre(res.Registre, "source", false)), Compact(res.Registre), "RG-20")
		f.Hors(cs.ID, "registry.source", "texte libre (RG-20 : « source à la discrétion du réviseur »)")
	}
}
