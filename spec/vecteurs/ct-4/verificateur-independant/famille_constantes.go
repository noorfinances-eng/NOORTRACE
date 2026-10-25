// Famille « constantes » : constantes.json (A.2), chaque valeur rederivée.

package main

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Mnemonique est la phrase publique des comptes Hardhat (CT-4 §7.4, A.2).
const Mnemonique = "test test test test test test test test test test test junk"

// cleHardhat dérive la clé du compte i (m/44'/60'/0'/0/i, EX-7.3).
func cleHardhat(i int) ([]byte, error) {
	g, err := GraineBIP39(Mnemonique)
	if err != nil {
		return nil, err
	}
	return DeriverBIP32(g, "m/44'/60'/0'/0/"+strconv.Itoa(i))
}

func (c *Ctx) enregistrerCle(prive []byte) string {
	a, err := AdresseDePrivee(prive)
	if err != nil {
		return ""
	}
	h := Hex0x(a)
	c.Cles[h] = prive
	return h
}

func pubNonCompressee(prive []byte) string {
	xy, err := ClePublique(prive)
	if err != nil {
		return "erreur : " + err.Error()
	}
	return Hex0x(append([]byte{4}, xy...))
}

func ed25519Pub(etiquette string) string {
	k := ed25519.NewKeyFromSeed(Sha256([]byte(etiquette)))
	return Hex0x(k.Public().(ed25519.PublicKey))
}

// FamilleConstantes vérifie constantes.json.
func (c *Ctx) FamilleConstantes() {
	f := c.R.F("constantes")
	k, _, err := LireJSON(filepath.Join(c.Racine, "constantes.json"))
	if err != nil {
		f.Erreur("constantes.json", "lecture", err, "A.2")
		return
	}
	c.Constantes = k
	cas := "constantes.json"
	cmp := func(val, att, rec, regle string) { f.Comparer(cas, val, att, rec, regle) }

	ch := k.Get("chain")
	cmp("chain.evm_chain_id", "2124", ch.Get("evm_chain_id").Num, "A.2")
	cmp("chain.bft_chain_id", "noortrace-2124-dev", ch.Get("bft_chain_id").S(), "A.2")
	if n, ok := nombreBFT(ch.Get("bft_chain_id").S()); ok {
		cmp("chain : nombre de bft_chain_id = evm_chain_id", ch.Get("evm_chain_id").Num, n, "EX-4.6")
	}

	// Contrats : table de 5.3 et CREATE(déployeur, nonce).
	ct := k.Get("contracts")
	noms := map[string]string{"AttestationRegistry": "attestation_registry", "CuratorSetRegistry": "curator_set_registry", "PeriodRegistry": "period_registry", "RecorderRegistry": "recorder_registry"}
	deployeur, _ := DecoderHexN("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", 20)
	for _, l := range LignesTable(Section(c.Texte, "### 5.3 Adresses publiées")) {
		cs := Codes(l[0])
		ad := Codes(l[1])
		if len(cs) != 1 || len(ad) != 1 {
			continue
		}
		cle := noms[cs[0]]
		cmp("contracts."+cle+" (table de 5.3)", ad[0], ct.Get(cle).S(), "A.2")
		nonce, err := strconv.Atoi(strings.TrimSpace(l[2]))
		if err == nil {
			cmp("contracts."+cle+" = CREATE(déployeur, "+l[2]+")", Hex0x(AdresseCreation(deployeur, big.NewInt(int64(nonce)))), ct.Get(cle).S(), "RG-19")
		}
	}
	// CuratorSet de assureur-demo : capture.json de CT-6.
	if cap, _, err := LireJSON(filepath.Join(c.CT6, "registre", "capture", "capture.json")); err == nil {
		cmp("curator_set (capture.json de CT-6)", cap.Get("organisation").Get("curator_set").S(), k.Get("curator_set").S(), "A.2")
		ap := cap.Get("organisation").Get("approbateurs")
		var adrs []string
		for _, i := range k.Get("approvers").Get("accounts").Arr {
			n, _ := strconv.Atoi(i.Num)
			p, err := cleHardhat(n)
			if err == nil {
				a, _ := AdresseDePrivee(p)
				adrs = append(adrs, Hex0x(a))
			}
		}
		cmp("approvers.accounts = approbateurs de capture.json", Compact(ap), Compact(TableauChaines(adrs)), "A.2")
		cmp("approvers.threshold", cap.Get("organisation").Get("seuil").Num, k.Get("approvers").Get("threshold").Num, "A.2")
	} else {
		f.Erreur(cas, "capture.json de CT-6", err, "A.2")
	}
	cmp("relayer.account (compte Hardhat 0)", "0", k.Get("relayer").Get("account").Num, "A.2")

	// Jeu de validateurs du réseau de développement.
	vs := k.Get("validator_set")
	if c.JeuDev != nil {
		cmp("validator_set.valset_hash (jeu de l'exemple de 4.8)", Hex0x(c.JeuDev.Hachage()), vs.Get("valset_hash").S(), "CT-6 EX-11.8")
	}
	if vj, _, err := LireJSON(filepath.Join(c.CT6, "registre", "capture", "validators.json")); err == nil {
		if j, err := ChargerJeu(vj.Get("validators")); err == nil {
			cmp("validator_set.valset_hash (validators.json de la capture de CT-6)", Hex0x(j.Hachage()), vs.Get("valset_hash").S(), "CT-6 EX-11.8")
		} else {
			f.Erreur(cas, "validators.json de CT-6", err, "CT-6 EX-11.8")
		}
	}
	f.Hors(cas, "validator_set.file", "test/fixtures/ n'est pas lu (vérificateur écrit sans lire test/) ; le jeu vient de l'exemple de 4.8, « copie publique test/fixtures/certificat-commit/validators.json »")

	// Genèse.
	g := k.Get("genesis")
	if b, err := os.ReadFile(filepath.Join(c.Depot, filepath.FromSlash(g.Get("file").S()))); err == nil {
		cmp("genesis.sha256 = SHA-256 de "+g.Get("file").S(), Hex0x(Sha256(b)), g.Get("sha256").S(), "RG-17")
	} else {
		f.Erreur(cas, "genesis.file", err, "RG-17")
	}

	// Jeu d'essai.
	tv := k.Get("test_validators")
	var liste []*Value
	for _, v := range tv.Get("validators").Arr {
		id := v.Get("id").S()
		cmp("test_validators."+id+".seed", "noortrace/vecteurs/ct4/validateur/"+id, v.Get("seed").S(), "A.2")
		pk := Sha256([]byte(v.Get("seed").S()))
		cmp("test_validators."+id+".private_key = SHA-256(seed)", Hex0x(pk), v.Get("private_key").S(), "A.2")
		cmp("test_validators."+id+".pubKeyHex", pubNonCompressee(pk), v.Get("pubKeyHex").S(), "A.2")
		liste = append(liste, Objet("id", Chaine(id), "pubKeyHex", Chaine(v.Get("pubKeyHex").S())))
	}
	if j, err := ChargerJeu(Tableau(liste...)); err == nil {
		c.JeuEssai = &j
		cmp("test_validators.valset_hash", Hex0x(j.Hachage()), tv.Get("valset_hash").S(), "CT-6 EX-11.8")
	} else {
		f.Erreur(cas, "test_validators", err, "RG-18")
	}

	// Organisation et journal.
	org := k.Get("organisation")
	if id, e := RG1(org.Get("slug").S(), false); e == nil {
		cmp("organisation.org_id", Hex0x(id), org.Get("org_id").S(), "RG-1")
	}
	jou := k.Get("journal")
	if id, e := RG2(jou.Get("name").S()); e == nil {
		cmp("journal.journal_id", Hex0x(id), jou.Get("journal_id").S(), "RG-2")
	}

	// Comptes Hardhat.
	cmp("mnemonic", Mnemonique, k.Get("mnemonic").S(), "A.2")
	for _, a := range k.Get("accounts").Arr {
		i, _ := strconv.Atoi(a.Get("index").Num)
		chemin := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		cmp(fmt.Sprintf("accounts[%d].derivation_path", i), chemin, a.Get("derivation_path").S(), "A.2")
		p, err := cleHardhat(i)
		if err != nil {
			f.Erreur(cas, "dérivation", err, "A.2")
			continue
		}
		cmp(fmt.Sprintf("accounts[%d].private_key (BIP-39, BIP-32)", i), Hex0x(p), a.Get("private_key").S(), "A.2")
		cmp(fmt.Sprintf("accounts[%d].address", i), c.enregistrerCle(p), a.Get("address").S(), "A.2")
	}

	// Clés d'enregistreur.
	for _, r := range k.Get("recorders").Arr {
		id := r.Get("key_id").S()
		cmp(id+".chain_key_seed", "noortrace/vecteurs/v0/cle-chaine/"+id, r.Get("chain_key_seed").S(), "A.2")
		pk := Sha256([]byte(r.Get("chain_key_seed").S()))
		cmp(id+".chain_key_private = SHA-256(seed)", Hex0x(pk), r.Get("chain_key_private").S(), "A.2")
		cmp(id+".chain_key", c.enregistrerCle(pk), r.Get("chain_key").S(), "A.2")
		cmp(id+".ed25519_seed", "noortrace/vecteurs/v0/cle-enregistreur/"+id, r.Get("ed25519_seed").S(), "A.2")
		cmp(id+".public_key (Ed25519 de la graine)", ed25519Pub(r.Get("ed25519_seed").S()), r.Get("public_key").S(), "A.2")
	}

	// Manifestes de CT-1.
	for _, m := range k.Get("manifests").Arr {
		chemin := m.Get("file").S()
		mv, _, err := LireJSON(filepath.Join(c.Depot, filepath.FromSlash(chemin)))
		if err != nil {
			f.Erreur(cas, chemin, err, "CT-1 §10.2")
			continue
		}
		ph, err := PeriodHash(mv)
		if err != nil {
			f.Erreur(cas, chemin, err, "CT-1 §10.2")
			continue
		}
		cmp("periodHash de "+chemin, Hex0x(ph), m.Get("period_hash").S(), "CT-1 §10.2")
	}

	// Instance synthétique de production.
	pr := k.Get("production")
	if n, ok := nombreBFT(pr.Get("bft_chain_id").S()); ok {
		cmp("production : nombre de bft_chain_id = evm_chain_id", pr.Get("evm_chain_id").Num, n, "EX-4.6")
	}
	for _, m := range pr.Get("accounts").Obj {
		cmp("production."+m.Key+".seed", "noortrace/vecteurs/ct4/compte/"+m.Key, m.Val.Get("seed").S(), "A.2")
		pk := Sha256([]byte(m.Val.Get("seed").S()))
		cmp("production."+m.Key+".private_key = SHA-256(seed)", Hex0x(pk), m.Val.Get("private_key").S(), "A.2")
		cmp("production."+m.Key+".address", c.enregistrerCle(pk), m.Val.Get("address").S(), "A.2")
	}
	f.Hors(cas, "production.creation_code", "code de création synthétique (A.4) : aucune valeur à recalculer")

	// Exemples de 7.7 et 7.10.
	ex := k.Get("example")
	if id, e := RG1(ex.Get("slug").S(), false); e == nil {
		cmp("example.org_id", Hex0x(id), ex.Get("org_id").S(), "RG-1")
	}
	if id, e := RG2(ex.Get("journal").S()); e == nil {
		cmp("example.journal_id", Hex0x(id), ex.Get("journal_id").S(), "RG-2")
	}
	for i, a := range ex.Get("approvers").Arr {
		cmp(fmt.Sprintf("example.approvers[%d].seed", i), fmt.Sprintf("noortrace/exemple/ct4/approbateur/%d", i+1), a.Get("seed").S(), "A.2")
		pk := Sha256([]byte(a.Get("seed").S()))
		cmp(fmt.Sprintf("example.approvers[%d].private_key", i), Hex0x(pk), a.Get("private_key").S(), "A.2")
		cmp(fmt.Sprintf("example.approvers[%d].address", i), c.enregistrerCle(pk), a.Get("address").S(), "A.2")
	}
	for _, nom := range []string{"set_admin", "chain_key"} {
		o := ex.Get(nom)
		pk := Sha256([]byte(o.Get("seed").S()))
		cmp("example."+nom+".private_key", Hex0x(pk), o.Get("private_key").S(), "A.2")
		cmp("example."+nom+".address", c.enregistrerCle(pk), o.Get("address").S(), "A.2")
	}
	cmp("example.set_admin.seed", "noortrace/exemple/ct4/admin-jeu", ex.Get("set_admin").Get("seed").S(), "A.2")
	cmp("example.chain_key.seed", "noortrace/exemple/ct4/cle-chaine/rec-exemple-01", ex.Get("chain_key").Get("seed").S(), "A.2")
	cmp("example.ed25519.public_key", ed25519Pub(ex.Get("ed25519").Get("seed").S()), ex.Get("ed25519").Get("public_key").S(), "A.2")
	cmp("example.curator_set (20 premiers octets de SHA-256)", Hex0x(Sha256([]byte("noortrace/exemple/ct4/curator-set"))[:20]), ex.Get("curator_set").S(), "A.2")
	man := ex.Get("manifest")
	cmp("example.manifest.period_start", "1793520000", man.Get("period_start").Num, "A.2")
	cmp("example.manifest.period_end = period_start + 3600", "1793523600", man.Get("period_end").Num, "A.2")
	var feuilles [][]byte
	for i := 1; i <= 3; i++ {
		feuilles = append(feuilles, Sha256([]byte(fmt.Sprintf("noortrace/exemple/ct4/evenement/%d", i))))
	}
	cmp("example.manifest.root (trois événements, CT-1 §9.1)", Hex0x(RacineRFC6962(feuilles)), man.Get("root").S(), "A.2")
	cmp("example.manifest.nonce", Hex0x(Sha256([]byte("noortrace/exemple/ct4/nonce/1"))), man.Get("nonce").S(), "A.2")
	cmp("example.manifest.generated_at", "2026-11-01T09:00:01.000Z", man.Get("generated_at").S(), "A.2")
	cmp("example.manifest.org_id", ex.Get("org_id").S(), man.Get("org_id").S(), "A.2")
	cmp("example.manifest.journal_id", ex.Get("journal_id").S(), man.Get("journal_id").S(), "A.2")
	if ph, err := PeriodHash(man); err == nil {
		cmp("example.period_hash", Hex0x(ph), ex.Get("period_hash").S(), "CT-1 §10.2")
		cmp("example.period_hash (texte de A.2)", "0x266dd53a36a4c33232bd8dc4758eb036cc7adf8f483cb1ae8e7fc2a77034e8fb", Hex0x(ph), "A.2")
		org, _ := DecoderHexN(man.Get("org_id").S(), 32)
		jo, _ := DecoderHexN(man.Get("journal_id").S(), 32)
		if _, fp, e := RG4(org, jo, ph); e == nil {
			cmp("example.fingerprint", Hex0x(fp), ex.Get("fingerprint").S(), "RG-4")
		}
	} else {
		f.Erreur(cas, "example.manifest", err, "CT-1 §10.2")
	}

	// Frais : valeurs par défaut de 4.8.
	fe := k.Get("fees")
	for _, p := range [][2]string{{"transaction_type", "2"}, {"gas_limit", "3000000"}, {"gas_limit_max", "16777216"}, {"provision_days", "30"}, {"refill_below_days", "7"}} {
		cmp("fees."+p[0], p[1], fe.Get(p[0]).Num, "EX-4.15")
	}
	cmp("fees.max_fee_per_gas_wei", "1", fe.Get("max_fee_per_gas_wei").S(), "EX-4.15")
	cmp("fees.max_priority_fee_per_gas_wei", "1", fe.Get("max_priority_fee_per_gas_wei").S(), "EX-4.15")

	// Transactions de la capture de CT-6 (B.4) : relues dans les propositions.
	roles := map[string]string{"inscription": "RecorderRegistered(bytes32,address,bytes32,bytes32,address)", "ancre": "Anchored(bytes32,address,bytes32)", "cloture": "PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)"}
	for _, t := range k.Get("capture_transactions").Arr {
		h, _ := strconv.ParseUint(t.Get("block_number").Num, 10, 64)
		bc := c.Capture[h]
		nom := fmt.Sprintf("capture_transactions[%d]", h)
		if bc == nil || len(bc.Txs) != 1 {
			f.Erreur(cas, nom, fmt.Errorf("bloc %d absent de la capture de CT-6", h), "EX-A.4")
			continue
		}
		raw := bc.Txs[0]
		cmp(nom+".transaction_hash = keccak256(txsRaw[0])", Hex0x(Keccak256(raw)), t.Get("transaction_hash").S(), "EX-A.4")
		cmp(nom+".transaction_hash = transactions[0] de l'en-tête", bc.EnTete.Transactions[0], t.Get("transaction_hash").S(), "EX-A.4")
		tx, err := DecoderTx2(raw)
		if err != nil {
			f.Erreur(cas, nom, err, "EX-A.4")
			continue
		}
		cmp(nom+".nonce", tx.Nonce.String(), t.Get("nonce").Num, "EX-A.4")
		cmp(nom+".max_fee_per_gas", tx.Plafond.String(), t.Get("max_fee_per_gas").S(), "EX-A.4")
		cmp(nom+".max_priority_fee_per_gas", tx.Pourboire.String(), t.Get("max_priority_fee_per_gas").S(), "EX-A.4")
		cmp(nom+".gas_limit", tx.Gaz.String(), t.Get("gas_limit").S(), "EX-A.4")
		exp, err := Expediteur(raw, tx)
		if err == nil {
			cmp(nom+" : expéditeur (relayeur, compte Hardhat 0)", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", exp, "EX-A.4")
		}
		if sig, ok := roles[t.Get("role").S()]; ok && len(bc.Recus[0].Journaux) > 0 {
			cmp(nom+".role : topics[0] du journal", Hex0x(Keccak256([]byte(sig))), Hex0x(bc.Recus[0].Journaux[0].Sujets[0]), "5.7")
		}
	}
}

// nombreBFT rend le nombre que porte un identifiant noortrace-<n>-<suffixe>.
func nombreBFT(id string) (string, bool) {
	p := strings.Split(id, "-")
	if len(p) != 3 || p[0] != "noortrace" {
		return "", false
	}
	return p[1], true
}
