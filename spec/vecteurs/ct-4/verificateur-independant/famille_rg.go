// Familles identifiants, doctypes, empreintes, condenses, appels et
// transactions (A.4) : RG-1 à RG-15.

package main

import (
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
)

// ------------------------------------------------------------ identifiants

// FamilleIdentifiants : RG-1, RG-2.
func (c *Ctx) FamilleIdentifiants() {
	f := c.R.F("identifiants")
	for _, cs := range c.lireFamille(f, "identifiants.json", "identifiants") {
		in := cs.Input
		switch in.Get("kind").S() {
		case "slug":
			id, e := RG1(in.Get("value").S(), in.Get("production") != nil && in.Get("production").Bool)
			if c.confronterIssue(f, cs, e) {
				f.Comparer(cs.ID, "org_id", cs.Expected.Get("org_id").S(), Hex0x(id), "RG-1")
			}
		case "journal":
			id, e := RG2(in.Get("value").S())
			if c.confronterIssue(f, cs, e) {
				f.Comparer(cs.ID, "journal_id", cs.Expected.Get("journal_id").S(), Hex0x(id), "RG-2")
			}
		default:
			f.Erreur(cs.ID, "input.kind", fmt.Errorf("sorte %q inconnue", in.Get("kind").S()), "RG-1")
		}
	}
}

// ------------------------------------------------------------ doctypes

// FamilleDoctypes : RG-3.
func (c *Ctx) FamilleDoctypes() {
	f := c.R.F("doctypes")
	for _, cs := range c.lireFamille(f, "doctypes.json", "doctypes") {
		in := cs.Input
		if in.Has("label") {
			dt, e := RG3Libelle(in.Get("label").S())
			if c.confronterIssue(f, cs, e) {
				f.Comparer(cs.ID, "doc_type", cs.Expected.Get("doc_type").S(), Hex0x(dt), "RG-3")
			}
			continue
		}
		b, err := DecoderHexN(in.Get("doc_type").S(), 32)
		if err != nil {
			f.Erreur(cs.ID, "input.doc_type", err, "RG-3")
			continue
		}
		lib, e := RG3Valeur(b)
		if c.confronterIssue(f, cs, e) {
			f.Comparer(cs.ID, "label", cs.Expected.Get("label").S(), lib, "RG-3")
		}
	}
}

// ------------------------------------------------------------ empreintes

// FamilleEmpreintes : RG-4 ; pour les manifestes de CT-1, periodHash
// recalculé du manifeste et empreinte égale à anchor_fingerprint de
// attendu.json.
func (c *Ctx) FamilleEmpreintes() {
	f := c.R.F("empreintes")
	attendus := map[string]string{}
	if a, _, err := LireJSON(filepath.Join(c.CT1, "manifestes", "attendu.json")); err == nil {
		for _, p := range a.Get("periodes").Arr {
			attendus[p.Get("fichier").S()] = p.Get("anchor_fingerprint").S()
		}
	} else {
		f.Erreur("attendu.json de CT-1", "lecture", err, "RG-4")
	}
	for _, cs := range c.lireFamille(f, "empreintes.json", "empreintes") {
		in := cs.Input
		org, e1 := DecoderHexN(in.Get("org_id").S(), 32)
		jou, e2 := DecoderHexN(in.Get("journal_id").S(), 32)
		ph, e3 := DecoderHexN(in.Get("period_hash").S(), 32)
		if e1 != nil || e2 != nil || e3 != nil {
			f.Erreur(cs.ID, "input", fmt.Errorf("champs illisibles"), "RG-4")
			continue
		}
		if m := in.Get("manifest"); m != nil {
			mv, _, err := LireJSON(filepath.Join(c.Depot, filepath.FromSlash(m.S())))
			if err != nil {
				f.Erreur(cs.ID, "manifeste", err, "CT-1 §10.2")
			} else if p, err := PeriodHash(mv); err == nil {
				f.Comparer(cs.ID, "period_hash recalculé de "+m.S(), in.Get("period_hash").S(), Hex0x(p), "CT-1 §10.2")
				f.Comparer(cs.ID, "org_id du manifeste", in.Get("org_id").S(), mv.Get("org_id").S(), "RG-4")
				f.Comparer(cs.ID, "journal_id du manifeste", in.Get("journal_id").S(), mv.Get("journal_id").S(), "RG-4")
			}
		}
		pre, fp, e := RG4(org, jou, ph)
		if in.Has("fingerprint") {
			c.comparerAlteration(f, cs, "fingerprint")
		}
		if e == nil && in.Has("fingerprint") {
			if d := in.Get("fingerprint").S(); d != Hex0x(fp) {
				e = echec("RG-4", "empreinte déclarée %s au lieu de %s", d, Hex0x(fp))
			}
		}
		if c.confronterIssue(f, cs, e) {
			f.Comparer(cs.ID, "preimage", cs.Expected.Get("preimage").S(), Hex0x(pre), "RG-4")
			f.Comparer(cs.ID, "fingerprint", cs.Expected.Get("fingerprint").S(), Hex0x(fp), "RG-4")
			if m := in.Get("manifest"); m != nil {
				if a, ok := attendus[filepath.Base(m.S())]; ok {
					f.Comparer(cs.ID, "fingerprint = anchor_fingerprint de attendu.json de CT-1", a, Hex0x(fp), "RG-4")
				}
			}
		}
	}
}

// ------------------------------------------------------------ condenses

func (c *Ctx) manifestesCT1() map[string]*Value {
	out := map[string]*Value{}
	for _, n := range []string{"periode-1.json", "periode-2.json", "periode-3.json"} {
		if v, _, err := LireJSON(filepath.Join(c.CT1, "manifestes", n)); err == nil {
			if p, err := PeriodHash(v); err == nil {
				out[Hex0x(p)] = v
			}
		}
	}
	return out
}

// metaDuManifeste tire PeriodMeta d'un manifeste (CT-1 §10.4, EX-6.8).
func metaDuManifeste(m *Value, ph []byte, uri string) *Value {
	return Objet("org_id", Chaine(m.Get("org_id").S()), "journal_id", Chaine(m.Get("journal_id").S()),
		"period_hash", Chaine(Hex0x(ph)), "root", Chaine(m.Get("root").S()),
		"period_start", Chaine(m.Get("period_start").Num), "period_end", Chaine(m.Get("period_end").Num),
		"first_seq", Chaine(m.Get("first_seq").Num), "last_seq", Chaine(m.Get("last_seq").Num),
		"version", &Value{Kind: KindNumber, Num: m.Get("version").Num}, "uri", Chaine(uri))
}

func (c *Ctx) comparerCondense(f *Famille, cs Cas, rg string, pre []byte) {
	d := Keccak256(pre)
	if dec := cs.Input.Get("digest"); dec != nil {
		c.comparerAlteration(f, cs, "digest")
		if e := (dec.S() != Hex0x(d)); e {
			c.confronterIssue(f, cs, echec(rg, "condensé déclaré %s au lieu de %s", dec.S(), Hex0x(d)))
			return
		}
	}
	if c.confronterIssue(f, cs, nil) {
		f.Comparer(cs.ID, "preimage", cs.Expected.Get("preimage").S(), Hex0x(pre), rg)
		f.Comparer(cs.ID, "preimage_length", cs.Expected.Get("preimage_length").Num, strconv.Itoa(len(pre)), rg)
		f.Comparer(cs.ID, "digest", cs.Expected.Get("digest").S(), Hex0x(d), rg)
		f.Comparer(cs.ID, "eip191_digest", cs.Expected.Get("eip191_digest").S(), Hex0x(HachageSigne(d)), "RG-12")
	}
}

// FamilleCondenses : RG-5 à RG-13.
func (c *Ctx) FamilleCondenses() {
	f := c.R.F("condenses")
	mans := c.manifestesCT1()
	for _, cs := range c.lireFamille(f, "condenses.json", "condenses") {
		in := cs.Input
		chain := big.NewInt(0)
		if v := in.Get("chain_id"); v != nil {
			chain, _ = EntierLitteral(v.Num)
		}
		contrat, _ := DecoderHexN(in.Get("contract").S(), 20)
		switch {
		case len(cs.Checks) == 1 && cs.Checks[0] == "RG-5":
			m, err := LireMeta(in.Get("period_meta"))
			if err != nil {
				f.Erreur(cs.ID, "period_meta", err, "RG-5")
				continue
			}
			var prec *Precedente
			if p := in.Get("previous"); p != nil {
				pe, _ := Decimal(p.Get("period_end").S())
				ls, _ := Decimal(p.Get("last_seq").S())
				prec = &Precedente{pe, ls}
			}
			e := RG5(m, prec, in.Get("slug").S(), in.Get("journal_name").S())
			if c.confronterIssue(f, cs, e) {
				f.Comparer(cs.ID, "period_meta", Compact(cs.Expected.Get("period_meta")), Compact(in.Get("period_meta")), "RG-5")
				vide := new(big.Int).Add(m.LastSeq, big.NewInt(1)).Cmp(m.FirstSeq) == 0
				f.Comparer(cs.ID, "empty", strconv.FormatBool(cs.Expected.Get("empty").Bool), strconv.FormatBool(vide), "RG-5")
				if mv, ok := mans[Hex0x(m.PeriodHash)]; ok {
					tire := metaDuManifeste(mv, m.PeriodHash, m.URI)
					f.Vrai(cs.ID, "period_meta tiré du manifeste de CT-1 champ pour champ", EgalJSON(tire, in.Get("period_meta")), Compact(tire), "RG-5")
				}
			}
		case cs.Checks[0] == "RG-6":
			m, err := LireMeta(in.Get("period_meta"))
			if err != nil {
				f.Erreur(cs.ID, "period_meta", err, "RG-6")
				continue
			}
			c.comparerCondense(f, cs, "RG-6", PreimagePeriode(chain, contrat, m))
		case cs.Checks[0] == "RG-7":
			org, _ := DecoderHexN(in.Get("org_id").S(), 32)
			jou, _ := DecoderHexN(in.Get("journal_id").S(), 32)
			ck, _ := DecoderHexN(in.Get("chain_key").S(), 20)
			ed, _ := DecoderHexN(in.Get("ed25519_public_key").S(), 32)
			pre, e := PreimageInscription(chain, contrat, org, jou, ck, ed)
			if e != nil {
				c.confronterIssue(f, cs, e)
				continue
			}
			c.comparerCondense(f, cs, "RG-7", pre)
		case cs.Checks[0] == "RG-8":
			org, _ := DecoderHexN(in.Get("org_id").S(), 32)
			ck, _ := DecoderHexN(in.Get("chain_key").S(), 20)
			reg, err := Decimal(in.Get("registered_at").S())
			if err != nil {
				f.Erreur(cs.ID, "registered_at", err, "RG-8")
				continue
			}
			pre, e := PreimageRevocation(chain, contrat, org, ck, reg)
			if e != nil {
				c.confronterIssue(f, cs, e)
				continue
			}
			if ts, ok := c.horodatageInscription(in.Get("chain_key").S()); ok && cs.Refusal.IsNull() {
				f.Comparer(cs.ID, "registered_at = horodatage du bloc de RecorderRegistered (capture de CT-6)", ts, reg.String(), "RG-8")
			}
			c.comparerCondense(f, cs, "RG-8", pre)
		case cs.Checks[0] == "RG-9":
			fp, _ := DecoderHexN(in.Get("fingerprint").S(), 32)
			dt, _ := DecoderHexN(in.Get("doc_type").S(), 32)
			c.comparerCondense(f, cs, "RG-9", PreimageAncre(chain, contrat, fp, dt))
		case cs.Checks[0] == "RG-10":
			fp, _ := DecoderHexN(in.Get("fingerprint").S(), 32)
			c.comparerCondense(f, cs, "RG-10", PreimageRevocationAncre(chain, contrat, fp))
		case cs.Checks[0] == "RG-11":
			arg, _ := DecoderHexN(in.Get("arg").S(), 32)
			n, _ := Decimal(in.Get("nonce").S())
			pre, e := PreimageAdmin(chain, contrat, in.Get("op").S(), arg, n)
			if e != nil {
				c.confronterIssue(f, cs, e)
				continue
			}
			c.comparerCondense(f, cs, "RG-11", pre)
		case len(cs.Checks) == 1 && cs.Checks[0] == "RG-12":
			c.casSignature(f, cs)
		case len(cs.Checks) == 2 && cs.Checks[0] == "RG-12" && cs.Checks[1] == "RG-13":
			c.casSeuil(f, cs)
		default:
			f.Erreur(cs.ID, "checks", fmt.Errorf("combinaison %v non prévue", cs.Checks), "EX-A.3")
		}
	}
}

// horodatageInscription rend l'horodatage du bloc de la capture de CT-6 dont
// le reçu porte RecorderRegistered sous cette clé de chaîne (EX-6.11).
func (c *Ctx) horodatageInscription(cle string) (string, bool) {
	topic := Hex0x(Keccak256([]byte("RecorderRegistered(bytes32,address,bytes32,bytes32,address)")))
	for _, h := range c.hauteursCapture() {
		bc := c.Capture[h]
		for _, r := range bc.Recus {
			for _, j := range r.Journaux {
				if len(j.Sujets) == 4 && Hex0x(j.Sujets[0]) == topic && Hex0x(j.Sujets[2][12:]) == cle {
					return bc.EnTete.Timestamp.String(), true
				}
			}
		}
	}
	return "", false
}

// reproduire signe le condensé avec la clé connue du signataire (RFC 6979)
// et confronte la signature des vecteurs (EX-A.1).
func (c *Ctx) reproduire(f *Famille, cas, valeur, signer string, h []byte, s SignatureEVM) {
	k, ok := c.Cles[signer]
	if !ok {
		f.Hors(cas, valeur+" (RFC 6979)", "clé privée du signataire "+signer+" inconnue des constantes")
		return
	}
	r, err := SignerEVM(k, h)
	if err != nil {
		f.Erreur(cas, valeur, err, "EX-A.1")
		return
	}
	f.Comparer(cas, valeur+" reproduite (RFC 6979)", Hex0x(s.Octets65()), Hex0x(r.Octets65()), "EX-A.1")
}

func (c *Ctx) casSignature(f *Famille, cs Cas) {
	in := cs.Input
	d, err := DecoderHexN(in.Get("digest").S(), 32)
	if err != nil {
		f.Erreur(cs.ID, "digest", err, "RG-12")
		return
	}
	s, signer, err := LireSignature(in.Get("signature"))
	if err != nil {
		f.Erreur(cs.ID, "signature", err, "RG-12")
		return
	}
	var dec []byte
	if v := in.Get("eip191_digest"); v != nil {
		dec, _ = DecoderHexN(v.S(), 32)
	}
	h, adr, e := RG12(d, s, signer, dec)
	if c.confronterIssue(f, cs, e) {
		f.Comparer(cs.ID, "eip191_digest", cs.Expected.Get("eip191_digest").S(), Hex0x(h), "RG-12")
		f.Comparer(cs.ID, "recovered", cs.Expected.Get("recovered").S(), adr, "RG-12")
		f.Comparer(cs.ID, "signature65", cs.Expected.Get("signature65").S(), Hex0x(s.Octets65()), "RG-12")
		c.reproduire(f, cs.ID, "signature", signer, h, s)
	}
}

func (c *Ctx) casSeuil(f *Famille, cs Cas) {
	in := cs.Input
	d, err := DecoderHexN(in.Get("digest").S(), 32)
	if err != nil {
		f.Erreur(cs.ID, "digest", err, "RG-12")
		return
	}
	var signataires []string
	var sigs []SignatureEVM
	var e *Echec
	for _, o := range in.Get("signatures").Arr {
		s, signer, err := LireSignature(o)
		if err != nil {
			f.Erreur(cs.ID, "signature", err, "RG-12")
			return
		}
		if _, _, ee := RG12(d, s, signer, nil); ee != nil && e == nil {
			e = ee
		}
		signataires = append(signataires, signer)
		sigs = append(sigs, s)
	}
	var membres []string
	for _, m := range in.Get("members").Arr {
		membres = append(membres, m.S())
	}
	t, _ := strconv.Atoi(in.Get("threshold").Num)
	if e == nil {
		e = RG13(signataires, membres, t)
	}
	if th := in.Get("transaction_hash"); th != nil {
		c.signaturesDeLaCapture(f, cs.ID, th.S(), sigs)
	}
	if c.confronterIssue(f, cs, e) {
		f.Comparer(cs.ID, "signers", Compact(cs.Expected.Get("signers")), Compact(TableauChaines(signataires)), "RG-13")
		for i, s := range sigs {
			c.reproduire(f, cs.ID, fmt.Sprintf("signatures[%d]", i), signataires[i], HachageSigne(d), s)
		}
	}
}

// signaturesDeLaCapture confronte des signatures à celles que porte la
// transaction réelle de la capture de CT-6 (EX-A.4).
func (c *Ctx) signaturesDeLaCapture(f *Famille, cas, th string, sigs []SignatureEVM) {
	for _, h := range c.hauteursCapture() {
		bc := c.Capture[h]
		for _, raw := range bc.Txs {
			if Hex0x(Keccak256(raw)) != th {
				continue
			}
			tx, err := DecoderTx2(raw)
			if err != nil {
				f.Erreur(cas, "transaction réelle", err, "EX-A.4")
				return
			}
			var lues []SignatureEVM
			d := tx.Donnees
			k := len(sigs)
			debut := len(d) - 96*k
			for i := 0; i < k && debut >= 0; i++ {
				o := d[debut+96*i:]
				lues = append(lues, SignatureEVM{V: int(new(big.Int).SetBytes(o[:32]).Int64()), R: new(big.Int).SetBytes(o[32:64]), S: new(big.Int).SetBytes(o[64:96])})
			}
			var a, b []string
			for i := range sigs {
				a = append(a, Hex0x(sigs[i].Octets65()))
				if i < len(lues) {
					b = append(b, Hex0x(lues[i].Octets65()))
				}
			}
			f.Comparer(cas, "signatures = celles de la transaction réelle, dans son ordre", strings.Join(a, ","), strings.Join(b, ","), "EX-A.4")
			return
		}
	}
	f.Hors(cas, "transaction "+th, "absente de la capture de CT-6")
}

// ------------------------------------------------------------ appels

// donneesReelles rend les données de la transaction réelle d'un bloc de la
// capture de CT-6 (EX-A.4).
func (c *Ctx) donneesReelles(h uint64) ([]byte, string, error) {
	bc := c.Capture[h]
	if bc == nil || len(bc.Txs) == 0 {
		return nil, "", fmt.Errorf("bloc %d absent de la capture", h)
	}
	tx, err := DecoderTx2(bc.Txs[0])
	if err != nil {
		return nil, "", err
	}
	return tx.Donnees, Hex0x(Keccak256(bc.Txs[0])), nil
}

// FamilleAppels : RG-14.
func (c *Ctx) FamilleAppels() {
	f := c.R.F("appels")
	for _, cs := range c.lireFamille(f, "appels.json", "appels") {
		in := cs.Input
		args := in.Get("args")
		if ct := in.Get("contract"); ct != nil {
			b, err := ArgumentsConstructeur(ct.S(), args)
			if err != nil {
				c.confronterIssue(f, cs, echec("RG-14", "%v", err))
				continue
			}
			if c.confronterIssue(f, cs, nil) {
				f.Comparer(cs.ID, "constructor_args", cs.Expected.Get("constructor_args").S(), Hex0x(b), "RG-14")
			}
			continue
		}
		fn := in.Get("function").S()
		d, err := DonneesAppel(fn, args)
		var e *Echec
		if err != nil {
			e = echec("RG-14", "%v", err)
		} else if dec := in.Get("calldata"); dec != nil && dec.S() != Hex0x(d) {
			e = echec("RG-14", "données déclarées différentes de l'encodage de 6.7.2")
		}
		if !c.confronterIssue(f, cs, e) {
			continue
		}
		f.Comparer(cs.ID, "calldata", cs.Expected.Get("calldata").S(), Hex0x(d), "RG-14")
		f.Comparer(cs.ID, "length", cs.Expected.Get("length").Num, strconv.Itoa(len(d)), "RG-14")
		k, lu := 0, 0
		if s := args.Get("signatures"); s != nil {
			k = len(s.Arr)
		}
		if m := args.Get("period_meta"); m != nil {
			lu = len(m.Get("uri").S())
		}
		f.Comparer(cs.ID, "longueur de la table de 6.7.2", strconv.Itoa(LongueurAttendue(fn, k, lu)), strconv.Itoa(len(d)), "RG-14")
		if bn := in.Get("block_number"); bn != nil {
			h, _ := strconv.ParseUint(bn.Num, 10, 64)
			reel, th, err := c.donneesReelles(h)
			if err != nil {
				f.Erreur(cs.ID, "transaction réelle", err, "EX-A.4")
				continue
			}
			f.Comparer(cs.ID, "calldata = donnée de la transaction réelle (txsRaw du certificat capturé)", Hex0x(reel), Hex0x(d), "EX-A.4")
			f.Comparer(cs.ID, "transaction_hash de la transaction réelle", in.Get("transaction_hash").S(), th, "EX-A.4")
		}
	}
}

// ------------------------------------------------------------ transactions

// ContexteTx est le contexte de RG-15.
type ContexteTx struct {
	Chain     *big.Int
	GasLimit  *big.Int
	Objet     string
	Dest      string
	Donnees   string
	Provision *big.Int
	Remplace  *big.Int
}

// RG15 vérifie une transaction sérialisée (EX-6.18).
func RG15(raw []byte, ctx ContexteTx) (Tx2, *Echec) {
	tx, err := DecoderTx2(raw)
	if err == ErrPasType2 {
		return tx, echec("RG-15", "transaction d'un autre type que 2 (premier octet 0x%02x)", raw[0])
	}
	if err != nil {
		return tx, echec("RG-15", "transaction illisible : %v", err)
	}
	if tx.ChainID.Cmp(ctx.Chain) != 0 {
		return tx, echec("RG-15", "chainId %s au lieu de %s", tx.ChainID, ctx.Chain)
	}
	p := big.NewInt(1)
	if ctx.Remplace != nil {
		p = new(big.Int).Mul(ctx.Remplace, big.NewInt(11))
		p.Add(p, big.NewInt(9))
		p.Div(p, big.NewInt(10))
	}
	if tx.Pourboire.Cmp(tx.Plafond) != 0 || tx.Plafond.Cmp(p) != 0 {
		return tx, echec("RG-15", "frais %s et %s au lieu de %s et %s", tx.Pourboire, tx.Plafond, p, p)
	}
	if tx.Gaz.Cmp(ctx.GasLimit) != 0 || tx.Gaz.Cmp(big.NewInt(1<<24)) > 0 {
		return tx, echec("RG-15", "gasLimit %s au lieu de fees.gas_limit %s (au plus 2^24)", tx.Gaz, ctx.GasLimit)
	}
	if !tx.ListeVide {
		return tx, echec("RG-15", "liste d'accès non vide")
	}
	if tx.YParity.Cmp(big.NewInt(1)) > 0 || tx.R.Sign() <= 0 || tx.R.Cmp(secpN) >= 0 || tx.S.Sign() <= 0 || tx.S.Cmp(secpDemiN) > 0 {
		return tx, echec("RG-15", "signature non canonique")
	}
	if _, err := Expediteur(raw, tx); err != nil {
		return tx, echec("RG-15", "signature : %v", err)
	}
	switch ctx.Objet {
	case "appel":
		if tx.Dest == nil || Hex0x(tx.Dest) != ctx.Dest {
			return tx, echec("RG-15", "appel : to différent du contrat visé %s", ctx.Dest)
		}
		if tx.Valeur.Sign() != 0 {
			return tx, echec("RG-15", "appel : value non nul")
		}
		if _, err := DecoderAppel(tx.Donnees); err != nil {
			return tx, echec("RG-15", "appel : données non conformes à RG-14 : %v", err)
		}
		if ctx.Donnees != "" && Hex0x(tx.Donnees) != ctx.Donnees {
			return tx, echec("RG-15", "appel : données différentes de celles visées")
		}
	case "deploiement":
		if tx.Dest != nil {
			return tx, echec("RG-15", "déploiement avec destinataire %s", Hex0x(tx.Dest))
		}
		if tx.Valeur.Sign() != 0 {
			return tx, echec("RG-15", "déploiement : value non nul")
		}
		if Hex0x(tx.Donnees) != ctx.Donnees {
			return tx, echec("RG-15", "déploiement : données différentes du code de création suivi des arguments")
		}
	case "approvisionnement":
		if tx.Dest == nil || Hex0x(tx.Dest) != ctx.Dest {
			return tx, echec("RG-15", "approvisionnement : to différent de l'expéditeur approvisionné")
		}
		if ctx.Provision == nil || tx.Valeur.Cmp(ctx.Provision) > 0 {
			return tx, echec("RG-15", "approvisionnement : value %s au-delà de la provision %v", tx.Valeur, ctx.Provision)
		}
		if len(tx.Donnees) != 0 {
			return tx, echec("RG-15", "approvisionnement : données non vides")
		}
	default:
		return tx, echec("RG-15", "objet %q inconnu", ctx.Objet)
	}
	return tx, nil
}

func lireContexteTx(v *Value) (ContexteTx, error) {
	var ctx ContexteTx
	var ok bool
	ctx.Chain, ok = EntierLitteral(v.Get("evm_chain_id").Num)
	if !ok {
		return ctx, fmt.Errorf("evm_chain_id illisible")
	}
	ctx.GasLimit, ok = EntierLitteral(v.Get("fees").Get("gas_limit").Num)
	if !ok {
		return ctx, fmt.Errorf("fees.gas_limit illisible")
	}
	ctx.Objet = v.Get("objet").S()
	ctx.Dest = v.Get("to").S()
	ctx.Donnees = v.Get("data").S()
	if p := v.Get("provision"); p != nil {
		ctx.Provision, _ = Decimal(p.S())
	}
	if r := v.Get("remplace"); r != nil {
		ctx.Remplace, _ = Decimal(r.S())
	}
	return ctx, nil
}

// FamilleTransactions : RG-15 et transactions de la capture (EX-A.4).
func (c *Ctx) FamilleTransactions() {
	f := c.R.F("transactions")
	reelles := map[string][]byte{}
	for _, h := range c.hauteursCapture() {
		for _, raw := range c.Capture[h].Txs {
			reelles[Hex0x(Keccak256(raw))] = raw
		}
	}
	for _, cs := range c.lireFamille(f, "transactions.json", "transactions") {
		in := cs.Input
		raw, err := DecoderHex(in.Get("raw_transaction").S())
		if err != nil || len(raw) == 0 {
			f.Erreur(cs.ID, "raw_transaction", fmt.Errorf("illisible"), "RG-15")
			continue
		}
		ctx, err := lireContexteTx(in.Get("context"))
		if err != nil {
			f.Erreur(cs.ID, "context", err, "RG-15")
			continue
		}
		// Recalcul de la transaction depuis ses champs et sa clé ; sans
		// champs (forme non protégée, liste d'accès, s haut de l'exemple de
		// 6.7.3), l'expéditeur recouvré est la clé de chaîne de rec-test-02.
		if fl := in.Get("fields"); fl != nil {
			c.recalculerTx(f, cs, fl, raw, reelles)
		} else {
			cle := Sha256([]byte("noortrace/vecteurs/v0/cle-chaine/rec-test-02"))
			a, _ := AdresseDePrivee(cle)
			var exp string
			var err error
			if raw[0] == 0x02 {
				var tx Tx2
				if tx, err = DecoderTx2(raw); err == nil {
					exp, err = Expediteur(raw, tx)
				}
			} else {
				var protegee bool
				exp, protegee, err = ExpediteurAncien(raw)
				f.Vrai(cs.ID, "transaction de type 0 non protégée (v dans {27, 28})", err == nil && !protegee, fmt.Sprint(err), "RG-15")
			}
			switch {
			case err != nil && cs.Refusal != nil && !cs.Refusal.IsNull():
				// Enveloppe illisible refusée par RG-15 (6.9, transaction_illisible) : aucun expéditeur à recouvrer.
				f.Hors(cs.ID, "expéditeur", "transaction illisible : aucun expéditeur à recouvrer (RG-15 echoue)")
			case err != nil:
				f.Erreur(cs.ID, "expéditeur", err, "6.7.3")
			default:
				f.Comparer(cs.ID, "expéditeur recouvré (clé de chaîne de rec-test-02, exemple de 6.7.3)", Hex0x(a), exp, "6.7.3")
			}
		}
		_, e := RG15(raw, ctx)
		c.confronterIssue(f, cs, e)
	}
}

func (c *Ctx) recalculerTx(f *Famille, cs Cas, fl *Value, raw []byte, reelles map[string][]byte) {
	ent := func(cle string) *big.Int {
		v := fl.Get(cle)
		if v == nil {
			return nil
		}
		if v.Kind == KindNumber {
			n, _ := EntierLitteral(v.Num)
			return n
		}
		n, _ := Decimal(v.S())
		return n
	}
	t := Tx2{ChainID: ent("chain_id"), Nonce: ent("nonce"), Pourboire: ent("max_priority_fee_per_gas"), Plafond: ent("max_fee_per_gas"), Gaz: ent("gas_limit"), Valeur: ent("value")}
	for _, n := range []*big.Int{t.ChainID, t.Nonce, t.Pourboire, t.Plafond, t.Gaz, t.Valeur} {
		if n == nil {
			f.Erreur(cs.ID, "fields", fmt.Errorf("champ entier illisible"), "RG-15")
			return
		}
	}
	if to := fl.Get("to"); to != nil && !to.IsNull() {
		t.Dest, _ = DecoderHexN(to.S(), 20)
	}
	t.Donnees, _ = DecoderHex(fl.Get("data").S())
	k, err := c.cleDe(cs.Input.Get("signer_key").S())
	if err != nil {
		f.Erreur(cs.ID, "signer_key", err, "RG-15")
		return
	}
	charge := t.ChargeSignee()
	t, err = SignerTx2(t, k)
	if err != nil {
		f.Erreur(cs.ID, "signature", err, "RG-15")
		return
	}
	ser := t.Serialiser()
	exp := cs.Expected
	f.Comparer(cs.ID, "raw_transaction recalculée = input.raw_transaction", cs.Input.Get("raw_transaction").S(), Hex0x(ser), "6.7.3")
	if exp != nil && !exp.IsNull() {
		f.Comparer(cs.ID, "signing_payload", exp.Get("signing_payload").S(), Hex0x(charge), "6.7.3")
		f.Comparer(cs.ID, "signing_hash", exp.Get("signing_hash").S(), Hex0x(Keccak256(charge)), "6.7.3")
		f.Comparer(cs.ID, "y_parity", exp.Get("y_parity").Num, t.YParity.String(), "6.7.3")
		f.Comparer(cs.ID, "r", exp.Get("r").S(), Hex0x(u256(t.R)), "6.7.3")
		f.Comparer(cs.ID, "s", exp.Get("s").S(), Hex0x(u256(t.S)), "6.7.3")
		f.Comparer(cs.ID, "raw_transaction", exp.Get("raw_transaction").S(), Hex0x(ser), "6.7.3")
		f.Comparer(cs.ID, "transaction_hash", exp.Get("transaction_hash").S(), Hex0x(Keccak256(ser)), "6.7.3")
		a, _ := AdresseDePrivee(k)
		f.Comparer(cs.ID, "from", exp.Get("from").S(), Hex0x(a), "6.7.3")
		if exp2, err := Expediteur(raw, t); err == nil {
			f.Comparer(cs.ID, "expéditeur recouvré de raw_transaction", Hex0x(a), exp2, "6.7.3")
		}
	}
	if strings.HasPrefix(cs.ID, "capture-") {
		th := Hex0x(Keccak256(ser))
		reel, ok := reelles[th]
		f.Vrai(cs.ID, "transaction réelle de la capture de CT-6 de même hachage", ok, th, "EX-A.4")
		if ok {
			f.Comparer(cs.ID, "octets = transaction réelle (txsRaw du certificat capturé)", Hex0x(reel), Hex0x(ser), "EX-A.4")
		}
	}
}
