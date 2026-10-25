// Famille « texte » : ce que le texte de CT-4 imprime, recalculé (tables de
// sélecteurs, d'événements, d'erreurs, de docType, d'étiquettes et
// d'opérations ; exemples de 6.2 à 6.7 ; ligne de règles ; quorum ;
// provision) ; exemples annotés validés contre leur schéma et confrontés aux
// fichiers des vecteurs qui les reprennent.

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func hexLigne(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// valeurApres rend la première valeur 0x… qui suit « libellé = » dans sec.
func valeurApres(sec, libelle string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(libelle) + "\\s*=\\s*`?(0x[0-9a-f]+)")
	m := re.FindStringSubmatch(sec)
	if m == nil {
		return "absente du texte"
	}
	return m[1]
}

// FamilleTexte recalcule les valeurs imprimées par CT-4.
func (c *Ctx) FamilleTexte() {
	f := c.R.F("texte")
	t := c.Texte
	cas := "CT-4-registre.md"

	// 6.7.1 : sélecteurs.
	for _, l := range LignesTable(Section(t, "#### 6.7.1 Sélecteurs")) {
		sigs, sels := Codes(l[0]), Codes(l[1])
		if len(sigs) != len(sels) {
			f.Erreur(cas, "6.7.1 : "+l[0], fmt.Errorf("%d signatures pour %d sélecteurs", len(sigs), len(sels)), "6.7.1")
			continue
		}
		for i := range sigs {
			f.Comparer("6.7.1", sigs[i], sels[i], Hex0x(Selecteur(sigs[i])), "6.7.1")
		}
	}
	var noms []string
	for nom := range signaturesFonctions {
		noms = append(noms, nom)
	}
	sort.Strings(noms)
	for _, nom := range noms {
		sig := signaturesFonctions[nom]
		trouve := strings.Contains(Section(t, "#### 6.7.1 Sélecteurs"), "`"+sig+"`")
		f.Vrai("6.7.1", "signature de "+nom+" employée par ce vérificateur présente dans la table", trouve, sig, "6.7.1")
	}
	// 5.7 : sujets des événements.
	for _, l := range LignesTable(Section(t, "### 5.7 Événements")) {
		sigs, tops := Codes(l[0]), Codes(l[2])
		if len(sigs) != len(tops) {
			f.Erreur("5.7", l[0], fmt.Errorf("%d signatures pour %d sujets", len(sigs), len(tops)), "5.7")
			continue
		}
		for i := range sigs {
			f.Comparer("5.7", sigs[i], tops[i], Hex0x(Keccak256([]byte(sigs[i]))), "5.7")
		}
	}
	// 5.8 : sélecteurs des erreurs.
	reErr := regexp.MustCompile("`([A-Za-z]+\\([a-z0-9,]*\\))` `(0x[0-9a-f]{8})`")
	sec58 := Section(t, "### 5.8 Refus")
	for _, m := range reErr.FindAllStringSubmatch(sec58, -1) {
		f.Comparer("5.8", m[1], m[2], Hex0x(Selecteur(m[1])), "6.7.1")
	}
	f.Comparer("5.8", "Error(string)", "0x08c379a0", Hex0x(Selecteur("Error(string)")), "6.7.1")
	// 6.4 : table des docType.
	for _, l := range LignesTable(Section(t, "### 6.4 `docType`")) {
		cs := append(Codes(l[0]), Codes(l[1])...)
		if len(cs) == 2 {
			f.Comparer("6.4", cs[0], cs[1], Hex0x(Keccak256([]byte(cs[0]))), "RG-3")
		}
	}
	// 6.2, 6.3 : exemples.
	sec62 := Section(t, "### 6.2 Organisation : slug et `org_id`")
	for _, s := range []string{"assureur-demo", "canton-demo"} {
		f.Comparer("6.2", "org_id de "+s, valeurApres(sec62, `keccak256(utf8("`+s+`"))`), Hex0x(Keccak256([]byte(s))), "RG-1")
	}
	sec63 := Section(t, "### 6.3 Journal : nom et `journal_id`")
	for _, s := range []string{"journal-principal", "journal-sinistres"} {
		f.Comparer("6.3", "journal_id de "+s, valeurApres(sec63, `keccak256(utf8("`+s+`"))`), Hex0x(Keccak256([]byte(s))), "RG-2")
	}
	// 6.6.2 : étiquettes, longueurs et opérations.
	sec662 := Section(t, "#### 6.6.2 Préimages")
	for _, e := range []string{"noortrace-periode", "noortrace-enregistreur-inscrit", "noortrace-enregistreur-revoque", "noor-attestation-ancre", "noor-attestation-revoque"} {
		re := regexp.MustCompile("`" + regexp.QuoteMeta(e) + "`\\s*=\\s*`(0x[0-9a-f]+)`\\s*\\(([0-9]+)\\)")
		m := re.FindStringSubmatch(sec662)
		if m == nil {
			f.Erreur("6.6.2", e, fmt.Errorf("étiquette absente du texte"), "6.6.2")
			continue
		}
		f.Comparer("6.6.2", "octets de "+e, m[1], Hex0x([]byte(e)), "RG-6")
		f.Comparer("6.6.2", "longueur de "+e, m[2], strconv.Itoa(len(e)), "RG-6")
	}
	for _, l := range LignesTable(sec662) {
		if len(l) < 3 {
			continue
		}
		if ops := Codes(l[1]); len(ops) == 1 && strings.HasPrefix(ops[0], "CuratorSet.") {
			m := regexp.MustCompile("= `(0x[0-9a-f]{64})`").FindStringSubmatch(l[1])
			if m != nil {
				f.Comparer("6.6.2", "op "+ops[0], m[1], Hex0x(Keccak256([]byte(ops[0]))), "RG-11")
			}
		}
		// Longueurs des préimages : « a + b + … = n ».
		if m := regexp.MustCompile(`^([0-9 +]+) = ([0-9]+)$`).FindStringSubmatch(l[2]); m != nil {
			somme := 0
			for _, x := range strings.Split(m[1], "+") {
				n, _ := strconv.Atoi(strings.TrimSpace(x))
				somme += n
			}
			f.Comparer("6.6.2", "longueur de la préimage de "+Codes(l[0])[0], m[2], strconv.Itoa(somme), "6.6.2")
		}
	}
	// 6.6.3 : préfixe et n/2.
	sec663 := Section(t, "#### 6.6.3 Hachage signé et forme de la signature")
	f.Comparer("6.6.3", "préfixe EIP-191", valeurApres(sec663, "`P`"), Hex0x(PrefixeEIP191), "RG-12")
	f.Comparer("6.6.3", "n/2", regexp.MustCompile("`n/2` =\\s*`(0x[0-9a-f]+)`").FindStringSubmatch(sec663)[1], Hex0x(octets32(secpDemiN)), "RG-12")

	c.texteExemples664(f)
	c.texteExemple673(f)

	// EX-4.3 : ligne de règles du réseau de développement.
	if g, _, err := LireJSON(filepath.Join(c.Depot, "chain", "config", "alloc-dev.json")); err == nil {
		ligne, err := LigneRegles(g)
		if err == nil {
			sec := Section(t, "### 4.2 Genèse")
			blocs := regexp.MustCompile("(?s)```text\n(chainId=noortrace-2124-dev[^\n]*)\n```").FindStringSubmatch(sec)
			att := "absente du texte"
			if blocs != nil {
				att = blocs[1]
			}
			f.Comparer("EX-4.3", "ligne de règles de chain/config/alloc-dev.json", att, ligne, "EX-4.3")
		}
	}
	// 4.4 : quorum.
	for _, l := range LignesTable(Section(t, "### 4.4 Validateurs et quorum")) {
		if len(l) != 4 {
			continue
		}
		n, err := strconv.Atoi(l[0])
		if err != nil {
			continue
		}
		f.Comparer("4.4", "f pour N = "+l[0], l[1], strconv.Itoa(Fautes(n)), "CT-6 EX-11.8")
		f.Comparer("4.4", "quorum pour N = "+l[0], l[2], strconv.Itoa(Quorum(n)), "CT-6 EX-11.8")
		f.Comparer("4.4", "arrêts qui arrêtent la chaîne pour N = "+l[0], l[3], strconv.Itoa(n-Quorum(n)+1), "CT-6 EX-11.8")
	}
	// EX-4.19, EX-4.20 : provision.
	b := 24 * (100000 + 350000)
	p := 30*b + 3000000
	f.Comparer("EX-4.19", "b d'un journal horaire", "10 800 000", grouper(b), "EX-4.19")
	f.Comparer("EX-4.19", "P d'un journal horaire", "327 000 000", grouper(p), "EX-4.19")
	f.Comparer("EX-4.20", "transactions au plafond de 2^24", "19", strconv.Itoa(p/(1<<24)), "EX-4.19")
	f.Comparer("EX-4.20", "blocs pleins (arrondi)", "11", strconv.Itoa((p+15000000)/30000000), "EX-4.19")
	f.Comparer("EX-4.27", "tête au-delà de laquelle le bloc 8316 sort de la fenêtre", "308 316", grouper(8316+300000), "EX-4.27")
	f.Comparer("9.5", "fenêtre de 300 000 hauteurs à 1,10 bloc/s (heures)", "75,8", strings.Replace(strconv.FormatFloat(300000/1.10/3600, 'f', 1, 64), ".", ",", 1), "9.5")
	f.Comparer("EX-9.7", "3 000 000 hauteurs à 1,10 bloc/s (jours)", "31,6", strings.Replace(strconv.FormatFloat(3000000/1.10/86400, 'f', 1, 64), ".", ",", 1), "9.5")

	c.texteAnnotes(f)
	f.Hors("4.6, EX-4.23", "SHA-256 du binaire et du correctif", "artefacts hors du dépôt public ou non versionnés : non recalculables ici")
}

func grouper(n int) string {
	s := strconv.Itoa(n)
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	return strings.Join(out, " ")
}

// texteExemples664 recalcule les exemples de 6.5 et 6.6.4 depuis la capture
// de CT-6.
func (c *Ctx) texteExemples664(f *Famille) {
	t := c.Texte
	sec := Section(t, "#### 6.6.4 Exemples")
	chain := c.ChainID
	ct := c.Constantes.Get("contracts")
	adr := func(k string) []byte { b, _ := DecoderHexN(ct.Get(k).S(), 20); return b }
	// Clôture du bloc 16668.
	bc := c.Capture[16668]
	if bc == nil || len(bc.Txs) == 0 {
		f.Erreur("6.6.4", "bloc 16668", fmt.Errorf("absent de la capture"), "EX-A.4")
		return
	}
	tx, err := DecoderTx2(bc.Txs[0])
	if err != nil {
		f.Erreur("6.6.4", "transaction 16668", err, "EX-A.4")
		return
	}
	d := tx.Donnees[4:]
	tmeta := d[64 : 64+384-32]
	e := concat(u256i(0x20), tmeta)
	blocE := regexp.MustCompile(`(?s)E\(meta\)\s+=(.*?)\(384 octets\)`).FindStringSubmatch(sec)
	if blocE != nil {
		var hexs []string
		for _, l := range strings.Split(blocE[1], "\n") {
			ch := strings.Fields(l)
			if len(ch) > 0 && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ch[0]) {
				hexs = append(hexs, ch[0])
			}
		}
		f.Comparer("6.6.4", "E(meta) de la clôture du bloc 16668 (lue dans sa donnée d'appel)", strings.Join(hexs, ""), Hex0x(e)[2:], "RG-6")
	}
	f.Comparer("6.6.4", "keccak256(E)", valeurApres(sec, "keccak256(E)"), Hex0x(Keccak256(e)), "RG-6")
	pre := concat(u256(chain), adr("period_registry"), EtiqPeriode, Keccak256(e))
	pd := Keccak256(pre)
	f.Comparer("6.6.4", "periodDigest", valeurApres(sec, "periodDigest "), Hex0x(pd), "RG-6")
	hs := HachageSigne(pd)
	hsTexte := regexp.MustCompile(`hachage signé = (0x[0-9a-f]+)`).FindAllStringSubmatch(sec, -1)
	if len(hsTexte) >= 2 {
		f.Comparer("6.6.4", "hachage signé de la clôture", hsTexte[0][1], Hex0x(hs), "RG-12")
	}
	k := int(new(big.Int).SetBytes(d[64+352 : 64+384]).Int64())
	off := 64 + 352
	for i := 0; i < k; i++ {
		o := d[off+32+96*i:]
		s := SignatureEVM{V: int(o[31]), R: new(big.Int).SetBytes(o[32:64]), S: new(big.Int).SetBytes(o[64:96])}
		a, err := s.Recouvrir(hs)
		if err != nil {
			f.Erreur("6.6.4", "signature", err, "RG-12")
			continue
		}
		f.Vrai("6.6.4", fmt.Sprintf("signature %d de la clôture (r %s…) imprimée avec son signataire %s", i, Hex0x(octets32(s.R))[:12], a),
			strings.Contains(sec, Hex0x(octets32(s.R))) && strings.Contains(sec, a), "", "RG-12")
	}
	// Ancre du bloc 16660.
	ba := c.Capture[16660]
	if ba != nil && len(ba.Txs) == 1 {
		ta, _ := DecoderTx2(ba.Txs[0])
		da := ta.Donnees[4:]
		fp, dt := da[0:32], da[32:64]
		pa := PreimageAncre(chain, adr("attestation_registry"), fp, dt)
		ad := Keccak256(pa)
		f.Comparer("6.6.4", "anchorDigest", valeurApres(sec, "anchorDigest "), Hex0x(ad), "RG-9")
		if len(hsTexte) >= 2 {
			f.Comparer("6.6.4", "hachage signé de l'ancre", hsTexte[1][1], Hex0x(HachageSigne(ad)), "RG-12")
		}
		f.Vrai("6.6.4", "préimage de l'ancre de 138 octets", len(pa) == 138, "", "RG-9")
		sec65 := Section(c.Texte, "### 6.5 Empreinte d'ancre")
		f.Vrai("6.5", "empreinte du bloc 16660 imprimée en EX-6.7", strings.Contains(sec65, Hex0x(fp)), Hex0x(fp), "RG-4")
	}
	// Inscription du bloc 16648, révocation, adminOpDigest.
	bi := c.Capture[16648]
	if bi != nil && len(bi.Txs) == 1 {
		ti, _ := DecoderTx2(bi.Txs[0])
		di := ti.Donnees[4:]
		pre, _ := PreimageInscription(chain, adr("recorder_registry"), di[0:32], di[32:64], di[76:96], di[96:128])
		rd := Keccak256(pre)
		f.Comparer("6.6.4", "registerDigest du bloc 16648", regexp.MustCompile("`registerDigest` =\\s*`(0x[0-9a-f]+)`").FindStringSubmatch(sec)[1], Hex0x(rd), "RG-7")
		f.Vrai("6.6.4", "hachage signé de l'inscription imprimé", strings.Contains(sec, Hex0x(HachageSigne(rd))), Hex0x(HachageSigne(rd)), "RG-12")
		ts := bi.EnTete.Timestamp
		f.Vrai("6.6.4", "registeredAt = horodatage du bloc 16648 ("+ts.String()+")", strings.Contains(sec, ts.String()) && strings.Contains(sec, "0x"+ts.Text(16)), "", "RG-8")
		pr, _ := PreimageRevocation(chain, adr("recorder_registry"), di[0:32], di[76:96], ts)
		f.Vrai("6.6.4", "revokeDigest de 142 octets imprimé", len(pr) == 142 && strings.Contains(sec, Hex0x(Keccak256(pr))), Hex0x(Keccak256(pr)), "RG-8")
	}
	cs, _ := DecoderHexN(c.Constantes.Get("curator_set").S(), 20)
	arg := mot20(func() []byte { b, _ := DecoderHexN("0x90f79bf6eb2c4f870365e785982e1f101e93b906", 20); return b }())
	pa, _ := PreimageAdmin(chain, cs, "CuratorSet.proposeAdmin", arg, big.NewInt(0))
	f.Vrai("6.6.4", "adminOpDigest de proposeAdminSigned vers Hardhat 3, nonce 0, préimage de 148 octets", len(pa) == 148 && strings.Contains(sec, Hex0x(Keccak256(pa))), Hex0x(Keccak256(pa)), "RG-11")
	// EX-6.17.
	sec672 := Section(t, "#### 6.7.2 Arguments")
	f.Vrai("EX-6.17", "données de la clôture du bloc 16668 : 644 octets", len(tx.Donnees) == 644 && strings.Contains(sec672, "644 octets"), strconv.Itoa(len(tx.Donnees)), "RG-14")
	f.Comparer("EX-6.17", "début des données de la clôture : 0x8af03732 ‖ u256(0x40) ‖ u256(0x1a0)", Hex0x(concat(Selecteur(signaturesFonctions["submitPeriod"]), u256i(0x40), u256i(0x1a0))), Hex0x(tx.Donnees[:68]), "RG-14")
	if ba != nil && bi != nil {
		ta, _ := DecoderTx2(ba.Txs[0])
		ti, _ := DecoderTx2(bi.Txs[0])
		f.Comparer("EX-6.17", "longueur de l'anchor du bloc 16660", "196", strconv.Itoa(len(ta.Donnees)), "RG-14")
		f.Comparer("EX-6.17", "longueur du registerRecorder du bloc 16648", "388", strconv.Itoa(len(ti.Donnees)), "RG-14")
	}
}

// texteExemple673 recalcule l'exemple de 6.7.3 (anchor envoyé par la clé de
// chaîne de rec-test-02 au nonce 0).
func (c *Ctx) texteExemple673(f *Famille) {
	sec := Section(c.Texte, "#### 6.7.3 Transaction")
	ba := c.Capture[16660]
	if ba == nil || len(ba.Txs) != 1 {
		return
	}
	reel, _ := DecoderTx2(ba.Txs[0])
	dest, _ := DecoderHexN(c.Constantes.Get("contracts").Get("attestation_registry").S(), 20)
	t := Tx2{ChainID: c.ChainID, Nonce: big.NewInt(0), Pourboire: big.NewInt(1), Plafond: big.NewInt(1), Gaz: big.NewInt(3000000), Valeur: big.NewInt(0), Dest: dest, Donnees: reel.Donnees}
	cle := Sha256([]byte("noortrace/vecteurs/v0/cle-chaine/rec-test-02"))
	charge := t.ChargeSignee()
	blocs := regexp.MustCompile(`(?s)à signer\s+=\s+(.*?)\nhachage`).FindStringSubmatch(sec)
	if blocs != nil {
		txt := hexLigne(strings.ReplaceAll(blocs[1], "<196 octets de données d'appel de l'anchor du bloc 16660>", Hex0x(reel.Donnees)[2:]))
		f.Comparer("6.7.3", "charge à signer de l'exemple", txt, Hex0x(charge)[2:], "RG-15")
	}
	f.Comparer("6.7.3", "hachage de la charge", valeurApres(sec, "hachage      "), Hex0x(Keccak256(charge)), "RG-15")
	s, err := SignerTx2(t, cle)
	if err != nil {
		f.Erreur("6.7.3", "signature", err, "RG-15")
		return
	}
	f.Vrai("6.7.3", "yParity "+s.YParity.String()+", r et s imprimés", strings.Contains(sec, "yParity "+s.YParity.String()) && strings.Contains(sec, Hex0x(u256(s.R))) && strings.Contains(sec, Hex0x(u256(s.S))), "", "RG-15")
	ser := s.Serialiser()
	f.Vrai("6.7.3", fmt.Sprintf("transaction de %d octets, préfixe imprimé", len(ser)), strings.Contains(sec, fmt.Sprintf("(%d octets)", len(ser))) && strings.Contains(sec, Hex0x(ser)[:50]), "", "RG-15")
	f.Comparer("6.7.3", "hachage de la transaction", valeurApres(sec, "hachage de la transaction "), Hex0x(Keccak256(ser)), "RG-15")
	_, e := RG15(ser, ContexteTx{Chain: c.ChainID, GasLimit: big.NewInt(3000000), Objet: "appel", Dest: Hex0x(dest)})
	f.Vrai("6.7.3", "l'exemple passe RG-15", e == nil, fmt.Sprint(e), "RG-15")
}

// texteAnnotes valide les exemples annotés et les confronte aux vecteurs.
func (c *Ctx) texteAnnotes(f *Famille) {
	copies := map[string]string{
		"instance-registre":                     "manifestes/valides/developpement/instance-r1.json",
		"operations-registre/demande_signature": "demandes/valides/inscription-rec-exemple-01.json",
		"inscription-client":                    "inscription/valides/relecteur-exemple-fini.json",
		"operations-registre":                   "capture/periode-1/capture-16648-0-inscription.json",
	}
	for _, ex := range ExemplesAnnotes(c.Texte) {
		cas := fmt.Sprintf("exemple « %s » (ligne %d)", ex.Schema, ex.Ligne)
		if ex.Err != nil {
			f.Erreur(cas, "JSON", ex.Err, "EX-A.6")
			continue
		}
		errs := c.Schemas.Valider(SchemaDeAnnotation(ex.Schema), ex.Valeur)
		f.Vrai(cas, "conforme à "+SchemaDeAnnotation(ex.Schema), len(errs) == 0, strings.Join(errs, " ; "), "EX-A.6")
		if fichier, ok := copies[ex.Schema]; ok {
			v, _, err := LireJSON(filepath.Join(c.Racine, filepath.FromSlash(fichier)))
			if err != nil {
				f.Erreur(cas, fichier, err, "A.4")
			} else {
				f.Vrai(cas, "égal à "+fichier+" (valeurs JSON)", EgalJSON(v, ex.Valeur), "", "A.4")
			}
		}
		switch ex.Schema {
		case "instance-registre":
			c.texteManifeste48(f, cas, ex.Valeur)
		case "validateurs":
			if j, err := ChargerJeu(ex.Valeur.Get("sets").Arr[0].Get("validators")); err == nil {
				src := ex.Valeur.Get("sets").Arr[0].Get("source").S()
				f.Vrai(cas, "hachage du jeu imprimé dans source", strings.Contains(src, Hex0x(j.Hachage())), Hex0x(j.Hachage()), "CT-6 EX-11.8")
				if c.JeuDev != nil {
					f.Comparer(cas, "jeu = jeu de l'exemple de 4.8", Hex0x(c.JeuDev.Hachage()), Hex0x(j.Hachage()), "EX-9.10")
				}
			}
		case "operations-registre":
			// Index de 9.4 : SHA-256 des fichiers de la capture de CT-6.
			rep := filepath.Join(c.CT6, "registre", "capture")
			fs := ex.Valeur.Get("files")
			ents := append([]*Value{fs.Get("block"), fs.Get("certificate")}, fs.Get("receipts").Arr...)
			for _, o := range ents {
				b, err := os.ReadFile(filepath.Join(rep, o.Get("name").S()))
				if err != nil {
					f.Erreur(cas, o.Get("name").S(), err, "CP-6")
					continue
				}
				f.Comparer(cas, "SHA-256 de "+o.Get("name").S()+" (capture de CT-6)", o.Get("sha256").S(), Hex0x(Sha256(b)), "CP-6")
			}
		case "operations-registre/sortie":
			o := ex.Valeur.Get("outputs")
			d, _, err := LireJSON(filepath.Join(c.Racine, "inscription", "valides", "relecteur-exemple-fini.json"))
			if err == nil {
				for _, st := range d.Get("steps").Arr {
					if st.Get("step").S() == "inscription" {
						f.Comparer(cas, "outputs.transaction_hash = étape inscription de 7.10", st.Get("transaction_hash").S(), o.Get("transaction_hash").S(), "7.10")
						f.Comparer(cas, "outputs.block_number = étape inscription de 7.10", st.Get("block_number").Num, o.Get("block_number").Num, "7.10")
						f.Comparer(cas, "outputs.capture = étape inscription de 7.10", st.Get("capture").S(), o.Get("capture").S(), "7.10")
					}
				}
			}
		}
	}
}

// texteManifeste48 recalcule les valeurs de l'exemple de manifeste de 4.8.
func (c *Ctx) texteManifeste48(f *Famille, cas string, m *Value) {
	rep := c.Depot
	g := m.Get("genesis")
	b, err := os.ReadFile(filepath.Join(c.Depot, filepath.FromSlash(g.Get("file").S())))
	if err != nil {
		f.Erreur(cas, "genèse", err, "RG-17")
		return
	}
	f.Vrai(cas, "RG-17 sur chain/config/alloc-dev.json", rg17(m, b) == nil, fmt.Sprint(rg17(m, b)), "RG-17")
	f.Vrai(cas, "RG-18", rg18(m) == nil, fmt.Sprint(rg18(m)), "RG-18")
	f.Vrai(cas, "RG-19 (evidence nul)", c.rg19(m, rep) == nil, fmt.Sprint(c.rg19(m, rep)), "RG-19")
}
