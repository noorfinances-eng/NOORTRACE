package registre

// Recalculs de 11.3 confrontés aux vecteurs (attendu.json et trie.json de la
// famille registre, exemple de EX-11.4) : préimage et hachage BFT, encodage
// des reçus, racine du trie, journaux décodés, hachage du jeu, quorum,
// lecture canonique des lignes, signature R ‖ S ‖ V.

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

const racineReg = "../../spec/vecteurs/ct-6/registre"

func lireFichier(t testing.TB, chemin string) []byte {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexBrut(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("hexadécimal illisible : %s", s)
	}
	return b
}

// recusJSON convertit des reçus JSON (forme de registre.json) en reçus.
func recusJSON(t testing.TB, v *jsonv.Valeur) []recu {
	t.Helper()
	var out []recu
	for _, r := range v.Elements {
		ty, _ := quantite(r.Membre("type").S())
		st, _ := quantite(r.Membre("status").S())
		cu, _ := quantite(r.Membre("cumulativeGasUsed").S())
		rc := recu{genre: byte(ty), statut: byte(st), cumul: cu}
		for _, j := range r.Membre("logs").Elements {
			var jn journal
			jn.adresse, _ = adresse(j.Membre("address").S())
			for _, s := range j.Membre("topics").Elements {
				h, _ := hex32(s.S())
				jn.sujets = append(jn.sujets, h)
			}
			jn.donnees = hexBrut(t, j.Membre("data").S())
			rc.journaux = append(rc.journaux, jn)
		}
		out = append(out, rc)
	}
	return out
}

func TestTrieSynthetique(t *testing.T) {
	v, err := jsonv.Analyser(lireFichier(t, filepath.Join(racineReg, "trie.json")))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := racineRecus(nil); cryptographie.Hex32(r) != v.Membre("vide").S() {
		t.Errorf("racine vide %x", r)
	}
	for _, c := range v.Membre("recus").Elements {
		r, ok := racineRecus(recusJSON(t, c.Membre("receipts")))
		if !ok || cryptographie.Hex32(r) != c.Membre("root").S() {
			t.Errorf("reçus n=%s : racine %x, attendue %s", c.Membre("n").Texte, r, c.Membre("root").S())
		}
	}
	for _, c := range v.Membre("generique").Elements {
		var couples []couple
		for _, p := range c.Membre("pairs").Elements {
			couples = append(couples, couple{cle: quartets(hexBrut(t, p.Membre("key").S())), valeur: hexBrut(t, p.Membre("value").S())})
		}
		n := noeudTrie(couples, 0)
		if r := cryptographie.Keccak256(n); cryptographie.Hex32(r) != c.Membre("root").S() {
			t.Errorf("couples n=%s : racine %x, attendue %s", c.Membre("n").Texte, r, c.Membre("root").S())
		}
	}
}

// entreesCapture : toutes les entrées des jeux de parties dérivés de la
// capture, par hauteur.
func entreesCapture(t testing.TB) map[uint64]entreeRegistre {
	out := map[uint64]entreeRegistre{}
	for _, rep := range []string{"periode-1-point", "periode-2", "variantes/invalide-r10-inscription-cle-inconnue"} {
		es, d := lireRegistre(lireFichier(t, filepath.Join(racineReg, rep, "registre.json")))
		if d != nil {
			t.Fatal(d.Fr)
		}
		for _, e := range es {
			out[e.bloc.numero] = e
		}
	}
	return out
}

func TestBlocsCapture(t *testing.T) {
	var att struct {
		Blocs []struct {
			Height           uint64          `json:"height"`
			BftPreimage      string          `json:"bft_preimage"`
			BftBlockHash     string          `json:"bft_block_hash"`
			ReceiptsRoot     string          `json:"receipts_root"`
			ReceiptEncodings []string        `json:"receipt_encodings"`
			BlockTime        string          `json:"block_time"`
			Emitter          string          `json:"emitter"`
			Event            json.RawMessage `json:"event"`
		} `json:"blocs"`
	}
	if err := json.Unmarshal(lireFichier(t, filepath.Join(racineReg, "attendu.json")), &att); err != nil {
		t.Fatal(err)
	}
	es := entreesCapture(t)
	if len(att.Blocs) != 8 {
		t.Errorf("%d blocs, 8 attendus", len(att.Blocs))
	}
	for _, b := range att.Blocs {
		e, ok := es[b.Height]
		if !ok {
			t.Errorf("bloc %d absent des parties", b.Height)
			continue
		}
		if p := "0x" + hex.EncodeToString(preimageBFT(&e.bloc)); p != b.BftPreimage {
			t.Errorf("bloc %d : préimage %s", b.Height, p)
		}
		if h := hachageBFT(&e.bloc); cryptographie.Hex32(h) != b.BftBlockHash {
			t.Errorf("bloc %d : hachage %x", b.Height, h)
		}
		for i := range e.recus {
			if enc := "0x" + hex.EncodeToString(encoderRecu(&e.recus[i])); enc != b.ReceiptEncodings[i] {
				t.Errorf("bloc %d : encodage du reçu %d", b.Height, i)
			}
		}
		if r, _ := racineRecus(e.recus); cryptographie.Hex32(r) != b.ReceiptsRoot {
			t.Errorf("bloc %d : racine %x", b.Height, r)
		}
		j := e.journalProuve()
		if hexA(j.adresse) != b.Emitter {
			t.Errorf("bloc %d : émetteur %s", b.Height, hexA(j.adresse))
		}
		got, _ := json.Marshal(evenement(&e))
		var x, y any
		_ = json.Unmarshal(got, &x)
		_ = json.Unmarshal(b.Event, &y)
		if !reflect.DeepEqual(x, y) {
			t.Errorf("bloc %d : événement %s, attendu %s", b.Height, got, b.Event)
		}
	}
}

// TestExempleEX114 : bloc 8316 de l'exemple de EX-11.4.
func TestExempleEX114(t *testing.T) {
	p := hexBrut(t, "6e6f6f722f76312f626674626c6f636b68617368"+
		"293cde1df216315a74cfa45851f246fd1e32f6d92734c26ac567be95968f1bc2"+
		"000000000000207c000000006ad8b09f"+
		"6d3c48fd05042b6c6c65bec56affb2db5d7b1571a4f4df22b81f8410246de64a"+
		"2b733fd11b9a29ec7ee2135b50c9e4b8e878088c95d613fbe287f9a22d91612b"+
		"9a980c5c887bb493cffb54eb12dbbabfcaa6f27bedbbadd166797b91b4c75220"+
		"000000000006a8d20000000001c9c380"+
		"0000000000000000000000000000000000000000000000000000000000000001")
	if len(p) != 212 {
		t.Fatalf("préimage de %d octets", len(p))
	}
	var e entete
	copy(e.parent[:], p[20:52])
	e.numero = new(big.Int).SetBytes(p[52:60]).Uint64()
	e.horodatage = new(big.Int).SetBytes(p[60:68]).Uint64()
	copy(e.etat[:], p[68:100])
	copy(e.transactions[:], p[100:132])
	copy(e.recus[:], p[132:164])
	e.gazUtilise = new(big.Int).SetBytes(p[164:172]).Uint64()
	e.gazLimite = new(big.Int).SetBytes(p[172:180]).Uint64()
	copy(e.baseFee[:], p[180:212])
	if string(preimageBFT(&e)) != string(p) {
		t.Errorf("préimage différente")
	}
	if h := cryptographie.Hex32(hachageBFT(&e)); h != "0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c" {
		t.Errorf("BFTBlockHash %s", h)
	}
}

func TestSujetsEtDocTypes(t *testing.T) {
	for sig, sujet := range map[string]string{signatureCloture: hexSujetCloture, signatureAncre: hexSujetAncre, signatureInscription: hexSujetInscription} {
		if h := cryptographie.Keccak256([]byte(sig)); cryptographie.Hex32(h) != sujet {
			t.Errorf("%s : %x", sig, h)
		}
	}
	if h := cryptographie.Keccak256([]byte("noortrace/periode/v0")); cryptographie.Hex32(h) != hexDocTypePeriode {
		t.Errorf("docType de période %x", h)
	}
	if h := cryptographie.Keccak256([]byte("noortrace/point-de-controle/v0")); cryptographie.Hex32(h) != DocTypePoint {
		t.Errorf("docType de point %x", h)
	}
}

func TestQuorum(t *testing.T) {
	for n, q := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3, 5: 4, 6: 4, 7: 5, 10: 7, 128: 86} {
		if quorum(n) != q {
			t.Errorf("quorum(%d) = %d, attendu %d", n, quorum(n), q)
		}
	}
}

// TestLignesCapture : toutes les lignes capturées sont canoniques et
// valides ; la ligne au membre « Domain » de la variante est acceptée mais
// non canonique (AV-R-2).
func TestLignesCapture(t *testing.T) {
	for _, rep := range []string{"periode-1-point", "periode-2", "variantes/valide-ligne-non-canonique"} {
		certs, d := lireCertificats(lireFichier(t, filepath.Join(racineReg, rep, "certificat-commit.json")))
		if d != nil {
			t.Fatal(d.Fr)
		}
		for _, c := range certs {
			for i, l := range append([]string{c.proposition}, c.precommits...) {
				_, canon, err := lireLigne(l)
				if err != nil {
					t.Fatal(err)
				}
				nonCanon := strings.HasPrefix(l, `{"Domain"`)
				if canon == nonCanon {
					t.Errorf("%s, bloc %d, ligne %d : canonique %v", rep, c.hauteur, i, canon)
				}
			}
		}
	}
}

func TestSignatureRSV(t *testing.T) {
	graine := cryptographie.Sha256([]byte("essai"))
	cle := secp256k1.PrivKeyFromBytes(graine[:])
	m := cryptographie.Sha256([]byte("message"))
	sig := signerRSV(cle, m)
	pub, err := recouvrer(m, sig)
	if err != nil || string(pub) != string(cle.PubKey().SerializeUncompressed()) {
		t.Fatalf("recouvrement : %v", err)
	}
	// S haut : n − S, V inversé, même point recouvré par une autre lecture.
	haut := append([]byte{}, sig...)
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(secp256k1.S256().N, s)
	s.FillBytes(haut[32:64])
	haut[64] ^= 1
	if _, err := recouvrer(m, haut); err == nil {
		t.Errorf("S haut accepté")
	}
	v2 := append([]byte{}, sig...)
	v2[64] = 27
	if _, err := recouvrer(m, v2); err == nil {
		t.Errorf("V = 27 accepté")
	}
	if _, err := recouvrer(m, sig[:64]); err == nil {
		t.Errorf("signature de 64 octets acceptée")
	}
	nul := make([]byte, 65)
	if _, err := recouvrer(m, nul); err == nil {
		t.Errorf("R = S = 0 accepté")
	}
}

func TestHachageJeuCapture(t *testing.T) {
	jeux, d := lireValidateurs(lireFichier(t, filepath.Join(racineReg, "periode-1", "validateurs.json")))
	if d != nil {
		t.Fatal(d.Fr)
	}
	if h := cryptographie.Hex32(hachageJeu(&jeux[0])); h != "0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751" {
		t.Errorf("hachage du jeu %s", h)
	}
}
