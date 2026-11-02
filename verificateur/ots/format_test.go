package ots

// O-1 (EX-10.2, EX-10.5) et O-3 (EX-10.7) sur des fichiers construits, dont
// des entrées hostiles : troncatures, longueurs absurdes, varuint non
// minimaux, profondeur, tailles.

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var empreinteTest = sha256.Sum256([]byte("e"))

func doitLire(t *testing.T, b []byte) *Preuve {
	t.Helper()
	p, d := Analyser(b)
	if d != nil {
		t.Fatalf("refusé : %v", d)
	}
	return p
}

func doitRefuser(t *testing.T, b []byte, motif string) {
	t.Helper()
	p, d := Analyser(b)
	if d == nil || p != nil {
		t.Fatalf("accepté, refus attendu (%s)", motif)
	}
	if !strings.Contains(d.Message.Fr, motif) {
		t.Errorf("défaut %q, %q attendu", d.Message.Fr, motif)
	}
	if d.Message.En == "" || d.Position < 0 || d.Position > len(b) {
		t.Errorf("défaut mal formé : %+v", d)
	}
}

func TestFormatNominal(t *testing.T) {
	p := doitLire(t, fichierOTS(empreinteTest, opAp([]byte{1}), opSHA(), attBitcoin(1001)))
	if p.Empreinte != empreinteTest || len(p.Arbre) != 1 || p.Arbre[0].Op != opAppend || len(p.Arbre[0].Sous) != 1 {
		t.Fatalf("arbre inattendu : %+v", p.Arbre)
	}
	// Fourches : ff branche ff branche branche, dans l'ordre du fichier.
	p = doitLire(t, fichierOTS(empreinteTest, fourche(), attAttente("a"), fourche(), opSHA(), attBitcoin(5), attInconnue([8]byte{1}, nil)))
	x := executer(p)
	if len(x.Attestations) != 3 || x.Attestations[0].Genre != GenreAttente || x.Attestations[1].Genre != GenreBitcoin || x.Attestations[2].Genre != GenreInconnue {
		t.Fatalf("attestations %+v", x.Attestations)
	}
}

func TestFormatEnTete(t *testing.T) {
	b := fichierOTS(empreinteTest, attBitcoin(1))
	m := append([]byte{}, b...)
	m[3] ^= 1
	doitRefuser(t, m, "en-tête magique")
	m = append([]byte{}, b...)
	m[31] = 0x02
	doitRefuser(t, m, "version 02")
	m = append([]byte{}, b...)
	m[31] = 0x81 // varuint 0x81 0x00 non admis : seule la version 01
	doitRefuser(t, m, "version 81")
	m = append([]byte{}, b...)
	m[32] = 0x02
	doitRefuser(t, m, "opération de hachage du fichier 02")
	doitRefuser(t, nil, "en-tête magique")
	doitRefuser(t, b[:40], "fin de fichier prématurée")
	doitRefuser(t, b[:64], "fin de fichier prématurée")
}

func TestFormatFinExacte(t *testing.T) {
	b := fichierOTS(empreinteTest, attBitcoin(1))
	doitRefuser(t, append(b, 0x00), "1 octet(s) après l'arbre")
	doitRefuser(t, append(b, 0xff, 0x00), "2 octet(s) après l'arbre")
}

func TestFormatTroncatures(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repOTS, "preuves", "periode-1.ots"))
	if err != nil {
		t.Fatal(err)
	}
	doitLire(t, b)
	for n := 0; n < len(b); n++ {
		if p, d := Analyser(b[:n]); d == nil || p != nil {
			t.Fatalf("préfixe de %d octets accepté", n)
		}
	}
}

func TestFormatEtiquettes(t *testing.T) {
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x04}, attBitcoin(1)), "étiquette d'opération inconnue 04")
	doitRefuser(t, fichierOTS(empreinteTest, fourche(), fourche(), attBitcoin(1)), "étiquette d'opération inconnue ff")
	doitRefuser(t, fichierOTS(empreinteTest, fourche(), attBitcoin(1)), "fin de fichier prématurée")
	// Opérations hors profil : reconnues, lues sans argument.
	for _, op := range []byte{opSHA1, opRIPEMD160, opKeccak256, opReverse, opHexlify} {
		doitLire(t, fichierOTS(empreinteTest, []byte{op}, attBitcoin(1)))
	}
}

func TestFormatArguments(t *testing.T) {
	doitRefuser(t, fichierOTS(empreinteTest, opAp(nil), attBitcoin(1)), "argument de 0 octets")
	doitRefuser(t, fichierOTS(empreinteTest, opPre(make([]byte, 4097)), attBitcoin(1)), "argument de 4097 octets")
	doitLire(t, fichierOTS(empreinteTest, opPre(make([]byte, 4096)), attBitcoin(1)))
	doitLire(t, fichierOTS(empreinteTest, opAp([]byte{0}), attBitcoin(1)))
	// Longueur absurde : 2^62 annoncés.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{opAppend}, varuintTest(1<<62), []byte{1}), "argument de 4611686018427387904 octets")
	// Longueur plausible mais au-delà de la fin du fichier.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{opAppend}, varuintTest(100), []byte{1, 2}), "fin de fichier prématurée")
}

func TestFormatVaruint(t *testing.T) {
	// Forme minimale à plusieurs octets : admise.
	p := doitLire(t, fichierOTS(empreinteTest, attBitcoin(1<<32-1)))
	if x := executer(p); x.Attestations[0].Hauteur != 1<<32-1 {
		t.Fatalf("hauteur %d", x.Attestations[0].Hauteur)
	}
	// Hauteur 2^32 : refusée.
	doitRefuser(t, fichierOTS(empreinteTest, attBitcoin(1<<32)), "hauteur Bitcoin 4294967296")
	// Forme non minimale (groupe final nul) dans la hauteur, la longueur
	// d'un argument, la longueur d'une charge.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], []byte{0x02, 0x81, 0x00}), "non minimale")
	doitRefuser(t, fichierOTS(empreinteTest, []byte{opAppend, 0x81, 0x00, 0x01}, attBitcoin(1)), "non minimale")
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], []byte{0x82, 0x00, 0x01, 0x01}), "non minimale")
	// Zéro sur un octet : forme minimale.
	doitLire(t, fichierOTS(empreinteTest, attBitcoin(0)))
	// Neuf octets admis, dix refusés.
	neuf := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], vb(neuf)), "hauteur Bitcoin")
	dix := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], vb(dix)), "plus de 9 octets")
	doitRefuser(t, fichierOTS(empreinteTest, []byte{opAppend}, dix), "plus de 9 octets")
}

func TestFormatAttestations(t *testing.T) {
	// Charge Bitcoin non consommée exactement.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], vb([]byte{0x05, 0x00})), "non consommée exactement")
	// Charge Bitcoin vide.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteBitcoin[:], vb(nil)), "fin de fichier prématurée")
	// Charge de 8192 octets admise (inconnue), 8193 refusée.
	doitLire(t, fichierOTS(empreinteTest, attInconnue([8]byte{9}, make([]byte, MaxCharge))))
	doitRefuser(t, fichierOTS(empreinteTest, attInconnue([8]byte{9}, make([]byte, MaxCharge+1))), "charge d'attestation de 8193 octets")
	// URI : vide admise, 1000 admis, 1001 refusés, caractère hors liste.
	doitLire(t, fichierOTS(empreinteTest, attAttente("")))
	doitLire(t, fichierOTS(empreinteTest, attAttente(strings.Repeat("a", MaxURI))))
	doitRefuser(t, fichierOTS(empreinteTest, attAttente(strings.Repeat("a", MaxURI+1))), "URI de 1001 octets")
	doitRefuser(t, fichierOTS(empreinteTest, attAttente("https://a b")), "hors de A-Z")
	doitRefuser(t, fichierOTS(empreinteTest, attAttente("https://a?b")), "hors de A-Z")
	doitLire(t, fichierOTS(empreinteTest, attAttente("ABCxyz019-._/:")))
	// URI suivie d'un octet dans la charge.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00}, etiquetteAttente[:], vb(enc(vb([]byte("a")), []byte{0x00}))), "non consommée exactement")
	// Étiquette tronquée.
	doitRefuser(t, fichierOTS(empreinteTest, []byte{0x00, 0x05, 0x88}), "fin de fichier prématurée")
}

func chaineOps(n int, op []byte, fin []byte) []byte {
	return enc(bytes.Repeat(op, n), fin)
}

func TestFormatProfondeur(t *testing.T) {
	p := doitLire(t, fichierOTS(empreinteTest, chaineOps(MaxOperationsChemin, opSHA(), attBitcoin(1))))
	x := executer(p)
	if x.Operations != MaxOperationsChemin || !x.Attestations[0].Calcule {
		t.Fatalf("exécution : %+v", x)
	}
	doitRefuser(t, fichierOTS(empreinteTest, chaineOps(MaxOperationsChemin+1, opSHA(), attBitcoin(1))), "plus de 255 opérations")
	// La borne porte sur un chemin, pas sur le fichier : deux chemins de 255.
	doitLire(t, fichierOTS(empreinteTest, fourche(), chaineOps(255, opSHA(), attBitcoin(1)), chaineOps(255, []byte{opReverse}, attBitcoin(2))))
	// Profondeur hostile : 100 000 opérations imbriquées, sans débordement
	// de pile.
	doitRefuser(t, fichierOTS(empreinteTest, chaineOps(100000, opSHA(), attBitcoin(1))), "plus de 255 opérations")
	// Fourches imbriquées : ff 08 ff 08 … , chacune ouverte sous la
	// précédente.
	doitRefuser(t, fichierOTS(empreinteTest, chaineOps(300, enc(fourche(), attBitcoin(1), opSHA()), attBitcoin(2))), "plus de 255 opérations")
}

func TestFormatTaille(t *testing.T) {
	// 256 Kio : la borne d'EX-10.2 s'applique avant toute lecture.
	gros := fichierOTS(empreinteTest, attInconnue([8]byte{1}, make([]byte, MaxCharge)))
	gros = append(gros, make([]byte, TailleMax)...)
	doitRefuser(t, gros, "plus de 256 Kio")
	// Fichier de 256 Kio exactement, fait de fourches larges : lu.
	var arbre []byte
	unite := enc(fourche(), opSHA(), attBitcoin(1))
	for len(arbre)+len(unite)+20 < TailleMax-len(fichierOTS(empreinteTest)) {
		arbre = append(arbre, unite...)
	}
	b := fichierOTS(empreinteTest, arbre, attBitcoin(2))
	if len(b) > TailleMax {
		t.Fatalf("fichier de %d octets", len(b))
	}
	p := doitLire(t, b)
	if x := executer(p); len(x.Attestations) < 10000 {
		t.Fatalf("%d attestations", len(x.Attestations))
	}
}

func TestExecutionBornes(t *testing.T) {
	// Résultat de 4096 octets admis ; 4097 refusé (O-3).
	p := doitLire(t, fichierOTS(empreinteTest, opAp(make([]byte, MaxMessage-32)), opSHA(), attBitcoin(1)))
	if x := executer(p); x.Defaut != nil || x.Attestations[0].Longueur != 32 {
		t.Fatalf("exécution : %+v", x)
	}
	p = doitLire(t, fichierOTS(empreinteTest, opAp(make([]byte, MaxMessage-31)), opSHA(), attBitcoin(1)))
	x := executer(p)
	if x.Defaut == nil || !strings.Contains(x.Defaut.Fr, "résultat de 4097 octets") || x.Attestations[0].Calcule || !x.Attestations[0].EnDefaut {
		t.Fatalf("exécution : %+v", x)
	}
	// Croissance par f1 répétées jusqu'au dépassement.
	p = doitLire(t, fichierOTS(empreinteTest, chaineOps(3, opPre(make([]byte, 2000)), attBitcoin(1))))
	if x := executer(p); x.Defaut == nil {
		t.Fatal("dépassement non vu")
	}
	// Opérations : f0, f1, 08.
	p = doitLire(t, fichierOTS(empreinteTest, opPre([]byte("a")), opAp([]byte("b")), attAttente("u")))
	x = executer(p)
	if x.Attestations[0].Longueur != 34 {
		t.Fatalf("longueur %d", x.Attestations[0].Longueur)
	}
	p = doitLire(t, fichierOTS(empreinteTest, opPre([]byte("a")), opAp([]byte("b")), opSHA(), attAttente("u")))
	w := sha256.Sum256(enc([]byte("a"), empreinteTest[:], []byte("b")))
	if x := executer(p); x.Attestations[0].Resultat != w {
		t.Fatal("résultat faux")
	}
	// Une opération hors profil : rien n'est exécuté sous elle, même une
	// opération qui dépasserait les bornes.
	p = doitLire(t, fichierOTS(empreinteTest, []byte{opRIPEMD160}, opAp(make([]byte, 4096)), attBitcoin(1)))
	x = executer(p)
	if x.Defaut != nil || x.HorsProfil != 1 || x.Attestations[0].OpHorsProfil != opRIPEMD160 || x.Attestations[0].Calcule {
		t.Fatalf("exécution : %+v", x)
	}
}
