package jsonv

// Essais de la revue de sécurité interne de l'étape 8 : CT-6 EX-15.1 (borne
// du nombre de valeurs et mémoire par valeur), (clé d'égalité pour
// uniqueItems), objets sans table d'index.

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// tableauDeZeros rend « [0,0,…,0] » de n éléments (n + 1 valeurs, racine
// comprise).
func tableauDeZeros(n int) []byte {
	return []byte("[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]")
}

// TestBorneValeurs : CT-6 EX-15.1. Une entrée lue sous une limite de taille L admet
// au plus L / 16 valeurs ; au-delà, ErrValeurs, comme la profondeur rend
// ErrProfondeur ; en deçà, la lecture aboutit.
func TestBorneValeurs(t *testing.T) {
	limite := int64(1 << 20)
	max := ValeursMax(limite)
	if max != 65536 {
		t.Fatalf("ValeursMax(1 Mio) = %d", max)
	}
	if _, err := AnalyserLimite(tableauDeZeros(max-1), limite); err != nil {
		t.Fatalf("%d valeurs sous une borne de %d : %v", max, max, err)
	}
	_, err := AnalyserLimite(tableauDeZeros(max), limite)
	if !errors.Is(err, ErrValeurs) {
		t.Fatalf("%d valeurs sous une borne de %d : %v", max+1, max, err)
	}
	// Plancher : une petite limite admet toujours ValeursPlancher valeurs.
	if ValeursMax(10) != ValeursPlancher {
		t.Fatalf("plancher : %d", ValeursMax(10))
	}
	// Les objets comptent aussi : « [{},{},…] ».
	objets := []byte("[" + strings.TrimSuffix(strings.Repeat("{},", max), ",") + "]")
	if _, err := AnalyserLimite(objets, limite); !errors.Is(err, ErrValeurs) {
		t.Fatalf("objets : %v", err)
	}
	// Analyser sans limite applique la borne de LimiteDefaut (64 Mio / 16).
	if ValeursMax(LimiteDefaut) != 4194304 {
		t.Fatalf("borne par défaut : %d", ValeursMax(LimiteDefaut))
	}
}

// TestMemoireParValeur : CT-6 EX-15.1. La mémoire allouée par valeur d'un tableau
// de petits nombres reste sous un seuil écrit (le lecteur relu en coûtait
// environ 175 octets par octet lu, soit 350 par valeur, mesure de la revue de sécurité).
func TestMemoireParValeur(t *testing.T) {
	const n = 1 << 19 // 1 Mio de texte, 524 289 valeurs
	b := tableauDeZeros(n)
	var avant, apres runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&avant)
	v, err := AnalyserLimite(b, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&apres)
	parValeur := float64(apres.TotalAlloc-avant.TotalAlloc) / float64(n+1)
	// Mesuré après correction : 152 octets (structure de 104 octets allouée
	// par blocs, croissance de la tranche d'éléments, copie du texte) ; le
	// seuil laisse une marge sans admettre le double.
	if parValeur > 160 {
		t.Fatalf("%.0f octets alloués par valeur, seuil 160", parValeur)
	}
	runtime.KeepAlive(v)
	if len(v.Elements) != n {
		t.Fatalf("%d éléments", len(v.Elements))
	}
}

// TestVuesDuTexteSource : une chaîne sans échappement et le texte d'un
// nombre sont lus sans copie, et leur valeur est exacte.
func TestVuesDuTexteSource(t *testing.T) {
	v, err := Analyser([]byte(`{"a":"été","b":12.50,"c":"x\ny","d":true,"e":null,"f":"é"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Membre("a").S() != "été" || v.Membre("b").Texte != "12.50" || v.Membre("b").Num != 12.5 || v.Membre("c").S() != "x\ny" || !v.Membre("d").Bool || !v.Membre("e").EstNul() || v.Membre("f").S() != "é" {
		t.Fatalf("valeurs : %+v", v)
	}
}

// TestObjetsSansIndex : la recherche d'un membre, la détection d'un doublon
// et Noms() valent pour un objet de moins de huit membres (parcours) comme
// pour un objet plus grand (table).
func TestObjetsSansIndex(t *testing.T) {
	petit, _ := Analyser([]byte(`{"a":1,"b":2,"a":3}`))
	if !petit.Doublon || petit.Membre("a").Num != 3 || !petit.A("b") || petit.A("c") || len(petit.Noms()) != 2 {
		t.Fatalf("petit objet : %+v", petit)
	}
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; i < 40; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"k` + strings.Repeat("x", i) + `":` + strings.Repeat("1", i+1))
	}
	sb.WriteString(`,"k":9}`)
	grand, err := Analyser([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !grand.Doublon || grand.Membre("k").Num != 9 || !grand.A("kxx") || grand.A("z") || len(grand.Noms()) != 40 {
		t.Fatalf("grand objet : doublon %v, k %v, noms %d", grand.Doublon, grand.Membre("k").Num, len(grand.Noms()))
	}
	sans, _ := Analyser([]byte(`{"a":1,"b":2}`))
	if sans.Doublon {
		t.Fatal("doublon à tort")
	}
	// SansMembres et NouvelObjet passent par la même construction.
	c := grand.SansMembres("k")
	if c.A("k") || len(c.Noms()) != 39 {
		t.Fatalf("SansMembres : %d noms", len(c.Noms()))
	}
	o := NouvelObjet(Membre{Nom: "x", Valeur: NouvelleChaine("1")}, Membre{Nom: "x", Valeur: NouvelleChaine("2")})
	if !o.Doublon || o.Membre("x").S() != "2" {
		t.Fatal("NouvelObjet : doublon non noté ou dernière occurrence non rendue")
	}
}

// TestCleEgalite : uniqueItems en temps linéaire. Deux valeurs ont la même clé si et seulement si
// Egales les tient pour égales.
func TestCleEgalite(t *testing.T) {
	couples := []struct {
		a, b   string
		egales bool
	}{
		{`{"a":1,"b":[1,2]}`, `{"b":[1,2],"a":1.0}`, true},
		{`{"a":1,"a":2}`, `{"a":2}`, true},
		{`[1,2]`, `[2,1]`, false},
		{`"1"`, `1`, false},
		{`null`, `false`, false},
		{`{"a":{"b":null}}`, `{"a":{"b":null}}`, true},
		{`{"a":{"b":null}}`, `{"a":{"b":0}}`, false},
		{`"a\"b"`, `"a\"b"`, true},
		{`["a","b"]`, `["a\",\"b"]`, false},
		{`1e2`, `100`, true},
	}
	for _, c := range couples {
		a, err1 := Analyser([]byte(c.a))
		b, err2 := Analyser([]byte(c.b))
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		if Egales(a, b) != c.egales {
			t.Fatalf("Egales(%s, %s) = %v", c.a, c.b, !c.egales)
		}
		if (CleEgalite(a) == CleEgalite(b)) != c.egales {
			t.Errorf("CleEgalite(%s) = %q, CleEgalite(%s) = %q, Egales %v", c.a, CleEgalite(a), c.b, CleEgalite(b), c.egales)
		}
	}
}
