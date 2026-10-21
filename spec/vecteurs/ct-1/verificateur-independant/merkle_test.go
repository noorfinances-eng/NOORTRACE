package main

import (
	"bytes"
	"testing"
)

// Entrées, nœuds et racines de référence RFC 6962 (jeu de test historique de
// Certificate Transparency, repris par transparency-dev/merkle).
var (
	entreesRFC6962 = [][]byte{
		h(""), h("00"), h("10"), h("2021"), h("3031"), h("40414243"),
		h("5051525354555657"), h("606162636465666768696a6b6c6d6e6f"),
	}
	noeudsRFC6962 = [][][]byte{{
		h("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
		h("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
		h("0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7"),
		h("07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7"),
		h("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
		h("4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658"),
		h("b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f"),
		h("46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1"),
	}, {
		h("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
		h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		h("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"),
		h("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
	}, {
		h("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
		h("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
	}, {
		h("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
	}}
	racinesRFC6962 = [][]byte{
		h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		h("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
		h("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
		h("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"),
		h("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
		h("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"),
		h("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"),
		h("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"),
		h("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
	}
)

func TestRacinesRFC6962(t *testing.T) {
	for n := 1; n <= 8; n++ {
		if got := MTH(entreesRFC6962[:n]); !bytes.Equal(got, racinesRFC6962[n]) {
			t.Errorf("n = %d : racine %x", n, got)
		}
	}
	for i, e := range entreesRFC6962 {
		if got := Feuille(e); !bytes.Equal(got, noeudsRFC6962[0][i]) {
			t.Errorf("feuille %d : %x", i, got)
		}
	}
	if got := Noeud(noeudsRFC6962[0][0], noeudsRFC6962[0][1]); !bytes.Equal(got, noeudsRFC6962[1][0]) {
		t.Errorf("nœud 0,1 : %x", got)
	}
}

func TestRacineVide(t *testing.T) {
	if got := Racine(nil); !bytes.Equal(got, RacineVide) {
		t.Fatalf("période vide : %x", got)
	}
	if !bytes.Equal(RacineVideRFC6962, racinesRFC6962[0]) {
		t.Fatal("MTH({}) de la RFC 6962 ≠ SHA-256(\"\")")
	}
	if bytes.Equal(RacineVide, RacineVideRFC6962) {
		t.Fatal("les deux conventions doivent différer")
	}
}

func TestCheminsRFC6962(t *testing.T) {
	nh := noeudsRFC6962
	cas := []struct {
		m, n    int
		attendu [][]byte
	}{
		{0, 1, [][]byte{}},
		{0, 8, [][]byte{nh[0][1], nh[1][1], nh[2][1]}},
		{5, 8, [][]byte{nh[0][4], nh[1][3], nh[2][0]}},
		{2, 3, [][]byte{nh[1][0]}},
		{1, 5, [][]byte{nh[0][0], nh[1][1], nh[0][4]}},
	}
	for _, c := range cas {
		got := Chemin(c.m, entreesRFC6962[:c.n])
		if len(got) != len(c.attendu) {
			t.Errorf("PATH(%d, %d) : longueur %d", c.m, c.n, len(got))
			continue
		}
		for i := range got {
			if !bytes.Equal(got[i], c.attendu[i]) {
				t.Errorf("PATH(%d, %d)[%d] : %x", c.m, c.n, i, got[i])
			}
		}
		feuille := Feuille(entreesRFC6962[c.m])
		if err := VerifierInclusion(feuille, uint64(c.m), uint64(c.n), got, racinesRFC6962[c.n]); err != nil {
			t.Errorf("vérification PATH(%d, %d) : %v", c.m, c.n, err)
		}
	}
	// Chaque feuille de chaque taille se vérifie contre sa racine.
	for n := 1; n <= 8; n++ {
		for m := 0; m < n; m++ {
			p := Chemin(m, entreesRFC6962[:n])
			if err := VerifierInclusion(Feuille(entreesRFC6962[m]), uint64(m), uint64(n), p, racinesRFC6962[n]); err != nil {
				t.Errorf("(%d, %d) : %v", m, n, err)
			}
		}
	}
}

func TestVerifierInclusionRefus(t *testing.T) {
	p := Chemin(3, entreesRFC6962[:5])
	f := Feuille(entreesRFC6962[3])
	root := racinesRFC6962[5]
	if err := VerifierInclusion(f, 5, 5, p, root); err != ErrIndiceHorsArbre {
		t.Errorf("indice hors arbre : %v", err)
	}
	if err := VerifierInclusion(f, 3, 5, p[:2], root); err != ErrCheminTropCourt {
		t.Errorf("chemin tronqué : %v", err)
	}
	if err := VerifierInclusion(f, 3, 5, append(append([][]byte{}, p...), p[0]), root); err != ErrCheminTropLong {
		t.Errorf("chemin trop long : %v", err)
	}
	permute := [][]byte{p[1], p[0], p[2]}
	if err := VerifierInclusion(f, 3, 5, permute, root); err != ErrRacineDifferente {
		t.Errorf("chemin permuté : %v", err)
	}
	if err := VerifierInclusion(f, 2, 5, p, root); err == nil {
		t.Error("indice décalé accepté")
	}
}

// Exemple numérique complet de CT-1 §9.4 (cinq feuilles).
func TestExempleCT1Section94(t *testing.T) {
	D := [][]byte{
		h("64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179"),
		h("dd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0"),
		h("adeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832"),
		h("471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00"),
		h("506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05"),
	}
	L := []string{
		"d5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b",
		"3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c",
		"8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e",
		"3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db",
		"a93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0",
	}
	for i := range D {
		if got := Feuille(D[i]); !bytes.Equal(got, h(L[i])) {
			t.Errorf("L(%d) = %x", i, got)
		}
	}
	n01 := Noeud(h(L[0]), h(L[1]))
	n23 := Noeud(h(L[2]), h(L[3]))
	n0123 := Noeud(n01, n23)
	if !bytes.Equal(n01, h("a5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e")) {
		t.Errorf("N01 = %x", n01)
	}
	if !bytes.Equal(n23, h("2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8")) {
		t.Errorf("N23 = %x", n23)
	}
	if !bytes.Equal(n0123, h("22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6")) {
		t.Errorf("N0123 = %x", n0123)
	}
	racine := h("6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06")
	if got := Racine(D); !bytes.Equal(got, racine) {
		t.Errorf("racine = %x", got)
	}
	chemin := Chemin(3, D)
	attendu := [][]byte{h(L[2]), n01, h(L[4])}
	for i := range attendu {
		if i >= len(chemin) || !bytes.Equal(chemin[i], attendu[i]) {
			t.Errorf("path[%d]", i)
		}
	}
	if err := VerifierInclusion(h(L[3]), 3, 5, chemin, racine); err != nil {
		t.Error(err)
	}
}
