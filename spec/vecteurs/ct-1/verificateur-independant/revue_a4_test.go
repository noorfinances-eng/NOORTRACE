package main

// CT-1 §11.4 : « une relation dont un terme est absent, n'a pas le type JSON
// que le schéma lui donne […] n'est pas tenue, et le contrôle qui l'évalue
// échoue » ; « pour A-4, request_hash est un terme de sa propre règle, qui ne
// se lit pas : la règle n'est pas tenue ». Un approval objet dont
// request_hash est absent ou n'est pas une chaîne met donc A-4 en échec, que
// voisins.json soit exploitable ou non ; un request_hash chaîne qui ne
// désigne aucun voisin laisse A-4 non exécutée, raison admise (événement de
// demande hors du dossier).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// approvalModifie rend une altération de evenement.json qui applique f à
// l'objet décodé.
func approvalModifie(t *testing.T, f func(ev map[string]any)) func(string) string {
	return func(s string) string {
		var ev map[string]any
		if err := json.Unmarshal([]byte(s), &ev); err != nil {
			t.Fatal(err)
		}
		f(ev)
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func TestRevueA4RequestHashIllisible(t *testing.T) {
	src := publie("valide-seq-6")
	cas := []struct {
		nom       string
		f         func(ev map[string]any)
		voisins   bool
		attenduA4 string
	}{
		{"approval {}", func(ev map[string]any) { ev["approval"] = map[string]any{} }, false, "echoue"},
		{"request_hash retiré", func(ev map[string]any) { delete(ev["approval"].(map[string]any), "request_hash") }, false, "echoue"},
		{"request_hash nombre", func(ev map[string]any) { ev["approval"].(map[string]any)["request_hash"] = 7 }, false, "echoue"},
		{"request_hash null", func(ev map[string]any) { ev["approval"].(map[string]any)["request_hash"] = nil }, false, "echoue"},
		{"approval {} et voisins.json inexploitable", func(ev map[string]any) { ev["approval"] = map[string]any{} }, true, "echoue"},
		{"request_hash chaîne d'un autre hash", func(ev map[string]any) {
			ev["approval"].(map[string]any)["request_hash"] = "0x" + strings.Repeat("ab", 32)
		}, false, "non_execute_admis"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			alt := map[string]func(string) string{"evenement.json": approvalModifie(t, c.f)}
			if c.voisins {
				alt["voisins.json"] = remplacerContenu("{")
			}
			d := VerifierDossier(copierDossier(t, src, alt, true))
			if d.Illisible != "" {
				t.Fatalf("entrée inutilisable : %s", d.Illisible)
			}
			if got := etatDe(d, "A-4"); got != c.attenduA4 {
				t.Errorf("A-4 : %s, attendu %s (%v)", got, c.attenduA4, d.Resultats.parID["A-4"])
			}
		})
	}
	t.Run("dossier publié : A-4 réussie", func(t *testing.T) {
		d := VerifierDossier(copierDossier(t, src, nil, false))
		if got := etatDe(d, "A-4"); got != "reussi" {
			t.Errorf("A-4 : %s, attendu reussi", got)
		}
	})
}

// Relecture à l'aveugle d'A-4 (étape 8), depuis CT-1 §11.4 seul :
// cas de la règle que TestRevueA4RequestHashIllisible ne fixe pas.
//   - request_hash objet, tableau ou booléen : mal typé, A-4 en échec ;
//   - request_hash lu et voisins.json inexploitable : non exécutée, sans
//     raison admise ;
//   - la demande se reconnaît au hash recalculé du voisin, jamais à son
//     membre hash déclaré ;
//   - demande trouvée : status différent de "retenue", ou qui n'est pas une
//     chaîne, met A-4 en échec ;
//   - request_hash chaîne hors du motif hex32 (majuscules) : terme lu, E-1
//     échoue par le schéma, mais aucun hash recalculé (hexadécimal
//     minuscule) ne l'égale : demande hors du dossier, raison admise
//     (relation existentielle, §11.4).
func TestRelectureAveugleA4(t *testing.T) {
	src := publie("valide-seq-6")
	if !fichierExiste(filepath.Join(src, "voisins.json")) {
		t.Skipf("dossier %s absent", src)
	}
	brut, err := os.ReadFile(filepath.Join(src, "voisins.json"))
	if err != nil {
		t.Fatal(err)
	}
	// previousModifie rend voisins.json dont previous a subi f (hash et sig
	// laissés tels quels), et le hash recalculé de ce previous.
	previousModifie := func(f func(p map[string]any)) (string, string) {
		var vo map[string]any
		if err := json.Unmarshal(brut, &vo); err != nil {
			t.Fatal(err)
		}
		f(vo["previous"].(map[string]any))
		b, err := json.Marshal(vo)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ParseJSONV0(b)
		if err != nil {
			t.Fatal(err)
		}
		h, ok := HashCalculable(v.Get("previous"))
		if !ok {
			t.Fatal("hash du voisin incalculable")
		}
		return string(b), Hex0x(h)
	}
	fixerRH := func(rh any) func(ev map[string]any) {
		return func(ev map[string]any) { ev["approval"].(map[string]any)["request_hash"] = rh }
	}
	nouvelIntent := func(p map[string]any) { p["intent"] = "intention modifiée après scellement" }
	voIntent, hIntent := previousModifie(nouvelIntent)
	voExecutee, hExecutee := previousModifie(func(p map[string]any) { p["execution"].(map[string]any)["status"] = "executee" })
	voStatusNombre, hStatusNombre := previousModifie(func(p map[string]any) { p["execution"].(map[string]any)["status"] = 5 })

	var ev0 map[string]any
	octetsEv, err := os.ReadFile(filepath.Join(src, "evenement.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(octetsEv, &ev0); err != nil {
		t.Fatal(err)
	}
	rhPublie := ev0["approval"].(map[string]any)["request_hash"].(string)

	cas := []struct {
		nom       string
		ev        func(ev map[string]any)
		voisins   func(string) string
		attenduA4 string
	}{
		{"request_hash objet", fixerRH(map[string]any{}), nil, "echoue"},
		{"request_hash tableau", fixerRH([]any{rhPublie}), nil, "echoue"},
		{"request_hash booléen", fixerRH(true), nil, "echoue"},
		{"request_hash lu, voisins.json inexploitable", nil, remplacerContenu("null"), "non_execute"},
		{"request_hash en majuscules du hash de previous", fixerRH("0x" + strings.ToUpper(rhPublie[2:])), nil, "non_execute_admis"},
		{"previous altéré, hash déclaré = request_hash", nil, remplacerContenu(voIntent), "non_execute_admis"},
		{"previous altéré, request_hash = son hash recalculé", fixerRH(hIntent), remplacerContenu(voIntent), "reussi"},
		{"demande trouvée, status executee", fixerRH(hExecutee), remplacerContenu(voExecutee), "echoue"},
		{"demande trouvée, status nombre", fixerRH(hStatusNombre), remplacerContenu(voStatusNombre), "echoue"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			alt := map[string]func(string) string{}
			if c.ev != nil {
				alt["evenement.json"] = approvalModifie(t, c.ev)
			}
			if c.voisins != nil {
				alt["voisins.json"] = c.voisins
			}
			d := VerifierDossier(copierDossier(t, src, alt, true))
			if d.Illisible != "" {
				t.Fatalf("entrée inutilisable : %s", d.Illisible)
			}
			if got := etatDe(d, "A-4"); got != c.attenduA4 {
				t.Errorf("A-4 : %s, attendu %s (%v)", got, c.attenduA4, d.Resultats.parID["A-4"])
			}
		})
	}
}
