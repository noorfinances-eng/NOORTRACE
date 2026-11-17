package main

// Essais des lignes de CT-3 que la rédaction de l'expiration taisait
// (complément du 2026-11-16, point 12 de la section 0), écrits depuis le seul
// texte : instant d'opération indécodable (EX-13.19, point 2), preuve
// rejouée reconstruite (EX-13.19, point 6, révision 0.6), inscription rejouée
// sans preuve quand l'opération expirer est placée plus loin (EX-13.19,
// point 6), entrée au created_at indécodable jamais échue (EX-13.17,
// EX-13.32, A.10), liste des entrées échues avant chaque pas d'une trace
// (A.10), requête d'expirer ($defs/requete_expirer, EX-13.17), et cas
// annuaire/exports/expiration-entree-portee.json (EX-A.13, INDEX.md).

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Instants qui respectent le motif de $defs/horodatage sans se décoder
// (CT-1 §3 : date inexistante).
const (
	instantTrente   = "2026-02-30T08:00:30.000Z"
	instantNovembre = "2026-11-31T08:10:30.000Z"
)

// filtrer garde les écarts d'un code.
func filtrer(ec []EcartExport, code string) string {
	var g []EcartExport
	for _, x := range ec {
		if x.Code == code {
			g = append(g, x)
		}
	}
	return ecartsTexte(g)
}

// entreeDuDoc rend l'indice et l'entrée d'identifiant id dans entries.
func entreeDuDoc(t *testing.T, doc *Value, id string) (int, *Value) {
	t.Helper()
	for i, x := range doc.Get("entries").Arr {
		if x.Get("id").S() == id {
			return i, x
		}
	}
	t.Fatalf("entrée %s absente du document", id)
	return -1, nil
}

// Règle 1. EX-13.19, point 2 (complément du 2026-11-16) : « l'instant d'une
// opération qui respecte le motif sans se décoder (CT-1 §3) est un écart
// revision_incoherente à son pointeur, et l'ordre de l'opération suivante se
// juge sur le dernier instant décodé ».
func TestRejeuInstantIndecodable(t *testing.T) {
	s, _ := essaiExport(t)
	sch, doc := s.e.Sch, s.e.Doc

	// La première opération : aucun instant ne la précède, l'écart est dû
	// quand même.
	premier := Copier(doc)
	poser(premier.Get("operations").Arr[0], "at", Chaine(instantTrente))
	if got := filtrer(VerifierAnnuaireExporte(sch, premier), "revision_incoherente"); got != "revision_incoherente /operations/0/at" {
		t.Errorf("premier instant indécodable : %q", got)
	}

	// L'opération 2 indécodable, la 3 antérieure à la 1 : la 3 se juge sur
	// l'instant de la 1, dernier instant décodé ; chaque pointeur une fois.
	suite := Copier(doc)
	ops := suite.Get("operations").Arr
	poser(ops[1], "at", Chaine(instantNovembre))
	t0, _ := LireInstant(ops[0].Get("at").S())
	poser(ops[2], "at", Chaine((t0 - 20000).String()))
	if got := filtrer(VerifierAnnuaireExporte(sch, suite), "revision_incoherente"); got != "revision_incoherente /operations/1/at;revision_incoherente /operations/2/at" {
		t.Errorf("ordre après un instant indécodable : %q", got)
	}

	// L'opération 3 postérieure à la 1 : seul l'instant indécodable est
	// relevé.
	apres := Copier(doc)
	poser(apres.Get("operations").Arr[1], "at", Chaine(instantNovembre))
	if got := filtrer(VerifierAnnuaireExporte(sch, apres), "revision_incoherente"); got != "revision_incoherente /operations/1/at" {
		t.Errorf("instant indécodable seul : %q", got)
	}
}

// Règle 2. EX-13.19, point 6 (révision 0.6) : la preuve rejouée est
// reconstruite (message du document, signature normalisée, nonce et instants
// du message, received_at égal à l'instant de l'opération) et c'est elle qui
// est comparée au document.
func TestPreuveRejoueeReconstruite(t *testing.T) {
	s, _ := essaiExport(t)
	sch, doc := s.e.Sch, s.e.Doc

	// received_at du document décalé, dans la fenêtre du message : la preuve
	// reste valable (point 4), le rejeu aboutit à d'autres entrées.
	recu := Copier(doc)
	_, x := entreeDuDoc(t, recu, "apb-0002")
	p := x.Get("addresses").Arr[0].Get("proof")
	r, _ := LireInstant(p.Get("received_at").S())
	poser(p, "received_at", Chaine((r + 1000).String()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, recu)); got != "operations_incoherentes /entries" {
		t.Errorf("received_at autre que l'instant de l'opération : %q", got)
	}

	// Signature du document sous sa forme haute (s → n − s, v inversé) :
	// non canonique (point 4), et la preuve rejouée porte la forme
	// normalisée.
	haute := Copier(doc)
	_, x = entreeDuDoc(t, haute, "apb-0002")
	p = x.Get("addresses").Arr[0].Get("proof")
	sig, err := DecoderSignature(p.Get("signature").S())
	if err != nil {
		t.Fatal(err)
	}
	sig.S = new(big.Int).Sub(secpN, sig.S)
	sig.V = 55 - sig.V
	poser(p, "signature", Chaine(sig.Encoder()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, haute)); got != "operations_incoherentes /entries;preuve_invalide /entries/0/addresses/0/proof" {
		t.Errorf("signature haute dans le document : %q", got)
	}

	// Instant indécodable d'une inscription avec preuve : la preuve rejouée
	// porte received_at égal à cet instant, l'entrée created_at égal à cet
	// instant ; le document qui porte ces mêmes textes ne diffère pas du
	// rejeu (pas d'écart /entries).
	indec := Copier(doc)
	poser(indec.Get("operations").Arr[1], "at", Chaine(instantNovembre))
	_, x = entreeDuDoc(t, indec, "apb-0002")
	poser(x, "created_at", Chaine(instantNovembre))
	poser(x.Get("addresses").Arr[0].Get("proof"), "received_at", Chaine(instantNovembre))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, indec)); got != "preuve_discordante /entries/0/addresses/0/proof;revision_incoherente /operations/1/at" {
		t.Errorf("inscription à l'instant indécodable : %q", got)
	}
}

// essaiExpire rend l'annuaire de la suite de la trace expiration-entree
// juste après l'expiration d'apb-0001, et une copie d'apb-0001 prise avant
// elle.
func essaiExpire(t *testing.T) (*essaiAnnuaire, *Value) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T08:00:00.000Z")
	s.inscrire(essaiIdentite("approbateur-1"), k.Comptes[1], t0)
	s.inscrire(essaiIdentite("approbateur-2"), k.Comptes[2], t0+600000)
	if r := s.operer("valider", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0002","address":"`+k.Comptes[2]+`"}`, t0+1200000); !r.Accepte {
		t.Fatalf("validation : %s", r.Raison)
	}
	avant := Copier(s.e.entreeParID("apb-0001"))
	c1 := creeLe(t, s.e, "apb-0001")
	if r := s.expirer(`{"entry":"apb-0001"}`, c1+essaiTTLEntree); !r.Accepte {
		t.Fatalf("expiration : %q", r.Raison)
	}
	return s, avant
}

// Règle 3. EX-13.19, point 6 (complément du 2026-11-16) : l'opération
// expirer qui fait rejouer une inscription sans preuve est placée plus loin ;
// la preuve n'est pas cherchée dans le document, même s'il porte encore
// l'entrée ; l'entrée du rejeu a pour created_at l'instant de l'inscrire qui
// l'a créée ; l'adresse sans preuve n'est jamais comparée ; un expirer dont
// by n'est pas service est refusé par le schéma.
func TestInscriptionSansPreuvePlusLoin(t *testing.T) {
	// Le cas publié : entrée encore portée, preuve signée par une autre clé.
	if b, err := os.ReadFile(filepath.Join("..", "annuaire", "exports", "expiration-entree-portee.json")); err == nil {
		doc, err := ParseJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		if got := ecartsTexte(VerifierAnnuaireExporte(schemasConsoleTest(t), doc)); got != "operations_incoherentes /entries;preuve_invalide /entries/0/addresses/0/proof" {
			t.Errorf("cas expiration-entree-portee.json : %q", got)
		}
	}

	// Entrée encore portée avec sa preuve exacte : la preuve n'est pas
	// cherchée, l'expirer rejoué retire l'entrée, la comparaison finale
	// relève celle que le document porte encore.
	s, avant := essaiExpire(t)
	sch := s.e.Sch
	portee := Copier(s.e.Doc)
	ent := portee.Get("entries")
	ent.Arr = append([]*Value{avant}, ent.Arr...)
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, portee)); got != "operations_incoherentes /entries" {
		t.Errorf("entrée expirée encore portée, preuve exacte : %q", got)
	}

	// Un expirer placé plus haut : l'identifiant ne peut plus être créé,
	// l'inscription qui le reprend ne se rejoue pas.
	s2, _ := essaiExpire(t)
	at := creeLe(t, s2.e, "apb-0002") + essaiTTLEntree
	s2.inscrire(essaiIdentite("u.martin"), s2.k.Comptes[1], at)
	haut := Copier(s2.e.Doc)
	for _, x := range haut.Get("entries").Arr {
		if x.Get("id").S() == "apb-0003" {
			poser(x, "id", Chaine("apb-0001"))
		}
	}
	hops := haut.Get("operations").Arr
	poser(hops[len(hops)-1], "entry", Chaine("apb-0001"))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, haut)); got != fmt.Sprintf("operations_incoherentes /operations/%d", len(hops)-1) {
		t.Errorf("expirer placé plus haut : %q", got)
	}

	// created_at de l'entrée du rejeu = at de l'inscrire qui l'a créée : un
	// at indécodable rend l'entrée jamais échue, l'expirer ne se rejoue pas.
	e, _ := essaiExport(t)
	indec := Copier(e.e.Doc)
	poser(indec.Get("operations").Arr[0], "at", Chaine(instantTrente))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, indec)); got != "revision_incoherente /operations/0/at;operations_incoherentes /operations/4" {
		t.Errorf("inscription sans preuve à l'instant indécodable : %q", got)
	}

	// by ≠ service : une seule erreur schema.
	by := Copier(e.e.Doc)
	poser(by.Get("operations").Arr[4], "by", Chaine(essaiAdmin))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, by)); got != "schema null" {
		t.Errorf("expirer par un administrateur : %q", got)
	}
}

// Règle 4. EX-13.17, EX-13.32, A.10 : une entrée dont le created_at respecte
// le motif sans se décoder n'est jamais échue ; expirer la refuse
// (etat_incompatible).
func TestCreeLeIndecodableJamaisEchue(t *testing.T) {
	s, _ := essaiExpire(t)
	s.inscrire(essaiIdentite("approbateur-3"), s.k.Comptes[3], creeLe(t, s.e, "apb-0002")+essaiTTLEntree)
	x := s.e.entreeParID("apb-0003")
	if x == nil {
		t.Fatal("entrée apb-0003 absente")
	}
	loin, _ := LireInstant("2030-01-01T00:00:00.000Z")
	if got := s.e.EntreesEchues(loin, essaiTTLEntree); len(got) != 1 || got[0] != "apb-0003" {
		t.Fatalf("témoin : entrées échues %v", got)
	}
	poser(x, "created_at", Chaine(instantTrente))
	if got := s.e.EntreesEchues(loin, essaiTTLEntree); len(got) != 0 {
		t.Errorf("entrée au created_at indécodable échue : %v", got)
	}
	if r := s.expirer(`{"entry":"apb-0003"}`, loin); r.Accepte || r.Raison != "etat_incompatible" {
		t.Errorf("expirer d'une entrée au created_at indécodable : accepté %v, raison %q", r.Accepte, r.Raison)
	}
}

// traceModifiee écrit sous une racine montée la trace expiration-entree
// modifiée par f, sous le nom donné, et rend le rapport.
func traceModifiee(t *testing.T, nom string, f func(steps *Value)) *Rapport {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "annuaire", "traces", "expiration-entree.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	tr, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	f(tr.Get("steps"))
	poser(tr, "id", Chaine(nom))
	racine := monterRacineCT3(t, []string{"annuaire", filepath.Join("annuaire", "traces")}, nil)
	texte, err := Stringify2(tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(racine, "annuaire", "traces", nom+".json"), []byte(texte+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return VerifierVecteurs(racine)
}

// Règle 5. A.10 : avant chaque pas, la liste des entrées échues à at (durée
// de vie 2 592 000 000, ordre de entries) est vide, sauf avant un expirer
// accepté, où elle est exactement l'entrée du pas.
func TestEchuesExactementLEntreeDuPas(t *testing.T) {
	// Sans la validation d'apb-0002 (pas 5), l'expirer accepté d'apb-0001
	// placé à l'échéance d'apb-0002 trouve deux entrées échues.
	rap := traceModifiee(t, "deux-echues", func(steps *Value) {
		steps.Arr = append(append([]*Value{}, steps.Arr[:4]...), steps.Arr[5:8]...)
		poser(steps.Arr[6], "at", Chaine("2026-12-10T08:10:30.000Z"))
	})
	vu := map[string]bool{}
	for _, c := range rap.Comparaisons {
		if !strings.HasPrefix(c.Vecteur, "annuaire/traces/deux-echues.json ") || !strings.Contains(c.Grandeur, "échue") {
			continue
		}
		vu[c.Vecteur] = true
		switch {
		case strings.HasPrefix(c.Vecteur, "annuaire/traces/deux-echues.json pas 7 "):
			if c.Concorde || !strings.Contains(c.Obtenu, "apb-0002") {
				t.Errorf("deux entrées échues avant l'expirer accepté non relevées : %s / %s", c.Attendu, c.Obtenu)
			}
		default:
			if !c.Concorde {
				t.Errorf("%s : attendu %s, obtenu %s", c.Vecteur, c.Attendu, c.Obtenu)
			}
		}
	}
	if len(vu) != 7 {
		t.Errorf("%d pas contrôlés, 7 attendus", len(vu))
	}
}

// Règle 6. $defs/requete_expirer (EX-13.17) : un objet au seul membre entry,
// conforme à $defs/identifiant_entree ; toute autre forme est
// requete_invalide. L'exemple du texte est la requête du pas 8 de la trace
// expiration-entree.
func TestRequeteExpirerDefinition(t *testing.T) {
	s, _ := essaiExpire(t)
	at := creeLe(t, s.e, "apb-0002") + essaiTTLEntree
	for _, req := range []string{`{}`, `[]`, `{"entry":1}`, `{"entry":"apb-0002","reason":null}`,
		`{"entry":"APB-0002"}`, `{"entry":"apb-"}`, `{"entry":"apb-0002-"}`,
		`{"entry":"apb-` + strings.Repeat("0", 125) + `"}`, `{"session_identity":"` + essaiAdmin + `","entry":"apb-0002"}`} {
		if r := s.expirer(req, at); r.Accepte || r.Raison != "requete_invalide" {
			t.Errorf("requête %s : accepté %v, raison %q", req, r.Accepte, r.Raison)
		}
	}
	// 128 caractères, conforme : la forme passe, l'entrée est inconnue.
	if r := s.expirer(`{"entry":"apb-`+strings.Repeat("0", 124)+`"}`, at); r.Raison != "entree_inconnue" {
		t.Errorf("identifiant de 128 caractères : %q", r.Raison)
	}
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		return
	}
	rap := VerifierVecteurs("..")
	n := 0
	for _, c := range rap.Comparaisons {
		if c.Vecteur == "CT-3 EX-13.17 (exemple)" {
			n++
			if !c.Concorde {
				t.Errorf("%s : attendu %s, obtenu %s", c.Grandeur, c.Attendu, c.Obtenu)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d contrôles de l'exemple de requête expirer, 2 attendus", n)
	}
}

// Cas nouveau d'exports/ (EX-A.13, complément du 2026-11-16) : sa couverture
// est exigée, et il est compté contre la section « Cas nommés » d'INDEX.md
// (EX-A.10, révision 0.8 et complément du 2026-11-16).
func TestCasEntreePortee(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	rap := VerifierVecteurs("..")
	vu := false
	for _, c := range rap.Comparaisons {
		if c.Vecteur == "annuaire/exports/attendu.json" && strings.Contains(c.Grandeur, "encore portée") {
			vu = true
			if !c.Concorde {
				t.Errorf("%s : %s", c.Grandeur, c.Obtenu)
			}
		}
	}
	if !vu {
		t.Errorf("couverture du cas d'une entrée expirée encore portée non contrôlée")
	}
	AppliquerPlancherCT3(rap, "..")
	for _, e := range rap.Erreurs {
		t.Errorf("erreur : %s", e)
	}
	notee := false
	for _, n := range rap.Notes {
		notee = notee || strings.HasPrefix(n, "annuaire/exports/ : ")
	}
	if !notee {
		t.Errorf("exports/ non compté contre INDEX.md : %v", rap.Notes)
	}

	// INDEX.md dont la section « Cas nommés » ne nomme pas le cas : code 1
	// (EX-A.10, complément du 2026-11-16 : seule cette section compte).
	racine := indexModifie(t, nil, func(s string) string {
		return strings.Replace(s, "`annuaire/exports/expiration-entree-portee.json`, ", "", 1)
	})
	const msg = "INDEX.md (Cas nommés) : le cas annuaire/exports/expiration-entree-portee.json est présent mais l'index ne le nomme pas"
	if code, sortie := lancerCT3(t, racine); code != 1 || !strings.Contains(sortie, msg) {
		t.Errorf("index sans le cas : code %d, message « %s » attendu :\n%s", code, msg, tronquer(sortie, 2000))
	}
}
