package dossier

// Règles de CT-1 révision 0.5 (table d'alignement de la section 17, ligne
// verificateur/) et de CT-6 révision 0.4 (section 16) que le paquet
// applique : chaque règle changée a un cas en réussite et un cas en échec.
// Les événements de base sont ceux du journal publié
// spec/vecteurs/ct-1/journal-valide (seq 1 à 12), modifiés en texte.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

const journalValide = "../../spec/vecteurs/ct-1/journal-valide/evenements.json"

// evenementsJournal rend le texte JSON compact de chaque événement du
// journal valide, indexé par seq.
func evenementsJournal(t *testing.T) map[int]string {
	t.Helper()
	b, err := os.ReadFile(journalValide)
	if err != nil {
		t.Fatal(err)
	}
	var brut []json.RawMessage
	if err := json.Unmarshal(b, &brut); err != nil {
		t.Fatal(err)
	}
	out := map[int]string{}
	for _, r := range brut {
		var e struct {
			Seq int `json:"seq"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			t.Fatal(err)
		}
		var c strings.Builder
		var v any
		json.Unmarshal(r, &v)
		enc := json.NewEncoder(&c)
		enc.SetEscapeHTML(false)
		enc.Encode(v)
		out[e.Seq] = strings.TrimSpace(c.String())
	}
	return out
}

// evt construit un Evt depuis un texte JSON, après substitutions
// (ancien, nouveau, ancien, nouveau…), chacune devant porter.
func evt(t *testing.T, texte string, subs ...string) *Evt {
	t.Helper()
	for i := 0; i+1 < len(subs); i += 2 {
		n := strings.Replace(texte, subs[i], subs[i+1], 1)
		if n == texte {
			t.Fatalf("substitution sans effet : %s", subs[i])
		}
		texte = n
	}
	v, err := jsonv.Analyser([]byte(texte))
	if err != nil {
		t.Fatal(err)
	}
	return nouvelEvt(commun.T("essai", "test"), v)
}

// evtModif construit un Evt depuis un texte JSON modifié par f, sur sa
// forme décodée.
func evtModif(t *testing.T, texte string, f func(map[string]any)) *Evt {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(texte), &v); err != nil {
		t.Fatal(err)
	}
	f(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return evt(t, string(b))
}

func sous(v map[string]any, chemin ...string) map[string]any {
	for _, c := range chemin {
		v = v[c].(map[string]any)
	}
	return v
}

// TestE3RegleExacte : règle exacte de E-3 (CT-1 §5.3, révision 0.5 ; CT-6
// EX-5.17), sorte par sorte. Le premier cas est la faille corrigée en
// premier : un appel a_approuver exécuté sans approbation passait.
func TestE3RegleExacte(t *testing.T) {
	j := evenementsJournal(t)
	cas := []struct {
		nom     string
		seq     int
		subs    []string
		attendu commun.Statut
	}{
		// Témoins : chaque sorte publiée passe E-3.
		{"échange (seq 1)", 1, nil, commun.Reussi},
		{"appel autorisé exécuté (seq 2)", 2, nil, commun.Reussi},
		{"appel retenu (seq 5)", 5, nil, commun.Reussi},
		{"décision (seq 6)", 6, nil, commun.Reussi},
		{"appel approuvé exécuté (seq 7)", 7, nil, commun.Reussi},
		{"rotation (seq 9)", 9, nil, commun.Reussi},
		{"appel refusé (seq 11)", 11, nil, commun.Reussi},
		{"politique (seq 12)", 12, nil, commun.Reussi},
		// 1. Appel d'outil : politique, statut et approbation.
		{"appel a_approuver exécuté sans approbation", 2, []string{`"decision":"autorise"`, `"decision":"a_approuver"`}, commun.Echoue},
		{"appel a_approuver exécuté, approbation refusée", 7, []string{`"decision":"approuve"`, `"decision":"refuse"`}, commun.Echoue},
		{"appel autorisé avec une approbation", 7, []string{`"decision":"a_approuver"`, `"decision":"autorise"`}, commun.Echoue},
		{"appel retenu autorisé", 5, []string{`"decision":"a_approuver"`, `"decision":"autorise"`}, commun.Echoue},
		{"appel refusé autorisé", 11, []string{`"decision":"refuse"`, `"decision":"autorise"`}, commun.Echoue},
		{"appel sans_objet", 2, []string{`"decision":"autorise"`, `"decision":"sans_objet"`}, commun.Echoue},
		{"appel retenu à effets", 5, []string{`"effects":[]`, `"effects":[{"action":"ecriture","amount":null,"currency":null,"object":"X","system":"SAP"}]`}, commun.Echoue},
		{"appel refusé à effets", 11, []string{`"effects":[]`, `"effects":[{"action":"ecriture","amount":null,"currency":null,"object":"X","system":"SAP"}]`}, commun.Echoue},
		{"appel exécuté de durée négative", 2, []string{`"duration_ms":`, `"duration_ms":-1,"x":`}, commun.Echoue},
		// 2. Échange avec le modèle : approval nul.
		{"échange avec approval", 1, []string{`"approval":null`, `"approval":{"decision":"approuve"}`}, commun.Echoue},
		// 3. Décision, rotation, politique.
		{"décision à effets", 6, []string{`"effects":[]`, `"effects":[{"action":"ecriture","amount":null,"currency":null,"object":"X","system":"SAP"}]`}, commun.Echoue},
		{"décision dont arguments.value n'est pas A", 6, []string{`"ticket":"apr-2201"}`, `"ticket":"apr-9999"}`}, commun.Echoue},
		{"rotation sans launched_by du journal", 9, []string{`"launched_by":"noortrace-enregistreur"`, `"launched_by":"u.martin@assureur-demo.example"`}, commun.Echoue},
		{"politique sans launched_by du journal", 12, []string{`"launched_by":"noortrace-enregistreur"`, `"launched_by":"admin"`}, commun.Echoue},
		{"politique à effets (non contraints)", 12, []string{`"effects":[]`, `"effects":[{"action":"ecriture","amount":null,"currency":null,"object":"politique","system":"noortrace"}]`}, commun.Reussi},
		{"nom réservé inconnu", 1, []string{`"tool":"noortrace.modele.echange"`, `"tool":"noortrace.autre"`}, commun.Echoue},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			e := evt(t, j[c.seq], c.subs...)
			r := regleE3(e)
			if r.statut != c.attendu {
				t.Errorf("E-3 %s (%s), attendu %s", r.statut, r.detail.Fr, c.attendu)
			}
		})
	}
	// Changement de politique : arguments.value = { policy_version (1 à
	// 128 caractères), policy_sha256 }.
	for nom, c := range map[string]struct {
		version any
		attendu commun.Statut
	}{
		"version de 128 caractères": {strings.Repeat("é", 128), commun.Reussi},
		"version de 129 caractères": {strings.Repeat("é", 129), commun.Echoue},
		"version vide":              {"", commun.Echoue},
		"version nombre":            {12, commun.Echoue},
	} {
		e := evtModif(t, j[12], func(v map[string]any) {
			sous(v, "execution", "arguments", "value")["policy_version"] = c.version
		})
		if r := regleE3(e); r.statut != c.attendu {
			t.Errorf("politique, %s : E-3 %s (%s), attendu %s", nom, r.statut, r.detail.Fr, c.attendu)
		}
	}
	e := evtModif(t, j[12], func(v map[string]any) {
		sous(v, "execution", "arguments", "value")["autre"] = 1
	})
	if r := regleE3(e); r.statut != commun.Echoue {
		t.Errorf("politique à trois membres : E-3 %s", r.statut)
	}
}

// TestE4ChaineNonVide : policy.redaction d'un événement qui porte une
// référence rédigée est une chaîne non vide au sens de CT-1 §3 (révision
// 0.5) ; U+FEFF compte comme un blanc.
func TestE4ChaineNonVide(t *testing.T) {
	j := evenementsJournal(t)
	base := j[7] // référence rédigée, policy.redaction « pii-v1 »
	for nom, c := range map[string]struct {
		val     string
		attendu commun.Statut
	}{
		"pii-v1":           {`"pii-v1"`, commun.Reussi},
		"vide":             {`""`, commun.Echoue},
		"blancs":           {`" \t"`, commun.Echoue},
		"U+FEFF":           {`"\ufeff"`, commun.Echoue},
		"U+3000 et lettre": {`"\u3000a"`, commun.Reussi},
		"null":             {`null`, commun.Echoue},
	} {
		var val any
		json.Unmarshal([]byte(c.val), &val)
		e := evtModif(t, base, func(v map[string]any) { sous(v, "policy")["redaction"] = val })
		if r := regleE4(e); r.statut != c.attendu {
			t.Errorf("%s : E-4 %s, attendu %s", nom, r.statut, c.attendu)
		}
	}
	if commun.ChaineNonVide("\u0085\u00a0\u2028\ufeff") || !commun.ChaineNonVide(" a ") {
		t.Error("ChaineNonVide")
	}
}

// TestE1IdentifiantsNuls : org_id ou journal_id de 32 octets nuls met E-1
// en échec (CT-1 §3, révision 0.5).
func TestE1IdentifiantsNuls(t *testing.T) {
	j := evenementsJournal(t)
	if r := regleE1(evt(t, j[2])); r.statut != commun.Reussi {
		t.Fatalf("témoin : %s", r.detail.Fr)
	}
	for _, champ := range []string{"org_id", "journal_id"} {
		var v map[string]any
		json.Unmarshal([]byte(j[2]), &v)
		ancien := v[champ].(string)
		e := evt(t, j[2], `"`+champ+`":"`+ancien+`"`, `"`+champ+`":"0x`+strings.Repeat("0", 64)+`"`)
		if r := regleE1(e); r.statut != commun.Echoue {
			t.Errorf("%s nul : E-1 %s", champ, r.statut)
		}
	}
}

// TestE9ToutesLesSignatures : une signature sans approvers[i] met E-9 en
// échec (CT-1 §11.4, révision 0.5 ; CT-6 EX-5.19) ; un approbateur sans
// signature relève de E-5 seule.
func TestE9ToutesLesSignatures(t *testing.T) {
	j := evenementsJournal(t)
	base := j[7]
	if r := regleE9(evt(t, base)); r.statut != commun.Reussi {
		t.Fatalf("témoin : %s", r.detail.Fr)
	}
	// Signature en trop : la seconde signature n'a plus d'approbateur.
	e := evt(t, base, `,"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"]`, `]`)
	if r := regleE9(e); r.statut != commun.Echoue {
		t.Errorf("signature sans approbateur : E-9 %s", r.statut)
	}
	if r := regleE5(e); r.statut != commun.Echoue {
		t.Errorf("signature sans approbateur : E-5 %s", r.statut)
	}
	// Approbateur sans signature : E-5 seule.
	var v map[string]any
	json.Unmarshal([]byte(base), &v)
	sigs := v["approval"].(map[string]any)["signatures"].([]any)
	e = evt(t, base, `,"`+sigs[1].(string)+`"]`, `]`)
	if r := regleE9(e); r.statut != commun.Reussi {
		t.Errorf("approbateur sans signature : E-9 %s (%s)", r.statut, r.detail.Fr)
	}
	if r := regleE5(e); r.statut != commun.Echoue {
		t.Errorf("approbateur sans signature : E-5 %s", r.statut)
	}
}

// remplacerIndex substitue dans dossier.json sans toucher aux parties.
func remplacerIndex(t *testing.T, rep, ancien, nouveau string) {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	n := strings.Replace(string(b), ancien, nouveau, 1)
	if n == string(b) {
		t.Fatalf("dossier.json : « %s » introuvable", ancien)
	}
	os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(n), 0o644)
}

// TestD1OrgJournal : D-1 compare aussi org_id et journal_id de l'index à
// ceux de evenement.json (CT-1 §11.4, révision 0.5).
func TestD1OrgJournal(t *testing.T) {
	_, m := analyser(t, racineCT1+"/valide-seq-7")
	attendre(t, m, "D-1", commun.Reussi, "")
	for _, champ := range []string{"org_id", "journal_id"} {
		rep := copier(t, racineCT1+"/valide-seq-7")
		b, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
		var idx map[string]any
		json.Unmarshal(b, &idx)
		remplacerIndex(t, rep, idx[champ].(string), "0x"+strings.Repeat("1", 64))
		a, m := analyser(t, rep)
		attendre(t, m, "D-1", commun.Echoue, "")
		if l := echecs(a); strings.Join(l, ",") != "D-1" {
			t.Errorf("%s : échecs %v, attendu [D-1]", champ, l)
		}
	}
}

// TestD1EvenementInexploitable : evenement.json inexploitable, index
// conforme : D-1 non exécutée (prerequis_en_echec), jamais réussie (CT-6
// EX-5.14).
func TestD1EvenementInexploitable(t *testing.T) {
	_, m := analyser(t, racineCT1+"/invalide-partie-nulle")
	attendre(t, m, "D-1", commun.NonExecute, commun.PrerequisEnEchec)
	attendre(t, m, "E-1", commun.Echoue, "")
	_, m = analyser(t, racineCT1+"/invalide-nombre-non-entier")
	attendre(t, m, "D-1", commun.NonExecute, commun.PrerequisEnEchec)
}

// TestD2Raison : la raison d'une partie absente est une chaîne non vide au
// sens de CT-1 §3 (U+FEFF est un blanc) ; une entrée qui n'est pas un
// fichier ordinaire ne compte pas comme présente pour une partie déclarée
// absente.
func TestD2Raison(t *testing.T) {
	for nom, c := range map[string]struct {
		raison  string
		attendu commun.Statut
	}{
		"blancs":  {`" "`, commun.Echoue},
		"U+FEFF":  {`"\ufeff"`, commun.Echoue},
		"U+0085":  {`"\u0085"`, commun.Echoue},
		"lettres": {`"autre raison"`, commun.Reussi},
	} {
		rep := copier(t, racineCT1+"/valide-seq-7")
		remplacerIndex(t, rep, `"reason_if_absent": "hors périmètre CT-1"`, `"reason_if_absent": `+c.raison)
		_, m := analyser(t, rep)
		attendre(t, m, "D-2", c.attendu, "")
		_ = nom
	}
	// Un répertoire du nom d'une partie déclarée absente n'est pas un
	// fichier ordinaire : D-2 réussit.
	rep := copier(t, racineCT1+"/valide-seq-7")
	os.Mkdir(filepath.Join(rep, "preuve.ots"), 0o755)
	_, m := analyser(t, rep)
	attendre(t, m, "D-2", commun.Reussi, "")
	os.Remove(filepath.Join(rep, "preuve.ots"))
	os.WriteFile(filepath.Join(rep, "preuve.ots"), []byte("x"), 0o644)
	_, m = analyser(t, rep)
	attendre(t, m, "D-2", commun.Echoue, "")
}

// TestA1RaisonExacte : approval nul exige approbations.json déclaré absent
// avec la raison exacte « aucune approbation liée » ; sous une autre
// raison, A-1 échoue et A-2 à A-4 sont prerequis_en_echec (CT-1 §11.1,
// §11.4, révision 0.5 ; CT-6 EX-5.16).
func TestA1RaisonExacte(t *testing.T) {
	base := racineCT1 + "/valide-seq-6"
	b, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	if !strings.Contains(string(b), `"approval": null`) {
		t.Skip("valide-seq-6 n'a pas approval nul")
	}
	_, m := analyser(t, base)
	attendre(t, m, "A-1", commun.Reussi, "")
	for _, id := range []string{"A-2", "A-3", "A-4"} {
		attendre(t, m, id, commun.NonExecute, commun.PartieAbsente)
	}
	rep := copier(t, base)
	remplacerIndex(t, rep, `"reason_if_absent": "aucune approbation liée"`, `"reason_if_absent": "aucune approbation"`)
	a, m := analyser(t, rep)
	attendre(t, m, "A-1", commun.Echoue, "")
	for _, id := range []string{"A-2", "A-3", "A-4"} {
		attendre(t, m, id, commun.NonExecute, commun.PrerequisEnEchec)
	}
	if l := echecs(a); strings.Join(l, ",") != "A-1" {
		t.Errorf("échecs %v, attendu [A-1]", l)
	}
}

// TestVoisinsInexploitables : voisins.json inexploitable : A-4 et K-6 non
// exécutées, prerequis_en_echec, et non piece_hors_dossier (CT-1 §11.4,
// révision 0.5 ; CT-6 EX-5.9, EX-5.18).
func TestVoisinsInexploitables(t *testing.T) {
	// A-4 : témoin piece_hors_dossier (la demande seq 5 n'est pas un
	// voisin de seq 7).
	_, m := analyser(t, racineCT1+"/valide-seq-7")
	attendre(t, m, "A-4", commun.NonExecute, commun.PieceHorsDossier)
	for nom, contenu := range map[string]string{"null": "null", "sans forme canonique": `{"version":0.0,"previous":null,"next":null}`} {
		t.Run(nom, func(t *testing.T) {
			rep := copier(t, racineCT1+"/valide-seq-7")
			b, _ := os.ReadFile(filepath.Join(rep, "voisins.json"))
			remplacer(t, rep, "voisins.json", string(b), contenu)
			_, m := analyser(t, rep)
			attendre(t, m, "A-4", commun.NonExecute, commun.PrerequisEnEchec)
		})
	}
	// K-6 : le point de valide-seq-7-point-de-controle a last_seq = 8, le
	// voisin suivant : K-6 réussie ; sans voisins.json exploitable,
	// prerequis_en_echec, et non piece_hors_dossier.
	base := racineCT1 + "/valide-seq-7-point-de-controle"
	_, m = analyser(t, base)
	attendre(t, m, "K-6", commun.Reussi, "")
	rep := copier(t, base)
	b, _ := os.ReadFile(filepath.Join(rep, "voisins.json"))
	remplacer(t, rep, "voisins.json", string(b), "null")
	_, m = analyser(t, rep)
	attendre(t, m, "K-6", commun.NonExecute, commun.PrerequisEnEchec)
}

// TestEnveloppesContrairesAuSchema : voisins.json exploitable mais
// contraire au schéma de son enveloppe : C-1 en échec, C-2, C-3 et P-3
// exécutées sur les valeurs lues (CT-1 §11.4, révision 0.5). Un previous qui
// n'est ni un objet ni null est un événement qui n'est pas un objet : E-1 en
// échec, et les relations qui le lisent ne sont pas tenues.
func TestEnveloppesContrairesAuSchema(t *testing.T) {
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "voisins.json", `"version": 0`, `"version": 0, "membre_en_trop": 1`)
	a, m := analyser(t, rep)
	attendre(t, m, "C-1", commun.Echoue, "")
	for _, id := range []string{"C-2", "C-3", "P-3"} {
		attendre(t, m, id, commun.Reussi, "")
	}
	if l := echecs(a); strings.Join(l, ",") != "C-1" {
		t.Errorf("échecs %v, attendu [C-1]", l)
	}
	// previous = 5 : E-1, C-1, C-2, C-3, P-3 en échec.
	rep = copier(t, racineCT1+"/valide-seq-7")
	var v map[string]json.RawMessage
	b, _ := os.ReadFile(filepath.Join(rep, "voisins.json"))
	json.Unmarshal(b, &v)
	v["previous"] = json.RawMessage("5")
	nb, _ := json.Marshal(v)
	remplacer(t, rep, "voisins.json", string(b), string(nb))
	a, m = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,C-1,C-2,C-3,P-3" {
		t.Errorf("previous = 5 : échecs %s", l)
	}
	// E-2 à E-11 ne s'exécutent pas sur lui : non_execute,
	// prerequis_en_echec, faute d'échec ailleurs (CT-6 EX-5.13, compléments
	// de la révision 0.4) ; A-4 ne le prend pas pour candidat.
	for _, id := range []string{"E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"} {
		attendre(t, m, id, commun.NonExecute, commun.PrerequisEnEchec)
	}
	attendre(t, m, "A-4", commun.NonExecute, commun.PieceHorsDossier)
	// previous absent : C-1, C-2, C-3, P-3 en échec ; E-1 ne le concerne
	// pas (un membre absent n'est pas un événement), E-2 à E-11 réussies.
	rep = copier(t, racineCT1+"/valide-seq-7")
	delete(v, "previous")
	nb2, _ := json.Marshal(v)
	remplacer(t, rep, "voisins.json", string(b), string(nb2))
	a, m = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "C-1,C-2,C-3,P-3" {
		t.Errorf("previous absent : échecs %s", l)
	}
	for _, id := range []string{"E-1", "E-2", "E-7", "E-11"} {
		attendre(t, m, id, commun.Reussi, "")
	}
	// Élément de events qui n'est pas un objet : E-1 et A-2 en échec.
	rep = copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "approbations.json", `"events": [`, `"events": [5,`)
	a, m = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,A-1,A-2" {
		t.Errorf("events[0] = 5 : échecs %s", l)
	}
	attendre(t, m, "E-7", commun.NonExecute, commun.PrerequisEnEchec)
}

// TestPartieSansFormeCanonique : une partie sans forme canonique autre que
// evenement.json (cas (d) de CT-1 §11.4, révision 0.5) met E-2 en échec et
// laisse son contrôle porteur non exécuté (prerequis_en_echec) ; rien n'en
// est lu.
func TestPartieSansFormeCanonique(t *testing.T) {
	cas := []struct {
		fichier, ancien, nouveau, porteur string
	}{
		{"chemin.json", `"version": 0`, `"version": 0.0`, "M-2"},
		{"manifeste.json", `"version": 0`, `"version": 0.0`, "P-1"},
		{"manifeste.sig", `"version": 0`, `"version": 0.0`, "P-5"},
		{"cles.json", `"version": 0`, `"version": 0.0`, "E-8"},
		{"approbations.json", `"version": 0`, `"version": 0.0`, "A-1"},
		{"voisins.json", `"version": 0`, `"version": 0.0`, "C-1"},
	}
	for _, c := range cas {
		t.Run(c.fichier, func(t *testing.T) {
			rep := copier(t, racineCT1+"/valide-seq-7")
			remplacer(t, rep, c.fichier, c.ancien, c.nouveau)
			a, m := analyser(t, rep)
			attendre(t, m, "E-2", commun.Echoue, "")
			attendre(t, m, c.porteur, commun.NonExecute, commun.PrerequisEnEchec)
			if l := echecs(a); strings.Join(l, ",") != "E-2" {
				t.Errorf("échecs %v, attendu [E-2]", l)
			}
		})
	}
}

// TestSeqEnChaine : cascade de CT-1 §11.4 (révision 0.5) : evenement.json
// dont seq est la chaîne "7" met en échec D-1, E-1, E-7, E-8, C-1, C-2,
// M-1, M-3, P-2 et A-2 (relations à terme mal typé non tenues).
func TestSeqEnChaine(t *testing.T) {
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "evenement.json", `"seq": 7,`, `"seq": "7",`)
	a, _ := analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "D-1,E-1,E-7,E-8,C-1,C-2,M-1,M-3,P-2,A-2" {
		t.Errorf("échecs %s", l)
	}
}

// TestAT1Revision05 : attestation-perimetre.json à clé en double hors de
// signed.attestation, et date inexistante de l'inscription : AT-1 en échec
// (CT-1 §11.4, révision 0.5 ; CT-6 EX-4.15, EX-4.16).
func TestAT1Revision05(t *testing.T) {
	base := racineCT1 + "/valide-seq-12-attestation-inscrite"
	_, m := analyser(t, base)
	attendre(t, m, "AT-1", commun.Reussi, "")
	attendre(t, m, "AT-6", commun.Reussi, "")
	// Clé en double hors de signed.attestation.
	rep := copier(t, base)
	remplacer(t, rep, "attestation-perimetre.json", `"version": 0`, `"version": 0, "version": 0`)
	a, m := analyser(t, rep)
	attendre(t, m, "AT-1", commun.Echoue, "")
	if a.Attestation == nil || a.Attestation.Retenue {
		t.Error("attestation sans forme canonique retenue")
	}
	attendre(t, m, "E-2", commun.Reussi, "")
	// Date inexistante de l'inscription : AT-1, et non AT-6.
	rep = copier(t, base)
	b, _ := os.ReadFile(filepath.Join(rep, "attestation-perimetre.json"))
	var at map[string]any
	json.Unmarshal(b, &at)
	ts := at["inscription"].(map[string]any)["event"].(map[string]any)["ts"].(string)
	remplacer(t, rep, "attestation-perimetre.json", `"ts": "`+ts+`"`, `"ts": "2026-02-30T00:00:00.000Z"`)
	_, m = analyser(t, rep)
	attendre(t, m, "AT-1", commun.Echoue, "")
	attendre(t, m, "AT-6", commun.NonExecute, commun.PrerequisEnEchec)
}

// TestDecisionsComplements : lignes « conforme » ou « à vérifier » du
// binaire dans le tableau des décisions (compléments de CT-1 révision 0.5 et
// de CT-6 révision 0.4), chacune par un cas.
func TestDecisionsComplements(t *testing.T) {
	ev7, _ := os.ReadFile(filepath.Join(racineCT1, "valide-seq-7", "evenement.json"))
	var e7 map[string]any
	json.Unmarshal(ev7, &e7)
	h7 := e7["hash"].(string)

	// Point 1 (EX-5.15, « sauf s'il échoue sur ce qu'il lit des autres
	// parties ») : evenement.json = null, manifeste de 7200 s, key_id en
	// double dans cles.json : E-1, E-8, P-1, P-5.
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "evenement.json", string(ev7), "null")
	remplacer(t, rep, "manifeste.json", `"period_end": 1793872800`, `"period_end": 1793876400`)
	cles, _ := os.ReadFile(filepath.Join(rep, "cles.json"))
	var c map[string]any
	json.Unmarshal(cles, &c)
	keys := c["keys"].([]any)
	k0 := keys[0].(map[string]any)
	double := map[string]any{"key_id": k0["key_id"], "public_key": "0x" + strings.Repeat("ab", 32), "valid_from": k0["valid_from"], "valid_to": k0["valid_to"]}
	c["keys"] = append(keys, double)
	nc, _ := json.Marshal(c)
	remplacer(t, rep, "cles.json", string(cles), string(nc))
	a, _ := analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,E-8,P-1,P-5" {
		t.Errorf("point 1 : échecs %s", l)
	}

	// Points 2 et 23 (EX-5.9, CT-1 §10.5) : last_seq est le seq de
	// l'événement prouvé : K-6 se juge sur lui seul, voisins.json = null.
	rep = copier(t, racineCT1+"/valide-seq-7-point-de-controle")
	pc, _ := os.ReadFile(filepath.Join(rep, "points-de-controle.json"))
	var pt map[string]any
	json.Unmarshal(pc, &pt)
	k := pt["checkpoint"].(map[string]any)
	n := strings.Replace(string(pc), `"tree_size": 8,`, `"tree_size": 7,`, 1)
	n = strings.Replace(n, `"last_seq": 8,`, `"last_seq": 7,`, 1)
	n = strings.Replace(n, k["last_hash"].(string), h7, 1)
	remplacer(t, rep, "points-de-controle.json", string(pc), n)
	vb, _ := os.ReadFile(filepath.Join(rep, "voisins.json"))
	remplacer(t, rep, "voisins.json", string(vb), "null")
	_, m := analyser(t, rep)
	attendre(t, m, "K-1", commun.Reussi, "")
	attendre(t, m, "K-6", commun.Reussi, "")
	attendre(t, m, "C-1", commun.Echoue, "")

	// Points 3 et 30 (EX-4.11 point 1, EX-5.16) : approval nul,
	// approbations.json déclarée présente sans fichier : D-2 et A-1.
	rep = copier(t, racineCT1+"/valide-seq-12-attestation-inscrite")
	remplacerIndex(t, rep, `"sha256": null,
      "present": false,
      "reason_if_absent": "aucune approbation liée"`, `"sha256": "0x`+strings.Repeat("1", 64)+`",
      "present": true,
      "reason_if_absent": null`)
	a, _ = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "D-2,A-1" {
		t.Errorf("points 3, 30 : échecs %s", l)
	}

	// Point 8 (et 22) : execution.tool = 5 : E-1, E-3 et les cascades.
	rep = copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "evenement.json", `"tool": "sap.payments.create"`, `"tool": 5`)
	a, _ = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,E-3,E-7,E-8,C-2,M-1" {
		t.Errorf("point 8 : échecs %s", l)
	}

	// Point 21 : approval = 5 : E-1, A-1 à A-4 (A-4 comprise) et cascades.
	rep = copier(t, racineCT1+"/valide-seq-7")
	i := strings.Index(string(ev7), `"approval": {`)
	j := strings.Index(string(ev7), `"execution": {`)
	remplacer(t, rep, "evenement.json", string(ev7)[i:j], `"approval": 5,`+"\n  ")
	a, _ = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,E-3,E-5,E-7,E-8,E-9,C-2,M-1,A-1,A-2,A-3,A-4" {
		t.Errorf("point 21 : échecs %s", l)
	}

	// Points 12, 19, 20, 28 : demande non objet (valide-seq-6, previous =
	// "x") : E-1, C-1, C-2, C-3, P-3 ; A-4 piece_hors_dossier.
	rep = copier(t, racineCT1+"/valide-seq-6")
	vb, _ = os.ReadFile(filepath.Join(rep, "voisins.json"))
	var v map[string]json.RawMessage
	json.Unmarshal(vb, &v)
	v["previous"] = json.RawMessage(`"x"`)
	nv, _ := json.Marshal(v)
	remplacer(t, rep, "voisins.json", string(vb), string(nv))
	a, m = analyser(t, rep)
	if l := strings.Join(echecs(a), ","); l != "E-1,C-1,C-2,C-3,P-3" {
		t.Errorf("demande non objet : échecs %s", l)
	}
	if v := m["A-4"]; v.Statut == commun.Echoue {
		t.Errorf("A-4 en échec pour un voisin non objet")
	}
}

// TestE8PremierePartieSansEvenement : evenement.json inexploitable et
// cles.json dont un key_id est en double, conforme à son schéma : la
// première partie de E-8 ne lit que cles.json, elle échoue et l'échec
// l'emporte (CT-1 §11.4 ; CT-6 EX-5.15, point 1 ; vecteur
// invalide-evenement-nul-autres-echecs). Le binaire rendait E-8
// non_execute.
func TestE8PremierePartieSansEvenement(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	cles, _ := os.ReadFile(filepath.Join(base, "cles.json"))
	var c map[string]any
	json.Unmarshal(cles, &c)
	keys := c["keys"].([]any)
	if len(keys) < 2 {
		t.Fatal("cles.json de valide-seq-7 à une seule clé")
	}
	// Seconde entrée : key_id de la première, sa propre clé publique et ses
	// propres dates (conforme au schéma, uniqueItems compris).
	keys[1].(map[string]any)["key_id"] = keys[0].(map[string]any)["key_id"]
	nc, _ := json.Marshal(c)
	for _, nul := range []bool{true, false} {
		rep := copier(t, base)
		remplacer(t, rep, "cles.json", string(cles), string(nc))
		if nul {
			remplacer(t, rep, "evenement.json", string(ev), "null")
		}
		_, m := analyser(t, rep)
		attendre(t, m, "E-8", commun.Echoue, "")
		if !strings.Contains(m["E-8"].Detail.Fr, "en double") {
			t.Errorf("E-8 : %s", m["E-8"].Detail.Fr)
		}
	}
	// Témoin : cles.json intact, evenement.json = null : E-8 non exécutée.
	rep := copier(t, base)
	remplacer(t, rep, "evenement.json", string(ev), "null")
	_, m := analyser(t, rep)
	attendre(t, m, "E-8", commun.NonExecute, commun.PrerequisEnEchec)
}

// TestOrigineSeqNonEntier : la règle d'origine de C-2 (prev_hash nul si et
// seulement si seq = 1) n'est évaluée que pour un seq entier ; sinon elle
// n'est ni tenue ni violée et E-1 seule porte le défaut (point 36 des
// décisions ; CT-1 §11.4 ; CT-6 EX-5.13). C-2 reste en échec si prev_hash
// diffère du hash recalculé de l'événement précédent.
func TestOrigineSeqNonEntier(t *testing.T) {
	j := evenementsJournal(t)
	// Événement prouvé seq 1 (sans voisin précédent) dont seq devient la
	// chaîne "1", prev_hash nul : l'origine n'est pas évaluée.
	a := &Analyse{statut: map[string]commun.Verification{}}
	a.Evenement = evt(t, j[1], `"seq":1,`, `"seq":"1",`)
	a.voisinsLus = true
	if v := a.c2(); v.Statut == commun.Echoue {
		t.Errorf("seq \"1\", prev_hash nul : C-2 en échec (%s)", v.Detail.Fr)
	}
	// Témoin : seq entier 2 avec prev_hash nul viole l'origine.
	a.Evenement = evt(t, j[1], `"seq":1,`, `"seq":2,`)
	if v := a.c2(); v.Statut != commun.Echoue {
		t.Errorf("seq 2, prev_hash nul : C-2 %s", v.Statut)
	}
	// Voisin précédent à seq non entier : l'origine n'est pas évaluée pour
	// lui ; la relation prev_hash = hash recalculé reste jugée.
	a.Evenement = evt(t, j[2])
	a.Precedent = evt(t, j[1], `"seq":1,`, `"seq":"1",`)
	if v := a.c2(); v.Statut != commun.Echoue || strings.Contains(v.Detail.Fr, "seq = 1") {
		t.Errorf("voisin à seq \"1\" : C-2 %s (%s), attendu l'échec sur le hash seul", v.Statut, v.Detail.Fr)
	}
	// Voisin précédent à seq entier 2 et prev_hash nul : l'origine est
	// violée pour lui.
	a.Precedent = evt(t, j[1], `"seq":1,`, `"seq":2,`)
	if v := a.c2(); v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, "voisin") {
		t.Errorf("voisin à seq 2 et prev_hash nul : C-2 %s (%s)", v.Statut, v.Detail.Fr)
	}
	// Dossier : evenement.json de seq "7" : C-2 échoue par les hash, non
	// par l'origine.
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "evenement.json", `"seq": 7,`, `"seq": "7",`)
	_, m := analyser(t, rep)
	if d := m["C-2"].Detail.Fr; m["C-2"].Statut != commun.Echoue || strings.Contains(d, "seq = 1") {
		t.Errorf("seq \"7\" : C-2 %s (%s)", m["C-2"].Statut, d)
	}
}
