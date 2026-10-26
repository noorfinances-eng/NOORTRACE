package main

// Révision 0.5 de CT-2 : valeurs imprimées par la spécification (exemples de
// 5.4.5, 6.8.16, 12.11, tables d'EX-5.30, d'EX-12.39 et de 16.4), recalculées
// depuis les blocs du document recopiés dans testdata/spec, et règles
// d'analyse exercées hors des vecteurs (EX-5.28, EX-5.29, EX-5.34, EX-6.30,
// EX-12.33, EX-12.38).

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// EX-5.35 : la transcription de 5.4.5 donne la forme consolidée imprimée et
// les valeurs tirées (code.model, intent, appel de fonction en position 2).
func TestExempleGemini545(t *testing.T) {
	a := &AnalyseurSSE{}
	a.Ecrire(lireSpec(t, "ex-5-4-5-flux.sse"))
	evs, final := a.FinGemini()
	if len(evs) != 2 || final {
		t.Fatalf("%d événements, data final %v", len(evs), final)
	}
	var vals []*Value
	for _, e := range evs {
		v, err := ParseJSON([]byte(e.Data))
		if err != nil {
			t.Fatal(err)
		}
		vals = append(vals, v)
	}
	c := ConsoliderGemini(vals, true)
	if c.Incomplet || c.Forme == nil {
		t.Fatal("forme incomplète")
	}
	if !MemeValeur(c.Forme, valeurSpec(t, "ex-5-4-5-consolidee.json")) {
		t.Errorf("forme consolidée : %s", doitIntegral(c.Forme))
	}
	if cm := CodeModelGemini("gemini", c.Forme, "gemini-exemple", nil); doitIntegral(cm) != `"gemini/gemini-exemple-001"` {
		t.Errorf("code.model : %s", doitIntegral(cm))
	}
	if i, _ := IntentGemini(c.Forme); i != "Je consulte le sinistre 2026-81044." {
		t.Errorf("intent : %q", i)
	}
	ap := AppelsGemini(c.Forme)
	if len(ap) != 1 || ap[0].Position != 2 || !ap[0].ID.IsNull() || ap[0].Nom != "demo__claims_get" || doitIntegral(ap[0].Args) != `{"claim_id":"2026-81044"}` {
		t.Errorf("appels : %+v", ap)
	}
	// arrêté après le premier morceau : incomplet (aucun finishReason)
	c1 := ConsoliderGemini(vals[:1], true)
	if !c1.Incomplet || !c1.Forme.Has("noortrace_flux_incomplet") {
		t.Error("flux coupé non marqué incomplet")
	}
}

// EX-5.34 : un data sans ligne vide finale est distribué ; une dernière ligne
// sans fin de ligne est d'abord lue comme une ligne.
func TestDataFinalGemini(t *testing.T) {
	a := &AnalyseurSSE{}
	a.Ecrire([]byte("data: {\"a\":1}\r\n\r\ndata: {\"b\":2}\r\n"))
	evs, final := a.FinGemini()
	if len(evs) != 2 || !final || evs[1].Data != `{"b":2}` {
		t.Errorf("%v %v", evs, final)
	}
	a = &AnalyseurSSE{}
	a.Ecrire([]byte("data: {\"a\":1}\n\ndata: {\"b\":2}"))
	if evs, final := a.FinGemini(); len(evs) != 2 || !final || evs[1].Data != `{"b":2}` {
		t.Errorf("ligne incomplète non lue : %v", evs)
	}
	a = &AnalyseurSSE{}
	a.Ecrire([]byte("data: {\"a\":1}\r\ndata: {\"b\""))
	if evs, final := a.FinGemini(); len(evs) != 1 || !final || evs[0].Data != "{\"a\":1}\n{\"b\"" {
		t.Errorf("deux lignes data jointes attendues : %v", evs)
	}
	// sans distribution du data final (autres formats), la ligne reste abandonnée
	a = &AnalyseurSSE{}
	a.Ecrire([]byte("data: {\"a\":1}\n\ndata: {\"b\":2}"))
	if evs := a.Fin(); len(evs) != 1 {
		t.Errorf("Fin : %v", evs)
	}
}

// EX-5.30 : corps exacts de la table.
func TestCorpsErreurGemini(t *testing.T) {
	cas := map[string]string{
		"corps_non_analysable":     `{"error":{"code":400,"message":"noortrace: corps de requete non analysable","status":"INVALID_ARGUMENT"}}`,
		"cle_dans_url":             `{"error":{"code":400,"message":"noortrace: cle d'API dans l'URL refusee","status":"INVALID_ARGUMENT"}}`,
		"flux_sans_sse":            `{"error":{"code":400,"message":"noortrace: streamGenerateContent exige alt=sse","status":"INVALID_ARGUMENT"}}`,
		"parametre_non_admis":      `{"error":{"code":400,"message":"noortrace: parametre de requete non admis","status":"INVALID_ARGUMENT"}}`,
		"serveurs_mcp_fournisseur": `{"error":{"code":400,"message":"noortrace: serveurs MCP declares au fournisseur refuses","status":"INVALID_ARGUMENT"}}`,
		"taille":                   `{"error":{"code":413,"message":"noortrace: corps de requete trop grand","status":"INVALID_ARGUMENT"}}`,
		"content_encoding":         `{"error":{"code":415,"message":"noortrace: requete comprimee refusee","status":"INVALID_ARGUMENT"}}`,
		"mode_degrade":             `{"error":{"code":503,"message":"noortrace: echange bloque, enregistreur en mode degrade","status":"UNAVAILABLE"}}`,
		"delai":                    `{"error":{"code":504,"message":"noortrace: delai du fournisseur depasse","status":"DEADLINE_EXCEEDED"}}`,
	}
	for r, attendu := range cas {
		if got := doitIntegral(CorpsErreurGemini(r)); got != attendu {
			t.Errorf("%s : %s", r, got)
		}
	}
}

// EX-5.2, EX-5.28, EX-5.29 : route, segment, chaîne de requête.
func TestCibleGemini(t *testing.T) {
	cas := []struct {
		methode, cible  string
		trouvee         bool
		raison, segment string
	}{
		{"POST", "/v1beta/models/gemini-2.0-flash:generateContent", true, "", "gemini-2.0-flash"},
		{"POST", "/v1beta/models/gemini-exemple:generateContent?alt=json", true, "", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:streamGenerateContent?alt=sse", true, "", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:streamGenerateContent?alt=%73se", true, "", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:streamGenerateContent?alt=sse&alt=sse", true, "parametre_non_admis", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:streamGenerateContent?alt=json", true, "flux_sans_sse", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:generateContent?alt=sse", true, "parametre_non_admis", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple:generateContent?alt=json&key=x", true, "cle_dans_url", "gemini-exemple"},
		{"POST", "/v1beta/models/gemini-exemple%3AgenerateContent", false, "", ""},
		{"POST", "/v1beta/models/gemini-exemple:countTokens", false, "", ""},
		{"POST", "/v1beta/models/Gemini:generateContent", false, "", ""},
		{"POST", "/v1beta/tunedModels/m:generateContent", false, "", ""},
		{"GET", "/v1beta/models/gemini-exemple:generateContent", false, "", ""},
	}
	for _, c := range cas {
		r := AnalyserCibleGemini(c.methode, c.cible, RoutesGemini)
		if r.Trouvee != c.trouvee || r.RaisonRequete != c.raison || r.Segment != c.segment {
			t.Errorf("%s %s : %+v", c.methode, c.cible, r)
		}
	}
	if r := AnalyserCibleGemini("POST", "/v1beta/models/a%2Fb:generateContent", RoutesGemini); !r.CheminInvalide {
		t.Error("barre oblique encodée non refusée (EX-5.2)")
	}
}

// 6.8.16 : le lot imprimé, normalisé, donne les pièces et les deux
// événements imprimés (hash et sig compris).
func TestExempleOTel6816(t *testing.T) {
	rss, err := DecoderOTLPJSON(lireSpec(t, "ex-6-8-16-lot.json"), 128, 100000)
	if err != nil {
		t.Fatal(err)
	}
	spans := NormaliserSpans(rss)
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	pol := politiqueSpec(t)
	src := doit(t, `{"alias":"otel-sinistres","host":{"launched_by":"svc-agent-sinistres@assureur-demo.example","on_behalf_of":"service-sinistres","scope":"sinistres:lecture,paiement","host_group":"agent-sinistres","accept_declared_delegation":true},`+
		`"policy_source":{"ingest":["inference","outil"],"overlap":"ignorer","class_default":null,"tools":{}},"policy_version":"2026-11-10-otel"}`)
	opts := doit(t, `{"prompt_in_request":"reference","prompt_system":"redige"}`)
	prev := exemple6816.prev
	for i, ts := range []string{"2026-11-10T10:41:07.512Z", "2026-11-10T10:41:07.514Z"} {
		sorte := "inference"
		if i == 1 {
			sorte = "outil"
		}
		c := construireOTel("otel-sinistres", src.Get("host"), src.Get("policy_source"), spans[i].N, sorte, pol, opts)
		for k, v := range exemple6816.pieces {
			if !strings.HasPrefix(k, string(rune('0'+i))+"/") {
				continue
			}
			p := c.pieces[k[2:]]
			if p == nil || p.SHA256Hex() != v[0] {
				t.Errorf("pièce %s", k)
			}
		}
		ev := c.evenement(int64(21+i), ts, prev, src)
		if chaineDe(ev, "hash") != exemple6816.hash[i] || chaineDe(ev, "sig") != exemple6816.sig[i] {
			t.Errorf("événement %d : %s", i+1, doitIntegral(ev))
		}
		prev = chaineDe(ev, "hash")
	}
}

// EX-6.30 : règles du décodage protobuf.
func TestProtobufOTel(t *testing.T) {
	hexa := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	champ := func(num int, contenu ...[]byte) []byte { // champ LEN
		b := bytes.Join(contenu, nil)
		return append(append(varintPB(uint64(num<<3|2)), varintPB(uint64(len(b)))...), b...)
	}
	vi := func(num int, v uint64) []byte { return append(varintPB(uint64(num<<3)), varintPB(v)...) }
	lot := func(any []byte) []byte { // un span portant un attribut « k » de valeur any
		kv := champ(9, champ(1, []byte("k")), champ(2, any))
		return champ(1, champ(2, champ(2, champ(1, make([]byte, 16)), kv)))
	}
	if _, err := DecoderOTLPProtobuf(lot(vi(2, 1)), 128, 100000); err != nil {
		t.Fatalf("lot de référence refusé : %v", err)
	}
	refuses := map[string][]byte{
		"étiquette 0":              hexa("02 00"),
		"type de fil 3":            hexa("0b"),
		"varint de onze octets":    hexa("08 ff ff ff ff ff ff ff ff ff ff 01"),
		"longueur au-delà":         hexa("0a 05 00"),
		"resource_spans en VARINT": hexa("08 01"),
		"bool_value 2":             lot(vi(2, 2)),
		"deux membres du oneof":    lot(append(champ(1, []byte("a")), vi(2, 1)...)),
		"chaîne non UTF-8":         lot(champ(1, []byte{0xff})),
		"name présent deux fois":   champ(1, champ(2, champ(2, champ(5, []byte("a")), champ(5, []byte("b"))))),
	}
	for nom, b := range refuses {
		if _, err := DecoderOTLPProtobuf(b, 128, 100000); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
	// champ inconnu (numéro 99, LEN) sauté ; corps vide = lot vide
	if rs, err := DecoderOTLPProtobuf(hexa("9a 06 01 00"), 128, 100000); err != nil || len(rs) != 0 {
		t.Errorf("champ inconnu : %v %v", rs, err)
	}
	// réponses d'EX-6.27
	if _, pb := ReponseOTel(200, 0, true); len(pb) != 0 {
		t.Error("succès protobuf non vide")
	}
	j, pb := ReponseOTel(200, 2, true)
	if !bytes.HasPrefix(pb, []byte{0x0a}) || doitIntegral(j) != `{"partialSuccess":{"errorMessage":"noortrace: 2 span(s) rejete(s), identifiants invalides","rejectedSpans":"2"}}` {
		t.Errorf("succès partiel : %x %s", pb, doitIntegral(j))
	}
}

// EX-12.33 : formes d'échéance admises et ramenées à CT-1 §3.
func TestEcheanceWorm(t *testing.T) {
	cas := map[string]string{
		"2037-11-10T11:00:05Z":            "2037-11-10T11:00:05.000Z",
		"2037-11-10T11:00:05.1239999Z":    "2037-11-10T11:00:05.123Z",
		"2037-11-10T12:00:05.5+01:00":     "2037-11-10T11:00:05.500Z",
		"Tue, 10 Nov 2037 11:00:05 GMT":   "2037-11-10T11:00:05.000Z",
		"2037-02-30T11:00:05Z":            "",
		"10/11/2037":                      "",
		"Tue, 10 Nov 2037 11:00:05 +0000": "",
	}
	for in, att := range cas {
		tm, ok := LireEcheance(in)
		got := ""
		if ok {
			got = FormaterHorodatage(tm)
		}
		if got != att {
			t.Errorf("%q : %q", in, got)
		}
	}
	// copied_at + 4 018 j − 1 h de l'exemple d'EX-12.29
	c, _ := ParseHorodatage(CopieExempleISO)
	if m := FormaterHorodatage(c.Add(4018*24*time.Hour - time.Hour)); m != "2037-11-10T10:00:05.412Z" {
		t.Error(m)
	}
}

// EX-12.35 à EX-12.39 : exemples imprimés en 12.11.
func TestExemplesGel1211(t *testing.T) {
	objets := lireSpec(t, "ex-12-35-objets.ndjson")
	if len(objets) != LongueurObjetsExemple || Hex0x(SHA256(objets)) != EmpreinteObjetsExemple {
		t.Errorf("liste des objets : %d octets, %s", len(objets), Hex0x(SHA256(objets)))
	}
	pose := valeurSpec(t, "ex-12-37-pose.json")
	if b, _ := CanoniqueIntegral(pose); len(b) != LongueurPoseExemple || Hex0x(SHA256(b)) != EmpreintesImprimees1211[0] {
		t.Errorf("0001-pose : %d octets, %s", len(b), Hex0x(SHA256(b)))
	}
	levee := valeurSpec(t, "ex-12-37-levee.json")
	if b, _ := CanoniqueIntegral(levee); Hex0x(SHA256(b)) != EmpreintesImprimees1211[3] {
		t.Errorf("0004-levee : %s", Hex0x(SHA256(b)))
	}
	if g := EncoderComposant("journal démo/pièce.json", true); g != "journal%20d%C3%A9mo/pi%C3%A8ce.json" {
		t.Error(g)
	}
	if g := EncoderComposant("a+b/c=", false); g != "a%2Bb%2Fc%3D" {
		t.Error(g)
	}
	// règle de garde : levée par la même personne, demande expirée d'une ms
	recs := []*Value{pose}
	if _, errs := RegleDeGarde(recs); len(errs) != 0 {
		t.Errorf("pose seule : %v", errs)
	}
}

// EX-16.4, EX-16.5 : cas reference de 16.4 (valeurs imprimées de la table).
func TestCoutAgentReference(t *testing.T) {
	in := EntreesCout{H: 2920, e: 120, be: 2560, bp: 6144, np: 2, A: 10, Nh: 8760, oj: 40, bj: 131072, S: 268435456, Canc: 28032, Dl: 4018, Dlp: 4018,
		Worm: true, Dw: 4018, k: 12, pl: 0.5, pw: 1, pput: 0.0001, pget: 0.00001, plh: 0.0001, pout: 0.1}
	s := CoutAgent(in)
	for nom, c := range map[string][2]float64{
		"L": {s.L, 16.223}, "W_st": {s.Wst, 10.374}, "W_put": {s.Wput, 4}, "W_get": {s.Wget, 47.38}, "W_net": {s.Wnet, 0.094},
		"C_a": {s.Ca, 2803.2}, "C": {s.C, 2881.27}, "C_J": {s.CJ, 28812.701}, "O_s": {s.Os, 292}, "O_w": {s.Ow, 35332},
	} {
		if Arrondi3(c[0]) != c[1] {
			t.Errorf("%s : %v, attendu %v", nom, Arrondi3(c[0]), c[1])
		}
	}
}

// Une altération de chaque famille de la révision 0.5 est détectée.
func TestAlterationsRevision05(t *testing.T) {
	racine := construireArbre(t)
	rap := VerifierVecteursCT2(racine, true)
	if _, _, d, _ := rap.Comptes(); d != 0 || len(rap.Erreurs) != 0 {
		t.Fatalf("arbre de départ : %d discordance(s), erreurs %v", d, rap.Erreurs)
	}
	remplacer := func(rel, ancien, nouveau string) {
		t.Helper()
		p := filepath.Join(racine, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), ancien) {
			t.Fatalf("%s : %q introuvable", rel, ancien)
		}
		os.WriteFile(p, []byte(strings.Replace(string(b), ancien, nouveau, 1)), 0o644)
	}
	remplacer("otel/json-exemple-6-8-16/attendu.json", `"duration_ms": 413`, `"duration_ms": 414`)
	remplacer("worm/etats.json", `"verdict": "non_conforme"`, `"verdict": "conforme"`)
	remplacer("worm/gardes.json", `"code": "meme_identite"`, `"code": "demande_inconnue"`)
	remplacer("cout-agent/cas.json", `"total": 2881.27`, `"total": 2881.271`)
	vus := map[string]bool{}
	for _, x := range VerifierVecteursCT2(racine, true).Comparaisons {
		if !x.Concorde && !x.HorsPerimetre {
			vus[x.Famille] = true
		}
	}
	for _, f := range []string{FamilleOTel, FamilleWorm, FamilleCoutAgent} {
		if !vus[f] {
			t.Errorf("%s : altération non détectée", f)
		}
	}
}
