package main

// Valeurs imprimées par CT-2 (sections 8.1, 10.3, 10.6, 10.9, 12.5, annexe A),
// recalculées depuis les exemples de la spécification recopiés dans
// testdata/spec (extraits des blocs de code du document, sans retouche).

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func lireSpec(t *testing.T, nom string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/spec/" + nom)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func valeurSpec(t *testing.T, nom string) *Value {
	t.Helper()
	v, err := ParseJSON(lireSpec(t, nom))
	if err != nil {
		t.Fatalf("%s : %v", nom, err)
	}
	return v
}

func politiqueSpec(t *testing.T) *Politique {
	t.Helper()
	p, mq := ChargerPolitique(valeurSpec(t, "pii-v1.json"))
	if len(mq) > 0 {
		t.Fatalf("pii-v1 : %v", mq)
	}
	return p
}

func verifierPiece(t *testing.T, nom string, p *Piece, octets string, longueur int, sha string, redigee bool) {
	t.Helper()
	if octets != "" && string(p.Octets) != octets {
		t.Errorf("%s : octets\n obtenu  %s\n attendu %s", nom, p.Octets, octets)
	}
	if len(p.Octets) != longueur {
		t.Errorf("%s : length %d, attendu %d", nom, len(p.Octets), longueur)
	}
	if p.SHA256Hex() != sha {
		t.Errorf("%s : sha256 %s, attendu %s", nom, p.SHA256Hex(), sha)
	}
	if p.Redigee != redigee {
		t.Errorf("%s : redacted %v, attendu %v", nom, p.Redigee, redigee)
	}
}

// §10.6 : pii-v1 seul, 1462 octets en JCS intégral, SHA-256 0x9116…7f4e.
func TestPolitiquePiiV1Empreinte(t *testing.T) {
	c, err := CanoniqueIntegral(valeurSpec(t, "pii-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1462 || Hex0x(SHA256(c)) != "0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e" {
		t.Errorf("pii-v1 : %d octets, %s", len(c), Hex0x(SHA256(c)))
	}
}

// §10.6 : membre policy de l'exemple de 15.3, 6126 octets, policy_sha256
// 0xa75a…8912 ; valeur en ligne de l'événement de politique, 116 octets,
// sha256 0x77d3…253e (version 0.3 : 4482 octets et 0xd87b…c811 en version
// 0.2) ; le membre redaction est pii-v1 octet pour octet ; rules est un
// document politique-approbation-v0, mode erreur, avec une entrée de
// separation.identities pour poste-cursor, et storage.relay_mac_key porte un
// encoding (15.3, EX-7.22).
func TestEnsembleDePolitiqueExemple(t *testing.T) {
	conf := valeurSpec(t, "configuration-exemple.json")
	pol := conf.Get("policy")
	c, err := CanoniqueIntegral(pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 6126 || Hex0x(SHA256(c)) != "0xa75af9f5870779f14be7fc8f285a62287660097d6b6377153181a352d69f8912" {
		t.Errorf("policy : %d octets, %s", len(c), Hex0x(SHA256(c)))
	}
	val := Objet("policy_version", Chaine("2026-11-01"), "policy_sha256", Chaine(Hex0x(SHA256(c))))
	cv, err := Canonique(val) // JCS v0, en ligne
	if err != nil {
		t.Fatal(err)
	}
	if string(cv) != `{"policy_sha256":"0xa75af9f5870779f14be7fc8f285a62287660097d6b6377153181a352d69f8912","policy_version":"2026-11-01"}` ||
		len(cv) != 116 || Hex0x(SHA256(cv)) != "0x77d3368adad6a5a62421901ee91ec7c500950a2c8038a7d58d0450b3665c253e" {
		t.Errorf("valeur en ligne : %s (%d octets, %s)", cv, len(cv), Hex0x(SHA256(cv)))
	}
	if !MemeValeur(pol.Get("redaction"), valeurSpec(t, "pii-v1.json")) {
		t.Error("le membre redaction de l'exemple diffère de pii-v1 (10.9)")
	}
	ap := pol.Get("approval")
	if chaineDe(ap, "mode") != "erreur" {
		t.Errorf("approval.mode : %s, attendu erreur (15.3, CT-3 EX-11.1)", chaineDe(ap, "mode"))
	}
	if r := ap.Get("rules"); !EstObjet(r) || texteOuAbsent(r.Get("version")) != "0" || chaineDe(r, "separation", "self_approval") != "interdite" {
		t.Errorf("approval.rules : document politique-approbation-v0 attendu (15.3) : %s", texteOuAbsent(r))
	}
	if k := conf.Get("storage").Get("relay_mac_key"); !EstObjet(k) || chaineDe(k, "encoding") == "" {
		t.Errorf("storage.relay_mac_key : référence de secret avec encoding attendue (EX-7.22, EX-15.3) : %s", texteOuAbsent(k))
	}
}

// §10.9, premier exemple, et annexe A pas 4 : pièce « arguments ».
func TestRedactionArgumentsAnnexeA(t *testing.T) {
	req := valeurSpec(t, "annexe-a-hote-requete.jsonl")
	args := req.Get("params").Get("arguments")
	clair, _ := CanoniqueIntegral(args)
	if string(clair) != `{"amount":"7400.00","beneficiary_iban":"CH9300762011623852957","claim_id":"2026-77812","currency":"CHF"}` || len(clair) != 104 {
		t.Errorf("valeur reçue en JCS intégral : %s (%d)", clair, len(clair))
	}
	p, res, err := PieceRedigeeJSON(politiqueSpec(t), "arguments", "sap.payments.create", args)
	if err != nil {
		t.Fatal(err)
	}
	verifierPiece(t, "arguments", p, `{"amount":"7400.00","beneficiary_iban":"[REDIGE:iban]","claim_id":"2026-77812","currency":"CHF"}`,
		96, "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4", true)
	if len(res.Decomptes) != 1 || res.Decomptes[0] != (Decompte{"identifiants-arguments-resultat", "iban", 1}) {
		t.Errorf("décompte : %+v", res.Decomptes)
	}
	// EX-10.15 : idempotence
	v, _ := ParseJSON(p.Octets)
	p2, _, _ := PieceRedigeeJSON(politiqueSpec(t), "arguments", "sap.payments.create", v)
	if string(p2.Octets) != string(p.Octets) || p2.Redigee {
		t.Errorf("idempotence : %s redacted=%v", p2.Octets, p2.Redigee)
	}
}

// §10.9, second exemple : cinq détecteurs, cinq correspondances.
func TestRedactionTexteLibre(t *testing.T) {
	v, err := ParseJSON([]byte(`{"note":"Virement au bénéficiaire CH93 0076 2011 6238 5295 7, assuré 756.1234.5678.97, joignable au +41 44 123 45 67 ou j.dupont@example.ch ; carte 3782 822463 10005."}`))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := CanoniqueIntegral(v)
	if len(c) != 171 {
		t.Errorf("valeur reçue : %d octets, attendu 171", len(c))
	}
	p, res, err := PieceRedigeeJSON(politiqueSpec(t), "resultat", "x", v)
	if err != nil {
		t.Fatal(err)
	}
	verifierPiece(t, "résultat", p, `{"note":"Virement au bénéficiaire [REDIGE:iban], assuré [REDIGE:avs], joignable au [REDIGE:telephone] ou [REDIGE:email] ; carte [REDIGE:carte]."}`,
		148, "0x89a34ad286014dee1e1030caf6d50d32327a77da216dfb4a19154f15b73d5f8e", true)
	if len(res.Decomptes) != 5 {
		t.Errorf("décomptes : %+v", res.Decomptes)
	}
}

// §10.9 et annexe B : clé de pseudonymisation de test et jetons imprimés.
func TestPseudonymesDeTest(t *testing.T) {
	k := SHA256([]byte(EtiquetteClePseudoTest))
	if Hex0x(k) != ClePseudoTestHex {
		t.Fatalf("clé de test : %s", Hex0x(k))
	}
	if j := Pseudonyme(k, "iban", "CH9300762011623852957"); j != "50d46ea9a82b" {
		t.Errorf("[PSEUDO:iban:%s], attendu 50d46ea9a82b", j)
	}
	if j := Pseudonyme(k, "email", "j.dupont@example.ch"); j != "b8ac789204a6" {
		t.Errorf("[PSEUDO:email:%s], attendu b8ac789204a6", j)
	}
	// par la politique : même document que pii-v1, action pseudonyme, clé de test
	doc := valeurSpec(t, "pii-v1.json")
	Definir(doc, "name", Chaine("pii-pseudo-test"))
	Definir(doc, "pseudonym_key", Objet("env", Chaine(VariableClePseudoTest), "encoding", Chaine("hex")))
	for _, r := range doc.Get("rules").Arr {
		Definir(r, "action", Objet("kind", Chaine("pseudonyme")))
	}
	os.Unsetenv(VariableClePseudoTest)
	pol, mq := ChargerPolitique(doc)
	if len(mq) > 0 {
		t.Fatal(mq)
	}
	s, n := pol.RedigerTexte("pseudonyme", Detecteur{Type: "iban"}, "IBAN CH93 0076 2011 6238 5295 7.")
	if s != "IBAN [PSEUDO:iban:50d46ea9a82b]." || n != 1 {
		t.Errorf("pseudonyme iban : %q", s)
	}
	s, _ = pol.RedigerTexte("pseudonyme", Detecteur{Type: "email"}, "j.dupont@EXAMPLE.ch")
	if s != "[PSEUDO:email:b8ac789204a6]" {
		t.Errorf("pseudonyme email (domaine en minuscules) : %q", s)
	}
}

// Annexe A pas 2 : pièce de définition d'outil, 406 octets, 0x7d2f…498a.
func TestDefinitionOutilAnnexeA(t *testing.T) {
	p, err := PieceJSON(valeurSpec(t, "annexe-a-definition.json"), false, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	verifierPiece(t, "définition", p, "", 406, "0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a", false)
}

// Annexe A pas 10 : pièce « résultat », 109 octets, 0x8506…3b8c ; pas 8 :
// arguments relayés octet pour octet (EX-4.20) ; pas 14 : réécritures.
func TestResultatEtRelaisAnnexeA(t *testing.T) {
	rep := valeurSpec(t, "annexe-a-amont-reponse.jsonl")
	p, _, err := PieceRedigeeJSON(politiqueSpec(t), "resultat", "sap.payments.create", rep.Get("result"))
	if err != nil {
		t.Fatal(err)
	}
	verifierPiece(t, "résultat", p, `{"content":[{"text":"Paiement PAY-2026-55120 créé","type":"text"}],"isError":false,"resultType":"complete"}`,
		109, "0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c", false)
	hote := lireSpec(t, "annexe-a-hote-requete.jsonl")
	amont := lireSpec(t, "annexe-a-amont-requete.jsonl")
	vh, _ := ParseJSON(hote)
	va, _ := ParseJSON(amont)
	ah, aa := vh.Get("params").Get("arguments"), va.Get("params").Get("arguments")
	if string(hote[ah.Debut:ah.Fin]) != string(amont[aa.Debut:aa.Fin]) || ah.Fin-ah.Debut != 104 {
		t.Errorf("octets de params.arguments relayés : %q / %q", hote[ah.Debut:ah.Fin], amont[aa.Debut:aa.Fin])
	}
	if len(strings.TrimSuffix(string(hote), "\n")) != 408 || len(strings.TrimSuffix(string(amont), "\n")) != 420 {
		t.Error("longueurs des lignes de l'annexe A")
	}
	rh := valeurSpec(t, "annexe-a-hote-reponse.jsonl").Get("result")
	if !MemeValeur(sansIdentiteServeur(rh), sansIdentiteServeur(rep.Get("result"))) {
		t.Error("résultat rendu à l'hôte ≠ résultat amont aux réécritures près")
	}
}

// Annexe A pas 7 et EX-12.12 : ligne intention à neuf clés, 482 octets,
// 0xdd28…0b08 ; objet de reprise.
func TestIntentionAnnexeA(t *testing.T) {
	v := valeurSpec(t, "annexe-a-intention.json")
	c, _ := CanoniqueIntegral(v)
	if len(c) != 482 || Hex0x(SHA256(c)) != "0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08" {
		t.Errorf("intention : %d octets, %s", len(c), Hex0x(SHA256(c)))
	}
	if string(c) != strings.TrimSuffix(string(lireSpec(t, "annexe-a-intention.json")), "\n") {
		t.Error("la ligne imprimée n'est pas en JCS intégral")
	}
	if len(v.Obj) != 9 || !reIntentID.MatchString(chaineDe(v, "intent_id")) || chaineDe(v, "upstream_id") != "e-000000000041" {
		t.Errorf("intention : %d clés, intent_id %s", len(v.Obj), chaineDe(v, "intent_id"))
	}
	// arguments = référence complète de la pièce du pas 4
	if !MemeValeur(v.Get("arguments"), Objet("sha256", Chaine("0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4"), "length", Entier(96), "redacted", Booleen(true))) {
		t.Errorf("arguments : %s", doitIntegral(v.Get("arguments")))
	}
	r := ObjetReprise(Hex0x(SHA256(c)))
	cr, _ := CanoniqueIntegral(r)
	if string(cr) != `{"intention_sha256":"0xdd28b1c3e93808ddb24979a145ca1fe131ba0adc5390291b3287c0b329310b08","noortrace_reprise":"resultat inconnu : enregistreur arrete pendant le relais"}` {
		t.Errorf("objet de reprise : %s", cr)
	}
}

// Annexe A pas 12 et 13 : seq 4, forme canonique de 2249 octets, hash et
// signature ; ligne de segment de 2465 octets (\n compris) ; context de seq 2
// et seq 4 : définition et liste annoncée (EX-4.45).
func TestEvenementEtLigneDeSegmentAnnexeA(t *testing.T) {
	ev := valeurSpec(t, "annexe-a-seq4.json")
	h, c, err := HashEvenement(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 2249 || Hex0x(h) != "0x8e2f87b9398cab6229bf44a72cd05565d00c30eafd8e51fb14dfaf9074d05ca6" {
		t.Errorf("seq 4 : %d octets, %s", len(c), Hex0x(h))
	}
	pub, _ := OctetsHex("0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045", 32)
	sig, _ := OctetsHex(chaineDe(ev, "sig"), 64)
	if err := VerifierEd25519(pub, append(append([]byte{}, PrefixeSignatureEvenement...), c...), sig); err != nil {
		t.Errorf("signature de seq 4 : %v", err)
	}
	ligne, err := Canonique(ev)
	if err != nil {
		t.Fatal(err)
	}
	attendu := lireSpec(t, "annexe-a-ligne-segment-seq4.txt")
	if string(ligne)+"\n" != string(attendu) || len(attendu) != 2465 {
		t.Errorf("ligne de segment : %d octets", len(ligne)+1)
	}
	ev2 := valeurSpec(t, "annexe-a-seq2.json")
	h2, _, _ := HashEvenement(ev2)
	if Hex0x(h2) != "0x793ab66aab9ca28f1176d8ff023ffe98f0eadb514aecb329fdffd7420e821bd6" {
		t.Errorf("seq 2 : %s", Hex0x(h2))
	}
	def := valeurSpec(t, "annexe-a-definition.json")
	pd, _ := PieceJSON(def, false, MediaJSONExplicite)
	pl, _ := PieceJSON(Objet("tools", &Value{Kind: KindArray, Arr: []*Value{def}}), false, MediaJSONExplicite)
	if pl.SHA256Hex() != "0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e" || len(pl.Octets) != 418 {
		t.Errorf("liste annoncée : %d octets, %s", len(pl.Octets), pl.SHA256Hex())
	}
	for _, e := range []*Value{ev2, ev} {
		ctx := e.Get("context")
		if !EstTableau(ctx) || len(ctx.Arr) != 2 || chaineDe(ctx.Arr[0], "sha256") != pd.SHA256Hex() || chaineDe(ctx.Arr[1], "sha256") != pl.SHA256Hex() {
			t.Errorf("seq %d : context %s", Seq(e), doitIntegral(ctx))
		}
	}
}

// §8.1 : table des nombres imprimée par CT-2.
func TestTableNombresCT2(t *testing.T) {
	cas := [][2]string{
		{"1", "1"}, {"1.0", "1"}, {"1.50", "1.5"}, {"1e3", "1000"}, {"1E+2", "100"},
		{"1e21", "1e+21"}, {"1e20", "100000000000000000000"}, {"-0", "0"}, {"-0.0", "0"},
		{"0.000001", "0.000001"}, {"0.0000001", "1e-7"}, {"5e-324", "5e-324"},
		{"9007199254740993", "9007199254740992"},
		{"123456789012345678901234567890", "1.2345678901234568e+29"},
		{"3.141592653589793238462643383279", "3.141592653589793"},
	}
	for _, c := range cas {
		f, err := NombreDouble(c[0])
		if err != nil {
			t.Errorf("%s : %v", c[0], err)
			continue
		}
		if got := NombreES6(f); got != c[1] {
			t.Errorf("%s → %s, attendu %s", c[0], got, c[1])
		}
	}
	_ = fmt.Sprint
}
