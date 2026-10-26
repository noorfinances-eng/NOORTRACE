package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests de la révision 0.3 construits sans les vecteurs : valeurs imprimées
// par le texte de CT-3 (9.6, 9.7, 12.9, 13.3 à 13.13) et scénarios
// construits ici avec les clés dérivées du mnémonique (A.2).

func schemasConsoleTest(t *testing.T) *Schemas {
	t.Helper()
	d := filepath.Join("..", "..", "..", "schemas")
	var chemins []string
	for _, n := range []string{"politique-approbation-v0", "ticket-v0", "evenement-v0", "annuaire-approbateurs-v0", "console-approbation-v0", "console-service-v0"} {
		chemins = append(chemins, filepath.Join(d, n+".schema.json"))
	}
	sch, err := ChargerSchemas(chemins...)
	if err != nil {
		t.Skipf("schémas introuvables : %v", err)
	}
	return sch
}

func specTest(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "CT-3-approbations.md"))
	if err != nil {
		t.Skipf("spécification introuvable : %v", err)
	}
	return string(src)
}

// EX-13.7 : formes canoniques et refus.
func TestIdentiteCanonique(t *testing.T) {
	bonnes := []string{
		"oidc https://idp.assureur-demo.example approbateur-1",
		"utilisateur annuaire.interne u-123",
		"oidc https://idp.example:8443/realms/a " + strings.Repeat("s", 217), // 256 caractères
	}
	mauvaises := []string{
		"u.martin@assureur-demo.example",
		"oidc https://idp.assureur-demo.example?x=1 admin-1",
		"oidc https://idp.assureur-demo.example#f admin-1",
		"oidc http://idp.assureur-demo.example admin-1",
		"oidc https:// admin-1",
		"oidc https://idp.assureur-demo.example approbateur 1",
		"oidc  https://idp.assureur-demo.example approbateur-1",
		"oidc https://idp.assureur-demo.example appröbateur",
		"saml https://idp.assureur-demo.example a",
		"utilisateur " + strings.Repeat("d", 129) + " n",
		"oidc https://idp.example " + strings.Repeat("s", 256),
		"oidc https://idp.example:8443/realms/a " + strings.Repeat("s", 218), // 257 caractères
	}
	for _, s := range bonnes {
		if !IdentiteCanonique(s) {
			t.Errorf("refusée à tort : %q", s)
		}
	}
	for _, s := range mauvaises {
		if IdentiteCanonique(s) {
			t.Errorf("admise à tort : %q", s)
		}
	}
}

// EX-13.12 : l'exemple du texte (516 octets, préimage de 545, condensé
// imprimé) et les variantes refusées.
func TestMessageInscriptionExemple(t *testing.T) {
	ch := ChampsInscription{Origin: "https://console.assureur-demo.example", Org: "assureur-demo",
		OrgID: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", Identity: "oidc https://idp.assureur-demo.example approbateur-1",
		Address: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", IssuedAt: "2026-11-10T08:00:00.000Z", ExpiresAt: "2026-11-10T08:10:00.000Z", Nonce: "dbcddc22164b049171cc7a6cda847ff2"}
	m := MessageInscription(ch)
	if len(m) != 516 || len(PreimageEIP191([]byte(m))) != 545 {
		t.Fatalf("longueurs %d, %d", len(m), len(PreimageEIP191([]byte(m))))
	}
	if got := Hex0x(CondenseEIP191([]byte(m))); got != "0xaf9b14a62489fc34643813436d932180470bbfa1cb197aea3de5fe54f871c5ef" {
		t.Fatalf("condensé %s", got)
	}
	if lu, ok := AnalyserMessageInscription(m); !ok || lu != ch {
		t.Fatalf("analyse : %v %+v", ok, lu)
	}
	variantes := []string{
		strings.ReplaceAll(m, "\n", "\r\n"),
		m + "\n",
		m + "\nAutre: x",
		strings.Replace(m, "inscription/v0", "inscription/v1", 1),
		strings.Replace(m, "vote.", "vote!", 1),
		strings.Replace(m, "Origine: ", "origine: ", 1),
		strings.Replace(m, "Origine: ", "Origine:  ", 1),
		strings.Replace(m, "Identite: ", "Identité: ", 1),
		strings.Replace(m, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x70997970C51812dc3a010C7d01b50e0d17dc79C8", 1),
		strings.Replace(m, "Nonce: dbcddc22164b049171cc7a6cda847ff2", "Nonce: dbcddc22164b049171cc7a6cda847ff", 1),
		strings.Replace(m, "2026-11-10T08:00:00.000Z", "2026-11-10T08:00:00Z", 1),
		strings.Replace(m, "approbateur-1\n", "approbateur 1\n", 1),
	}
	for i, v := range variantes {
		if _, ok := AnalyserMessageInscription(v); ok {
			t.Errorf("variante %d admise", i)
		}
	}
	// EX-13.16 : séparation des domaines (adresses imprimées par le texte).
	k, _ := CalculerConstantes()
	sigInscr, _ := SignerMessage(k.Prives[k.Comptes[1]], []byte(m))
	if sigInscr != "0x8f799ab2a84552c45d92dbbb89107933a01e8ea1ad2628656cf1acae8a326e2b1e422a677308bd27d4821637bafa04f9338b07b3b19368ec10472caeaa0afbca1c" {
		t.Fatalf("signature d'inscription %s", sigInscr)
	}
	s, _ := NormaliserSignature(sigInscr)
	a := ObjetA("approuve", k.JournalID, k.OrgID, "0x16a40a774991992347027ea9832fc2398743b19295fe6a80fbaee8d4c529ff16", "apr-0001")
	if got, _ := AdresseVote(a, s); got != "0xfac296ad1fc770d69ff4d1f69b67efbba7ae46f9" {
		t.Errorf("inscription comme vote : %s", got)
	}
	sigVote, _ := SignerA(k.Prives[k.Comptes[1]], a)
	sv, _ := NormaliserSignature(sigVote)
	if got, _ := AdresseRecouvree(CondenseEIP191([]byte(m)), sv); got != "0x8768051a828bb4301030920c9b69759b08e64bde" {
		t.Errorf("vote comme inscription : %s", got)
	}
}

// Scénario d'annuaire construit ici (EX-13.13 à EX-13.19).
func TestAnnuaireScenario(t *testing.T) {
	sch := schemasConsoleTest(t)
	k, _ := CalculerConstantes()
	admin := "oidc https://idp.assureur-demo.example admin-1"
	p1 := "oidc https://idp.assureur-demo.example approbateur-1"
	doc := valeur(t, `{"version":0,"org":"assureur-demo","org_id":"`+k.OrgID+`","console_origin":"https://console.assureur-demo.example","registration_ttl_ms":600000,"administrators":["`+admin+`"],"revision":0,"updated_at":null,"entries":[],"operations":[]}`)
	e := &EtatAnnuaire{Doc: doc, Sch: sch}
	t0, _ := LireInstant("2026-11-10T08:00:00.000Z")
	id := func() string { return "apb-0001" }
	inscrire := func(sess, adr, nonce string, at Instant) IssueOperation {
		r := e.Appliquer("preparer_inscription", valeur(t, `{"session_identity":"`+sess+`","address":"`+adr+`"}`), at, nonce, id, ModeService)
		if !r.Accepte {
			t.Fatalf("préparation : %+v", r)
		}
		msg := r.Reponse.Get("message").S()
		sig, _ := SignerMessage(k.Prives[adr], []byte(msg))
		req := Objet("session_identity", Chaine(sess), "address", Chaine(adr), "message", Chaine(msg), "signature", Chaine(sig))
		return e.Appliquer("inscrire", req, at+30000, "", id, ModeService)
	}
	if r := inscrire(p1, k.Comptes[1], nonceA10(1), t0); !r.Accepte || !r.NouvelleEntree || r.Reponse.Get("state").S() != "en_attente" {
		t.Fatalf("inscription : %+v %s", r, Compact(r.Reponse))
	}
	// Défi présenté une seconde fois : nonce_deja_utilise.
	msg := MessageInscription(ChampsInscription{"https://console.assureur-demo.example", "assureur-demo", k.OrgID, p1, k.Comptes[1], t0.String(), (t0 + 600000).String(), nonceA10(1)})
	sig, _ := SignerMessage(k.Prives[k.Comptes[1]], []byte(msg))
	if r := e.Appliquer("inscrire", Objet("session_identity", Chaine(p1), "address", Chaine(k.Comptes[1]), "message", Chaine(msg), "signature", Chaine(sig)), t0+40000, "", id, ModeService); r.Raison != "nonce_deja_utilise" {
		t.Errorf("rejeu du défi : %+v", r)
	}
	valider := func(sess, adr string, at Instant) IssueOperation {
		return e.Appliquer("valider", valeur(t, `{"session_identity":"`+sess+`","entry":"apb-0001","address":"`+adr+`"}`), at, "", id, ModeService)
	}
	if r := valider(p1, k.Comptes[1], t0+60000); r.Raison != "non_administrateur" {
		t.Errorf("validation par la personne non administratrice : %+v", r)
	}
	if r := valider(admin, k.Comptes[1], t0+120000); !r.Accepte {
		t.Fatalf("validation : %+v", r)
	}
	// Rotation : la deuxième adresse validée révoque la première.
	if r := inscrire(p1, k.Comptes[2], nonceA10(2), t0+180000); !r.Accepte || r.NouvelleEntree {
		t.Fatalf("deuxième inscription : %+v", r)
	}
	if r := valider(admin, k.Comptes[2], t0+300000); !r.Accepte {
		t.Fatalf("deuxième validation : %+v", r)
	}
	x := e.entreeParID("apb-0001")
	a1 := adresseDeLEntree(x, k.Comptes[1])
	if a1.Get("state").S() != "revoquee" || a1.Get("revocation_cause").S() != "remplacee" || a1.Get("replaced_by").S() != k.Comptes[2] || AdresseActive(x) != k.Comptes[2] {
		t.Fatalf("rotation : %s", Compact(x))
	}
	// Adresse jamais réattribuée.
	if r := e.Appliquer("preparer_inscription", valeur(t, `{"session_identity":"oidc https://idp.assureur-demo.example autre","address":"`+k.Comptes[1]+`"}`), t0+400000, nonceA10(3), id, ModeService); r.Raison != "adresse_deja_attribuee" {
		t.Errorf("réattribution : %+v", r)
	}
	// Contrôles de la console (EX-13.18).
	ticket := valeur(t, `{"launched_by":"dem","self_approval":"interdite","policy_requester_addresses":[],"directory_requester_addresses":[],"members":["`+k.Comptes[1]+`","`+k.Comptes[2]+`"]}`)
	if ok, r, _ := ControleVote(e.Doc, p1, "voter", k.Comptes[1], ticket); ok || r != "adresse_non_attribuee" {
		t.Errorf("adresse révoquée : %v %s", ok, r)
	}
	if ok, r, _ := ControleVote(e.Doc, p1, "voter", k.Comptes[2], ticket); !ok {
		t.Errorf("vote autorisé refusé : %s", r)
	}
	// L'annuaire exporté se vérifie sans écart ; revision faussée : écart.
	if ec := VerifierAnnuaireExporte(sch, e.Doc); len(ec) != 0 {
		t.Fatalf("écarts : %+v", ec)
	}
	faux := Copier(e.Doc)
	poser(faux, "revision", Entier(3))
	if ec := VerifierAnnuaireExporte(sch, faux); len(ec) != 1 || ec[0].Code != "revision_incoherente" || *ec[0].Pointeur != "/revision" {
		t.Errorf("revision faussée : %+v", ec)
	}
	auto := Copier(e.Doc)
	poser(adresseDeLEntree(auto.Get("entries").Arr[0], k.Comptes[2]), "validated_by", Chaine(p1))
	ec := VerifierAnnuaireExporte(sch, auto)
	codes := []string{}
	for _, x := range ec {
		codes = append(codes, x.Code+" "+*x.Pointeur)
	}
	if strings.Join(codes, ";") != "operations_incoherentes /entries;auto_validation /entries/0/addresses/1/validated_by" {
		t.Errorf("auto-validation : %v", codes)
	}
}

// 12.9 : la vue d'exemple d'EX-12.15 donne un modèle signable, l'empreinte
// imprimée, et les refus que le texte annonce.
func TestModeleAffichageExemple(t *testing.T) {
	spec := specTest(t)
	vue, err := blocJSON(spec, "<!-- schema: console-approbation/vue_ticket -->")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := CalculerConstantes()
	h, _ := HachageEvenement(vue.Get("retained_event"))
	if Hex0x(h) != "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d" {
		t.Fatalf("hachage de l'événement retenue %s", Hex0x(h))
	}
	now, _ := LireInstant("2026-11-05T09:25:00.000Z")
	s := SessionConsole{Entree: "active", Adresses: []string{k.Comptes[1]}}
	m := ModeleAffichage(vue, s, Chaine("approuve"), Chaine(k.Comptes[1]), Chaine("Constat et facture concordants"), now)
	if Compact(m.Get("blocking")) != "[]" || !m.Get("signable").Bool || Compact(m.Get("remaining_ms")) != "2829904" {
		t.Fatalf("modèle : %s %s", Compact(m.Get("blocking")), Compact(m.Get("remaining_ms")))
	}
	if fp := m.Get("digests").Get("approuve").Get("fingerprint").S(); fp != "a57cbdad…64f7df7c" {
		t.Errorf("empreinte %s", fp)
	}
	// Événement modifié d'un caractère : evenement_invalide, aucun condensé.
	v2 := Copier(vue)
	poser(v2.Get("retained_event"), "ts", Chaine("2026-11-05T09:12:09.905Z"))
	m2 := ModeleAffichage(v2, s, Chaine("approuve"), Chaine(k.Comptes[1]), Nul(), now)
	if Compact(m2.Get("blocking")) != `["evenement_invalide"]` || !m2.Get("digests").IsNull() {
		t.Errorf("événement modifié : %s", Compact(m2.Get("blocking")))
	}
	// Condensé du service faux pour refuse seulement : empreinte_divergente.
	v3 := Copier(vue)
	poser(v3.Get("digests"), "refuse", Chaine("0x"+strings.Repeat("22", 32)))
	if m3 := ModeleAffichage(v3, s, Chaine("approuve"), Chaine(k.Comptes[1]), Nul(), now); Compact(m3.Get("blocking")) != `["empreinte_divergente"]` {
		t.Errorf("condensé faux : %s", Compact(m3.Get("blocking")))
	}
	// Motif de 1 025 points de code.
	if m4 := ModeleAffichage(vue, s, Chaine("approuve"), Chaine(k.Comptes[1]), Chaine(strings.Repeat("é", 1025)), now); Compact(m4.Get("blocking")) != `["motif_trop_long"]` {
		t.Errorf("motif : %s", Compact(m4.Get("blocking")))
	}
}

// EX-9.21 : l'exemple du texte et les formes refusées.
func TestVerifierReponseExemple(t *testing.T) {
	k, _ := CalculerConstantes()
	a := ObjetA("approuve", "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164", k.OrgID, "0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d", "apr-2201")
	d, _ := CondenseA(a)
	haut := "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09a770c4ec4f338561f271e0dfecc15f53f0bff32e1fc2794f85647391f249ff741c"
	bas := "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b"
	is := VerifierReponse(Objet("result", Chaine(haut)), d, k.Comptes[1])
	if is.Raison != "" || is.Signature != bas || is.Recouvree != k.Comptes[1] {
		t.Fatalf("s haut : %+v", is)
	}
	if is := VerifierReponse(Objet("result", Chaine("0x"+strings.ToUpper(bas[2:]))), d, k.Comptes[1]); is.Signature != bas {
		t.Errorf("majuscules : %+v", is)
	}
	if is := VerifierReponse(Objet("result", Chaine(bas[:130]+"25")), d, k.Comptes[1]); is.Raison != "signature_invalide" {
		t.Errorf("v = 37 : %+v", is)
	}
	if is := VerifierReponse(Objet("result", Chaine(bas[:130])), d, k.Comptes[1]); is.Raison != "signature_invalide" {
		t.Errorf("64 octets : %+v", is)
	}
	if is := VerifierReponse(Objet("result", Nul()), d, k.Comptes[1]); is.Raison != "reponse_invalide" {
		t.Errorf("null : %+v", is)
	}
	if is := VerifierReponse(Objet("error", Objet("code", Entier(4001), "message", Chaine("x"))), d, k.Comptes[1]); is.Raison != "refus_approbateur" {
		t.Errorf("4001 : %+v", is)
	}
	chaine, _ := SignerMessage(k.Prives[k.Comptes[1]], []byte(Hex0x(d)))
	if is := VerifierReponse(Objet("result", Chaine(chaine)), d, k.Comptes[1]); is.Raison != "adresse_differente" || is.Recouvree != "0x58047c881cfdadf1b8d785b79b29c5cc784ede6e" {
		t.Errorf("signature de la chaîne : %+v", is)
	}
	// EX-13.24 : requête exacte.
	if got := Compact(RequetePersonalSign(d, strings.ToUpper(k.Comptes[1][:2])+k.Comptes[1][2:])); got != `{"method":"personal_sign","params":["0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c","0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]}` {
		t.Errorf("requête : %s", got)
	}
}

// EX-13.22 : découverte construite ici.
func TestDecouverte(t *testing.T) {
	ann := func(uuid, nom, icone, obj string) *Value {
		return Objet("info", Objet("uuid", Chaine(uuid), "name", Chaine(nom), "icon", Chaine(icone), "rdns", Chaine("r")), "provider", Chaine(obj))
	}
	u1 := "11111111-1111-4111-8111-111111111111"
	u2 := "22222222-2222-4222-9222-222222222222"
	fs, rs := Decouvrir([]*Value{
		ann(u1, "a", "data:x", "p1"), ann(u2, "b", "data:x", "p2"), ann(u1, "a", "data:x", "p1"),
		ann(u1, "a", "data:x", "p3"), ann("33333333-3333-1333-8333-333333333333", "c", "data:x", "p4"), ann(u2, "", "data:x", "p2"),
	})
	if Compact(fs) != `[{"uuid":"`+u2+`","name":"b","rdns":"r","provider":"p2"}]` {
		t.Errorf("fournisseurs : %s", Compact(fs))
	}
	if Compact(rs) != `[{"index":0,"reason":"annonce_en_double"},{"index":3,"reason":"annonce_en_double"},{"index":4,"reason":"annonce_invalide"},{"index":5,"reason":"annonce_invalide"}]` {
		t.Errorf("écartées : %s", Compact(rs))
	}
}

// EX-13.28 : l'exemple du texte se déchiffre en la clé du compte 1 ; mauvais
// mot de passe, bornes.
func TestFichierCleExemple(t *testing.T) {
	spec := specTest(t)
	f, err := blocJSON(spec, "<!-- schema: console-approbation/fichier_cle -->")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := CalculerConstantes()
	is := LireFichierCle(f, MotDePasseFichierCle, k.Comptes[1])
	if is.Raison != "" || is.Adresse != k.Comptes[1] || Hex0x(is.Cle) != Hex0x(k.Prives[k.Comptes[1]]) || !is.DerivationFbl {
		t.Fatalf("déchiffrement : %+v", is)
	}
	if is := LireFichierCle(f, MotDePasseFichierCle+"!", k.Comptes[1]); is.Raison != "mot_de_passe_ou_mac" {
		t.Errorf("mauvais mot de passe : %+v", is)
	}
	if is := LireFichierCle(f, MotDePasseFichierCle, k.Comptes[2]); is.Raison != "adresse_differente" || is.Adresse != k.Comptes[1] {
		t.Errorf("autre adresse : %+v", is)
	}
	g := Copier(f)
	poser(g.Get("crypto").Get("kdfparams"), "c", Entier(10000001))
	if is := LireFichierCle(g, MotDePasseFichierCle, k.Comptes[1]); is.Raison != "fichier_cle_non_pris_en_charge" {
		t.Errorf("c hors borne : %+v", is)
	}
	g = Copier(f)
	poser(g, "version", Entier(1))
	if is := LireFichierCle(g, MotDePasseFichierCle, k.Comptes[1]); is.Raison != "fichier_cle_invalide" {
		t.Errorf("version 1 : %+v", is)
	}
	// Le sel, le vecteur d'initialisation et l'identifiant sont tirés des
	// étiquettes publiques de A.11.
	cr := f.Get("crypto")
	if "0x"+cr.Get("kdfparams").Get("salt").S() != Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/console/fichier-cle/pbkdf2/sel")) ||
		"0x"+cr.Get("cipherparams").Get("iv").S() != Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/console/fichier-cle/pbkdf2/iv")[:16]) ||
		f.Get("id").S() != uuidEtiquette("noortrace/vecteurs/ct3/console/fichier-cle/pbkdf2/uuid") {
		t.Errorf("étiquettes : %s", Compact(f))
	}
}

// Feuilles d'EX-9.16 : ordre JCS, échappement RFC 6901, objets et tableaux
// vides.
func TestFeuilles(t *testing.T) {
	v := valeur(t, `{"b":[1,{}],"a/b":{"~":null},"a":[],"é":"x"}`)
	var got []string
	for _, f := range Feuilles(v, "") {
		got = append(got, f.Pointeur+"="+Compact(f.Valeur))
	}
	want := "/a=[] /a~1b/~0=null /b/0=1 /b/1={} /é=\"x\""
	if strings.Join(got, " ") != want {
		t.Errorf("feuilles : %s", strings.Join(got, " "))
	}
	if f := Feuilles(valeur(t, `"x"`), ""); len(f) != 1 || f[0].Pointeur != "" {
		t.Errorf("racine scalaire : %+v", f)
	}
}
