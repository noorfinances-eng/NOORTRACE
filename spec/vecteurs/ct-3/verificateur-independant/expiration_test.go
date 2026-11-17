package main

// Essais du complément du 2026-11-16 de CT-3 (décision du porteur), écrits
// depuis le seul texte : opération expirer (EX-13.10, point 5 ; EX-13.17,
// « Expiration »), identifiant d'une entrée créée selon la convention des
// vecteurs (A.10), défi présenté retiré (EX-13.13 ; EX-13.15, pas 4), rejeu
// d'expirer et des inscriptions d'une entrée expirée (EX-13.19, point 6) et
// pas de trace sans échéance (A.10).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Valeurs écrites ici depuis le texte, sans reprendre les constantes du
// module : défaut de registration_entry_ttl_ms (10.3 : 2 592 000 000) et sa
// borne basse (86 400 000), employée par le rejeu (EX-13.19, point 6).
const (
	essaiTTLEntree  = 2592000000
	essaiBorneBasse = 86400000
	essaiAdmin      = "oidc https://idp.assureur-demo.example admin-1"
)

func essaiIdentite(nom string) string { return "oidc https://idp.assureur-demo.example " + nom }

// essaiAnnuaire part d'un annuaire vide de l'organisation des vecteurs.
type essaiAnnuaire struct {
	t *testing.T
	e *EtatAnnuaire
	k *Constantes
	n int
}

func nouvelEssaiAnnuaire(t *testing.T) *essaiAnnuaire {
	t.Helper()
	sch := schemasConsoleTest(t)
	k, err := CalculerConstantes()
	if err != nil {
		t.Fatal(err)
	}
	doc := valeur(t, `{"version":0,"org":"assureur-demo","org_id":"`+k.OrgID+`","console_origin":"https://console.assureur-demo.example","registration_ttl_ms":600000,"administrators":["`+essaiAdmin+`"],"revision":0,"updated_at":null,"entries":[],"operations":[]}`)
	return &essaiAnnuaire{t: t, e: &EtatAnnuaire{Doc: doc, Sch: sch}, k: k}
}

func (s *essaiAnnuaire) id() string { return identifiantA10(s.e) }

func (s *essaiAnnuaire) preparer(sess, adr string, at Instant) IssueOperation {
	s.n++
	return s.e.Appliquer("preparer_inscription", Objet("session_identity", Chaine(sess), "address", Chaine(adr)), at, fmt.Sprintf("%032x", s.n), s.id, ModeService)
}

// requeteSignee rend la requête inscrire du défi, signée par la clé du
// compte signataire.
func (s *essaiAnnuaire) requeteSignee(sess, adr, msg, signataire string) *Value {
	sig, err := SignerMessage(s.k.Prives[signataire], []byte(msg))
	if err != nil {
		s.t.Fatal(err)
	}
	return Objet("session_identity", Chaine(sess), "address", Chaine(adr), "message", Chaine(msg), "signature", Chaine(sig))
}

func (s *essaiAnnuaire) inscrireReq(req *Value, at Instant) IssueOperation {
	return s.e.Appliquer("inscrire", req, at, "", s.id, ModeService)
}

// inscrire prépare puis présente le défi, signé par l'adresse elle-même.
func (s *essaiAnnuaire) inscrire(sess, adr string, at Instant) IssueOperation {
	s.t.Helper()
	p := s.preparer(sess, adr, at)
	if !p.Accepte {
		s.t.Fatalf("préparation %s %s : %s", sess, adr, p.Raison)
	}
	r := s.inscrireReq(s.requeteSignee(sess, adr, p.Reponse.Get("message").S(), adr), at+30000)
	if !r.Accepte {
		s.t.Fatalf("inscription %s %s : %s", sess, adr, r.Raison)
	}
	return r
}

func (s *essaiAnnuaire) operer(methode, req string, at Instant) IssueOperation {
	return s.e.Appliquer(methode, valeur(s.t, req), at, "", s.id, ModeService)
}

func (s *essaiAnnuaire) expirer(req string, at Instant) IssueOperation {
	return s.operer("expirer", req, at)
}

func creeLe(t *testing.T, e *EtatAnnuaire, id string) Instant {
	t.Helper()
	x := e.entreeParID(id)
	if x == nil {
		t.Fatalf("entrée %s absente", id)
	}
	c, err := LireInstant(x.Get("created_at").S())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// EX-13.17, « Expiration » : ordre des refus requete_invalide,
// entree_inconnue, etat_incompatible ; effet sur entries, operations,
// revision, updated_at et les défis ; aucune réponse.
func TestExpirerOperation(t *testing.T) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T08:00:00.000Z")
	s.inscrire(essaiIdentite("approbateur-1"), k.Comptes[1], t0)
	s.inscrire(essaiIdentite("approbateur-2"), k.Comptes[2], t0+600000)
	if r := s.operer("valider", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0002","address":"`+k.Comptes[2]+`"}`, t0+1200000); !r.Accepte {
		t.Fatalf("validation : %s", r.Raison)
	}
	if r := s.operer("lier_demandeur", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","launched_by":"u.dupont@assureur-demo.example"}`, t0+1500000); !r.Accepte {
		t.Fatalf("alias : %s", r.Raison)
	}
	// Un défi en cours, qui ne doit pas changer.
	if r := s.preparer(essaiIdentite("approbateur-3"), k.Comptes[3], t0+1600000); !r.Accepte {
		t.Fatalf("défi : %s", r.Raison)
	}
	c1 := creeLe(t, s.e, "apb-0001")
	echeance := c1 + essaiTTLEntree
	// Forme : exactement { "entry" }, identifiant de $defs/identifiant_entree,
	// sans identité de session ; avant entree_inconnue.
	long := "apb-" + strings.Repeat("a", 125)
	for _, req := range []string{
		`{}`,
		`{"entry":"apb-0001","session_identity":"` + essaiAdmin + `"}`,
		`{"entry":"apb-9999","x":1}`,
		`{"entry":"APB-0001"}`,
		`{"entry":1}`,
		`{"entry":"` + long + `"}`,
	} {
		if r := s.expirer(req, echeance); r.Accepte || r.Raison != "requete_invalide" {
			t.Errorf("forme %s : accepté %v, raison %q, attendu requete_invalide", req, r.Accepte, r.Raison)
		}
	}
	if r := s.expirer(`{"entry":"apb-9999"}`, echeance); r.Raison != "entree_inconnue" {
		t.Errorf("entrée inconnue : %q", r.Raison)
	}
	// Une milliseconde avant l'échéance : etat_incompatible.
	if r := s.expirer(`{"entry":"apb-0001"}`, echeance-1); r.Accepte || r.Raison != "etat_incompatible" {
		t.Errorf("avant l'échéance : accepté %v, raison %q", r.Accepte, r.Raison)
	}
	// Entrée validée : jamais, même bien après l'échéance.
	if r := s.expirer(`{"entry":"apb-0002"}`, echeance+10*essaiTTLEntree); r.Accepte || r.Raison != "etat_incompatible" {
		t.Errorf("entrée validée : accepté %v, raison %q", r.Accepte, r.Raison)
	}
	rev, _ := EntierJSON(s.e.Doc.Get("revision"))
	defis := len(s.e.Defis)
	r := s.expirer(`{"entry":"apb-0001"}`, echeance)
	if !r.Accepte || r.Raison != "" {
		t.Fatalf("à l'échéance exacte : accepté %v, raison %q", r.Accepte, r.Raison)
	}
	if r.Reponse == nil || !r.Reponse.IsNull() {
		t.Errorf("réponse : %s, attendu null", Compact(r.Reponse))
	}
	if r.NouvelleEntree {
		t.Errorf("expirer ne crée pas d'entrée")
	}
	if s.e.entreeParID("apb-0001") != nil {
		t.Errorf("apb-0001 encore présente")
	}
	if got, _ := EntierJSON(s.e.Doc.Get("revision")); got != rev+1 {
		t.Errorf("revision %d, attendu %d", got, rev+1)
	}
	if got := s.e.Doc.Get("updated_at").S(); got != echeance.String() {
		t.Errorf("updated_at %s, attendu %s", got, echeance)
	}
	ops := s.e.Doc.Get("operations").Arr
	attendu := fmt.Sprintf(`{"seq":%d,"at":"%s","op":"expirer","by":"service","entry":"apb-0001","address":null,"launched_by":null,"reason":null,"administrators":null}`, rev+1, echeance)
	if got := Compact(ops[len(ops)-1]); got != attendu {
		t.Errorf("opération inscrite :\n %s\nattendu\n %s", got, attendu)
	}
	if len(s.e.Defis) != defis {
		t.Errorf("défis changés : %d, puis %d", defis, len(s.e.Defis))
	}
	// Déjà retirée : entree_inconnue.
	if r := s.expirer(`{"entry":"apb-0001"}`, echeance+60000); r.Raison != "entree_inconnue" {
		t.Errorf("entrée retirée : %q", r.Raison)
	}
	// L'adresse jamais validée, l'alias et l'identité sont libérés ;
	// l'identifiant n'est jamais réattribué (compteur des vecteurs, A.10).
	if r := s.inscrire(essaiIdentite("u.martin"), k.Comptes[1], echeance+600000); r.Reponse.Get("entry").S() != "apb-0003" {
		t.Errorf("adresse libérée : entrée %s, attendu apb-0003", r.Reponse.Get("entry").S())
	}
	if r := s.inscrire(essaiIdentite("approbateur-1"), k.Comptes[4], echeance+1200000); r.Reponse.Get("entry").S() != "apb-0004" {
		t.Errorf("réinscription : entrée %s, attendu apb-0004", r.Reponse.Get("entry").S())
	}
	if r := s.operer("lier_demandeur", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0004","launched_by":"u.dupont@assureur-demo.example"}`, echeance+1800000); !r.Accepte {
		t.Errorf("alias lié de nouveau : %s", r.Raison)
	}
	// Une entrée désactivée jamais validée expire aussi.
	c3 := creeLe(t, s.e, "apb-0003")
	if r := s.operer("desactiver", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0003","reason":"essai"}`, echeance+2400000); !r.Accepte {
		t.Fatalf("désactivation : %s", r.Raison)
	}
	if r := s.expirer(`{"entry":"apb-0003"}`, c3+essaiTTLEntree); !r.Accepte {
		t.Errorf("entrée désactivée jamais validée : %q", r.Raison)
	}
	// Une entrée dont l'adresse validée a été révoquée n'expire pas
	// (validated_at non nul).
	if r := s.operer("revoquer", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0002","address":"`+k.Comptes[2]+`","reason":"essai"}`, echeance+3000000); !r.Accepte {
		t.Fatalf("révocation : %s", r.Raison)
	}
	if r := s.expirer(`{"entry":"apb-0002"}`, echeance+20*essaiTTLEntree); r.Raison != "etat_incompatible" {
		t.Errorf("entrée validée puis révoquée : %q", r.Raison)
	}
}

// A.10 : identifiant compteur = nombre d'entrées jamais créées (entrées de
// l'annuaire et opérations expirer de operations) augmenté de un.
func TestIdentifiantCompteurAvecExpirations(t *testing.T) {
	doc := valeur(t, `{"entries":[{"id":"apb-0002"},{"id":"apb-0004"}],"operations":[`+
		`{"op":"inscrire","entry":"apb-0001"},{"op":"expirer","entry":"apb-0001"},`+
		`{"op":"inscrire","entry":"apb-0002"},{"op":"inscrire","entry":"apb-0003"},{"op":"expirer","entry":"apb-0003"},`+
		`{"op":"inscrire","entry":"apb-0004"},{"op":"changer_administrateurs","entry":null}]}`)
	if got := identifiantA10(&EtatAnnuaire{Doc: doc}); got != "apb-0005" {
		t.Errorf("identifiant %s, attendu apb-0005", got)
	}
	vide := valeur(t, `{"entries":[{"id":"apb-0001"},{"id":"apb-0002"}],"operations":[]}`)
	if got := identifiantA10(&EtatAnnuaire{Doc: vide}); got != "apb-0003" {
		t.Errorf("sans expiration : %s, attendu apb-0003", got)
	}
}

// EX-13.13 et EX-13.15, pas 4 : dès qu'un inscrire présente un défi, accepté
// ou refusé, le défi est retiré ; il ne compte plus dans les bornes ; son
// nonce présenté de nouveau est inconnu. Un refus avant le pas 4 ne touche
// pas aux défis.
func TestDefiPresenteRetire(t *testing.T) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T12:00:00.000Z")
	p1 := essaiIdentite("approbateur-1")
	msgs := map[int]string{}
	for i := 1; i <= 4; i++ {
		r := s.preparer(p1, k.Comptes[i], t0+Instant(i*10000))
		if !r.Accepte {
			t.Fatalf("défi %d : %s", i, r.Raison)
		}
		msgs[i] = r.Reponse.Get("message").S()
	}
	autre := func(i int) string { return fmt.Sprintf("0xabababababababababababababababababab%04d", i) }
	if r := s.preparer(p1, autre(5), t0+50000); r.Raison != "limite_annuaire" {
		t.Fatalf("cinquième défi : %q, attendu limite_annuaire", r.Raison)
	}
	// Refus avant le pas 4 (message_invalide) : le défi reste tenu.
	casse := strings.Replace(msgs[1], "Nonce: ", "Nonce:  ", 1)
	if r := s.inscrireReq(s.requeteSignee(p1, k.Comptes[1], casse, k.Comptes[1]), t0+55000); r.Raison != "message_invalide" {
		t.Fatalf("message altéré : %q", r.Raison)
	}
	if len(s.e.Defis) != 4 {
		t.Errorf("refus avant le pas 4 : %d défis, attendu 4", len(s.e.Defis))
	}
	// Inscription acceptée : son défi est retiré, un cinquième est admis.
	ok := s.requeteSignee(p1, k.Comptes[1], msgs[1], k.Comptes[1])
	if r := s.inscrireReq(ok, t0+60000); !r.Accepte {
		t.Fatalf("inscription : %s", r.Raison)
	}
	n1 := s.e.Defis
	if ch, _ := AnalyserMessageInscription(msgs[1]); s.e.defiParNonce(ch.Nonce) != nil {
		t.Errorf("défi accepté encore tenu (%d défis)", len(n1))
	}
	if r := s.preparer(p1, autre(5), t0+70000); !r.Accepte {
		t.Errorf("cinquième défi après l'inscription : %q", r.Raison)
	}
	// Inscription refusée après le pas 4 (signature d'une autre clé) : son
	// défi est retiré aussi.
	if r := s.inscrireReq(s.requeteSignee(p1, k.Comptes[2], msgs[2], k.Comptes[3]), t0+80000); r.Raison != "signature_invalide" {
		t.Fatalf("signature d'une autre clé : %q", r.Raison)
	}
	if ch, _ := AnalyserMessageInscription(msgs[2]); s.e.defiParNonce(ch.Nonce) != nil {
		t.Errorf("défi refusé après le pas 4 encore tenu")
	}
	if r := s.preparer(p1, autre(6), t0+90000); !r.Accepte {
		t.Errorf("sixième défi : %q", r.Raison)
	}
	if r := s.preparer(p1, autre(7), t0+100000); r.Raison != "limite_annuaire" {
		t.Errorf("quatre défis non présentés de nouveau : %q, attendu limite_annuaire", r.Raison)
	}
	// Le défi présenté une seconde fois : nonce_inconnu.
	if r := s.inscrireReq(ok, t0+110000); r.Raison != "nonce_inconnu" {
		t.Errorf("défi présenté deux fois : %q, attendu nonce_inconnu", r.Raison)
	}
}

// EX-13.13 : les bornes ne comptent que des défis non expirés et non
// présentés ; la vérification seule (AN-3, inscriptions.json) rend toujours
// nonce_deja_utilise pour un défi fourni marqué présenté.
func TestBornesDefisNonPresentes(t *testing.T) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T12:00:00.000Z")
	p1 := essaiIdentite("approbateur-1")
	for i := 1; i <= 4; i++ {
		ch := ChampsInscription{Origin: "https://console.assureur-demo.example", Org: "assureur-demo", OrgID: k.OrgID, Identity: p1,
			Address: fmt.Sprintf("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd%04d", i), IssuedAt: t0.String(), ExpiresAt: (t0 + 600000).String(), Nonce: fmt.Sprintf("%032x", 100+i)}
		s.e.Defis = append(s.e.Defis, &Defi{Champs: ch, Utilise: true})
	}
	if r := s.preparer(p1, k.Comptes[1], t0+1000); !r.Accepte {
		t.Errorf("quatre défis présentés ne comptent pas : %q", r.Raison)
	}
	// Vérification seule : nonce_deja_utilise.
	msg := MessageInscription(s.e.Defis[0].Champs)
	req := Objet("session_identity", Chaine(p1), "address", Chaine(s.e.Defis[0].Champs.Address), "message", Chaine(msg), "signature", Chaine("0x"+strings.Repeat("11", 65)))
	if res := s.e.VerifierInscription(req, t0+2000, ModeService); res.Raison != "nonce_deja_utilise" {
		t.Errorf("vérification seule d'un défi présenté : %q, attendu nonce_deja_utilise", res.Raison)
	}
}

// essaiExport construit, par les opérations du service, l'annuaire final
// de la suite de la trace expiration-entree (A.10) : apb-0001 jamais
// validée, avec un alias, expirée à l'échéance ; apb-0002 validée ; le
// compte 1 réinscrit par u.martin (apb-0003), approbateur-1 réinscrit
// (apb-0004).
func essaiExport(t *testing.T) (*essaiAnnuaire, Instant) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T08:00:00.000Z")
	s.inscrire(essaiIdentite("approbateur-1"), k.Comptes[1], t0)
	s.inscrire(essaiIdentite("approbateur-2"), k.Comptes[2], t0+600000)
	if r := s.operer("valider", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0002","address":"`+k.Comptes[2]+`"}`, t0+1200000); !r.Accepte {
		t.Fatalf("validation : %s", r.Raison)
	}
	if r := s.operer("lier_demandeur", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","launched_by":"u.dupont@assureur-demo.example"}`, t0+1500000); !r.Accepte {
		t.Fatalf("alias : %s", r.Raison)
	}
	c1 := creeLe(t, s.e, "apb-0001")
	if r := s.expirer(`{"entry":"apb-0001"}`, c1+essaiTTLEntree); !r.Accepte {
		t.Fatalf("expiration : %q", r.Raison)
	}
	s.inscrire(essaiIdentite("u.martin"), k.Comptes[1], c1+essaiTTLEntree+600000)
	s.inscrire(essaiIdentite("approbateur-1"), k.Comptes[4], c1+essaiTTLEntree+1200000)
	return s, c1
}

func ecartsTexte(ec []EcartExport) string {
	var l []string
	for _, x := range ec {
		p := "null"
		if x.Pointeur != nil {
			p = *x.Pointeur
		}
		l = append(l, x.Code+" "+p)
	}
	return strings.Join(l, ";")
}

// EX-13.19, point 6 : expirer se rejoue (by service, entrée présente, aucune
// adresse validée, at ≥ created_at + 86 400 000) ; l'inscription d'une entrée
// expirée se rejoue sans preuve ; un identifiant déjà créé plus haut, même
// expiré, ne se rejoue pas.
func TestRejeuExpiration(t *testing.T) {
	s, c1 := essaiExport(t)
	sch := s.e.Sch
	doc := s.e.Doc
	if ec := VerifierAnnuaireExporte(sch, doc); len(ec) != 0 {
		t.Fatalf("annuaire avec expiration : %s", ecartsTexte(ec))
	}
	ops := doc.Get("operations").Arr
	ix := -1
	for j, op := range ops {
		if op.Get("op").S() == "expirer" {
			ix = j
		}
	}
	if ix != 4 {
		t.Fatalf("opération expirer en %d, attendue en 4", ix)
	}
	// Borne basse incluse : à created_at + 86 400 000, sans écart.
	borne := Copier(doc)
	poser(borne.Get("operations").Arr[ix], "at", Chaine((c1 + essaiBorneBasse).String()))
	if ec := VerifierAnnuaireExporte(sch, borne); len(ec) != 0 {
		t.Errorf("expiration à la borne basse : %s", ecartsTexte(ec))
	}
	// Sous la borne basse d'une milliseconde : ne se rejoue pas.
	sous := Copier(doc)
	poser(sous.Get("operations").Arr[ix], "at", Chaine((c1 + essaiBorneBasse - 1).String()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, sous)); got != "operations_incoherentes /operations/4" {
		t.Errorf("expiration sous la borne basse : %q", got)
	}
	// Expiration d'une entrée validée, ajoutée en dernier.
	val := Copier(doc)
	vops := val.Get("operations")
	der := vops.Arr[len(vops.Arr)-1]
	at, _ := LireInstant(der.Get("at").S())
	at += 60000
	n := len(vops.Arr) + 1
	vops.Arr = append(vops.Arr, valeur(t, fmt.Sprintf(`{"seq":%d,"at":"%s","op":"expirer","by":"service","entry":"apb-0002","address":null,"launched_by":null,"reason":null,"administrators":null}`, n, at)))
	poser(val, "revision", Entier(int64(n)))
	poser(val, "updated_at", Chaine(at.String()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, val)); got != fmt.Sprintf("operations_incoherentes /operations/%d", n-1) {
		t.Errorf("expiration d'une entrée validée : %q", got)
	}
	// Expiration d'une entrée absente du rejeu.
	abs := Copier(doc)
	aops := abs.Get("operations")
	aops.Arr = append(aops.Arr, valeur(t, fmt.Sprintf(`{"seq":%d,"at":"%s","op":"expirer","by":"service","entry":"apb-0001","address":null,"launched_by":null,"reason":null,"administrators":null}`, n, at)))
	poser(abs, "revision", Entier(int64(n)))
	poser(abs, "updated_at", Chaine(at.String()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, abs)); got != fmt.Sprintf("operations_incoherentes /operations/%d", n-1) {
		t.Errorf("expiration d'une entrée déjà retirée : %q", got)
	}
	// Identifiant d'entrée expirée réattribué : l'entrée d'u.martin porte
	// apb-0001 au lieu d'apb-0003.
	re := Copier(doc)
	for _, x := range re.Get("entries").Arr {
		if x.Get("id").S() == "apb-0003" {
			poser(x, "id", Chaine("apb-0001"))
		}
	}
	k5 := -1
	for j, op := range re.Get("operations").Arr {
		if op.Get("entry").S() == "apb-0003" {
			poser(op, "entry", Chaine("apb-0001"))
			if k5 < 0 {
				k5 = j
			}
		}
	}
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, re)); got != fmt.Sprintf("operations_incoherentes /operations/%d", k5) {
		t.Errorf("identifiant réattribué : %q (opération %d attendue)", got, k5)
	}
	// Sans l'opération expirer du journal, l'inscription d'apb-0001 exige sa
	// preuve, absente du document.
	sans := Copier(doc)
	sops := sans.Get("operations")
	sops.Arr = append(sops.Arr[:ix:ix], sops.Arr[ix+1:]...)
	for j, op := range sops.Arr {
		poser(op, "seq", Entier(int64(j+1)))
	}
	poser(sans, "revision", Entier(int64(len(sops.Arr))))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, sans)); got != "operations_incoherentes /operations/0" {
		t.Errorf("inscription sans preuve ni expiration : %q", got)
	}
}

// A.10 : « aucun autre pas d'une trace n'a lieu à une échéance » ; avant un
// pas expirer accepté, l'entrée du pas est la seule échue. Une trace dont un
// pas du canal tombe à l'échéance d'une entrée est relevée.
func TestTraceSansEcheance(t *testing.T) {
	src := filepath.Join("..", "annuaire", "traces", "expiration-entree.json")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	tr, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	// Les six premiers pas, le sixième (lier_demandeur) déplacé à
	// l'échéance exacte d'apb-0001 : ses attendus ne changent pas.
	steps := tr.Get("steps")
	steps.Arr = steps.Arr[:6]
	c1, _ := LireInstant("2026-11-10T08:00:30.000Z")
	poser(steps.Arr[5], "at", Chaine((c1 + essaiTTLEntree).String()))
	poser(tr, "id", Chaine("echeance-non-traitee"))
	racine := monterRacineCT3(t, []string{"annuaire", filepath.Join("annuaire", "traces")}, nil)
	texte, err := Stringify2(tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(racine, "annuaire", "traces", "echeance-non-traitee.json"), []byte(texte+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rap := VerifierVecteurs(racine)
	releve, publie := false, 0
	for _, c := range rap.Comparaisons {
		if !strings.Contains(c.Grandeur, "échue") {
			continue
		}
		switch {
		case strings.HasPrefix(c.Vecteur, "annuaire/traces/echeance-non-traitee.json pas 6 "):
			releve = releve || !c.Concorde
		case strings.HasPrefix(c.Vecteur, "annuaire/traces/expiration-entree.json "):
			publie++
			if !c.Concorde {
				t.Errorf("trace publiée : %s · %s : attendu %s, obtenu %s", c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
			}
		default:
			if strings.HasPrefix(c.Vecteur, "annuaire/traces/echeance-non-traitee.json") && !c.Concorde {
				t.Errorf("%s · %s : attendu %s, obtenu %s", c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
			}
		}
	}
	if !releve {
		t.Errorf("pas du canal à l'échéance d'apb-0001 non relevé")
	}
	if publie != 15 {
		t.Errorf("%d contrôles d'échéance sur la trace publiée, 15 attendus", publie)
	}
	for _, c := range rap.Comparaisons {
		if strings.HasPrefix(c.Vecteur, "annuaire/traces/echeance-non-traitee.json") && !c.Concorde && !strings.Contains(c.Grandeur, "échue") {
			t.Errorf("autre écart : %s · %s", c.Vecteur, c.Grandeur)
		}
	}
}
