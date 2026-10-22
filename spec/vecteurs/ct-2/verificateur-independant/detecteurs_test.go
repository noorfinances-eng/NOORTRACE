package main

// Détecteurs de CT-2 §10.3 : exemples valides et invalides imprimés par la
// spécification (10.3.2 à 10.3.6), IBAN des onze pays de la table construits
// par la méthode de génération de 10.3.2 (98 − reste), frontières, séparateurs.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func rediger(t *testing.T, d string, s string) (string, int) {
	t.Helper()
	p := &Politique{}
	return p.RedigerTexte("remplacer", Detecteur{Type: d}, s)
}

func attendreRedaction(t *testing.T, d, entree, sortie string) {
	t.Helper()
	got, _ := rediger(t, d, entree)
	if got != sortie {
		t.Errorf("%s(%q) = %q, attendu %q", d, entree, got, sortie)
	}
}

// genererIBAN construit un IBAN valide : clé = 98 − (BBAN ‖ CC ‖ « 00 ») mod 97.
func genererIBAN(cc string, l int) string {
	bban := strings.Repeat("0123456789", 4)[:l-4]
	r := ResteIBAN(cc + "00" + bban)
	return fmt.Sprintf("%s%02d%s", cc, 98-r, bban)
}

func TestIBANExemplesSpecification(t *testing.T) {
	if r := ResteIBAN("CH9300762011623852957"); r != 1 {
		t.Errorf("CH9300762011623852957 : reste %d", r)
	}
	if r := ResteIBAN("CH9300762011623852958"); r != 28 {
		t.Errorf("CH9300762011623852958 : reste %d, attendu 28 (10.3.2)", r)
	}
	if r := ResteIBAN("GB19LOYD30961700709943"); r != 1 {
		t.Errorf("GB19LOYD30961700709943 (exemple Pay.UK) : reste %d", r)
	}
	attendreRedaction(t, "iban", "CH9300762011623852957", "[REDIGE:iban]")
	attendreRedaction(t, "iban", "IBAN CH93 0076 2011 6238 5295 7, merci", "IBAN [REDIGE:iban], merci")
	attendreRedaction(t, "iban", "CH9300762011623852958", "CH9300762011623852958")
	attendreRedaction(t, "iban", "GB19LOYD30961700709943", "[REDIGE:iban]")
	attendreRedaction(t, "iban", "ch9300762011623852957", "ch9300762011623852957")             // minuscules : non détecté
	attendreRedaction(t, "iban", "XCH9300762011623852957", "XCH9300762011623852957")           // frontière avant
	attendreRedaction(t, "iban", "CH9300762011623852957A", "CH9300762011623852957A")           // frontière après
	attendreRedaction(t, "iban", "CH93  0076 2011 6238 5295 7", "CH93  0076 2011 6238 5295 7") // séparateurs consécutifs
	attendreRedaction(t, "iban", "CH93 0076 2011 6238 5295 7", "[REDIGE:iban]")                // SEP : U+00A0, U+202F
	attendreRedaction(t, "iban", "CH93-0076-2011-6238-5295-7", "CH93-0076-2011-6238-5295-7")   // le trait d'union n'est pas admis
	attendreRedaction(t, "iban", "(CH9300762011623852957)", "([REDIGE:iban])")
}

func TestIBANOnzePays(t *testing.T) {
	if len(LongueursIBAN) != 11 {
		t.Fatalf("%d pays dans la table, attendu 11", len(LongueursIBAN))
	}
	for cc, l := range LongueursIBAN {
		iban := genererIBAN(cc, l)
		if len(iban) != l || ResteIBAN(iban) != 1 {
			t.Errorf("%s : %s (reste %d)", cc, iban, ResteIBAN(iban))
		}
		attendreRedaction(t, "iban", "x "+iban+" y", "x [REDIGE:iban] y")
		// un caractère de moins ou de plus : non détecté
		attendreRedaction(t, "iban", iban[:l-1], iban[:l-1])
		attendreRedaction(t, "iban", iban+"0", iban+"0")
	}
	// pays hors table (Norvège), clé valide par la même méthode : non détecté (10.8)
	no := genererIBAN("NO", 15)
	if ResteIBAN(no) != 1 {
		t.Fatal(no)
	}
	attendreRedaction(t, "iban", no, no)
}

func TestAVS(t *testing.T) {
	if !CleAVSValide("7561234567897") || CleAVSValide("7561234567890") {
		t.Error("clé AVS de l'exemple de l'ordonnance (10.3.3)")
	}
	attendreRedaction(t, "avs", "756.1234.5678.97", "[REDIGE:avs]")
	attendreRedaction(t, "avs", "756.1234.5678.90", "756.1234.5678.90")
	attendreRedaction(t, "avs", "7561234567897", "[REDIGE:avs]")
	attendreRedaction(t, "avs", "assuré 756 1234 5678 97.", "assuré [REDIGE:avs].")
	attendreRedaction(t, "avs", "7561234.5678.97", "[REDIGE:avs]")        // séparateurs indépendamment présents
	attendreRedaction(t, "avs", "756.1234 5678.97", "756.1234 5678.97")   // séparateurs différents
	attendreRedaction(t, "avs", "756.1234.5678.977", "756.1234.5678.977") // frontière après
	attendreRedaction(t, "avs", "A756.1234.5678.97", "A756.1234.5678.97") // frontière avant
	attendreRedaction(t, "avs", "756..1234.5678.97", "756..1234.5678.97") // séparateur non isolé
}

func TestCarte(t *testing.T) {
	if !LuhnValide("378282246310005") || LuhnValide("378282246310006") {
		t.Error("Luhn (10.3.4)")
	}
	attendreRedaction(t, "carte", "378282246310005", "[REDIGE:carte]")
	attendreRedaction(t, "carte", "carte 3782 822463 10005.", "carte [REDIGE:carte].")
	attendreRedaction(t, "carte", "378282246310006", "378282246310006")
	attendreRedaction(t, "carte", "3782-822463-10005", "[REDIGE:carte]")
	attendreRedaction(t, "carte", "3782.822463.10005", "3782.822463.10005")   // le point n'est pas admis
	attendreRedaction(t, "carte", "3782  822463 10005", "3782  822463 10005") // séparateurs consécutifs : suites trop courtes
	attendreRedaction(t, "carte", "X378282246310005", "X378282246310005")     // frontière avant
	attendreRedaction(t, "carte", "37828224631000", "37828224631000")         // 14 chiffres, Luhn faux
	// longueurs : 12 et 19 chiffres admis, 11 et 20 non
	for _, n := range []string{"000000000000", "0000000000000000000"} {
		attendreRedaction(t, "carte", n, "[REDIGE:carte]")
	}
	for _, n := range []string{"00000000000", "00000000000000000000"} {
		attendreRedaction(t, "carte", n, n)
	}
}

func TestEmail(t *testing.T) {
	attendreRedaction(t, "email", "j.dupont@example.ch", "[REDIGE:email]")
	attendreRedaction(t, "email", "écrire à j.dupont@example.ch ; merci", "écrire à [REDIGE:email] ; merci")
	// 10.3.5 : un « . » ou un « - » final n'appartient pas au domaine (point
	// final d'une phrase)
	attendreRedaction(t, "email", "écrire à j.dupont@example.ch.", "écrire à [REDIGE:email].")
	attendreRedaction(t, "email", "j@example.ch- suite", "[REDIGE:email]- suite")
	l64 := strings.Repeat("a", 64)
	l65 := strings.Repeat("a", 65)
	attendreRedaction(t, "email", l64+"@example.ch", "[REDIGE:email]")
	attendreRedaction(t, "email", l65+"@example.ch", l65+"@example.ch")
	attendreRedaction(t, "email", ".j@example.ch", ".j@example.ch") // Dot-string : pas de « . » initial
	attendreRedaction(t, "email", "a..b@example.ch", "a..b@example.ch")
	attendreRedaction(t, "email", "j@example.c", "j@example.c") // dernier label d'une lettre
	attendreRedaction(t, "email", "j@-example.ch", "j@-example.ch")
	attendreRedaction(t, "email", "a@b.ch et c@d.fr", "[REDIGE:email] et [REDIGE:email]")
	cs := DetecterEmail([]rune("x J.Dupont@EXAMPLE.CH y"))
	if len(cs) != 1 || cs[0].Valeur != "J.Dupont@example.ch" {
		t.Errorf("valeur du pseudonyme : %+v", cs)
	}
	// coût linéaire : lectures bornées autour de chaque « @ »
	debut := time.Now()
	DetecterEmail([]rune(strings.Repeat("a@", 64000)))
	DetecterEmail([]rune(strings.Repeat(strings.Repeat("a", 60)+"@", 2000)))
	if d := time.Since(debut); d > 2*time.Second {
		t.Errorf("détecteur email trop lent : %v", d)
	}
}

func TestTelephone(t *testing.T) {
	attendreRedaction(t, "telephone", "+41 44 123 45 67", "[REDIGE:telephone]")
	cs := DetecterTelephone([]rune("au +41 44 123 45 67 ou"))
	if len(cs) != 1 || cs[0].Valeur != "+41441234567" {
		t.Errorf("forme normalisée : %+v", cs)
	}
	attendreRedaction(t, "telephone", "+123456789012345", "[REDIGE:telephone]") // 15 chiffres
	attendreRedaction(t, "telephone", "+1234567890123456", "+1234567890123456") // 16 chiffres
	attendreRedaction(t, "telephone", "+1234567", "+1234567")                   // 7 chiffres
	attendreRedaction(t, "telephone", "+41 (0)44 123 45 67", "[REDIGE:telephone]")
	attendreRedaction(t, "telephone", "+41-44.123 45 67.", "[REDIGE:telephone].")
	attendreRedaction(t, "telephone", "044 123 45 67", "044 123 45 67") // forme nationale : non détectée
	attendreRedaction(t, "telephone", "+0441234567", "+0441234567")     // premier chiffre 0
	attendreRedaction(t, "telephone", "x+41441234567", "x+41441234567") // frontière avant
	attendreRedaction(t, "telephone", "+41441234567x", "+41441234567x") // frontière après
	// EX-10.9 : la fin d'une correspondance vaut frontière pour la suivante
	attendreRedaction(t, "telephone", "+41441234567+41441234567", "[REDIGE:telephone][REDIGE:telephone]")
	attendreRedaction(t, "telephone", "+41 44 123 45 67 (9h-17h)", "[REDIGE:telephone] (9h-17h)")
	attendreRedaction(t, "telephone", "+33 1 23 45 67 89 (2)", "[REDIGE:telephone] (2)")
	attendreRedaction(t, "telephone", "+41 (44 123 45 67", "+41 (44 123 45 67")
}

// Les cinq détecteurs nommés ne correspondent jamais à un jeton (EX-10.15).
func TestJetonsNonDetectes(t *testing.T) {
	for _, d := range []string{"iban", "avs", "carte", "email", "telephone"} {
		for _, j := range []string{"[REDIGE:iban]", "[PSEUDO:email:0123456789ab]", "[REDIGE:prompt-systeme]"} {
			if got, n := rediger(t, d, j); n != 0 || got != j {
				t.Errorf("%s a modifié le jeton %s", d, j)
			}
		}
	}
}

// Règles : champ, supprimer, path, motif nommé, portées, outils <alias>__*.
func TestReglesEtActions(t *testing.T) {
	doc, err := ParseJSON([]byte(`{"version":0,"name":"essai","pseudonym_key":null,
	  "named_patterns":{"numero-sinistre":{"pattern":"\\b20[0-9]{2}-[0-9]{5}\\b"}},
	  "rules":[
	    {"id":"montant","scopes":["arguments"],"tools":["sap__*"],"path":"/amount","detectors":[{"type":"champ","label":"montant"}],"action":{"kind":"remplacer"}},
	    {"id":"note","scopes":["arguments"],"tools":"*","path":"/notes","detectors":[{"type":"champ","label":"note"}],"action":{"kind":"supprimer"}},
	    {"id":"liste","scopes":["arguments"],"tools":"*","path":"/liste/1","detectors":[{"type":"champ","label":"element"}],"action":{"kind":"supprimer"}},
	    {"id":"sinistre","scopes":["arguments","resultat"],"tools":"*","detectors":[{"type":"regex","name":"numero-sinistre"}],"action":{"kind":"remplacer"}}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	pol, mq := ChargerPolitique(doc)
	if len(mq) > 0 {
		t.Fatal(mq)
	}
	v, _ := ParseJSON([]byte(`{"amount":7400.5,"notes":"x","liste":["a","b","c"],"claim":"dossier 2026-77812"}`))
	p, res, err := PieceRedigeeJSON(pol, "arguments", "sap__payments.create", v)
	if err != nil {
		t.Fatal(err)
	}
	attendu := `{"amount":"[REDIGE:montant]","claim":"dossier [REDIGE:numero-sinistre]","liste":["a","[REDIGE:element]","c"]}`
	if string(p.Octets) != attendu || !p.Redigee {
		t.Errorf("obtenu %s", p.Octets)
	}
	if len(res.Decomptes) != 4 {
		t.Errorf("décomptes : %+v", res.Decomptes)
	}
	// autre alias : la règle « montant » ne s'applique pas
	p, _, _ = PieceRedigeeJSON(pol, "arguments", "crm__x", v)
	if !strings.Contains(string(p.Octets), `"amount":7400.5`) {
		t.Errorf("règle sap__* appliquée à crm__x : %s", p.Octets)
	}
	// pointeur sans cible : règle sans effet, sans erreur
	w, _ := ParseJSON([]byte(`{"autre":1}`))
	p, res, _ = PieceRedigeeJSON(pol, "arguments", "sap__payments.create", w)
	if string(p.Octets) != `{"autre":1}` || p.Redigee || len(res.Notes) == 0 {
		t.Errorf("pointeur sans cible : %s %+v", p.Octets, res)
	}
	// idempotence
	q, _ := ParseJSON([]byte(attendu))
	p2, _, _ := PieceRedigeeJSON(pol, "arguments", "sap__payments.create", q)
	if string(p2.Octets) != attendu || p2.Redigee {
		t.Errorf("idempotence : %s", p2.Octets)
	}
	// RFC 6901 : ~1 décodé avant ~0
	j, _ := DecouperPointeur("/a~1b/m~0n/~01")
	if strings.Join(j, "|") != "a/b|m~n|~1" {
		t.Errorf("pointeur : %v", j)
	}
}
