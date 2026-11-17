package main

// Complément du 2026-11-16 de la révision 0.11 de CT-2 (décision du porteur) :
// un candidat plus court est éprouvé quand le plus long échoue (10.3.4 à
// 10.3.6), et les adresses d'exemple sont sous `ch.example` (10.3.5, 10.9).
// Un test par règle changée ; les exemples sont ceux que le texte imprime,
// complétés de cas qui isolent chaque clause de la règle.

import (
	"strings"
	"testing"
	"time"
)

// 10.3.4 `carte` : les sous-suites de groupes consécutifs d'une suite de
// chiffres sont éprouvées, par premier groupe de gauche à droite et, pour un
// même premier groupe, la plus longue d'abord ; la recherche reprend
// immédiatement après le candidat retenu, le reste de la suite compris.
func TestCarteSousSuitesDeGroupes(t *testing.T) {
	// exemples imprimés par 10.3.4
	attendreRedaction(t, "carte", "4111 1111 1111 1111 12/27", "[REDIGE:carte] 12/27")
	attendreRedaction(t, "carte", "4111-1111-1111-1111 123", "[REDIGE:carte] 123")
	attendreRedaction(t, "carte", "AB12 4111 1111 1111 1111", "AB12 [REDIGE:carte]")
	attendreRedaction(t, "carte", "1234 5678 9012", "1234 5678 9012")
	// cas obligatoire de l'annexe B.3 : carte précédée d'un groupe de chiffres
	attendreRedaction(t, "carte", "Réf. 12 4111 1111 1111 1111.", "Réf. 12 [REDIGE:carte].")
	// la suite entière est suivie d'une lettre (pas de frontière) : le
	// séparateur intérieur borde la sous-suite et vaut frontière
	attendreRedaction(t, "carte", "4111 1111 1111 1111 12a", "[REDIGE:carte] 12a")
	// la plus longue d'abord : la suite entière (19 chiffres) passe Luhn et
	// est retenue, et non sa sous-suite de 12 chiffres
	attendreRedaction(t, "carte", "000000 000000 0000000", "[REDIGE:carte]")
	// reprise juste après le candidat : le reste de la suite est examiné
	attendreRedaction(t, "carte", "4111 1111 1111 1111 4111 1111 1111 1111", "[REDIGE:carte] [REDIGE:carte]")
	// correspondance du premier au dernier chiffre du candidat ; N = ses chiffres
	cs := DetecterCarte([]rune("4111 1111 1111 1111 12/27"))
	if len(cs) != 1 || cs[0].Debut != 0 || cs[0].Fin != 19 || cs[0].Valeur != "4111111111111111" {
		t.Errorf("correspondance : %+v", cs)
	}
	// au plus huit candidats par premier groupe : coût linéaire (EX-10.23)
	debut := time.Now()
	DetecterCarte([]rune(strings.Repeat("1 ", 64000)))
	DetecterCarte([]rune(strings.Repeat("1234 ", 20000)))
	// reprise au milieu d'une longue suite : les groupes sont lus à mesure
	if n := len(DetecterCarte([]rune(strings.Repeat("4111 1111 1111 1111 ", 4000)))); n != 4000 {
		t.Errorf("%d correspondances, attendu 4000", n)
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Errorf("détecteur carte trop lent : %v", d)
	}
}

// 10.3.5 `email` : W = suite lue à gauche du « @ » sur 64 caractères au plus,
// L = plus longue fin Dot-string de W ; S = suite lue à droite sur 256
// caractères au plus, D = plus long préfixe de S qui est un domaine valide et
// qui est S entière (au plus 255 caractères) ou suivi dans S d'un « . » ou
// d'un « - ». Aucune frontière avant.
func TestEmailFinDotStringEtPrefixeDeDomaine(t *testing.T) {
	// exemples imprimés par 10.3.5
	attendreRedaction(t, "email", "export-jean.dupont@ch.example-1", "[REDIGE:email]-1")
	attendreRedaction(t, "email", "a..b@ch.example", "a..[REDIGE:email]")
	attendreRedaction(t, "email",
		"Lien : https://crm.ch.example/api/v1/clients/recherche?tri=nom&ordre=asc&page=1&filtre=actif&courriel=jean.dupont@ch.example",
		"Lien : https://crm.ch.example/api/v1/clients/rech[REDIGE:email]")
	attendreRedaction(t, "email", "j.@ch.example", "j.@ch.example")
	attendreRedaction(t, "email", "x@example", "x@example")
	// enregistrement à barres verticales (annexe B.3)
	attendreRedaction(t, "email",
		"DUPONT|Jean|1980-02-29|Rue-du-Lac-12|1003|Lausanne|VD|CH|client-premium|jean.dupont@ch.example",
		"DUPONT|Jean|1980-02[REDIGE:email]")
	// partie locale de 65 caractères : rédigée sur ses 64 derniers
	attendreRedaction(t, "email", strings.Repeat("a", 65)+"@ch.example", "a[REDIGE:email]")
	// fin Dot-string : un « . » initial de W est laissé en clair
	attendreRedaction(t, "email", ".j@ch.example", ".[REDIGE:email]")
	// plus long préfixe admissible : coupé au dernier « - » ou « . » qui
	// laisse un domaine valide. S = « a.example.invalid-f » a deux préfixes
	// admissibles, « a.example » (suivi d'un « . ») et « a.example.invalid »
	// (suivi d'un « - ») ; S entière ne l'est pas (dernier label
	// « invalid-f », qui n'est pas fait que de lettres). Le plus long est retenu :
	// le plus court laisserait « .invalid-f » en clair.
	attendreRedaction(t, "email", "j@a.example.invalid-f", "[REDIGE:email]-f")
	attendreRedaction(t, "email", "j@ch.example-1.x", "[REDIGE:email]-1.x")
	attendreRedaction(t, "email", "j@-ch.example", "j@-ch.example")
	// S lue sur 256 caractères : plus de 255, S entière n'est pas admise,
	// un préfixe suivi d'un « - » l'est
	long := "j@ch.example-" + strings.Repeat("x", 300)
	attendreRedaction(t, "email", long, "[REDIGE:email]-"+strings.Repeat("x", 300))
	// W bornée par la fin de la correspondance précédente : au premier « @ »,
	// S = « b.example.c » (dernier label d'une lettre) donne D = « b.example » ;
	// au second, W ne remonte pas au-delà de cette correspondance et vaut
	// « .c », d'où L = « c ». Sans la borne, W serait « b.example.c » et les
	// deux correspondances se chevaucheraient.
	attendreRedaction(t, "email", "a@b.example.c@d.invalid", "[REDIGE:email].[REDIGE:email]")
	// valeur du pseudonyme : partie locale telle quelle, domaine en minuscules
	cs := DetecterEmail([]rune("J.Dupont@CH.Example-1"))
	if len(cs) != 1 || cs[0].Debut != 0 || cs[0].Fin != 19 || cs[0].Valeur != "J.Dupont@ch.example" {
		t.Errorf("correspondance : %+v", cs)
	}
}

// 10.3.6 `telephone` : le candidat va jusqu'à la plus grande position `fin`
// du parcours dont le caractère est une frontière et qui laisse de 8 à 15
// chiffres (groupe compté s'il précède) ; aucun candidat sinon (reprise au
// séparateur).
func TestTelephoneRepriseAuSeparateur(t *testing.T) {
	// exemples imprimés par 10.3.6
	attendreRedaction(t, "telephone", "+41 44 123 45 67 13.11.2026", "[REDIGE:telephone].2026")
	attendreRedaction(t, "telephone", "+41 44 123 45 67a", "[REDIGE:telephone] 67a")
	attendreRedaction(t, "telephone", "+41441234567a", "+41441234567a")
	attendreRedaction(t, "telephone", "+41 44 123 45 67 89021", "[REDIGE:telephone] 89021")
	cs := DetecterTelephone([]rune("+41 44 123 45 67 13.11.2026"))
	if len(cs) != 1 || cs[0].Fin != 22 || cs[0].Valeur != "+414412345671311" {
		t.Errorf("correspondance : %+v", cs)
	}
	// le groupe entre parenthèses compte quand il précède la fin retenue
	cs = DetecterTelephone([]rune("+41 (0)44 123 45 67 89 01"))
	if len(cs) != 1 || cs[0].Valeur != "+41044123456789" {
		t.Errorf("groupe compté : %+v", cs)
	}
	// coût linéaire : le parcours s'arrête dès que le nombre dépasse 15
	debut := time.Now()
	DetecterTelephone([]rune(strings.Repeat("+1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 ", 4000)))
	if d := time.Since(debut); d > 2*time.Second {
		t.Errorf("détecteur telephone trop lent : %v", d)
	}
}

// 10.9 : adresse d'exemple sous `ch.example` ; `length` 171 et 148 et
// `sha256` inchangés ; pseudonyme de l'adresse d'exemple recalculé.
func TestExemples109DomaineReserve(t *testing.T) {
	v, err := ParseJSON([]byte(`{"note":"Virement au bénéficiaire CH93 0076 2011 6238 5295 7, assuré 756.1234.5678.97, joignable au +41 44 123 45 67 ou j.dupont@ch.example ; carte 3782 822463 10005."}`))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := CanoniqueIntegral(v); len(c) != 171 {
		t.Errorf("valeur reçue : %d octets, attendu 171", len(c))
	}
	p, _, err := PieceRedigeeJSON(politiqueSpec(t), "resultat", "x", v)
	if err != nil {
		t.Fatal(err)
	}
	verifierPiece(t, "résultat", p, `{"note":"Virement au bénéficiaire [REDIGE:iban], assuré [REDIGE:avs], joignable au [REDIGE:telephone] ou [REDIGE:email] ; carte [REDIGE:carte]."}`,
		148, "0x89a34ad286014dee1e1030caf6d50d32327a77da216dfb4a19154f15b73d5f8e", true)
	k := SHA256([]byte(EtiquetteClePseudoTest))
	if j := Pseudonyme(k, "email", "j.dupont@ch.example"); j != "ff93a7f99c38" {
		t.Errorf("[PSEUDO:email:%s], attendu ff93a7f99c38", j)
	}
	// même valeur pour le domaine écrit en capitales (domaine en minuscules)
	cs := DetecterEmail([]rune("j.dupont@CH.Example"))
	if len(cs) != 1 || Pseudonyme(k, "email", cs[0].Valeur) != "ff93a7f99c38" {
		t.Errorf("pseudonyme de j.dupont@CH.Example : %+v", cs)
	}
}
