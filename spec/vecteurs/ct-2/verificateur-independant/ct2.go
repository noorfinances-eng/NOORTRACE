// Parcours des familles de vecteurs CT-2 (annexe B de
// spec/CT-2-enregistreur.md) et confrontation aux valeurs attendues.
//
// Familles : constantes (en-tête de l'annexe B), jcs-integral (B.2),
// redaction (B.3), pieces-mcp (B.4), pieces-modele (B.5), evenements (B.6),
// INDEX.md (B.7). Une famille absente est une erreur : l'annexe B fixe la
// disposition.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Constantes de l'en-tête de l'annexe B.
const (
	SlugOrganisation     = "assureur-demo"
	OrgIDVecteurs        = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"
	NomJournalVecteurs   = "journal-demo"
	EtiquetteNonce       = "noortrace/vecteurs/v0/nonce/journal-demo/periode-"
	PeriodeDemoDebutISO  = "2026-11-10T10:00:00.000Z" // annexe B et 19.4
	PeriodeDemoFinISO    = "2026-11-10T11:00:00.000Z"
	PeriodeDemoDebutImpr = 1794304800 // secondes imprimées par l'annexe B (2026-11-10T10:00:00Z)
	PeriodeDemoFinImpr   = 1794308400
	LongueurPiiV1JCS     = 1462
	EmpreintePiiV1JCS    = "0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e"
	EmpreinteBlocPiiV1   = "0x8ff0f597d83979d91572f67cd51978485414cb650a1cdbebd7cc3030ca51227e" // SHA-256 des octets du bloc imprimé en 10.9 (sans saut de ligne final)
	TitreRapportCT2      = "Vérificateur indépendant CT-2 (Go, salle blanche)"
	FamilleConstantes    = "constantes"
	FamilleJCSIntegral   = "jcs-integral"
	FamilleRedaction     = "redaction"
	FamillePiecesMCP     = "pieces-mcp"
	FamillePiecesModele  = "pieces-modele"
	FamilleEvenements    = "evenements"
	FamilleIndex         = "index"
	FormatAnthropic      = "anthropic-messages"
	FormatChat           = "openai-chat"
	FormatResponses      = "openai-responses"
	MediaJSONExplicite   = "application/json"
	MediaTexte           = "text/plain"
	MediaFluxSSE         = "text/event-stream"
	PrefixeErreurCalculS = "! "
)

// JournalIDVecteurs = keccak256(UTF-8("journal-demo")).
func JournalIDVecteurs() string { return Hex0x(Keccak256([]byte(NomJournalVecteurs))) }

// NonceVecteurs = SHA-256(UTF-8("noortrace/vecteurs/v0/nonce/journal-demo/periode-N")).
func NonceVecteurs(n int) string {
	return Hex0x(SHA256([]byte(fmt.Sprintf("%s%d", EtiquetteNonce, n))))
}

// Contexte partagé entre familles.
type contexteCT2 struct {
	periodeDebut, periodeFin       int64     // secondes imprimées par l'annexe B
	periodeISODebut, periodeISOFin time.Time // dates imprimées par l'annexe B
	racine                         string
	strict                         bool
	piiV1                          *Politique
	pseudo                         *Politique
	autres                         []*Politique      // politique-regles-test.json (B.3) et politiques supplémentaires
	appels                         map[string]*Value // pieces-mcp : attendu.json par cas
}

// VerifierVecteursCT2 parcourt la racine des vecteurs CT-2 et rend le rapport.
func VerifierVecteursCT2(racine string, strict bool) *Rapport {
	rap := &Rapport{Titre: TitreRapportCT2, Racine: racine, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}, Details: []string{}}
	ctx := &contexteCT2{racine: racine, strict: strict, appels: map[string]*Value{}}
	familleConstantes(rap, ctx)
	familleJCSIntegral(rap, ctx)
	familleRedaction(rap, ctx)
	famillePiecesMCP(rap, ctx)
	famillePiecesModele(rap, ctx)
	familleEvenements(rap, ctx)
	familleIndex(rap, ctx)
	return rap
}

// politiqueNommee rend la politique de rédaction des vecteurs par son nom.
func (ctx *contexteCT2) politiqueNommee(nom string) *Politique {
	switch {
	case ctx.piiV1 != nil && ctx.piiV1.Nom == nom:
		return ctx.piiV1
	case ctx.pseudo != nil && ctx.pseudo.Nom == nom:
		return ctx.pseudo
	}
	for _, p := range ctx.autres {
		if p != nil && p.Nom == nom {
			return p
		}
	}
	return nil
}

func familleConstantes(rap *Rapport, ctx *contexteCT2) {
	f := FamilleConstantes
	rap.Comparer(f, "annexe B", "org_id = keccak256(\"assureur-demo\")", OrgIDVecteurs, Hex0x(Keccak256([]byte(SlugOrganisation))))
	rap.Comparer(f, "annexe B", "clé de pseudonymisation de test = SHA-256(\""+EtiquetteClePseudoTest+"\")", ClePseudoTestHex, Hex0x(SHA256([]byte(EtiquetteClePseudoTest))))
	// La ligne « Période de démonstration » de l'annexe B donne la période deux
	// fois (secondes UNIX et dates) ; si la spécification est trouvée à côté
	// des vecteurs (../../CT-2-enregistreur.md), ses valeurs imprimées sont
	// relues, sinon celles recopiées ici servent.
	ctx.periodeDebut, ctx.periodeFin = PeriodeDemoDebutImpr, PeriodeDemoFinImpr
	isoDebut, isoFin := PeriodeDemoDebutISO, PeriodeDemoFinISO
	source := "valeurs recopiées dans ce vérificateur"
	if d, fi, id, ifi, ok := periodeImprimee(filepath.Join(ctx.racine, "..", "..", "CT-2-enregistreur.md")); ok {
		ctx.periodeDebut, ctx.periodeFin, isoDebut, isoFin = d, fi, id, ifi
		source = "valeurs relues dans spec/CT-2-enregistreur.md"
	}
	d, _ := ParseHorodatage(isoDebut)
	fi, _ := ParseHorodatage(isoFin)
	ctx.periodeISODebut, ctx.periodeISOFin = d, fi
	note := source
	if d.Unix() != ctx.periodeDebut || fi.Unix() != ctx.periodeFin {
		note += fmt.Sprintf(" ; incohérence interne de la spécification : %d est %s ; les ts sont contrôlés contre les dates (2026-11-10, aussi en 19.4)",
			ctx.periodeDebut, FormaterHorodatage(unixUTC(ctx.periodeDebut)))
	}
	rap.ComparerAvecNote(f, "annexe B", "période de démonstration : secondes imprimées = dates imprimées",
		fmt.Sprintf("[%d, %d)", ctx.periodeDebut, ctx.periodeFin),
		fmt.Sprintf("[%d, %d) (%s → %s)", d.Unix(), fi.Unix(), FormaterHorodatage(d), FormaterHorodatage(fi)),
		d.Unix() == ctx.periodeDebut && fi.Unix() == ctx.periodeFin, note)
	rap.Note("constantes calculées : journal_id = keccak256(\"journal-demo\") = %s ; nonces périodes 1 et 2 = %s, %s",
		JournalIDVecteurs(), NonceVecteurs(1), NonceVecteurs(2))
}

// ---------------------------------------------------------------- jcs-integral

var reNomCas = regexp.MustCompile(`^[a-z0-9-]+$`)

func familleJCSIntegral(rap *Rapport, ctx *contexteCT2) {
	f := FamilleJCSIntegral
	chemin := filepath.Join(ctx.racine, "jcs-integral", "cas.json")
	if !fichierExiste(chemin) {
		rap.Erreur("%s : absent (annexe B.2)", relatif(ctx.racine, chemin))
		return
	}
	v := lireFichierJSON(rap, chemin)
	if v == nil {
		return
	}
	cas := v
	if EstObjet(v) && EstTableau(v.Get("cas")) {
		cas = v.Get("cas")
	}
	if !EstTableau(cas) {
		rap.Erreur("jcs-integral/cas.json : un tableau de cas est attendu (B.2)")
		return
	}
	noms := map[string]bool{}
	canoniquesAttendus := map[string]bool{}
	for i, c := range cas.Arr {
		nom := chaineDe(c, "name")
		etiq := fmt.Sprintf("cas.json[%d] %s", i, nom)
		if !reNomCas.MatchString(nom) || noms[nom] {
			rap.Comparer(f, etiq, "name unique et de motif ^[a-z0-9-]+$", "oui", "non")
		}
		noms[nom] = true
		in := c.Get("input")
		if !EstChaine(in) {
			rap.Comparer(f, etiq, "input est un texte JSON (chaîne)", "oui", "non")
			continue
		}
		att := c.Get("canonical")
		obt, err := CanoniqueIntegralTexte([]byte(in.Str))
		obtTexte := string(obt)
		if err != nil {
			obtTexte = "null (refus : " + err.Error() + ")"
		}
		switch {
		case att == nil:
			rap.Comparer(f, etiq, "canonical présent", "oui", "non")
		case att.IsNull():
			rap.ComparerAvecNote(f, etiq, "JCS intégral", "null (entrée invalide)", obtTexte, err != nil, "")
		case EstChaine(att):
			canoniquesAttendus[att.Str] = true
			rap.Comparer(f, etiq, "JCS intégral", att.Str, obtTexte)
		default:
			rap.Comparer(f, etiq, "canonical est une chaîne ou null", "oui", "non")
		}
	}
	// couverture des cas obligatoires de B.2 (notes, sans effet sur le code de retour)
	var manquants []string
	for _, r := range TableRFC8785 {
		if r.JSON == "" {
			continue
		}
		trouve := false
		for c := range canoniquesAttendus {
			if c == r.JSON || strings.Contains(c, ":"+r.JSON+"}") || strings.Contains(c, "["+r.JSON+"]") ||
				strings.Contains(c, ":"+r.JSON+",") || strings.Contains(c, ","+r.JSON+"]") || strings.Contains(c, ","+r.JSON+",") || strings.Contains(c, "["+r.JSON+",") {
				trouve = true
				break
			}
		}
		if !trouve {
			manquants = append(manquants, r.JSON)
		}
	}
	if len(manquants) > 0 {
		rap.Note("jcs-integral : valeurs de la table de l'annexe B de la RFC 8785 absentes des sorties attendues (couverture de B.2) : %s", strings.Join(manquants, ", "))
	}
	rap.Note("jcs-integral : %d cas lus", len(cas.Arr))
}

// LigneRFC8785 est une ligne de la table 1 (annexe B) de la RFC 8785.
type LigneRFC8785 struct {
	IEEE string // 16 chiffres hexadécimaux
	JSON string // "" pour NaN et Infinity
}

// TableRFC8785 recopie la table 1 de la RFC 8785 (annexe B, « Number
// Serialization Samples »), lue sur rfc-editor.org le 2026-10-22.
var TableRFC8785 = []LigneRFC8785{
	{"0000000000000000", "0"},
	{"8000000000000000", "0"},
	{"0000000000000001", "5e-324"},
	{"8000000000000001", "-5e-324"},
	{"7fefffffffffffff", "1.7976931348623157e+308"},
	{"ffefffffffffffff", "-1.7976931348623157e+308"},
	{"4340000000000000", "9007199254740992"},
	{"c340000000000000", "-9007199254740992"},
	{"4430000000000000", "295147905179352830000"},
	{"7fffffffffffffff", ""},
	{"7ff0000000000000", ""},
	{"44b52d02c7e14af5", "9.999999999999997e+22"},
	{"44b52d02c7e14af6", "1e+23"},
	{"44b52d02c7e14af7", "1.0000000000000001e+23"},
	{"444b1ae4d6e2ef4e", "999999999999999700000"},
	{"444b1ae4d6e2ef4f", "999999999999999900000"},
	{"444b1ae4d6e2ef50", "1e+21"},
	{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
	{"3eb0c6f7a0b5ed8d", "0.000001"},
	{"41b3de4355555553", "333333333.3333332"},
	{"41b3de4355555554", "333333333.33333325"},
	{"41b3de4355555555", "333333333.3333333"},
	{"41b3de4355555556", "333333333.3333334"},
	{"41b3de4355555557", "333333333.33333343"},
	{"becbf647612f3696", "-0.0000033333333333333333"},
	{"43143ff3c1cb0959", "1424953923781206.2"},
}

// ---------------------------------------------------------------- INDEX.md

func familleIndex(rap *Rapport, ctx *contexteCT2) {
	f := FamilleIndex
	chemin := filepath.Join(ctx.racine, "INDEX.md")
	octets, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("INDEX.md : absent (annexe B.7)")
		return
	}
	texte := strings.ToLower(string(octets))
	present := func(h string) string {
		if strings.Contains(texte, strings.ToLower(h)) || strings.Contains(texte, strings.ToLower(strings.TrimPrefix(h, "0x"))) {
			return "présent"
		}
		return "absent"
	}
	rap.Comparer(f, "INDEX.md", "journal_id imprimé = keccak256(\"journal-demo\")", "présent", present(JournalIDVecteurs()))
	rap.Comparer(f, "INDEX.md", "clé de pseudonymisation de test imprimée (hexadécimal)", "présent", present(ClePseudoTestHex))
	// nonces : chaque ligne qui nomme « …/periode-N » doit porter SHA-256 de l'étiquette
	reN := regexp.MustCompile(`periode-([0-9]+)`)
	reH := regexp.MustCompile(`0x[0-9a-f]{64}`)
	vus := map[string]bool{}
	for _, l := range strings.Split(string(octets), "\n") {
		m := reN.FindStringSubmatch(l)
		if m == nil || vus[m[1]] {
			continue
		}
		hs := reH.FindAllString(strings.ToLower(l), -1)
		if len(hs) == 0 {
			continue
		}
		vus[m[1]] = true
		n := 0
		fmt.Sscan(m[1], &n)
		attendu := NonceVecteurs(n)
		obt := "absent de la ligne"
		for _, h := range hs {
			if h == attendu {
				obt = attendu
			}
		}
		rap.Comparer(f, "INDEX.md", "nonce période "+m[1]+" = SHA-256(\""+EtiquetteNonce+m[1]+"\")", attendu, obt)
	}
	if len(vus) == 0 {
		rap.Note("INDEX.md : aucune ligne « periode-N » avec une empreinte : nonces non confrontés")
	}
	// chaque famille est nommée dans l'index
	for _, fam := range []string{"jcs-integral", "redaction", "pieces-mcp", "pieces-modele", "evenements"} {
		rap.Comparer(f, "INDEX.md", "famille "+fam+" décrite", "présent", present(fam))
	}
}

// ---------------------------------------------------------------- utilitaires

func sousRepertoires(dir string) []string {
	entrees, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entrees {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

var rePeriodeImprimee = regexp.MustCompile("\\[([0-9]{9,11}), ([0-9]{9,11})\\)` = ([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})Z → ([0-9]{2}:[0-9]{2}:[0-9]{2})Z")

// periodeImprimee relit la ligne « Période de démonstration » de l'annexe B.
func periodeImprimee(chemin string) (int64, int64, string, string, bool) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return 0, 0, "", "", false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.Contains(l, "Période de démonstration") {
			continue
		}
		m := rePeriodeImprimee.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		d, err1 := strconv.ParseInt(m[1], 10, 64)
		fi, err2 := strconv.ParseInt(m[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		return d, fi, m[3] + "T" + m[4] + ".000Z", m[3] + "T" + m[5] + ".000Z", true
	}
	return 0, 0, "", "", false
}
