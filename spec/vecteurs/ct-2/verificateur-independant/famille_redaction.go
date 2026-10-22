// Famille redaction (annexe B.3) : politique-pii-v1.json,
// politique-pseudonyme-test.json, cas.json.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func unixUTC(s int64) time.Time { return time.Unix(s, 0).UTC() }

func familleRedaction(rap *Rapport, ctx *contexteCT2) {
	f := FamilleRedaction
	dir := filepath.Join(ctx.racine, "redaction")
	if !fichierExiste(dir) {
		rap.Erreur("redaction/ : absent (annexe B.3)")
		return
	}
	// politique-pii-v1.json : octets du bloc de 10.9, JCS intégral de 10.6
	cheminPii := filepath.Join(dir, "politique-pii-v1.json")
	octets, err := os.ReadFile(cheminPii)
	if err != nil {
		rap.Erreur("redaction/politique-pii-v1.json : %v", err)
		return
	}
	brut := strings.TrimSuffix(string(octets), "\n")
	rap.Comparer(f, "politique-pii-v1.json", "octets identiques au bloc imprimé en 10.9 (SHA-256, saut de ligne final exclu)", EmpreinteBlocPiiV1, Hex0x(SHA256([]byte(brut))))
	docPii, err := ParseJSON(octets)
	if err != nil {
		rap.Erreur("redaction/politique-pii-v1.json : %v", err)
		return
	}
	c, err := CanoniqueIntegral(docPii)
	if err == nil {
		rap.Comparer(f, "politique-pii-v1.json", "longueur du JCS intégral (10.6)", fmt.Sprint(LongueurPiiV1JCS), fmt.Sprint(len(c)))
		rap.Comparer(f, "politique-pii-v1.json", "SHA-256 du JCS intégral (10.6)", EmpreintePiiV1JCS, Hex0x(SHA256(c)))
	}
	pii, mq := ChargerPolitique(docPii)
	rap.Comparer(f, "politique-pii-v1.json", "politique valide (forme, EX-10.6)", "oui", ouiOuListe(mq))
	rap.Comparer(f, "politique-pii-v1.json", "name", "pii-v1", pii.Nom)
	ctx.piiV1 = pii

	// politique-pseudonyme-test.json (B.3) : pii-v1 avec name pii-pseudo-test,
	// sa propre description, pseudonym_key {env, encoding hex}, l'action
	// pseudonyme sur chaque règle, et en tête la règle champ « iban-champ »
	cheminPseudo := filepath.Join(dir, "politique-pseudonyme-test.json")
	if docPseudo := lireFichierJSON(rap, cheminPseudo); docPseudo != nil {
		attendu := Copier(docPii)
		Definir(attendu, "name", Chaine("pii-pseudo-test"))
		Definir(attendu, "pseudonym_key", Objet("env", Chaine(VariableClePseudoTest), "encoding", Chaine("hex")))
		if rs := attendu.Get("rules"); EstTableau(rs) {
			for _, r := range rs.Arr {
				Definir(r, "action", Objet("kind", Chaine("pseudonyme")))
			}
			champ, _ := ParseJSON([]byte(RegleChampPseudoTest))
			rs.Arr = append([]*Value{champ}, rs.Arr...)
		}
		sansDesc := func(v *Value) *Value { c := Copier(v); Retirer(c, "description"); return c }
		comparerValeur(rap, f, "politique-pseudonyme-test.json", "pii-v1 avec name pii-pseudo-test, pseudonym_key {env, encoding hex}, action pseudonyme et règle iban-champ en tête, description exceptée (B.3)", sansDesc(attendu), sansDesc(docPseudo))
		pseudo, mq := ChargerPolitique(docPseudo)
		rap.Comparer(f, "politique-pseudonyme-test.json", "politique valide (forme, EX-10.6)", "oui", ouiOuListe(mq))
		if _, defini := os.LookupEnv(VariableClePseudoTest); !defini {
			rap.Note("redaction : %s non définie ; clé de test dérivée de l'annexe B (%s)", VariableClePseudoTest, ClePseudoTestHex)
		}
		ctx.pseudo = pseudo
	}

	// politique-regles-test.json (B.3 ; sa présence est contrôlée par les cas
	// de cas.json qui la nomment), puis toute autre politique du répertoire
	// (politique-*.json), qui n'est pas exigée par l'annexe B
	autres, _ := filepath.Glob(filepath.Join(dir, "politique-*.json"))
	for _, ch := range autres {
		base := filepath.Base(ch)
		if base == "politique-pii-v1.json" || base == "politique-pseudonyme-test.json" {
			continue
		}
		doc := lireFichierJSON(rap, ch)
		if doc == nil {
			continue
		}
		p, mq := ChargerPolitique(doc)
		rap.Comparer(f, base, "politique valide (forme, EX-10.6)", "oui", ouiOuListe(mq))
		ctx.autres = append(ctx.autres, p)
		if base == "politique-regles-test.json" {
			rap.Comparer(f, base, "name de la politique de règles (B.3)", "pii-regles-test", p.Nom)
			continue
		}
		rap.Note("redaction : politique supplémentaire %s (name %s), non exigée par l'annexe B.3", base, p.Nom)
	}

	// motifs.json : sous-ensemble commun ECMAScript/RE2 (EX-10.6)
	if mv := lireFichierJSON(rap, filepath.Join(dir, "motifs.json")); mv != nil && EstTableau(mv) {
		for i, m := range mv.Arr {
			motif := chaineDe(m, "pattern")
			admis := m.Get("admis")
			raison := ErreurMotifCommun(motif)
			obt := "admis"
			if raison != "" {
				obt = "refusé : " + raison
			}
			att := "refusé"
			if admis != nil && admis.Kind == KindBool && admis.Bool {
				att = "admis"
			}
			rap.ComparerAvecNote(f, fmt.Sprintf("motifs.json[%d] %s", i, motif), "sous-ensemble commun (EX-10.6)", att, obt, (raison == "") == (att == "admis"), chaineDe(m, "note"))
		}
	}

	// cas.json
	cheminCas := filepath.Join(dir, "cas.json")
	v := lireFichierJSON(rap, cheminCas)
	if v == nil {
		return
	}
	cas := v
	if EstObjet(v) && EstTableau(v.Get("cas")) {
		cas = v.Get("cas")
	}
	if !EstTableau(cas) {
		rap.Erreur("redaction/cas.json : un tableau de cas est attendu (B.3)")
		return
	}
	parPortee := map[string]int{}
	for i, c := range cas.Arr {
		nom := chaineDe(c, "name")
		etiq := fmt.Sprintf("cas.json[%d] %s", i, nom)
		pol := ctx.politiqueNommee(chaineDe(c, "policy"))
		if pol == nil {
			rap.Comparer(f, etiq, "politique connue (B.3 : pii-v1 ou pii-pseudo-test)", "connue", chaineDe(c, "policy")+" : inconnue")
			continue
		}
		portee := chaineDe(c, "scope")
		if !dansEnum(portee, Portees) {
			rap.Comparer(f, etiq, "portée parmi les six de 10.2.2", "oui", portee)
			continue
		}
		parPortee[portee]++
		outil := chaineDe(c, "tool")
		in := c.Get("input")
		att := c.Get("expected")
		if in == nil || !EstObjet(att) {
			rap.Erreur("redaction/cas.json[%d] : input ou expected absent", i)
			continue
		}
		texte := portee == "prompt_systeme" || strings.HasPrefix(chaineDe(c, "media_type"), "text/") || strings.HasPrefix(chaineDe(att, "media_type"), "text/")
		var p *Piece
		var res ResultatRedaction
		var errCalc error
		if texte {
			if !EstChaine(in) {
				rap.Comparer(f, etiq, "input chaîne pour une pièce texte", "chaîne", in.Kind.String())
				continue
			}
			p, res = PieceRedigeeTexte(pol, portee, outil, in.Str)
		} else {
			p, res, errCalc = PieceRedigeeJSON(pol, portee, outil, in)
		}
		if errCalc != nil {
			rap.Comparer(f, etiq, "pièce", chaineDe(att, "piece"), "calcul impossible : "+errCalc.Error())
			continue
		}
		rap.Comparer(f, etiq, "pièce (octets)", chaineDe(att, "piece"), string(p.Octets))
		rap.Comparer(f, etiq, "sha256", chaineDe(att, "sha256"), p.SHA256Hex())
		rap.Comparer(f, etiq, "length", texteOuAbsent(att.Get("length")), fmt.Sprint(len(p.Octets)))
		rap.Comparer(f, etiq, "redacted", texteOuAbsent(att.Get("redacted")), fmt.Sprint(p.Redigee))
		if pc := att.Get("piece"); EstChaine(pc) {
			rap.Comparer(f, etiq, "cohérence de l'attendu : sha256(piece) = sha256", chaineDe(att, "sha256"), Hex0x(SHA256([]byte(pc.Str))))
		}
		if m := att.Get("matches"); m != nil {
			a, o := decomptesAttendus(m), decomptesObtenus(res.Decomptes)
			rap.ComparerAvecNote(f, etiq, "matches (règle, détecteur, nombre ; EX-10.17)", strings.Join(a, " ; "), strings.Join(o, " ; "),
				memesDecomptes(m, res.Decomptes), "comparaison des triplets de nombre non nul ; un détecteur regex ou champ est reconnu sous « regex », son nom, ou « regex:<nom> » (resp. « champ », l'étiquette, « champ:<étiquette> »)")
		}
		// EX-10.15 : la pièce rédigée est un point fixe de la politique
		var p2 *Piece
		if texte {
			p2, _ = PieceRedigeeTexte(pol, portee, outil, string(p.Octets))
		} else if v2, err := ParseJSON(p.Octets); err == nil {
			p2, _, _ = PieceRedigeeJSON(pol, portee, outil, v2)
		}
		if p2 != nil {
			rap.Comparer(f, etiq, "idempotence (EX-10.15) : politique réappliquée à la pièce", string(p.Octets), string(p2.Octets))
		}
	}
	var ps []string
	for _, p := range Portees {
		ps = append(ps, fmt.Sprintf("%s %d", p, parPortee[p]))
	}
	rap.Note("redaction : %d cas lus (par portée : %s)", len(cas.Arr), strings.Join(ps, ", "))
}

// RegleChampPseudoTest est la règle placée en tête de
// politique-pseudonyme-test.json (annexe B.3).
const RegleChampPseudoTest = `{"id":"iban-champ","description":"IBAN du beneficiaire designe par pointeur : pseudonyme calcule sur la chaine elle-meme.","scopes":["arguments"],"tools":"*","path":"/iban_beneficiaire","detectors":[{"type":"champ","label":"iban"}],"action":{"kind":"pseudonyme"}}`

func ouiOuListe(mq []string) string {
	if len(mq) == 0 {
		return "oui"
	}
	return "non : " + strings.Join(mq, " ; ")
}

func decomptesAttendus(m *Value) []string {
	var out []string
	if EstTableau(m) {
		for _, x := range m.Arr {
			n, _ := EntierDe(x.Get("count"))
			if n == 0 {
				continue
			}
			out = append(out, fmt.Sprintf("%s/%s=%d", chaineDe(x, "rule"), chaineDe(x, "detector"), n))
		}
	}
	sort.Strings(out)
	return out
}

func decomptesObtenus(ds []Decompte) []string {
	var out []string
	for _, d := range ds {
		out = append(out, fmt.Sprintf("%s/%s=%d", d.Regle, d.Detecteur, d.Nombre))
	}
	sort.Strings(out)
	return out
}

// detecteurConcorde : désignation attendue d'un détecteur contre la forme
// « type » ou « type:nom » de ce vérificateur.
func detecteurConcorde(attendu, obtenu string) bool {
	if attendu == obtenu {
		return true
	}
	if i := strings.IndexByte(obtenu, ':'); i > 0 {
		return attendu == obtenu[:i] || attendu == obtenu[i+1:]
	}
	return false
}

func memesDecomptes(m *Value, ds []Decompte) bool {
	if !EstTableau(m) {
		return false
	}
	var att []*Value
	for _, x := range m.Arr {
		if n, _ := EntierDe(x.Get("count")); n != 0 {
			att = append(att, x)
		}
	}
	if len(att) != len(ds) {
		return false
	}
	pris := make([]bool, len(ds))
	for _, x := range att {
		n, _ := EntierDe(x.Get("count"))
		trouve := false
		for j, d := range ds {
			if !pris[j] && d.Regle == chaineDe(x, "rule") && int64(d.Nombre) == n && detecteurConcorde(chaineDe(x, "detector"), d.Detecteur) {
				pris[j] = true
				trouve = true
				break
			}
		}
		if !trouve {
			return false
		}
	}
	return true
}
