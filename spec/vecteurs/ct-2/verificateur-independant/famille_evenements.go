// Famille evenements (annexe B.6) : evenements/journal-demo/ {
// evenements.json, attendu.json, pieces.json, cles.json, segment.ndjson,
// intentions.ndjson, politique.json }.
//
// Recalculé : contrôles CT-1 de chaque événement et de la chaîne (E-1 à E-8,
// E-10, E-11, C-1 à C-3, code CT-1 repris), hash, sig, prev_hash, longueur
// canonique, JCS(A) et D_A ; références de pièces (E-6) avec pieces.json ;
// policy_sha256 depuis politique.json en JCS intégral ; idempotence de la
// politique sur chaque pièce rédigeable (EX-10.15), dont la pièce
// « arguments » de seq 7 ; intention_sha256 et lignes du journal
// d'intention (12.5) ; égalité octet par octet de segment.ndjson (12.2) ;
// corrélation (5.6) et effets (EX-7.6) recalculés sur les pièces rédigées ;
// séquence de 19.2 ; dossiers CT-1 éventuels.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// PieceFournie est une pièce de pieces.json.
type PieceFournie struct {
	SHA256, MediaType string
	Length            int64
	Redacted          *bool
	Octets            []byte
}

func lirePiecesFournies(rap *Rapport, chemin string) map[string]*PieceFournie {
	out := map[string]*PieceFournie{}
	v := lireFichierJSON(rap, chemin)
	if v == nil {
		return out
	}
	liste := v
	if EstObjet(v) && EstTableau(v.Get("pieces")) {
		liste = v.Get("pieces")
	}
	if !EstTableau(liste) {
		rap.Erreur("%s : tableau de pièces attendu (B.6)", chemin)
		return out
	}
	for _, p := range liste.Arr {
		pf := &PieceFournie{SHA256: chaineDe(p, "sha256"), MediaType: chaineDe(p, "media_type")}
		pf.Length, _ = EntierDe(p.Get("length"))
		if r := p.Get("redacted"); r != nil && r.Kind == KindBool {
			b := r.Bool
			pf.Redacted = &b
		}
		switch {
		case EstChaine(p.Get("bytes")):
			pf.Octets = []byte(p.Get("bytes").Str)
		case EstChaine(p.Get("texte")):
			pf.Octets = []byte(p.Get("texte").Str)
		}
		out[pf.SHA256] = pf
	}
	return out
}

// kindDemo rend « outil/statut » d'un événement, pour la séquence de 19.2.
func kindDemo(ev *Value) string {
	return Outil(ev) + "/" + chaineDe(ev, "execution", "status")
}

// SequenceDemo est la séquence de 19.2 (seq 1 à 8) et de B.6.
var SequenceDemo = []string{
	OutilPolitique + "/executee",
	OutilModele + "/executee",
	"demo__claims.get/executee",
	OutilModele + "/executee",
	"demo__payments.create/retenue",
	OutilApprobation + "/executee",
	"demo__payments.create/executee",
	OutilModele + "/executee",
}

func familleEvenements(rap *Rapport, ctx *contexteCT2) {
	f := FamilleEvenements
	dir := filepath.Join(ctx.racine, "evenements", "journal-demo")
	if !fichierExiste(dir) {
		rap.Erreur("evenements/journal-demo/ : absent (annexe B.6)")
		return
	}
	nom := "journal-demo"
	evs := listeEvenements(lireFichierJSON(rap, filepath.Join(dir, "evenements.json")))
	if len(evs) == 0 {
		rap.Erreur("evenements/journal-demo/evenements.json : aucun événement reconnu")
		return
	}
	var cles *JeuCles
	if v := lireFichierJSON(rap, filepath.Join(dir, "cles.json")); v != nil {
		j, mq := ChargerCles(v)
		for _, m := range mq {
			rap.Erreur("evenements/journal-demo/cles.json : %s", m)
		}
		cles = j
	}
	if cles == nil {
		rap.Erreur("evenements/journal-demo/cles.json : absent ou illisible")
		return
	}
	for _, k := range []string{"rec-test-01", "rec-test-02"} {
		if c := cles.Trouver(k); c != nil {
			rap.Comparer(f, nom, "cles.json : clé publique de "+k+" = dérivée de la graine de CT-1 §13", Hex0x(ClePubliqueDepuisGraine(GraineCleTest(k))), Hex0x(c.PublicKey))
		}
	}
	attendu := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))

	// 1. verdict CT-1
	res := ControlerChaine(evs, cles)
	valide, ctrl, _ := lireAttendu(attendu)
	comparerVerdict(rap, f, nom, valide, ctrl, res, ctx.strict)
	rap.Detail("[evenements] %s\n%s", nom, res.Resume("    "))

	// 2. valeurs par événement
	valeursJournalCT2(rap, nom, evs, cles, attendu)

	// 3. séquence et constantes de la démonstration (19.2, annexe B)
	var obt []string
	for _, ev := range evs {
		obt = append(obt, fmt.Sprintf("%d:%s", Seq(ev), kindDemo(ev)))
	}
	var att []string
	for i, k := range SequenceDemo {
		att = append(att, fmt.Sprintf("%d:%s", i+1, k))
	}
	rap.Comparer(f, nom, "séquence des huit événements de 19.2 (outil/statut)", strings.Join(att, " "), strings.Join(obt, " "))
	jid := JournalIDVecteurs()
	for _, ev := range evs {
		etiq := fmt.Sprintf("%s · seq %d", nom, Seq(ev))
		if chaineDe(ev, "org_id") != OrgIDVecteurs || chaineDe(ev, "journal_id") != jid || chaineDe(ev, "recorder_key_id") != "rec-test-01" ||
			chaineDe(ev, "code", "recorder") != VersionEnregistreurVecteurs {
			rap.Comparer(f, etiq, "org_id, journal_id (keccak256), recorder_key_id rec-test-01, code.recorder 0.1.0 (B.6)",
				OrgIDVecteurs+" "+jid+" rec-test-01 "+VersionEnregistreurVecteurs,
				chaineDe(ev, "org_id")+" "+chaineDe(ev, "journal_id")+" "+chaineDe(ev, "recorder_key_id")+" "+chaineDe(ev, "code", "recorder"))
		}
		d, fi := ctx.periodeISODebut, ctx.periodeISOFin
		if t, ok := Ts(ev); !ok || t.Before(d) || !t.Before(fi) {
			note := ""
			if ok && t.Unix() >= ctx.periodeDebut && t.Unix() < ctx.periodeFin {
				note = fmt.Sprintf("ts dans [%d, %d), les secondes imprimées par l'annexe B, qui ne désignent pas les dates imprimées", ctx.periodeDebut, ctx.periodeFin)
			}
			rap.ComparerAvecNote(f, etiq, "ts dans la période de démonstration "+FormaterHorodatage(d)+" → "+FormaterHorodatage(fi)+" (annexe B, 19.4)", "oui", chaineDe(ev, "ts"), false, note)
		}
	}
	rap.Comparer(f, nom, "identité du journal (org_id, journal_id de tous les événements, B.6)", "conforme", conformeSi(func() bool {
		for _, ev := range evs {
			if chaineDe(ev, "org_id") != OrgIDVecteurs || chaineDe(ev, "journal_id") != jid {
				return false
			}
		}
		return true
	}()))
	if len(evs) >= 2 && Outil(evs[1]) == OutilModele {
		rap.Comparer(f, nom+" · seq 2", "code.model de l'échange n° 1 (19.2)", "demo/modele-demo-1", chaineDe(evs[1], "code", "model"))
	}

	// 4. politique
	docPol := lireFichierJSON(rap, filepath.Join(dir, "politique.json"))
	var pol *Politique
	shaPolitique := ""
	if docPol != nil {
		c, err := CanoniqueIntegral(docPol)
		if err != nil {
			rap.Erreur("politique.json : JCS intégral impossible : %v", err)
		} else {
			shaPolitique = Hex0x(SHA256(c))
			rap.Comparer(f, nom, "policy_sha256 = SHA-256(JCS intégral de politique.json) (EX-10.21)", chaineDe(attendu, "policy_sha256"), shaPolitique)
		}
		if p1 := premierPolitique(evs); p1 != nil {
			rap.Comparer(f, nom+" · seq 1", "arguments.value.policy_sha256 = SHA-256(JCS intégral de politique.json)", chaineDe(p1, "execution", "arguments", "value", "policy_sha256"), shaPolitique)
			rap.Comparer(f, nom+" · seq 1", "arguments.value.policy_version = politique.version", chaineDe(docPol, "version"), chaineDe(p1, "execution", "arguments", "value", "policy_version"))
		} else {
			rap.Comparer(f, nom, "seq 1 est noortrace.journal.politique (EX-9.1)", "oui", "non")
		}
		for _, ev := range evs {
			if chaineDe(ev, "code", "policy_version") != chaineDe(docPol, "version") {
				rap.Comparer(f, fmt.Sprintf("%s · seq %d", nom, Seq(ev)), "code.policy_version = politique.version (EX-9.1)", chaineDe(docPol, "version"), chaineDe(ev, "code", "policy_version"))
			}
		}
		rap.Comparer(f, nom, "politique.version de la démonstration (19.2)", "demo-2026-11", chaineDe(docPol, "version"))
		red := docPol.Get("redaction")
		var mq []string
		pol, mq = ChargerPolitique(red)
		rap.Comparer(f, nom, "politique.json : membre redaction valide (EX-10.6)", "oui", ouiOuListe(mq))
		if ctx.piiV1 != nil {
			comparerValeur(rap, f, nom, "politique.json : redaction = redaction/politique-pii-v1.json", ctx.piiV1.Document, red)
		}
	}
	if pol == nil {
		pol = ctx.piiV1
	}

	// 5. pièces
	pieces := lirePiecesFournies(rap, filepath.Join(dir, "pieces.json"))
	controlerPiecesJournal(rap, nom, evs, pieces, pol, docPol, shaPolitique, ctx)

	// 6. segment
	controlerSegment(rap, nom, filepath.Join(dir, "segment.ndjson"), evs, attendu)

	// 7. journal d'intention
	entrees := lireFichierJSON(rap, filepath.Join(dir, "entrees.json"))
	controlerIntentions(rap, nom, dir, evs, attendu, entrees)

	// 8. échanges, corrélation, contexte et effets
	corr := controlerEchangesEtCorrelation(rap, nom, evs, entrees, pol)
	controlerContexteAppels(rap, nom, evs, entrees, pieces)
	if lc := attendu.Get("correlation").Get("calls"); EstTableau(lc) {
		for _, x := range lc.Arr {
			seq, _ := entierDe(x, "seq")
			c, ok := corr[seq]
			attTexte := fmt.Sprintf("échange %s, appel %s, hérite de %s", texteOuAbsent(x.Get("exchange_seq")), texteOuAbsent(x.Get("tool_call_id")), texteOuAbsent(x.Get("inherits_from_seq")))
			obt := "aucun appel d'outil à ce seq"
			if ok {
				ech, app, her := "null", "null", "null"
				if c.EchangeSeq != 0 {
					ech = fmt.Sprint(c.EchangeSeq)
				}
				if c.AppelID != "" {
					app = c.AppelID
				}
				if c.Herite != 0 {
					her = fmt.Sprint(c.Herite)
				}
				obt = fmt.Sprintf("échange %s, appel %s, hérite de %s", ech, app, her)
			}
			rap.Comparer(f, fmt.Sprintf("%s · seq %d", nom, seq), "corrélation : exchange_seq, tool_call_id, inherits_from_seq (EX-5.22, EX-7.12)", attTexte, obt)
		}
	}
	controlerEffets(rap, nom, evs, pieces, docPol)

	// 8 bis. autres valeurs déclarées par attendu.json
	valeursSupplementaires(rap, nom, dir, evs, attendu, docPol)

	// 9. dossiers CT-1 éventuels (contrôles 1, 2, 3, 6 ; 7 hors périmètre)
	verifierDossiersDemo(rap, ctx, filepath.Join(ctx.racine, "evenements"))
}

// verifierDossiersDemo vérifie, avec le code CT-1 repris, tout répertoire
// sous evenements/ qui porte un dossier.json (l'annexe B.6 n'en prévoit pas ;
// un dossier fourni est vérifié). Verdict attendu : attendu.json du dossier,
// sinon valide.
func verifierDossiersDemo(rap *Rapport, ctx *contexteCT2, racine string) {
	f := FamilleEvenements
	var dossiers []string
	filepath.WalkDir(racine, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "dossier.json" {
			dossiers = append(dossiers, filepath.Dir(p))
		}
		return nil
	})
	sort.Strings(dossiers)
	for _, d := range dossiers {
		nom := "dossier " + relatif(ctx.racine, d)
		valide, ctrl := true, []string(nil)
		if fichierExiste(filepath.Join(d, "attendu.json")) {
			if v := lireFichierJSON(rap, filepath.Join(d, "attendu.json")); v != nil {
				valide, ctrl, _ = lireAttendu(v)
			}
		}
		res := VerifierDossier(d)
		if nonAdmis := res.NonExecutesNonAdmis(); valide && res.Resultats.Valide() && len(nonAdmis) > 0 {
			rap.ComparerAvecNote(f, nom, "verdict du dossier (CT-1 §11.4)", "valide", "non exécuté sans raison admise : "+strings.Join(nonAdmis, ","), false, "")
		} else {
			comparerVerdict(rap, f, nom, valide, ctrl, res.Resultats, ctx.strict)
		}
		rap.Detail("[evenements] %s\n%s", nom, res.Resultats.Resume("    "))
		for _, b := range res.Bornes {
			rap.Detail("    %s", b)
		}
		rap.Note("%s : dossier CT-1 vérifié (contrôles 1, 2, 3, 6 ; 7, signatures EIP-191, hors périmètre ; 4, 5, 8 non exécutables : CT-4, CT-5)", relatif(ctx.racine, d))
	}
}

func conformeSi(b bool) string {
	if b {
		return "conforme"
	}
	return "non conforme"
}

func premierPolitique(evs []*Value) *Value {
	if len(evs) > 0 && Outil(evs[0]) == OutilPolitique && Seq(evs[0]) == 1 {
		return evs[0]
	}
	return nil
}

// valeursJournalCT2 confronte attendu.json : events (ou hashes, forme CT-1)
// [{ seq, hash, sig, prev_hash, canonical_length }], A et D_A (ou
// approbation { A, D_A }).
func valeursJournalCT2(rap *Rapport, nom string, evs []*Value, cles *JeuCles, attendu *Value) {
	f := FamilleEvenements
	parSeq := map[int64]*Value{}
	for _, ev := range evs {
		parSeq[Seq(ev)] = ev
	}
	liste := attendu.Get("events")
	if !EstTableau(liste) {
		liste = attendu.Get("hashes")
	}
	if !EstTableau(liste) {
		rap.Erreur("evenements/%s/attendu.json : ni events ni hashes (B.6)", nom)
		liste = &Value{Kind: KindArray}
	}
	for _, a := range liste.Arr {
		seq, _ := entierDe(a, "seq")
		ev := parSeq[seq]
		etiq := fmt.Sprintf("%s · seq %d", nom, seq)
		if ev == nil {
			rap.Comparer(f, etiq, "événement présent", "oui", "non")
			continue
		}
		h, c, err := HashEvenement(ev)
		if err != nil {
			rap.Comparer(f, etiq, "hash", chaineDe(a, "hash"), "forme canonique impossible : "+err.Error())
			continue
		}
		rap.Comparer(f, etiq, "hash = SHA-256(P_H ‖ JCS_v0(E'))", chaineDe(a, "hash"), Hex0x(h))
		rap.Comparer(f, etiq, "hash porté par l'événement", chaineDe(a, "hash"), chaineDe(ev, "hash"))
		if n, ok := entierDe(a, "canonical_length"); ok {
			rap.Comparer(f, etiq, "longueur de la forme canonique", fmt.Sprint(n), fmt.Sprint(len(c)))
		}
		if p := chaineDe(a, "prev_hash"); p != "" {
			recalc := Zero32
			if prev := parSeq[seq-1]; prev != nil {
				if hp, _, err := HashEvenement(prev); err == nil {
					recalc = Hex0x(hp)
				}
			}
			rap.Comparer(f, etiq, "prev_hash = hash recalculé du précédent", p, recalc)
		}
		if s := chaineDe(a, "sig"); s != "" {
			rap.Comparer(f, etiq, "sig portée par l'événement", s, chaineDe(ev, "sig"))
		}
		cle := cles.Trouver(chaineDe(ev, "recorder_key_id"))
		obt := "valide"
		if cle == nil {
			obt = "clé inconnue"
		} else if sig, err := OctetsHex(chaineDe(ev, "sig"), 64); err != nil {
			obt = err.Error()
		} else if err := VerifierEd25519(cle.PublicKey, append(append([]byte{}, PrefixeSignatureEvenement...), c...), sig); err != nil {
			obt = err.Error()
		}
		rap.Comparer(f, etiq, "signature Ed25519 (P_S ‖ JCS_v0(E'))", "valide", obt)
	}
	ap := attendu
	if a := attendu.Get("approbation"); EstObjet(a) {
		ap = a
	}
	var evApp *Value
	for _, ev := range evs {
		if Outil(ev) == OutilApprobation {
			evApp = ev
		}
	}
	if ap.Get("A") != nil || ap.Get("D_A") != nil {
		if evApp == nil {
			rap.Comparer(f, nom, "événement noortrace.approbation.decision", "présent", "absent")
			return
		}
		A := ObjetSigneApprobation(evApp)
		if att := ap.Get("A"); att != nil {
			ca, _ := Canonique(att)
			cb, _ := Canonique(A)
			rap.Comparer(f, nom, "JCS(A) (CT-1 §6.3)", string(ca), string(cb))
		}
		if da := chaineDe(ap, "D_A"); da != "" {
			d, err := CondenseApprobation(A)
			if err != nil {
				rap.Comparer(f, nom, "D_A", da, err.Error())
			} else {
				rap.Comparer(f, nom, "D_A = SHA-256(P_A ‖ JCS(A))", da, Hex0x(d))
			}
		}
	}
}

// porteeReference rend la portée de rédaction d'une référence d'événement,
// ou "" si la pièce n'est pas rédigée (définition d'outil, politique).
func porteeReference(ev *Value, chemin string) (string, bool) {
	modele := Outil(ev) == OutilModele
	switch {
	case chemin == "execution.arguments" && modele:
		return "requete", false
	case chemin == "execution.result" && modele:
		return "reponse", false
	case chemin == "execution.arguments":
		return "arguments", false
	case chemin == "execution.result":
		return "resultat", false
	case chemin == "intent":
		return "reponse", true
	}
	return "", false
}

func controlerPiecesJournal(rap *Rapport, nom string, evs []*Value, pieces map[string]*PieceFournie, pol *Politique, docPol *Value, shaPolitique string, ctx *contexteCT2) {
	f := FamilleEvenements
	// cohérence de chaque pièce fournie
	var shas []string
	for s := range pieces {
		shas = append(shas, s)
	}
	sort.Strings(shas)
	for _, s := range shas {
		p := pieces[s]
		etiq := nom + "/pieces.json · " + abrege(s)
		rap.Comparer(f, etiq, "sha256 des octets (E-6)", s, Hex0x(SHA256(p.Octets)))
		rap.Comparer(f, etiq, "length des octets (E-6)", fmt.Sprint(p.Length), fmt.Sprint(len(p.Octets)))
	}
	referencees := map[string]bool{}
	for _, ev := range evs {
		etiqEv := fmt.Sprintf("%s · seq %d", nom, Seq(ev))
		for _, rf := range references(ev) {
			if rf.ref.Has("value") {
				continue // en ligne : contrôlée par E-6 (code CT-1)
			}
			sha := chaineDe(rf.ref, "sha256")
			referencees[sha] = true
			p := pieces[sha]
			etiq := etiqEv + " · " + rf.chemin
			if p == nil {
				rap.Comparer(f, etiq, "pièce référencée présente dans pieces.json (E-6)", "présente", "absente")
				continue
			}
			n, _ := entierDe(rf.ref, "length")
			rap.Comparer(f, etiq, "length de la référence = longueur de la pièce", fmt.Sprint(n), fmt.Sprint(len(p.Octets)))
			if p.Redacted != nil {
				rap.Comparer(f, etiq, "redacted de la référence = redacted de pieces.json", texteOuAbsent(rf.ref.Get("redacted")), fmt.Sprint(*p.Redacted))
			}
			mtRef := chaineDe(rf.ref, "media_type")
			rap.Comparer(f, etiq, "media_type de la référence = media_type de pieces.json", vide(mtRef), vide(p.MediaType))
			controlerPieceRedigeable(rap, etiq, ev, rf.chemin, p, pol)
		}
		if pv := chaineDe(ev, "code", "prompt_version"); pv != "" {
			referencees[pv] = true
			p := pieces[pv]
			if p == nil {
				rap.Comparer(f, etiqEv+" · code.prompt_version", "pièce « prompt système » présente dans pieces.json", "présente", "absente")
			} else if Outil(ev) == OutilModele {
				rap.Comparer(f, etiqEv+" · code.prompt_version", "media_type de la pièce « prompt système » (8.2)", MediaTexte, vide(p.MediaType))
				q, _ := PieceRedigeeTexte(pol, "prompt_systeme", "", string(p.Octets))
				rap.Comparer(f, etiqEv+" · code.prompt_version", "idempotence de la politique sur la pièce « prompt système » (EX-10.15)", string(p.Octets), string(q.Octets))
			}
		}
		// EX-10.16, EX-10.20 : policy.redaction non nul si et seulement si une référence est rédigée
		red := false
		for _, rf := range references(ev) {
			if r := rf.ref.Get("redacted"); r != nil && r.Kind == KindBool && r.Bool {
				red = true
			}
		}
		attRed := "null"
		if red && pol != nil {
			attRed = pol.Nom
		}
		rap.Comparer(f, etiqEv, "policy.redaction = nom de la politique si et seulement si une référence est rédigée (EX-10.20)", texteOuAbsent(ev.Get("policy").Get("redaction")), attRed)
	}
	// document d'ensemble de politique stocké comme pièce (EX-8.11)
	if shaPolitique != "" {
		if p := pieces[shaPolitique]; p != nil {
			referencees[shaPolitique] = true
			c, _ := CanoniqueIntegral(docPol)
			rap.Comparer(f, nom+"/pieces.json · politique", "pièce « document d'ensemble de politique » = JCS intégral de politique.json", string(c), string(p.Octets))
			rap.Comparer(f, nom+"/pieces.json · politique", "media_type (8.2)", MediaJSONExplicite, vide(p.MediaType))
		} else {
			rap.Note("evenements/%s : la pièce « document d'ensemble de politique » (%s) n'est pas dans pieces.json (EX-8.11 la stocke ; B.6 ne l'exige pas)", nom, abrege(shaPolitique))
		}
	}
	var non []string
	for _, s := range shas {
		if !referencees[s] {
			non = append(non, abrege(s))
		}
	}
	if len(non) > 0 {
		rap.Note("evenements/%s/pieces.json : pièce(s) non référencée(s) : %s", nom, strings.Join(non, ", "))
	}
	// pièce « arguments » de seq 7 confrontée à pieces-mcp (B.6)
	for _, ev := range evs {
		if Seq(ev) != 7 {
			continue
		}
		sha := chaineDe(ev, "execution", "arguments", "sha256")
		var trouves []string
		for cas, a := range ctx.appels {
			if chaineDe(a, "tool_announced") == Outil(ev) && chaineDe(a, "pieces", "arguments", "sha256") == sha {
				trouves = append(trouves, cas)
			}
		}
		sort.Strings(trouves)
		if len(trouves) > 0 {
			rap.Note("evenements/%s · seq 7 : pièce « arguments » identique à celle de pieces-mcp/%s", nom, strings.Join(trouves, ", "))
		} else {
			rap.Note("evenements/%s · seq 7 : aucun cas de pieces-mcp ne porte la même pièce « arguments » (%s) ; idempotence vérifiée ci-dessus seulement", nom, abrege(sha))
		}
	}
}

// controlerPieceRedigeable vérifie qu'une pièce JSON est en JCS intégral et
// que la politique réappliquée la laisse inchangée (EX-10.15).
func controlerPieceRedigeable(rap *Rapport, etiq string, ev *Value, chemin string, p *PieceFournie, pol *Politique) {
	f := FamilleEvenements
	portee, texte := porteeReference(ev, chemin)
	if portee == "" {
		if p.MediaType == MediaJSONExplicite || p.MediaType == "" {
			if v, err := ParseJSON(p.Octets); err == nil {
				rap.Comparer(f, etiq, "pièce en JCS intégral (8.1)", string(p.Octets), doitIntegral(v))
			} else {
				rap.Comparer(f, etiq, "pièce JSON analysable", "oui", err.Error())
			}
		}
		return
	}
	outil := ""
	if !strings.HasPrefix(Outil(ev), "noortrace.") {
		outil = Outil(ev)
	}
	if texte || strings.HasPrefix(p.MediaType, "text/") {
		q, _ := PieceRedigeeTexte(pol, portee, outil, string(p.Octets))
		rap.Comparer(f, etiq, "idempotence de la politique (EX-10.15, portée "+portee+")", string(p.Octets), string(q.Octets))
		return
	}
	v, err := ParseJSON(p.Octets)
	if err != nil {
		rap.Comparer(f, etiq, "pièce JSON analysable", "oui", err.Error())
		return
	}
	rap.Comparer(f, etiq, "pièce en JCS intégral (8.1)", string(p.Octets), doitIntegral(v))
	q, _, err := PieceRedigeeJSON(pol, portee, outil, v)
	if err == nil {
		rap.Comparer(f, etiq, "idempotence de la politique (EX-10.15, portée "+portee+")", string(p.Octets), string(q.Octets))
	}
}

func vide(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

func abrege(s string) string {
	if len(s) > 14 {
		return s[:10] + "…" + s[len(s)-4:]
	}
	return s
}

// ---------------------------------------------------------------- segment (12.2)

var clesEnteteSegment = []string{"epoch", "first_seq", "instance_id", "journal_id", "noortrace_segment", "opened_at", "org_id", "prev_hash", "recorder", "recorder_key_id"}

func controlerSegment(rap *Rapport, nom, chemin string, evs []*Value, attendu *Value) {
	f := FamilleEvenements
	octets, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("evenements/%s/segment.ndjson : %v", nom, err)
		return
	}
	etiq := nom + "/segment.ndjson"
	if bytes.HasPrefix(octets, bomUTF8) {
		rap.Comparer(f, etiq, "sans marque d'ordre d'octets (EX-12.3)", "oui", "non")
	}
	i := bytes.IndexByte(octets, '\n')
	if i < 0 {
		rap.Comparer(f, etiq, "en-tête terminé par \\n", "oui", "non")
		return
	}
	entete, err := ParseJSON(octets[:i])
	if err != nil {
		rap.Comparer(f, etiq, "en-tête JSON", "oui", err.Error())
		return
	}
	cEntete, err := Canonique(entete)
	if err != nil {
		rap.Comparer(f, etiq, "en-tête en JCS v0", "oui", err.Error())
		return
	}
	rap.Comparer(f, etiq, "en-tête en JCS v0 (EX-12.3)", string(octets[:i]), string(cEntete))
	rap.Comparer(f, etiq, "clés de l'en-tête (EX-12.3)", strings.Join(clesEnteteSegment, ","), strings.Join(clesTriees(entete), ","))
	attendusEntete := []struct{ cle, val string }{
		{"noortrace_segment", "0"}, {"epoch", "1"}, {"first_seq", "1"}, {"prev_hash", Zero32},
		{"recorder", VersionEnregistreurVecteurs},
	}
	if len(evs) > 0 {
		attendusEntete = append(attendusEntete,
			struct{ cle, val string }{"org_id", chaineDe(evs[0], "org_id")},
			struct{ cle, val string }{"journal_id", chaineDe(evs[0], "journal_id")},
			struct{ cle, val string }{"recorder_key_id", chaineDe(evs[0], "recorder_key_id")})
	}
	for _, a := range attendusEntete {
		rap.Comparer(f, etiq, "en-tête : "+a.cle+" (B.6, EX-12.3)", a.val, texteOuAbsent(entete.Get(a.cle)))
	}
	if t, ok := ParseHorodatage(chaineDe(entete, "opened_at")); !ok {
		rap.Comparer(f, etiq, "en-tête : opened_at horodatage CT-1 §3", "oui", chaineDe(entete, "opened_at"))
	} else if len(evs) > 0 {
		if t0, ok := Ts(evs[0]); ok && t.After(t0) {
			rap.Comparer(f, etiq, "en-tête : opened_at ≤ ts du premier événement", "oui", chaineDe(entete, "opened_at"))
		}
	}
	if h := attendu.Get("segment_header"); h != nil {
		comparerValeur(rap, f, etiq, "en-tête attendu (attendu.json segment_header)", h, entete)
	}
	// lignes : JCS v0 de chaque événement complet, suivi de \n ; rien d'autre
	var attenduOctets bytes.Buffer
	attenduOctets.Write(octets[:i+1])
	for _, ev := range evs {
		c, err := Canonique(ev)
		if err != nil {
			rap.Comparer(f, etiq, fmt.Sprintf("ligne de seq %d en JCS v0", Seq(ev)), "oui", err.Error())
			return
		}
		attenduOctets.Write(c)
		attenduOctets.WriteByte('\n')
	}
	egal := bytes.Equal(octets, attenduOctets.Bytes())
	diag := "identiques"
	if !egal {
		diag = premiereDifference(attenduOctets.Bytes(), octets)
	}
	rap.ComparerAvecNote(f, etiq, "octets = en-tête + JCS v0 des événements complets, un par ligne (EX-12.3)",
		fmt.Sprintf("%d octets, SHA-256 %s", attenduOctets.Len(), Hex0x(SHA256(attenduOctets.Bytes()))),
		fmt.Sprintf("%d octets, SHA-256 %s", len(octets), Hex0x(SHA256(octets))), egal, diag)
}

func clesTriees(v *Value) []string {
	k := v.Keys()
	sort.Strings(k)
	return k
}

func premiereDifference(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			ligne := bytes.Count(a[:i], []byte{'\n'}) + 1
			return fmt.Sprintf("première différence à l'octet %d (ligne %d)", i, ligne)
		}
	}
	return fmt.Sprintf("longueurs %d et %d, préfixe commun", len(a), len(b))
}

// ---------------------------------------------------------------- intentions (12.5)

var clesIntention = []string{"arguments", "host", "intent_id", "journal_id", "org_id", "ticket", "tool", "upstream_id", "written_at"}

var reIntentID = regexp.MustCompile(`^i-([0-9]{20})-([0-9]{12})$`)

func controlerIntentions(rap *Rapport, nom, dir string, evs []*Value, attendu, entrees *Value) {
	f := FamilleEvenements
	chemin := filepath.Join(dir, "intentions.ndjson")
	octets, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("evenements/%s/intentions.ndjson : %v", nom, err)
		return
	}
	etiq := nom + "/intentions.ndjson"
	if len(octets) == 0 || octets[len(octets)-1] != '\n' {
		rap.Comparer(f, etiq, "chaque ligne terminée par \\n (12.5)", "oui", "non")
	}
	lignes := strings.Split(strings.TrimSuffix(string(octets), "\n"), "\n")
	var vals []*Value
	for k, l := range lignes {
		v, err := ParseJSON([]byte(l))
		if err != nil {
			rap.Comparer(f, etiq, fmt.Sprintf("ligne %d JSON", k+1), "oui", err.Error())
			return
		}
		rap.Comparer(f, etiq, fmt.Sprintf("ligne %d en JCS intégral (EX-12.12)", k+1), l, doitIntegral(v))
		vals = append(vals, v)
	}
	rap.Comparer(f, etiq, "trois lignes : intention, contexte, levée (B.6)", "3", fmt.Sprint(len(vals)))
	if len(vals) < 1 {
		return
	}
	in := vals[0]
	rap.Comparer(f, etiq, "ligne intention à neuf clés (EX-12.12)", strings.Join(clesIntention, ","), strings.Join(clesTriees(in), ","))
	shaIntention := Hex0x(SHA256([]byte(lignes[0])))
	if a := chaineDe(attendu, "intention_sha256"); a != "" {
		rap.Comparer(f, etiq, "intention_sha256 = SHA-256 de la ligne intention sans \\n (EX-12.14)", a, shaIntention)
	}
	id := chaineDe(in, "intent_id")
	m := reIntentID.FindStringSubmatch(id)
	rap.Comparer(f, etiq, "intent_id de forme i-<époque sur 20 chiffres>-<compteur sur 12 chiffres> (EX-12.12)", "oui", oui(m != nil))
	if a := chaineDe(attendu, "intent_id"); a != "" {
		rap.Comparer(f, etiq, "intent_id = attendu.intent_id", a, id)
	}
	if m != nil {
		// l'époque est celle du bail, que porte l'en-tête du segment (12.2)
		if seg, err := os.ReadFile(filepath.Join(dir, "segment.ndjson")); err == nil {
			if i := strings.IndexByte(string(seg), '\n'); i > 0 {
				if ent, err := ParseJSON(seg[:i]); err == nil {
					ep, _ := EntierDe(ent.Get("epoch"))
					rap.Comparer(f, etiq, "époque de l'intent_id = epoch de l'en-tête de segment", fmt.Sprintf("%020d", ep), m[1])
				}
			}
		}
	}
	rap.Comparer(f, etiq, "upstream_id de forme e-<douze chiffres> (4.4 pas 9)", "oui", oui(reIDAmont.MatchString(chaineDe(in, "upstream_id"))))
	if h := chaineDe(entrees, "host", "id"); h != "" {
		rap.Comparer(f, etiq, "host = id de l'entrée de connexion d'hôte (EX-12.12)", h, chaineDe(in, "host"))
	}
	// l'appel d'écriture relayé correspondant
	ref := in.Get("arguments")
	var ev, decision *Value
	for _, e := range evs {
		if Outil(e) == chaineDe(in, "tool") && chaineDe(e, "execution", "status") == "executee" &&
			chaineDe(e, "execution", "arguments", "sha256") == chaineDe(ref, "sha256") {
			ev = e
		}
		if Outil(e) == OutilApprobation {
			decision = e
		}
	}
	if ev == nil {
		rap.Comparer(f, etiq, "événement executee de même outil et même pièce « arguments » (EX-12.14)", "présent", "absent")
		return
	}
	etiqEv := fmt.Sprintf("%s (seq %d)", etiq, Seq(ev))
	comparerValeur(rap, f, etiqEv, "arguments = référence complète de la pièce de l'événement (EX-12.12)", ev.Get("execution").Get("arguments"), ref)
	rap.Comparer(f, etiqEv, "org_id, journal_id, ticket de l'intention = ceux de l'événement",
		chaineDe(ev, "org_id")+" "+chaineDe(ev, "journal_id")+" "+texteOuAbsent(ev.Get("policy").Get("ticket")),
		chaineDe(in, "org_id")+" "+chaineDe(in, "journal_id")+" "+texteOuAbsent(in.Get("ticket")))
	if tw, ok := ParseHorodatage(chaineDe(in, "written_at")); ok {
		te, _ := Ts(ev)
		rap.Comparer(f, etiqEv, "written_at ≤ ts de l'événement relayé", "oui", oui(!tw.After(te)))
		if decision != nil {
			td, _ := Ts(decision)
			rap.Comparer(f, etiqEv, "written_at ≥ ts de la décision (l'intention suit l'approbation, 4.4 pas 8)", "oui", oui(!tw.Before(td)))
		}
	} else {
		rap.Comparer(f, etiqEv, "written_at horodatage CT-1 §3", "oui", chaineDe(in, "written_at"))
	}
	if len(vals) >= 2 {
		cx := vals[1]
		rap.Comparer(f, etiqEv, "ligne contexte : intent_context = intent_id", id, chaineDe(cx, "intent_context"))
		rap.Comparer(f, etiqEv, "ligne contexte : clés", "event,intent_context", strings.Join(clesTriees(cx), ","))
		partiel := cx.Get("event")
		rap.Comparer(f, etiqEv, "événement partiel : clés (12.5)", "approval,code,context,delegation,effects,execution,intent,policy", strings.Join(clesTriees(partiel), ","))
		for _, k := range []string{"delegation", "code", "intent", "policy", "approval", "context"} {
			comparerValeur(rap, f, etiqEv, "événement partiel : "+k+" = celui de l'événement relayé", ev.Get(k), partiel.Get(k))
		}
		comparerValeur(rap, f, etiqEv, "événement partiel : execution = { tool, arguments } de l'événement relayé",
			Objet("arguments", Copier(ev.Get("execution").Get("arguments")), "tool", Chaine(Outil(ev))), partiel.Get("execution"))
		comparerValeur(rap, f, etiqEv, "événement partiel : effects = [] (frontal MCP : aucun effet déclaré par le SDK, 12.5)", TableauVide(), partiel.Get("effects"))
	}
	if len(vals) >= 3 {
		comparerValeur(rap, f, etiqEv, "ligne levée {\"lifted\", \"seq\"} (EX-12.13)", Objet("lifted", Chaine(id), "seq", Entier(Seq(ev))), vals[2])
	}
}

// ---------------------------------------------------------------- corrélation (5.6)

// formatDeReponse reconnaît le format d'une réponse de modèle à sa forme.
func formatDeReponse(rep *Value) string {
	switch {
	case chaineDe(rep, "type") == "message" || EstTableau(rep.Get("content")):
		return FormatAnthropic
	case EstTableau(rep.Get("choices")):
		return FormatChat
	case chaineDe(rep, "object") == "response" || EstTableau(rep.Get("output")):
		return FormatResponses
	}
	return ""
}

// inscrit est un échange du registre de corrélation (5.6), recalculé
// depuis les entrées brutes de la démonstration (entrees.json).
type inscrit struct {
	seq           int64
	t             time.Time
	run, groupe   string
	format        string
	clair, redige *Value
	appels        []AppelOutil
	consomme      []bool
}

// Correlation est le résultat de 5.6 pour un appel d'outil : l'échange
// retenu (0 sans correspondance), l'identifiant de l'appel du modèle ("" sans
// correspondance), ou le seq de l'appel retenu dont il hérite (EX-7.12).
type Correlation struct {
	EchangeSeq int64
	AppelID    string
	Herite     int64
}

// controlerEchangesEtCorrelation recalcule, depuis entrees.json, les pièces et
// grandeurs des échanges de modèle (5.3, 5.5) et la corrélation des appels
// d'outils (5.6, EX-5.22), et confronte aux événements.
func controlerEchangesEtCorrelation(rap *Rapport, nom string, evs []*Value, entrees *Value, pol *Politique) map[int64]Correlation {
	f := FamilleEvenements
	resultats := map[int64]Correlation{}
	if entrees == nil {
		rap.Erreur("evenements/%s/entrees.json : absent (B.6)", nom)
		return resultats
	}
	parSeq := map[int64]*Value{}
	for _, ev := range evs {
		parSeq[Seq(ev)] = ev
	}
	hote := entrees.Get("host")
	san := hote.Get("tool_name_sanitize")
	gabarit := chaineDe(hote, "tool_name_template")
	normaliser := san != nil && san.Kind == KindBool && san.Bool
	const fenetre = 600000 * time.Millisecond // model.correlation_window_ms par défaut (EX-5.22)
	delegation := func(run string) *Value {
		r := Nul()
		if run != "" {
			r = Chaine(run)
		}
		return Objet("launched_by", Copier(hote.Get("launched_by")), "on_behalf_of", Copier(hote.Get("on_behalf_of")), "scope", Copier(hote.Get("scope")), "run_id", r)
	}
	// 1. échanges de modèle
	var registre []*inscrit
	if xs := entrees.Get("exchanges"); EstTableau(xs) {
		for _, x := range xs.Arr {
			seq, _ := EntierDe(x.Get("seq"))
			ev := parSeq[seq]
			etiq := fmt.Sprintf("%s · seq %d", nom, seq)
			if ev == nil || Outil(ev) != OutilModele {
				rap.Comparer(f, etiq, "échange de modèle à ce seq (entrees.json)", "oui", "non")
				continue
			}
			format := chaineDe(x, "format")
			c := &CalculModele{Format: format, Libelle: chaineDe(x, "provider_label"), Requete: x.Get("request"), Statut: 200, ContentType: x.Get("response_content_type")}
			corps := []byte(chaineDe(x, "response_body"))
			if TypeDeMedia(chaineDe(x, "response_content_type")) == MediaFluxSSE {
				evsSSE, _ := AnalyserSSE(corps)
				cons, _ := Consolider(format, evsSSE)
				c.Consolidation, c.Reponse, c.EstErreur = cons, cons.Forme, cons.EstErreur()
			} else if v, err := ParseJSON(corps); err == nil {
				c.Reponse = v
			}
			calculerEchange(pol, c)
			ref := func(p *Piece) *Value {
				if p == nil {
					return Nul()
				}
				o := Objet("sha256", Chaine(p.SHA256Hex()), "length", Entier(int64(len(p.Octets))), "redacted", Booleen(p.Redigee))
				if p.MediaType != "" {
					Definir(o, "media_type", Chaine(p.MediaType))
				}
				return o
			}
			comparerValeur(rap, f, etiq, "pièce « requête » recalculée depuis entrees.json (5.3.1 pas 3)", ref(c.PieceRequete), ev.Get("execution").Get("arguments"))
			comparerValeur(rap, f, etiq, "pièce « réponse » recalculée (5.3.1 pas 7, 5.4)", ref(c.PieceReponse), ev.Get("execution").Get("result"))
			comparerValeur(rap, f, etiq, "intent tiré de la réponse rédigée (EX-5.21)", c.Intent, ev.Get("intent"))
			comparerValeur(rap, f, etiq, "code.model (EX-5.19)", c.CodeModel, ev.Get("code").Get("model"))
			comparerValeur(rap, f, etiq, "code.prompt_version (EX-8.6)", c.PromptVersion, ev.Get("code").Get("prompt_version"))
			comparerValeur(rap, f, etiq, "délégation = entrée de connexion d'hôte et run_id déclaré (EX-5.8, EX-7.2)", delegation(chaineDe(x, "run_id")), ev.Get("delegation"))
			t, _ := ParseHorodatage(chaineDe(x, "t_complet"))
			var redige *Value
			if c.PieceReponse != nil {
				redige, _ = ParseJSON(c.PieceReponse.Octets)
			}
			e := &inscrit{seq: seq, t: t, run: chaineDe(x, "run_id"), groupe: chaineDe(x, "host_group"), format: format, clair: c.Reponse, redige: redige, appels: AppelsOutils(format, c.Reponse)}
			e.consomme = make([]bool, len(e.appels))
			registre = append(registre, e)
		}
	}
	// 2. appels d'outils
	if xs := entrees.Get("calls"); EstTableau(xs) {
		for _, x := range xs.Arr {
			seq, _ := EntierDe(x.Get("seq"))
			ev := parSeq[seq]
			etiq := fmt.Sprintf("%s · seq %d", nom, seq)
			if ev == nil || SorteDe(Outil(ev)) != SorteOutil {
				rap.Comparer(f, etiq, "appel d'outil à ce seq (entrees.json)", "oui", "non")
				continue
			}
			lu := LireRequeteHote([]byte(chaineDe(x, "host_line")), "ligne")
			if lu.Msg == nil {
				rap.Comparer(f, etiq, "ligne d'hôte admise (4.4 pas 1)", "oui", texteOuAbsent(lu.Erreur))
				continue
			}
			annonce := chaineDe(lu.Msg, "params", "name")
			rap.Comparer(f, etiq, "execution.tool = params.name reçu", annonce, Outil(ev))
			run := chaineDe(lu.Msg, "params", "_meta", "noortrace/delegation", "run_id")
			comparerValeur(rap, f, etiq, "délégation = entrée de connexion d'hôte et run_id déclaré (EX-7.2)", delegation(run), ev.Get("delegation"))
			// ré-émission après approbation : reprend de l'appel retenu (4.4 pas 3, EX-7.12)
			if ap := ev.Get("approval"); EstObjet(ap) {
				var retenue *Value
				for _, e := range evs {
					if chaineDe(e, "execution", "status") == "retenue" && chaineDe(e, "policy", "ticket") == chaineDe(ap, "ticket") {
						retenue = e
					}
				}
				if retenue == nil {
					rap.Comparer(f, etiq, "appel retenu du ticket "+chaineDe(ap, "ticket"), "présent", "absent")
					continue
				}
				resultats[seq] = Correlation{Herite: Seq(retenue)}
				for _, k := range []string{"intent", "code"} {
					comparerValeur(rap, f, etiq, fmt.Sprintf("%s repris de l'appel retenu seq %d (EX-7.12)", k, Seq(retenue)), retenue.Get(k), ev.Get(k))
				}
				for _, k := range []string{"rule", "decision", "ticket"} {
					comparerValeur(rap, f, etiq, fmt.Sprintf("policy.%s repris de l'appel retenu seq %d (EX-7.12)", k, Seq(retenue)), retenue.Get("policy").Get(k), ev.Get("policy").Get(k))
				}
				continue
			}
			t, _ := ParseHorodatage(chaineDe(x, "t_recu"))
			cible, err := CanoniqueIntegral(argsOuVide(lu.Msg.Get("params").Get("arguments")))
			if err != nil {
				continue
			}
			candidats := []*inscrit{}
			for _, e := range registre {
				if e.groupe != chaineDe(x, "host_group") || (run != "" && e.run != "" && e.run != run) || e.t.After(t) || t.Sub(e.t) > fenetre {
					continue
				}
				candidats = append(candidats, e)
			}
			sort.SliceStable(candidats, func(i, j int) bool {
				if !candidats[i].t.Equal(candidats[j].t) {
					return candidats[i].t.After(candidats[j].t)
				}
				return candidats[i].seq > candidats[j].seq
			})
			var trouve *inscrit
			var appel AppelOutil
			vu := NomVuParModele(annonce, gabarit, normaliser)
			for _, e := range candidats {
				for j, a := range e.appels {
					if e.consomme[j] || (a.Nom != annonce && a.Nom != vu) {
						continue
					}
					args := a.Arguments
					if EstChaine(args) {
						v, err := ParseJSON([]byte(args.Str))
						if err != nil {
							continue // chaîne arguments non JSON : ne correspond jamais
						}
						args = v
					}
					if c, err := CanoniqueIntegral(argsOuVide(args)); err == nil && string(c) == string(cible) {
						trouve, appel = e, a
						e.consomme[j] = true
						break
					}
				}
				if trouve != nil {
					break
				}
			}
			if trouve == nil {
				resultats[seq] = Correlation{}
				for _, k := range []string{"intent", "code/model", "code/prompt_version"} {
					v := ev.Get(k)
					if k != "intent" {
						v = ev.Get("code").Get(strings.TrimPrefix(k, "code/"))
					}
					rap.Comparer(f, etiq, k+" sans correspondance : null (EX-5.22)", "null", texteOuAbsent(v))
				}
				continue
			}
			resultats[seq] = Correlation{EchangeSeq: trouve.seq, AppelID: appel.ID}
			texteRedige, _ := TexteAvantAppel(trouve.format, trouve.redige, appel)
			texteClair, _ := TexteAvantAppel(trouve.format, trouve.clair, appel)
			intent := Nul()
			if texteRedige != "" || texteClair != "" {
				redige := texteRedige != texteClair
				if redige || utf8.RuneCountInString(texteRedige) > 4096 {
					intent = Objet("sha256", Chaine(Hex0x(SHA256([]byte(texteRedige)))), "length", Entier(int64(len(texteRedige))), "redacted", Booleen(redige), "media_type", Chaine(MediaTexte))
				} else {
					intent = Chaine(texteRedige)
				}
			}
			comparerValeur(rap, f, etiq, fmt.Sprintf("intent corrélé à seq %d, tiré de la réponse rédigée (EX-5.22)", trouve.seq), intent, ev.Get("intent"))
			ex := parSeq[trouve.seq]
			for _, k := range []string{"model", "prompt_version"} {
				comparerValeur(rap, f, etiq, fmt.Sprintf("code.%s = celui de seq %d (EX-5.22)", k, trouve.seq), ex.Get("code").Get(k), ev.Get("code").Get(k))
			}
		}
	}
	// 3. décision : code de l'appel retenu (7.2)
	var retenue *Value
	for _, ev := range evs {
		if chaineDe(ev, "execution", "status") == "retenue" {
			retenue = ev
		}
		if Outil(ev) == OutilApprobation && retenue != nil {
			comparerValeur(rap, f, fmt.Sprintf("%s · seq %d", nom, Seq(ev)), fmt.Sprintf("code de la décision = celui de l'appel retenu seq %d (7.2)", Seq(retenue)), retenue.Get("code"), ev.Get("code"))
		}
	}
	return resultats
}

func argsOuVide(v *Value) *Value {
	if v == nil {
		return ObjetVide()
	}
	return v
}

// controlerContexteAppels : context d'un appel d'outil = pièce de la
// définition servie, puis pièce « liste annoncée » (EX-4.45, EX-7.7), depuis
// la liste servie d'entrees.json.
func controlerContexteAppels(rap *Rapport, nom string, evs []*Value, entrees *Value, pieces map[string]*PieceFournie) {
	f := FamilleEvenements
	servie := entrees.Get("served_list")
	if !EstTableau(servie) {
		return
	}
	pl, err := PieceJSON(Objet("tools", servie), false, MediaJSONExplicite)
	if err != nil {
		return
	}
	for _, ev := range evs {
		if SorteDe(Outil(ev)) != SorteOutil {
			continue
		}
		att := TableauVide()
		for _, d := range servie.Arr {
			if chaineDe(d, "name") == Outil(ev) {
				if pd, err := PieceJSON(d, false, MediaJSONExplicite); err == nil {
					att.Arr = append(att.Arr, Objet("sha256", Chaine(pd.SHA256Hex()), "length", Entier(int64(len(pd.Octets))), "redacted", Booleen(false), "media_type", Chaine(MediaJSONExplicite), "kind", Chaine("autre")))
				}
			}
		}
		att.Arr = append(att.Arr, Objet("sha256", Chaine(pl.SHA256Hex()), "length", Entier(int64(len(pl.Octets))), "redacted", Booleen(false), "media_type", Chaine(MediaJSONExplicite), "kind", Chaine("autre")))
		comparerValeur(rap, f, fmt.Sprintf("%s · seq %d", nom, Seq(ev)), "context = définition servie, liste annoncée (EX-4.45, EX-7.7)", att, ev.Get("context"))
	}
	if p := pieces[pl.SHA256Hex()]; p != nil {
		rap.Comparer(f, nom, "pièce « liste annoncée » fournie = JCS intégral de {\"tools\": liste servie}", string(pl.Octets), string(p.Octets))
	}
}

// ---------------------------------------------------------------- effets (EX-7.6)

func controlerEffets(rap *Rapport, nom string, evs []*Value, pieces map[string]*PieceFournie, docPol *Value) {
	f := FamilleEvenements
	for _, ev := range evs {
		if SorteDe(Outil(ev)) != SorteOutil {
			continue
		}
		etiq := fmt.Sprintf("%s · seq %d", nom, Seq(ev))
		if chaineDe(ev, "execution", "status") != "executee" {
			comparerValeur(rap, f, etiq, "effects [] pour un appel retenu ou refusé (EX-7.6)", TableauVide(), ev.Get("effects"))
			continue
		}
		alias, origine, ok := DecouperNomAnnonce(Outil(ev))
		if !ok {
			continue
		}
		conf := docPol.Get("servers").Get(alias)
		outil := conf.Get("tools").Get(origine)
		classe := chaineDe(outil, "class")
		source := "configuration (policy.servers." + alias + ".tools." + origine + ".class)"
		if classe == "" {
			classe = chaineDe(conf, "class_default")
			source = "configuration (class_default du serveur)"
		}
		if classe == "" {
			classe = "ecriture"
			source = "défaut"
		}
		gabarit := outil.Get("effects")
		var obt *Value
		var note string
		switch {
		case EstTableau(gabarit):
			args := valeurPiece(pieces, chaineDe(ev, "execution", "arguments", "sha256"))
			res := valeurPiece(pieces, chaineDe(ev, "execution", "result", "sha256"))
			obt, note = evaluerGabarit(gabarit, args, res)
			note = "gabarit évalué sur les valeurs rédigées des pièces (EX-7.6)" + note
		case classe == "ecriture":
			obt = &Value{Kind: KindArray, Arr: []*Value{Objet("system", Chaine(alias), "action", Chaine("ecriture"), "object", Chaine(origine), "amount", Nul(), "currency", Nul())}}
			note = "effet par défaut d'une classe ecriture ; classe : " + source
		default:
			obt = TableauVide()
			note = "classe lecture sans gabarit ; classe : " + source
		}
		rap.ComparerAvecNote(f, etiq, "effects (EX-7.6)", doitIntegral(ev.Get("effects")), doitIntegral(obt), MemeValeur(obt, ev.Get("effects")), note)
		if Seq(ev) == 7 {
			e := ev.Get("effects")
			if EstTableau(e) && len(e.Arr) == 1 {
				x := e.Arr[0]
				rap.Comparer(f, etiq, "effet de 19.2 pas 7 (system, action, amount, currency ; object PAY-…)", "demo ecriture 7400.00 CHF PAY-",
					chaineDe(x, "system")+" "+chaineDe(x, "action")+" "+chaineDe(x, "amount")+" "+chaineDe(x, "currency")+" "+prefixe(chaineDe(x, "object"), 4))
			} else {
				rap.Comparer(f, etiq, "un effet unique (19.2 pas 7)", "1", fmt.Sprint(len(e.Arr)))
			}
		}
	}
}

func prefixe(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func valeurPiece(pieces map[string]*PieceFournie, sha string) *Value {
	p := pieces[sha]
	if p == nil {
		return nil
	}
	v, err := ParseJSON(p.Octets)
	if err != nil {
		return nil
	}
	return v
}

var (
	reMontantCT1 = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$`)
	reDeviseCT1  = regexp.MustCompile(`^[A-Z]{3}$`)
)

// tronquerPoints tronque une chaîne à n points de code.
func tronquerPoints(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// evaluerGabarit applique le gabarit d'effets d'EX-7.6 : pointeurs résolus
// dans les valeurs rédigées, conversion (chaîne telle quelle, autre valeur en
// JCS intégral, null ou non résolu : effet non résolu), extraction (première
// correspondance, premier groupe s'il a participé), bornes de CT-1 ; un effet
// non résolu ou invalide est omis.
func evaluerGabarit(gabarit, args, res *Value) (*Value, string) {
	out := TableauVide()
	var notes []string
	racine := Objet("arguments", argsOuNul(args), "result", argsOuNul(res))
	valeur := func(spec *Value) (*Value, bool) {
		if spec == nil || spec.IsNull() {
			return Nul(), true
		}
		if !EstChaine(spec) {
			return nil, false
		}
		s := spec.Str
		if !strings.HasPrefix(s, "/") {
			return Chaine(s), true // chaîne fixe
		}
		jetons, err := DecouperPointeur(s)
		if err != nil {
			return nil, false
		}
		_, _, _, v := Resoudre(racine, jetons)
		if v == nil || v.IsNull() {
			return nil, false
		}
		if EstChaine(v) {
			return Chaine(v.Str), true
		}
		return Chaine(doitIntegral(v)), true
	}
	for i, g := range gabarit.Arr {
		obj, ok1 := valeur(g.Get("object"))
		amt, ok2 := valeur(g.Get("amount"))
		cur, ok3 := valeur(g.Get("currency"))
		if !ok1 || !ok2 || !ok3 {
			notes = append(notes, fmt.Sprintf("effet %d omis : pointeur non résolu", i))
			continue
		}
		if ex := g.Get("extract"); EstChaine(ex) {
			if raison := ErreurMotifCommun(ex.Str); raison != "" {
				notes = append(notes, fmt.Sprintf("effet %d omis : extract hors du sous-ensemble commun", i))
				continue
			}
			re := regexp.MustCompile(ex.Str)
			loc := re.FindStringSubmatchIndex(obj.Str)
			if loc == nil {
				notes = append(notes, fmt.Sprintf("effet %d omis : extraction sans correspondance", i))
				continue
			}
			if len(loc) >= 4 && loc[2] >= 0 {
				obj = Chaine(obj.Str[loc[2]:loc[3]])
			} else {
				obj = Chaine(obj.Str[loc[0]:loc[1]])
			}
		}
		o := tronquerPoints(obj.Str, 512)
		switch {
		case o == "":
			notes = append(notes, fmt.Sprintf("effet %d omis : objet vide", i))
			continue
		case EstChaine(amt) && !reMontantCT1.MatchString(amt.Str):
			notes = append(notes, fmt.Sprintf("effet %d omis : montant hors format", i))
			continue
		case EstChaine(cur) && !reDeviseCT1.MatchString(cur.Str):
			notes = append(notes, fmt.Sprintf("effet %d omis : devise hors format", i))
			continue
		case amt.IsNull() != cur.IsNull():
			notes = append(notes, fmt.Sprintf("effet %d omis : couple montant/devise incomplet", i))
			continue
		}
		out.Arr = append(out.Arr, Objet("system", Chaine(tronquerPoints(chaineDe(g, "system"), 128)), "action", Copier(g.Get("action")), "object", Chaine(o), "amount", amt, "currency", cur))
	}
	n := ""
	if len(notes) > 0 {
		n = " ; " + strings.Join(notes, " ; ")
	}
	return out, n
}

func argsOuNul(v *Value) *Value {
	if v == nil {
		return Nul()
	}
	return v
}

// nomCorrespond applique EX-5.22 pas 1 sans la configuration de la connexion
// d'hôte (absente des vecteurs) : égalité, puis normalisation
// tool_name_sanitize (caractères hors A-Z a-z 0-9 _ - remplacés par « _ ») du
// gabarit par défaut {tool_announced}, puis gabarit de Claude Code
// mcp__noortrace__{tool_announced} normalisé (exemple de 5.6).
func nomCorrespond(vu, annonce string) (string, bool) {
	switch {
	case vu == annonce:
		return "égalité", true
	case vu == normaliserNomOutil(annonce):
		return "gabarit {tool_announced} avec tool_name_sanitize", true
	case vu == normaliserNomOutil("mcp__noortrace__"+annonce):
		return "gabarit mcp__noortrace__{tool_announced} avec tool_name_sanitize", true
	}
	return "", false
}

func normaliserNomOutil(s string) string {
	var b strings.Builder
	for _, r := range s {
		if estAlnumASCII(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// valeursSupplementaires confronte les clés de attendu.json qui ne sont pas
// dans la liste de B.6 mais que le vecteur déclare : bornes de séquence,
// identité, outils, longueur du document de politique, segment, erreur
// rendue pour l'appel retenu, période (racine, nonce, empreinte).
func valeursSupplementaires(rap *Rapport, nom, dir string, evs []*Value, attendu, docPol *Value) {
	f := FamilleEvenements
	if len(evs) == 0 {
		return
	}
	if v := attendu.Get("first_seq"); v != nil {
		rap.Comparer(f, nom, "first_seq", texteOuAbsent(v), fmt.Sprint(Seq(evs[0])))
	}
	if v := attendu.Get("last_seq"); v != nil {
		rap.Comparer(f, nom, "last_seq", texteOuAbsent(v), fmt.Sprint(Seq(evs[len(evs)-1])))
	}
	if v := attendu.Get("org_id"); v != nil {
		rap.Comparer(f, nom, "org_id = keccak256(\"assureur-demo\")", texteOuAbsent(v), Hex0x(Keccak256([]byte(SlugOrganisation))))
	}
	if v := attendu.Get("journal_id"); v != nil {
		rap.Comparer(f, nom, "journal_id = keccak256(\"journal-demo\")", texteOuAbsent(v), JournalIDVecteurs())
	}
	if v := attendu.Get("policy_version"); v != nil {
		rap.Comparer(f, nom, "policy_version = politique.version", texteOuAbsent(v), chaineDe(docPol, "version"))
	}
	if v := attendu.Get("policy_length"); v != nil && docPol != nil {
		c, _ := CanoniqueIntegral(docPol)
		rap.Comparer(f, nom, "policy_length = longueur du JCS intégral de politique.json", texteOuAbsent(v), fmt.Sprint(len(c)))
	}
	parSeq := map[int64]*Value{}
	for _, ev := range evs {
		parSeq[Seq(ev)] = ev
	}
	if l := attendu.Get("events"); EstTableau(l) {
		for _, x := range l.Arr {
			if t := x.Get("tool"); t != nil {
				seq, _ := entierDe(x, "seq")
				rap.Comparer(f, fmt.Sprintf("%s · seq %d", nom, seq), "execution.tool", texteOuAbsent(t), Outil(parSeq[seq]))
			}
		}
	}
	// segment : empreinte et longueur des octets reconstruits (en-tête lu, lignes JCS v0)
	if a, b := attendu.Get("segment_sha256"), attendu.Get("segment_length"); a != nil || b != nil {
		octets, err := os.ReadFile(filepath.Join(dir, "segment.ndjson"))
		if err == nil {
			if i := bytes.IndexByte(octets, '\n'); i >= 0 {
				var buf bytes.Buffer
				buf.Write(octets[:i+1])
				for _, ev := range evs {
					c, _ := Canonique(ev)
					buf.Write(c)
					buf.WriteByte('\n')
				}
				if a != nil {
					rap.Comparer(f, nom, "segment_sha256 (en-tête + lignes JCS v0 recalculées)", texteOuAbsent(a), Hex0x(SHA256(buf.Bytes())))
				}
				if b != nil {
					rap.Comparer(f, nom, "segment_length", texteOuAbsent(b), fmt.Sprint(buf.Len()))
				}
			}
		}
	}
	// erreur rendue à l'hôte pour l'appel retenu (mode « erreur », 4.4 pas 6)
	for _, x := range attendu.Obj {
		if !strings.HasPrefix(x.Key, "error_rendered_seq_") {
			continue
		}
		seq, _ := EntierDe(&Value{Kind: KindNumber, Num: strings.TrimPrefix(x.Key, "error_rendered_seq_")})
		ev := parSeq[seq]
		mode := chaineDe(docPol, "approval", "mode")
		if ev == nil || chaineDe(ev, "execution", "status") != "retenue" {
			rap.Comparer(f, nom, x.Key+" : événement retenue à ce seq", "oui", "non")
			continue
		}
		etat := "en_attente"
		obt := Objet("code", Entier(-32015), "message", Chaine(MessagesErreurs[-32015]), "data", Objet("ticket", Copier(ev.Get("policy").Get("ticket")), "state", Chaine(etat)))
		comparerValeur(rap, f, fmt.Sprintf("%s · seq %d", nom, seq), "erreur -32015 rendue en mode « "+mode+" » (4.4 pas 6, table de 4.4)", x.Val, obt)
	}
	// période (CT-1 §9, §10) : heure des ts, nonce de la période 1, racine des événements
	if p := attendu.Get("period"); EstObjet(p) {
		t0, _ := Ts(evs[0])
		debut := t0.Unix() - t0.Unix()%3600
		rap.Comparer(f, nom, "period.period_start (heure UTC des ts)", texteOuAbsent(p.Get("period_start")), fmt.Sprint(debut))
		rap.Comparer(f, nom, "period.period_end", texteOuAbsent(p.Get("period_end")), fmt.Sprint(debut+3600))
		rap.ComparerAvecNote(f, nom, "period.nonce = SHA-256(\""+EtiquetteNonce+"1\")", texteOuAbsent(p.Get("nonce")), NonceVecteurs(1),
			texteOuAbsent(p.Get("nonce")) == NonceVecteurs(1), "N = 1 : première période du journal (l'annexe B ne dit pas ce que N numérote)")
		var D [][]byte
		for _, ev := range evs {
			if t, ok := Ts(ev); ok && t.Unix() >= debut && t.Unix() < debut+3600 {
				h, _, _ := HashEvenement(ev)
				D = append(D, h)
			}
		}
		rap.Comparer(f, nom, "period.root = racine RFC 6962 des hash des événements de la période (CT-1 §9)", texteOuAbsent(p.Get("root")), Hex0x(Racine(D)))
		if ph := p.Get("period_hash"); ph != nil {
			var man *Value
			filepath.WalkDir(dir, func(chemin string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() && d.Name() == "manifeste.json" && man == nil {
					if b, err := os.ReadFile(chemin); err == nil {
						man, _ = ParseJSON(b)
					}
				}
				return nil
			})
			if man == nil {
				horsPerimetre(rap, f, nom, "period.period_hash", texteOuAbsent(ph), "aucun manifeste fourni : generated_at n'est pas dans les vecteurs (B.6)")
			} else {
				h, _, err := PeriodHash(man)
				obt := ""
				if err != nil {
					obt = err.Error()
				} else {
					obt = Hex0x(h)
				}
				rap.Comparer(f, nom, "period.period_hash = SHA-256(P_M ‖ JCS_v0(manifeste du dossier)) (CT-1 §10)", texteOuAbsent(ph), obt)
				rap.Comparer(f, nom, "manifeste du dossier : root, nonce, période = valeurs recalculées",
					fmt.Sprintf("%s %s %d %d", Hex0x(Racine(D)), NonceVecteurs(1), debut, debut+3600),
					fmt.Sprintf("%s %s %s %s", chaineDe(man, "root"), chaineDe(man, "nonce"), texteOuAbsent(man.Get("period_start")), texteOuAbsent(man.Get("period_end"))))
			}
		}
	}
}
