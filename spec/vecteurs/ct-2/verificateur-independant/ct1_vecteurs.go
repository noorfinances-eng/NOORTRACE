// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/vecteurs.go).

// Parcours des familles de vecteurs et confrontation aux valeurs attendues.
//
// CT-1 ne fixe pas la disposition des fichiers de vecteurs. Deux dispositions
// sont reconnues, décrites dans README.md :
//   - celle des vecteurs publiés sous spec/vecteurs/ct-1 (cles/, journal-*/,
//     merkle/arbres.json, manifestes/ avec attendu.json, dossiers/*/attendu.json) ;
//   - une disposition de repli documentée (cles.json, jcs/, evenements/,
//     chaines/, arbres/, dossiers/attendus.json).
//
// Les fichiers sont reconnus par leur contenu autant que par leur nom.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// VerifierVecteurs parcourt la racine des vecteurs et rend le rapport.
func VerifierVecteurs(racine string, strict bool) *Rapport {
	rap := &Rapport{Racine: racine, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}, Details: []string{}}
	cles := familleCles(rap, racine)
	familleJCS(rap, racine)
	journal := familleJournaux(rap, racine, cles, strict)
	familleArbres(rap, racine)
	familleManifestes(rap, racine, cles, journal, strict)
	familleDossiers(rap, racine, strict)
	return rap
}

// lireFichierJSON lit et analyse un fichier ; l'erreur est consignée.
func lireFichierJSON(rap *Rapport, chemin string) *Value {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("%s : %v", chemin, err)
		return nil
	}
	v, err := ParseJSON(octets)
	if err != nil {
		rap.Erreur("%s : %v", chemin, err)
		return nil
	}
	return v
}

// fichiersAvecExtension liste les fichiers d'un répertoire portant l'une des
// extensions données.
func fichiersAvecExtension(dir string, extensions ...string) []string {
	entrees, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entrees {
		if e.IsDir() {
			continue
		}
		for _, ext := range extensions {
			if strings.HasSuffix(e.Name(), ext) {
				out = append(out, filepath.Join(dir, e.Name()))
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func relatif(racine, chemin string) string {
	r, err := filepath.Rel(racine, chemin)
	if err != nil {
		return chemin
	}
	return r
}

func fichierExiste(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func oui(b bool) string {
	if b {
		return "oui"
	}
	return "non"
}

func errTexte(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------- attendus

var reControle = regexp.MustCompile(`^[DECMPA]-[0-9]+$`)

// lireAttendu lit le verdict attendu d'un vecteur, sous l'une des formes :
//   - { "valide": bool, "controles_en_echec": [...] } ou { "valide": bool,
//     "diagnostics": [{ "controle": ... }] } ou { "valide": bool, "controle": "..." } ;
//   - { "expected": "valide" | "E-7" | [...] } (ou "attendu").
//
// Rend (valide, contrôles attendus en échec, déclaré).
func lireAttendu(v *Value) (bool, []string, bool) {
	if v == nil || v.Kind != KindObject {
		return true, nil, false
	}
	if e := v.Get("expected"); e != nil {
		return interpreterAttendu(e)
	}
	if e := v.Get("attendu"); e != nil {
		return interpreterAttendu(e)
	}
	va := v.Get("valide")
	if va == nil || va.Kind != KindBool {
		return true, nil, false
	}
	var ids []string
	if c := v.Get("controles_en_echec"); c != nil && c.Kind == KindArray {
		for _, x := range c.Arr {
			if x.Kind == KindString {
				ids = append(ids, x.Str)
			}
		}
	}
	if d := v.Get("diagnostics"); len(ids) == 0 && d != nil && d.Kind == KindArray {
		for _, x := range d.Arr {
			if s := chaineDe(x, "controle"); s != "" && !dansEnum(s, ids) {
				ids = append(ids, s)
			}
		}
	}
	if s := chaineDe(v, "controle"); len(ids) == 0 && s != "" {
		ids = append(ids, s)
	}
	return va.Bool, ids, true
}

func interpreterAttendu(e *Value) (bool, []string, bool) {
	switch e.Kind {
	case KindString:
		s := strings.TrimSpace(e.Str)
		switch strings.ToLower(s) {
		case "valide", "valid", "ok":
			return true, nil, true
		}
		return false, []string{s}, true
	case KindArray:
		var ids []string
		for _, x := range e.Arr {
			if x.Kind == KindString {
				ids = append(ids, strings.TrimSpace(x.Str))
			}
		}
		if len(ids) == 0 {
			return true, nil, true
		}
		return false, ids, true
	case KindBool:
		return e.Bool, nil, true
	}
	return true, nil, false
}

// ---------------------------------------------------------------- clés

// familleCles lit les clés de test (cles/cles-test.json, ou cles.json à la
// racine) et le jeu de clés publiques (cles/cles.json). Recalcule graines,
// clés publiques, encodage PKCS#8, nonces, org_id et journal_id (keccak256).
// Rend le jeu de clés publiques pour les autres familles.
func familleCles(rap *Rapport, racine string) *JeuCles {
	var jeu *JeuCles
	var fichiers []string
	for _, c := range []string{filepath.Join(racine, "cles", "cles-test.json"), filepath.Join(racine, "cles.json")} {
		if fichierExiste(c) {
			fichiers = append(fichiers, c)
		}
	}
	for _, f := range fichiersAvecExtension(filepath.Join(racine, "cles"), ".json") {
		if !dansEnum(f, fichiers) {
			fichiers = append(fichiers, f)
		}
	}
	if len(fichiers) == 0 {
		rap.Note("famille clés : aucun fichier (cles/*.json ou cles.json à la racine) ; les signatures des familles journaux et manifestes ne pourront pas être vérifiées")
		return nil
	}
	for _, f := range fichiers {
		nom := relatif(racine, f)
		v := lireFichierJSON(rap, f)
		if v == nil {
			continue
		}
		estJeu := v.Has("keys") && v.Get("keys").Kind == KindArray && len(v.Get("keys").Arr) > 0 && v.Get("keys").Arr[0].Has("source")
		if estJeu {
			j, mq := ChargerCles(v)
			for _, m := range mq {
				rap.Erreur("%s : %s", nom, m)
			}
			if j != nil {
				if jeu == nil {
					jeu = j
				} else {
					jeu.Cles = append(jeu.Cles, j.Cles...)
				}
			}
		}
		clesTest(rap, nom, v)
	}
	return jeu
}

// clesTest recalcule les valeurs d'un fichier de clés de test (§13).
func clesTest(rap *Rapport, nom string, v *Value) {
	tableau := v.Get("keys")
	if tableau == nil {
		tableau = v.Get("recorder_keys")
	}
	if tableau != nil && tableau.Kind == KindArray {
		for _, k := range tableau.Arr {
			id := chaineDe(k, "key_id")
			pub := chaineDe(k, "public_key")
			etiquette := chaineDe(k, "seed_label")
			if etiquette == "" {
				etiquette = GraineCleEnregistreur + id
			}
			graine := SHA256([]byte(etiquette))
			if s := chaineDe(k, "seed"); s != "" {
				rap.Comparer("clés", nom, "graine "+id+" = SHA-256(\""+etiquette+"\")", s, Hex0x(graine))
				if etiquette != GraineCleEnregistreur+id {
					rap.Comparer("clés", nom, "étiquette de graine "+id+" conforme à §13", GraineCleEnregistreur+id, etiquette)
				}
				if b, err := OctetsHex(s, 32); err == nil {
					graine = b
				}
			}
			if pub != "" {
				rap.Comparer("clés", nom, "clé publique "+id+" (RFC 8032 §5.1.5 depuis la graine)", pub, Hex0x(ClePubliqueDepuisGraine(graine)))
				if b, err := OctetsHex(pub, 32); err == nil {
					rap.Comparer("clés", nom, "clé publique "+id+" canonique et hors petit ordre", "oui", oui(ControlerClePubliqueEd25519(b) == nil))
				}
			}
			if der := chaineDe(k, "private_key_pkcs8_der"); der != "" {
				rap.Comparer("clés", nom, "clé privée PKCS#8 "+id, der, "0x302e020100300506032b657004220420"+Hex0x(graine)[2:])
			}
		}
	}
	if org := v.Get("org"); org != nil {
		if slug, id := chaineDe(org, "slug"), chaineDe(org, "org_id"); slug != "" && id != "" {
			rap.Comparer("clés", nom, "org_id = keccak256(\""+slug+"\")", id, Hex0x(Keccak256([]byte(slug))))
		}
	} else if slug := chaineDe(v, "org_slug"); slug != "" && chaineDe(v, "org_id") != "" {
		rap.Comparer("clés", nom, "org_id = keccak256(\""+slug+"\")", chaineDe(v, "org_id"), Hex0x(Keccak256([]byte(slug))))
	}
	if jr := v.Get("journal"); jr != nil {
		if n, id := chaineDe(jr, "nom"), chaineDe(jr, "journal_id"); n != "" && id != "" {
			rap.Comparer("clés", nom, "journal_id = keccak256(\""+n+"\")", id, Hex0x(Keccak256([]byte(n))))
		}
	} else if n := chaineDe(v, "journal_name"); n != "" && chaineDe(v, "journal_id") != "" {
		rap.Comparer("clés", nom, "journal_id = keccak256(\""+n+"\")", chaineDe(v, "journal_id"), Hex0x(Keccak256([]byte(n))))
	}
	if n := v.Get("nonces"); n != nil {
		switch n.Kind {
		case KindArray:
			for _, x := range n.Arr {
				etiquette := chaineDe(x, "etiquette")
				val := chaineDe(x, "nonce")
				if etiquette == "" || val == "" {
					continue
				}
				rap.Comparer("clés", nom, "nonce = SHA-256(\""+etiquette+"\")", val, Hex0x(SHA256([]byte(etiquette))))
			}
			rap.Note("%s : nonces recalculés depuis l'étiquette déclarée (noortrace/vecteurs/v0/nonce/<journal>/periode-N, table des vecteurs publiés de §13 ; l'exemple de référence de l'annexe A emploie noortrace/vecteurs/v0/nonce/periode-N)", nom)
		case KindObject:
			for _, m := range n.Obj {
				if m.Val.Kind == KindString {
					rap.Comparer("clés", nom, "nonce "+m.Key, m.Val.Str, Hex0x(NonceTest(m.Key)))
				}
			}
		}
	}
	comptes := v.Get("approbateurs").Get("comptes")
	if comptes == nil {
		comptes = v.Get("approvers")
	}
	if comptes != nil && comptes.Kind == KindArray {
		for i, a := range comptes.Arr {
			adr := chaineDe(a, "adresse")
			if adr == "" {
				adr = chaineDe(a, "address")
			}
			pk := chaineDe(a, "cle_privee")
			if pk == "" {
				pk = chaineDe(a, "private_key")
			}
			ok := EstHex(adr, 20) && (pk == "" || EstHex(pk, 32))
			rap.Comparer("clés", nom, fmt.Sprintf("approbateur %d : forme de l'adresse (20 octets minuscules) et de la clé privée (32 octets)", i+1), "oui", oui(ok))
		}
		rap.Note("%s : la dérivation des adresses d'approbateurs (secp256k1) est hors périmètre de ce vérificateur ; seule leur forme est contrôlée", nom)
	}
}

// ---------------------------------------------------------------- jcs

// familleJCS lit jcs/*.json (disposition de repli) : chaque fichier est un cas
// ou un tableau de cas { name, input (texte JSON), canonical (texte) | null }.
func familleJCS(rap *Rapport, racine string) {
	fichiers := fichiersAvecExtension(filepath.Join(racine, "jcs"), ".json")
	if len(fichiers) == 0 {
		rap.Note("famille jcs : aucun fichier jcs/*.json (les cas limites de §4 sont couverts par les tests du module ; la forme canonique est confrontée aux champs canonical des manifestes et aux hachages de tous les événements)")
		return
	}
	for _, f := range fichiers {
		nom := relatif(racine, f)
		v := lireFichierJSON(rap, f)
		if v == nil {
			continue
		}
		cas := []*Value{v}
		if v.Kind == KindArray {
			cas = v.Arr
		} else if c := v.Get("cases"); c != nil && c.Kind == KindArray {
			cas = c.Arr
		} else if c := v.Get("cas"); c != nil && c.Kind == KindArray {
			cas = c.Arr
		}
		for i, c := range cas {
			in := c.Get("input")
			if in == nil || in.Kind != KindString {
				rap.Erreur("%s[%d] : champ input (texte JSON) attendu", nom, i)
				continue
			}
			etiq := fmt.Sprintf("%s[%d]", nom, i)
			if n := chaineDe(c, "name"); n != "" {
				etiq = nom + " · " + n
			}
			att := c.Get("canonical")
			if att == nil {
				att = c.Get("expected")
			}
			invalide := att == nil || att.IsNull() || (att.Kind == KindString && att.Str == "invalide")
			if inv := c.Get("invalid"); inv != nil && inv.Kind == KindBool && inv.Bool {
				invalide = true
			}
			got, err := CanoniqueTexte([]byte(in.Str))
			switch {
			case invalide:
				obtenu := "invalide"
				if err == nil {
					obtenu = string(got)
				}
				rap.Comparer("jcs", etiq, "forme canonique", "invalide", obtenu)
			case att.Kind == KindString:
				obtenu := "invalide : " + errTexte(err)
				if err == nil {
					obtenu = string(got)
				}
				rap.Comparer("jcs", etiq, "forme canonique", att.Str, obtenu)
			default:
				rap.Erreur("%s : canonical doit être une chaîne ou null", etiq)
			}
		}
	}
}

// ---------------------------------------------------------------- journaux

// listeEvenements extrait un tableau d'événements d'une valeur : tableau nu,
// objet { events: [...] }, objet { event: {...} } ou événement nu.
func listeEvenements(v *Value) []*Value {
	switch {
	case v == nil:
		return nil
	case v.Kind == KindArray:
		return v.Arr
	case v.Get("events") != nil && v.Get("events").Kind == KindArray:
		return v.Get("events").Arr
	case v.Get("event") != nil && v.Get("event").Kind == KindObject:
		return []*Value{v.Get("event")}
	case v.Has("seq") && v.Has("sig"):
		return []*Value{v}
	}
	return nil
}

// clesDe charge un cles.json local s'il existe, sinon rend le jeu global.
func clesDe(rap *Rapport, chemin string, global *JeuCles) *JeuCles {
	if !fichierExiste(chemin) {
		return global
	}
	v := lireFichierJSON(rap, chemin)
	if v == nil {
		return global
	}
	j, mq := ChargerCles(v)
	for _, m := range mq {
		rap.Erreur("%s : %s", chemin, m)
	}
	if j == nil {
		return global
	}
	return j
}

// familleJournaux traite les répertoires journal-*/ (evenements.json,
// attendu.json, cles.json facultatif) et, en repli, evenements/**/*.json et
// chaines/*.json. Rend le journal valide de référence pour les manifestes.
func familleJournaux(rap *Rapport, racine string, cles *JeuCles, strict bool) []*Value {
	var journal []*Value
	entrees, _ := os.ReadDir(racine)
	var dirs []string
	for _, e := range entrees {
		if e.IsDir() && strings.HasPrefix(e.Name(), "journal") {
			dirs = append(dirs, filepath.Join(racine, e.Name()))
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		nom := relatif(racine, d)
		evFichier := filepath.Join(d, "evenements.json")
		if !fichierExiste(evFichier) {
			rap.Note("%s : pas de evenements.json", nom)
			continue
		}
		v := lireFichierJSON(rap, evFichier)
		evs := listeEvenements(v)
		if len(evs) == 0 {
			rap.Erreur("%s/evenements.json : aucun événement reconnu", nom)
			continue
		}
		clesLocales := clesDe(rap, filepath.Join(d, "cles.json"), cles)
		var attendu *Value
		if fichierExiste(filepath.Join(d, "attendu.json")) {
			attendu = lireFichierJSON(rap, filepath.Join(d, "attendu.json"))
		}
		valide, ctrl, _ := lireAttendu(attendu)
		res := ControlerChaine(evs, clesLocales)
		comparerVerdict(rap, "journaux", nom, valide, ctrl, res, strict)
		rap.Detail("[journaux] %s\n%s", nom, res.Resume("    "))
		if valide {
			journal = evs
			valeursJournal(rap, nom, evs, clesLocales, attendu)
			if fichierExiste(filepath.Join(d, "pieces.json")) {
				pieces(rap, nom, lireFichierJSON(rap, filepath.Join(d, "pieces.json")), evs)
			}
		}
	}

	// Disposition de repli : evenements/ et chaines/
	for _, sous := range []string{"evenements", "chaines"} {
		dir := filepath.Join(racine, sous)
		var fichiers []string
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
				fichiers = append(fichiers, p)
			}
			return nil
		})
		sort.Strings(fichiers)
		for _, f := range fichiers {
			nom := relatif(racine, f)
			v := lireFichierJSON(rap, f)
			evs := listeEvenements(v)
			if len(evs) == 0 {
				rap.Erreur("%s : aucun événement reconnu", nom)
				continue
			}
			valide, ctrl, _ := lireAttendu(v)
			var res *Resultats
			if len(evs) == 1 {
				res = ControlerEvenement(evs[0], cles)
				ControlerPremier(res, evs[0], fmt.Sprintf("seq %d", Seq(evs[0])))
			} else {
				res = ControlerChaine(evs, cles)
			}
			comparerVerdict(rap, sous, nom, valide, ctrl, res, strict)
			rap.Detail("[%s] %s\n%s", sous, nom, res.Resume("    "))
			if valide && filepath.Base(f) == "journal.json" {
				journal = evs
				valeursJournal(rap, nom, evs, cles, v)
			}
		}
	}
	if len(dirs) == 0 && journal == nil {
		rap.Note("famille journaux : aucun répertoire journal-*/ ni fichier evenements/ ou chaines/")
	}
	return journal
}

// valeursJournal confronte les valeurs attendues d'un journal valide : hash,
// prev_hash, signature et longueur canonique de chaque événement, objet signé
// d'approbation et condensé D_A, bornes de séquence.
func valeursJournal(rap *Rapport, nom string, evs []*Value, cles *JeuCles, attendu *Value) {
	parSeq := map[int64]*Value{}
	for _, ev := range evs {
		parSeq[Seq(ev)] = ev
	}
	hashes := attendu.Get("hashes")
	if hashes == nil || hashes.Kind != KindArray {
		// sans table d'attendus, les hash portés par les événements eux-mêmes servent de valeurs attendues
		for _, ev := range evs {
			etiq := fmt.Sprintf("%s · seq %d", nom, Seq(ev))
			h, _, err := HashEvenement(ev)
			if err != nil {
				rap.Comparer("journaux", etiq, "hash", chaineDe(ev, "hash"), "forme canonique impossible : "+err.Error())
				continue
			}
			rap.Comparer("journaux", etiq, "hash", chaineDe(ev, "hash"), Hex0x(h))
		}
	} else {
		for _, a := range hashes.Arr {
			seq, _ := entierDe(a, "seq")
			ev := parSeq[seq]
			etiq := fmt.Sprintf("%s · seq %d", nom, seq)
			if ev == nil {
				rap.Comparer("journaux", etiq, "événement présent", "oui", "non")
				continue
			}
			h, c, err := HashEvenement(ev)
			if err != nil {
				rap.Comparer("journaux", etiq, "hash", chaineDe(a, "hash"), "forme canonique impossible : "+err.Error())
				continue
			}
			rap.Comparer("journaux", etiq, "hash", chaineDe(a, "hash"), Hex0x(h))
			if n, ok := entierDe(a, "canonical_length"); ok {
				rap.Comparer("journaux", etiq, "longueur de la forme canonique", fmt.Sprint(n), fmt.Sprint(len(c)))
			}
			if p := chaineDe(a, "prev_hash"); p != "" {
				recalc := Zero32
				if prev := parSeq[seq-1]; prev != nil {
					if hp, _, err := HashEvenement(prev); err == nil {
						recalc = Hex0x(hp)
					}
				}
				rap.Comparer("journaux", etiq, "prev_hash = hash recalculé du précédent", p, recalc)
			}
			if s := chaineDe(a, "sig"); s != "" {
				rap.Comparer("journaux", etiq, "sig portée par l'événement", s, chaineDe(ev, "sig"))
			}
			if t := chaineDe(a, "tool"); t != "" {
				rap.Comparer("journaux", etiq, "execution.tool", t, Outil(ev))
			}
			if k := chaineDe(a, "recorder_key_id"); k != "" {
				rap.Comparer("journaux", etiq, "recorder_key_id", k, chaineDe(ev, "recorder_key_id"))
			}
			signatureEvenement(rap, etiq, ev, c, cles)
		}
	}
	if hashes == nil {
		for _, ev := range evs {
			if _, c, err := HashEvenement(ev); err == nil {
				signatureEvenement(rap, fmt.Sprintf("%s · seq %d", nom, Seq(ev)), ev, c, cles)
			}
		}
	}
	for _, ev := range evs {
		if EstRotation(ev) {
			r := NouveauxResultats()
			controlerRotation(r, ev, cles)
			rap.Comparer("journaux", fmt.Sprintf("%s · seq %d", nom, Seq(ev)), "contresignature de rotation (E-10)", "valide", verdictTexte(r.Echecs()))
		}
	}
	if fs, ok := entierDe(attendu, "first_seq"); ok && len(evs) > 0 {
		rap.Comparer("journaux", nom, "first_seq", fmt.Sprint(fs), fmt.Sprint(Seq(evs[0])))
	}
	if ls, ok := entierDe(attendu, "last_seq"); ok && len(evs) > 0 {
		rap.Comparer("journaux", nom, "last_seq", fmt.Sprint(ls), fmt.Sprint(Seq(evs[len(evs)-1])))
	}
	if ap := attendu.Get("approbation"); ap != nil {
		ticket := chaineDe(ap, "ticket")
		var evApp *Value
		for _, ev := range evs {
			if Outil(ev) == OutilApprobation && chaineDe(ev, "approval", "ticket") == ticket {
				evApp = ev
			}
		}
		if evApp == nil {
			rap.Comparer("journaux", nom, "événement d'approbation du ticket "+ticket, "présent", "absent")
		} else {
			A := ObjetSigneApprobation(evApp)
			if att := ap.Get("A"); att != nil {
				ca, _ := Canonique(att)
				cb, _ := Canonique(A)
				rap.Comparer("journaux", nom, "JCS(A) du ticket "+ticket, string(ca), string(cb))
			}
			if da := chaineDe(ap, "D_A"); da != "" {
				d, err := CondenseApprobation(A)
				if err != nil {
					rap.Comparer("journaux", nom, "D_A", da, err.Error())
				} else {
					rap.Comparer("journaux", nom, "D_A = SHA-256(P_A || JCS(A))", da, Hex0x(d))
				}
			}
			if appr := ap.Get("approvers"); appr != nil && appr.Kind == KindArray {
				rap.Comparer("journaux", nom, "approvers du ticket "+ticket, chainesJointes(appr), chainesJointes(evApp.Get("approval").Get("approvers")))
			}
		}
	}
}

func chainesJointes(v *Value) string {
	if v == nil || v.Kind != KindArray {
		return ""
	}
	var out []string
	for _, x := range v.Arr {
		out = append(out, chaineDe(x, ""))
	}
	return strings.Join(out, ",")
}

func signatureEvenement(rap *Rapport, etiq string, ev *Value, c []byte, cles *JeuCles) {
	if cles == nil {
		return
	}
	cle := cles.Trouver(chaineDe(ev, "recorder_key_id"))
	if cle == nil {
		rap.Comparer("journaux", etiq, "clé "+chaineDe(ev, "recorder_key_id")+" connue", "oui", "non")
		return
	}
	sig, err := OctetsHex(chaineDe(ev, "sig"), 64)
	obtenu := "valide"
	if err != nil {
		obtenu = err.Error()
	} else if err := VerifierEd25519(cle.PublicKey, append(append([]byte{}, PrefixeSignatureEvenement...), c...), sig); err != nil {
		obtenu = err.Error()
	}
	rap.Comparer("journaux", etiq, "signature Ed25519 ("+cle.KeyID+")", "valide", obtenu)
}

// pieces confronte les pièces fournies à part (E-6) : SHA-256 et longueur des
// octets UTF-8 du texte, et présence de la référence dans un événement.
func pieces(rap *Rapport, nom string, v *Value, evs []*Value) {
	if v == nil {
		return
	}
	liste := v.Get("pieces")
	if liste == nil || liste.Kind != KindArray {
		return
	}
	referencees := map[string]bool{}
	for _, ev := range evs {
		for _, rf := range references(ev) {
			referencees[chaineDe(rf.ref, "sha256")] = true
		}
		if pv := chaineDe(ev, "code", "prompt_version"); pv != "" {
			referencees[pv] = true
		}
		if ps := chaineDe(ev, "execution", "arguments", "value", "policy_sha256"); ps != "" {
			referencees[ps] = true
		}
	}
	nonRef := 0
	for _, p := range liste.Arr {
		texte := p.Get("texte")
		if texte == nil || texte.Kind != KindString {
			continue
		}
		etiq := nom + "/pieces.json · " + chaineDe(p, "nom")
		octets := []byte(texte.Str)
		rap.Comparer("journaux", etiq, "sha256 de la pièce", chaineDe(p, "sha256"), Hex0x(SHA256(octets)))
		if n, ok := entierDe(p, "length"); ok {
			rap.Comparer("journaux", etiq, "length de la pièce", fmt.Sprint(n), fmt.Sprint(len(octets)))
		}
		if !referencees[chaineDe(p, "sha256")] {
			nonRef++
		}
	}
	if nonRef > 0 {
		rap.Note("%s/pieces.json : %d pièce(s) dont le sha256 n'est référencé par aucun événement du journal", nom, nonRef)
	}
}

// ---------------------------------------------------------------- arbres

// familleArbres lit merkle/arbres.json ({ arbres: [{ n, leaves, root,
// proofs: [chemin] }] }) et, en repli, arbres/*.json ({ leaves, root,
// paths }). Recalcule feuilles, racine et chemins ; vérifie chaque chemin par
// l'algorithme de §9.3.
func familleArbres(rap *Rapport, racine string) {
	var fichiers []string
	if f := filepath.Join(racine, "merkle", "arbres.json"); fichierExiste(f) {
		fichiers = append(fichiers, f)
	}
	fichiers = append(fichiers, fichiersAvecExtension(filepath.Join(racine, "arbres"), ".json")...)
	if len(fichiers) == 0 {
		rap.Note("famille arbres : aucun fichier merkle/arbres.json ni arbres/*.json")
		return
	}
	for _, f := range fichiers {
		nom := relatif(racine, f)
		v := lireFichierJSON(rap, f)
		if v == nil {
			continue
		}
		if pv := v.Get("periode_vide"); pv != nil {
			rap.Comparer("arbres", nom+" · periode_vide", "racine (n = 0, convention NOORTRACE)", chaineDe(pv, "root"), Hex0x(RacineVide))
		}
		arbres := []*Value{v}
		if a := v.Get("arbres"); a != nil && a.Kind == KindArray {
			arbres = a.Arr
		}
		for i, a := range arbres {
			etiq := fmt.Sprintf("%s · arbres[%d]", nom, i)
			if n, ok := entierDe(a, "n"); ok {
				etiq = fmt.Sprintf("%s · n = %d", nom, n)
			}
			arbre(rap, etiq, a)
		}
	}
}

func arbre(rap *Rapport, etiq string, a *Value) {
	leaves := a.Get("leaves")
	if leaves == nil {
		leaves = a.Get("hashes")
	}
	if leaves == nil || leaves.Kind != KindArray {
		rap.Erreur("%s : champ leaves (tableau d'hexadécimal) attendu", etiq)
		return
	}
	var D [][]byte
	for i, l := range leaves.Arr {
		b, err := OctetsHex(chaineDe(l, ""), -1)
		if l.Kind != KindString || err != nil {
			rap.Erreur("%s : leaves[%d] n'est pas de l'hexadécimal 0x", etiq, i)
			return
		}
		D = append(D, b)
	}
	n := len(D)
	if nd, ok := entierDe(a, "n"); ok {
		rap.Comparer("arbres", etiq, "nombre de feuilles", fmt.Sprint(nd), fmt.Sprint(n))
	}
	L := make([][]byte, n)
	for i := range D {
		L[i] = Feuille(D[i])
	}
	if lh := a.Get("leaf_hashes"); lh != nil && lh.Kind == KindArray && len(lh.Arr) == n {
		for i := range L {
			rap.Comparer("arbres", etiq, fmt.Sprintf("L(%d)", i), chaineDe(lh.Arr[i], ""), Hex0x(L[i]))
		}
	}
	root := Racine(D)
	if r := a.Get("root"); r != nil && r.Kind == KindString {
		rap.Comparer("arbres", etiq, "racine", r.Str, Hex0x(root))
	}
	if n == 0 {
		rap.Note("%s : période vide, racine = 32 octets nuls (convention NOORTRACE), et non SHA-256(\"\") = %s (RFC 6962)", etiq, Hex0x(RacineVideRFC6962))
	}
	// Feuilles dérivées d'une étiquette (vecteur n = 1000) : recalcul si la
	// première feuille suit la règle annoncée.
	if n > 0 && Hex0x(D[0]) == Hex0x(SHA256([]byte("noortrace/vecteurs/v0/merkle/feuille/0"))) {
		toutes := true
		for i := range D {
			if Hex0x(D[i]) != Hex0x(SHA256([]byte(fmt.Sprintf("noortrace/vecteurs/v0/merkle/feuille/%d", i)))) {
				toutes = false
				break
			}
		}
		rap.Comparer("arbres", etiq, "feuilles D[i] = SHA-256(\"noortrace/vecteurs/v0/merkle/feuille/<i>\")", "oui", oui(toutes))
	}
	proofs := a.Get("proofs")
	if proofs == nil {
		proofs = a.Get("paths")
	}
	if proofs == nil || proofs.Kind != KindArray {
		return
	}
	for i, p := range proofs.Arr {
		idx := int64(i)
		pathV := p
		if p.Kind == KindObject {
			if li, ok := entierDe(p, "leaf_index"); ok {
				idx = li
			}
			pathV = p.Get("path")
		}
		if pathV == nil || pathV.Kind != KindArray {
			rap.Erreur("%s : proofs[%d] mal formé", etiq, i)
			continue
		}
		var attendu []string
		var path [][]byte
		for _, x := range pathV.Arr {
			attendu = append(attendu, chaineDe(x, ""))
			b, _ := OctetsHex(chaineDe(x, ""), 32)
			path = append(path, b)
		}
		if idx < 0 || idx >= int64(n) {
			rap.Comparer("arbres", etiq, fmt.Sprintf("chemin m = %d", idx), strings.Join(attendu, " "), "indice hors de l'arbre")
			continue
		}
		var obtenu []string
		for _, b := range Chemin(int(idx), D) {
			obtenu = append(obtenu, Hex0x(b))
		}
		rap.Comparer("arbres", etiq, fmt.Sprintf("chemin m = %d", idx), strings.Join(attendu, " "), strings.Join(obtenu, " "))
		if p.Kind == KindObject {
			if lh := chaineDe(p, "leaf_hash"); lh != "" {
				rap.Comparer("arbres", etiq, fmt.Sprintf("leaf_hash m = %d", idx), lh, Hex0x(L[idx]))
			}
			if r := chaineDe(p, "root"); r != "" {
				rap.Comparer("arbres", etiq, fmt.Sprintf("root de la preuve m = %d", idx), r, Hex0x(root))
			}
			if ts, ok := entierDe(p, "tree_size"); ok {
				rap.Comparer("arbres", etiq, fmt.Sprintf("tree_size de la preuve m = %d", idx), fmt.Sprint(ts), fmt.Sprint(n))
			}
		}
		racineAttendue := root
		if p.Kind == KindObject {
			if b, err := OctetsHex(chaineDe(p, "root"), 32); err == nil {
				racineAttendue = b
			}
		}
		err := VerifierInclusion(L[idx], uint64(idx), uint64(n), path, racineAttendue)
		rap.Comparer("arbres", etiq, fmt.Sprintf("vérification §9.3 du chemin m = %d", idx), "acceptée", acceptee(err))
	}
}

func acceptee(err error) string {
	if err == nil {
		return "acceptée"
	}
	return "rejetée : " + err.Error()
}

// ---------------------------------------------------------------- manifestes

type manifesteVecteur struct {
	nom  string
	base string
	v    *Value
	sig  *Value
}

// familleManifestes lit manifestes/ : manifestes (*.json portant
// period_start), signatures (*.sig ou *.json portant period_hash, appariées
// par nom de base puis par periodHash recalculé) et attendu.json
// ({ periodes: [{ fichier, canonical, period_hash, sig, root, count, seq,
// anchor_fingerprint, period_meta }], continuite: [{ de, a, valide }],
// discontinu: { fichier, precedent, valide } }).
func familleManifestes(rap *Rapport, racine string, cles *JeuCles, journal []*Value, strict bool) {
	dir := filepath.Join(racine, "manifestes")
	fichiers := fichiersAvecExtension(dir, ".json", ".sig")
	if len(fichiers) == 0 {
		rap.Note("famille manifestes : aucun fichier manifestes/*.json")
		return
	}
	var manifestes []*manifesteVecteur
	parBase := map[string]*manifesteVecteur{}
	sigs := map[string]*Value{}
	var sigsLibres []*Value
	var attendus *Value
	for _, f := range fichiers {
		v := lireFichierJSON(rap, f)
		if v == nil {
			continue
		}
		base := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		switch {
		case v.Kind == KindObject && v.Has("period_start") && v.Has("nonce"):
			m := &manifesteVecteur{nom: relatif(racine, f), base: filepath.Base(f), v: v}
			manifestes = append(manifestes, m)
			parBase[filepath.Base(f)] = m
		case v.Kind == KindObject && v.Has("period_hash") && v.Has("sig"):
			sigs[base] = v
			sigsLibres = append(sigsLibres, v)
		case filepath.Base(f) == "attendus.json" || filepath.Base(f) == "attendu.json":
			attendus = v
		default:
			rap.Note("%s : fichier non reconnu dans manifestes/ (ni manifeste, ni signature, ni attendu.json)", relatif(racine, f))
		}
	}
	for _, m := range manifestes {
		if s, ok := sigs[strings.TrimSuffix(m.base, ".json")]; ok {
			m.sig = s
			continue
		}
		if ph, _, err := PeriodHash(m.v); err == nil {
			for _, s := range sigsLibres {
				if chaineDe(s, "period_hash") == Hex0x(ph) {
					m.sig = s
				}
			}
		}
	}
	sort.SliceStable(manifestes, func(i, j int) bool {
		return LireManifeste(manifestes[i].v).PeriodStart < LireManifeste(manifestes[j].v).PeriodStart
	})

	attendusParFichier := map[string]*Value{}
	discontinuFichier := ""
	if attendus != nil {
		for _, a := range attendusManifeste(attendus) {
			if f := chaineDe(a, "fichier"); f != "" {
				attendusParFichier[f] = a
			} else if f := chaineDe(a, "file"); f != "" {
				attendusParFichier[f] = a
			}
		}
		discontinuFichier = chaineDe(attendus.Get("discontinu"), "fichier")
	}

	for _, m := range manifestes {
		res := ControlerManifeste(m.v, m.sig, cles)
		ph, c, err := PeriodHash(m.v)
		if err != nil {
			rap.Comparer("manifestes", m.nom, "periodHash", "calculable", err.Error())
		} else if m.sig != nil {
			rap.Comparer("manifestes", m.nom, "periodHash (manifeste.sig.period_hash)", chaineDe(m.sig, "period_hash"), Hex0x(ph))
			etat := "valide"
			if ctl := res.parID["P-5"]; ctl != nil && ctl.Etat == EtatEchoue {
				etat = strings.Join(ctl.Details, " ; ")
			}
			rap.Comparer("manifestes", m.nom, "signature du manifeste ("+chaineDe(m.sig, "recorder_key_id")+")", "valide", etat)
		} else {
			rap.Note("%s : aucune signature appariée (manifeste.sig)", m.nom)
		}
		// Le manifeste déclaré discontinu n'est pas confronté au journal : son
		// attendu porte sur la continuité avec son prédécesseur (plus bas) ; seul
		// il doit être bien formé et signé.
		if journal != nil && err == nil && m.base != discontinuFichier {
			if racineRecalc := ControlerManifesteContreJournal(res, m.v, journal); racineRecalc != nil {
				rap.Comparer("manifestes", m.nom, "racine recalculée depuis le journal valide (fenêtre [period_start, period_end))", LireManifeste(m.v).Root, Hex0x(racineRecalc))
			}
		}
		valide, ctrl := true, []string(nil)
		if a := attendusParFichier[m.base]; a != nil && err == nil {
			attendusManifesteValeurs(rap, m, a, ph, c, journal)
			if va, ids, present := lireAttendu(a); present {
				valide, ctrl = va, ids
			}
		}
		comparerVerdict(rap, "manifestes", m.nom, valide, ctrl, res, strict)
		rap.Detail("[manifestes] %s\n%s", m.nom, res.Resume("    "))
	}

	// Continuité : paires déclarées, sinon consécutives par period_start.
	if attendus != nil && (attendus.Has("continuite") || attendus.Has("discontinu")) {
		if ct := attendus.Get("continuite"); ct != nil && ct.Kind == KindArray {
			for _, p := range ct.Arr {
				de, a := parBase[chaineDe(p, "de")], parBase[chaineDe(p, "a")]
				if de == nil || a == nil {
					rap.Erreur("manifestes/attendu.json : continuité %q → %q : fichier inconnu", chaineDe(p, "de"), chaineDe(p, "a"))
					continue
				}
				r := NouveauxResultats()
				ControlerContinuite(r, de.v, a.v)
				va, ids, _ := lireAttendu(p)
				comparerVerdict(rap, "manifestes", "continuité "+de.base+" → "+a.base, va, ids, r, strict)
			}
		}
		if dc := attendus.Get("discontinu"); dc != nil && dc.Kind == KindObject {
			prec, f := parBase[chaineDe(dc, "precedent")], parBase[chaineDe(dc, "fichier")]
			if prec == nil || f == nil {
				rap.Erreur("manifestes/attendu.json : discontinu %q après %q : fichier inconnu", chaineDe(dc, "fichier"), chaineDe(dc, "precedent"))
			} else {
				r := NouveauxResultats()
				ControlerContinuite(r, prec.v, f.v)
				va, ids, present := lireAttendu(dc)
				if !present {
					va, ids = false, []string{"P-5"}
				}
				if !va && len(ids) == 0 {
					ids = []string{"P-5"}
				}
				comparerVerdict(rap, "manifestes", "continuité "+prec.base+" → "+f.base+" (discontinu)", va, ids, r, strict)
				rap.Detail("[manifestes] continuité %s → %s\n%s", prec.base, f.base, r.Resume("    "))
			}
		}
	} else {
		for i := 1; i < len(manifestes); i++ {
			r := NouveauxResultats()
			ControlerContinuite(r, manifestes[i-1].v, manifestes[i].v)
			comparerVerdict(rap, "manifestes", "continuité "+manifestes[i-1].base+" → "+manifestes[i].base, true, nil, r, strict)
		}
	}
}

func attendusManifeste(v *Value) []*Value {
	if v.Kind == KindArray {
		return v.Arr
	}
	for _, k := range []string{"periodes", "periods", "manifests", "manifestes"} {
		if p := v.Get(k); p != nil && p.Kind == KindArray {
			return p.Arr
		}
	}
	return []*Value{v}
}

// attendusManifesteValeurs confronte les valeurs attendues d'un manifeste :
// forme canonique, periodHash, signature, racine (recalculée depuis la liste
// de seq du journal), count, anchorFingerprint, correspondance PeriodMeta.
func attendusManifesteValeurs(rap *Rapport, m *manifesteVecteur, a *Value, ph, c []byte, journal []*Value) {
	mf := LireManifeste(m.v)
	if s := chaineDe(a, "canonical"); s != "" {
		rap.Comparer("manifestes", m.nom, "forme canonique JCS du manifeste", s, string(c))
	}
	if s := chaineDe(a, "period_hash"); s != "" {
		rap.Comparer("manifestes", m.nom, "periodHash (attendu.json)", s, Hex0x(ph))
	}
	if s := chaineDe(a, "sig"); s != "" && m.sig != nil {
		rap.Comparer("manifestes", m.nom, "sig (attendu.json = manifeste.sig)", s, chaineDe(m.sig, "sig"))
	}
	if s := chaineDe(a, "recorder_key_id"); s != "" {
		rap.Comparer("manifestes", m.nom, "recorder_key_id", s, mf.KeyID)
	}
	if s := chaineDe(a, "root"); s != "" {
		rap.Comparer("manifestes", m.nom, "root (attendu.json = manifeste)", s, mf.Root)
	}
	if seqs := a.Get("seq"); seqs != nil && seqs.Kind == KindArray && journal != nil {
		parSeq := map[int64]*Value{}
		for _, ev := range journal {
			parSeq[Seq(ev)] = ev
		}
		var D [][]byte
		complet := true
		for _, s := range seqs.Arr {
			n, ok := entierDe(s, "")
			ev := parSeq[n]
			if !ok || ev == nil {
				complet = false
				break
			}
			h, _, err := HashEvenement(ev)
			if err != nil {
				complet = false
				break
			}
			D = append(D, h)
		}
		if complet {
			rap.Comparer("manifestes", m.nom, fmt.Sprintf("racine recalculée depuis les %d seq déclarés", len(D)), mf.Root, Hex0x(Racine(D)))
		} else {
			rap.Erreur("%s : liste seq de attendu.json non résoluble dans le journal valide", m.nom)
		}
		if n, ok := entierDe(a, "count"); ok {
			rap.Comparer("manifestes", m.nom, "count = nombre de seq déclarés = manifeste.count", fmt.Sprint(n), fmt.Sprintf("%d", len(seqs.Arr)))
			rap.Comparer("manifestes", m.nom, "count du manifeste", fmt.Sprint(n), fmt.Sprint(mf.Count))
		}
	}
	if s := chaineDe(a, "anchor_fingerprint"); s != "" {
		fp, err := AnchorFingerprintManifeste(m.v)
		if err != nil {
			rap.Comparer("manifestes", m.nom, "anchorFingerprint", s, err.Error())
		} else {
			rap.Comparer("manifestes", m.nom, "anchorFingerprint = keccak256(org_id || journal_id || periodHash)", s, Hex0x(fp))
		}
	}
	if pm := a.Get("period_meta"); pm != nil && pm.Kind == KindObject {
		obtenu := fmt.Sprintf("orgId=%s journalId=%s periodHash=%s root=%s periodStart=%d periodEnd=%d firstSeq=%d lastSeq=%d version=0",
			mf.OrgID, mf.JournalID, Hex0x(ph), mf.Root, mf.PeriodStart, mf.PeriodEnd, mf.FirstSeq, mf.LastSeq)
		ps, _ := entierDe(pm, "periodStart")
		pe, _ := entierDe(pm, "periodEnd")
		fs, _ := entierDe(pm, "firstSeq")
		ls, _ := entierDe(pm, "lastSeq")
		ver, _ := entierDe(pm, "version")
		attendu := fmt.Sprintf("orgId=%s journalId=%s periodHash=%s root=%s periodStart=%d periodEnd=%d firstSeq=%d lastSeq=%d version=%d",
			chaineDe(pm, "orgId"), chaineDe(pm, "journalId"), chaineDe(pm, "periodHash"), chaineDe(pm, "root"), ps, pe, fs, ls, ver)
		rap.Comparer("manifestes", m.nom, "correspondance PeriodMeta (§10.4)", attendu, obtenu)
	}
}

// ---------------------------------------------------------------- dossiers

var reNomInvalide = regexp.MustCompile(`^invalide[-_]([DECMPA]-[0-9]+)`)

// familleDossiers parcourt dossiers/ : tout répertoire contenant dossier.json
// est un dossier. Verdict attendu : attendu.json dans le répertoire
// ({ valide, controle, controles_en_echec }), sinon dossiers/attendus.json,
// sinon le nom du répertoire (valide-*, invalide-<CTRL>-*), sinon « valide ».
func familleDossiers(rap *Rapport, racine string, strict bool) {
	dir := filepath.Join(racine, "dossiers")
	var dossiers []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "dossier.json" {
			dossiers = append(dossiers, filepath.Dir(p))
		}
		return nil
	})
	sort.Strings(dossiers)
	if len(dossiers) == 0 {
		rap.Note("famille dossiers : aucun répertoire dossiers/**/dossier.json")
		return
	}
	attendus := map[string]*Value{}
	if fichierExiste(filepath.Join(dir, "attendus.json")) {
		if v := lireFichierJSON(rap, filepath.Join(dir, "attendus.json")); v != nil {
			switch v.Kind {
			case KindObject:
				for _, m := range v.Obj {
					attendus[m.Key] = m.Val
				}
			case KindArray:
				for _, x := range v.Arr {
					if n := chaineDe(x, "dossier"); n != "" {
						attendus[n] = x
					}
				}
			}
		}
	}
	for _, d := range dossiers {
		nom := relatif(dir, d)
		valide, ctrl := true, []string(nil)
		source := "par défaut"
		switch {
		case fichierExiste(filepath.Join(d, "attendu.json")):
			if v := lireFichierJSON(rap, filepath.Join(d, "attendu.json")); v != nil {
				valide, ctrl, _ = lireAttendu(v)
				source = "attendu.json"
			}
		case attendus[nom] != nil:
			if attendus[nom].Kind == KindObject {
				valide, ctrl, _ = lireAttendu(attendus[nom])
			} else {
				valide, ctrl, _ = interpreterAttendu(attendus[nom])
			}
			source = "dossiers/attendus.json"
		case strings.HasPrefix(filepath.Base(d), "valide"):
			source = "nom du répertoire"
		case reNomInvalide.MatchString(filepath.Base(d)):
			valide, ctrl = false, []string{reNomInvalide.FindStringSubmatch(filepath.Base(d))[1]}
			source = "nom du répertoire"
		}
		res := VerifierDossier(d)
		etiq := "dossiers/" + nom
		if nonAdmis := res.NonExecutesNonAdmis(); valide && res.Resultats.Valide() && len(nonAdmis) > 0 {
			// Aucun échec, mais un contrôle non exécuté sans raison admise rend le dossier invalide (CT-1 §11.4).
			rap.ComparerAvecNote("dossiers", etiq+" (attendu : "+source+")", "verdict", "valide", "non exécuté sans raison admise : "+strings.Join(nonAdmis, ","), false, "")
		} else {
			comparerVerdict(rap, "dossiers", etiq+" (attendu : "+source+")", valide, ctrl, res.Resultats, strict)
		}
		rap.Detail("[dossiers] %s\n%s", etiq, res.Resultats.Resume("    "))
		for _, b := range res.Bornes {
			rap.Detail("    %s", b)
		}
	}
}
