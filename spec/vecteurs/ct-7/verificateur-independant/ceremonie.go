// Procès-verbal de cérémonie des clés (CT-7 §5.6 à §5.8) : condensé
// D_C = Keccak-256(P_C ‖ JCS(V)), V le procès-verbal privé de signatures
// (EX-5.7), et les vérifications CR-1 à CR-12, exécutées dans l'ordre
// (EX-5.9) : CR-1 en échec rend les onze autres non exécutées
// (prerequis_en_echec) ; sinon toutes sont exécutées et toutes celles qui
// échouent sont rapportées.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// PrefixeCeremonie est P_C (EX-5.7) : 28 octets.
const PrefixeCeremonie = "noortrace/ceremonie-cles/v0\n"

// TailleMaxProcesVerbal est la taille maximale du fichier lu (EX-5.9).
const TailleMaxProcesVerbal = 1 << 20

// Statuts d'une vérification (EX-5.9, EX-7.16).
const (
	Reussi     = "reussi"
	Echoue     = "echoue"
	NonExecute = "non_execute"
)

// idsCR sont les douze vérifications, dans l'ordre.
var idsCR = []string{"CR-1", "CR-2", "CR-3", "CR-4", "CR-5", "CR-6", "CR-7", "CR-8", "CR-9", "CR-10", "CR-11", "CR-12"}

// detailsParObjet donne, pour chaque objet de 5.1, le membre qui distingue la
// forme de purpose_details (CR-12) ; "" : purpose_details nul.
var detailsParObjet = map[string]string{
	"creation":                  "",
	"rotation":                  "",
	"sauvegarde":                "",
	"inscription_membres":       "",
	"autre":                     "",
	"rotation_urgence":          "decided_at",
	"revocation":                "tx_hash",
	"recompletement":            "tx_hash",
	"destruction":               "destruction_proof_sha256",
	"restauration":              "backup_ceremony_digest",
	"changement_administrateur": "approver_set_hash",
}

// ResultatCeremonie est le rapport de EX-5.9 : verdict, D_C, vérifications
// en échec et non exécutées, adresses des signataires.
type ResultatCeremonie struct {
	Statuts     map[string]string
	Details     map[string][]string
	Digest      string // "" : null (CR-1 en échec)
	Signataires []string
}

// Valide dit si les douze vérifications sont réussies.
func (r *ResultatCeremonie) Valide() bool {
	for _, id := range idsCR {
		if r.Statuts[id] != Reussi {
			return false
		}
	}
	return true
}

// Echecs et NonExecutees rendent les identifiants, dans l'ordre de CR-1 à CR-11.
func (r *ResultatCeremonie) Echecs() []string       { return r.selon(Echoue) }
func (r *ResultatCeremonie) NonExecutees() []string { return r.selon(NonExecute) }

func (r *ResultatCeremonie) selon(s string) []string {
	out := []string{}
	for _, id := range idsCR {
		if r.Statuts[id] == s {
			out = append(out, id)
		}
	}
	return out
}

func (r *ResultatCeremonie) echec(id, format string, args ...any) {
	r.Statuts[id] = Echoue
	r.Details[id] = append(r.Details[id], fmt.Sprintf(format, args...))
}

// CondenseCeremonie rend D_C d'un procès-verbal analysé.
func CondenseCeremonie(pv *Value) ([]byte, error) {
	c, err := Canonique(pv.Sans("signatures"))
	if err != nil {
		return nil, err
	}
	return Keccak256(append([]byte(PrefixeCeremonie), c...)), nil
}

// AnalyserInstant décode un horodatage de CT-1 §3 : motif exact, date
// existante du calendrier grégorien, jamais renormalisée.
func AnalyserInstant(s string) (time.Time, bool) {
	if len(s) != 24 || s[23] != 'Z' {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil || t.Format("2006-01-02T15:04:05.000Z") != s {
		return time.Time{}, false
	}
	return t, true
}

// algorithmeParUsage est la table de CR-5 (4.3).
var algorithmeParUsage = map[string][]string{
	"enregistreur":            {"ed25519"},
	"chaine":                  {"secp256k1"},
	"approbateur":             {"secp256k1"},
	"gouvernance":             {"secp256k1"},
	"administrateur_registre": {"secp256k1"},
	"deployeur":               {"secp256k1"},
	"relayeur":                {"secp256k1"},
	"tresorerie":              {"secp256k1"},
	"approvisionnement":       {"secp256k1"},
	"validateur":              {"secp256k1"},
	"tsa_interne":             {"rsa", "ecdsa_p256"},
	"enveloppe":               {"aes256"},
}

// classesProduction est la table de 4.3 (EX-4.2), appliquée par CR-6.
var classesProduction = map[string][]string{
	"enregistreur":            {"A", "B", "C"},
	"chaine":                  {"A", "B", "C"},
	"approbateur":             {"sans_objet"},
	"gouvernance":             {"A", "B", "C"},
	"administrateur_registre": {"A"},
	"deployeur":               {"A", "B", "C"},
	"relayeur":                {"A", "B", "C"},
	"tresorerie":              {"A", "B", "C"},
	"approvisionnement":       {"A", "B", "C"},
	"validateur":              {"D"},
	"tsa_interne":             {"A", "B", "C"},
	"enveloppe":               {"A", "B", "C"},
}

// Règle de sauvegarde de 4.4 reprise par CR-7.
var (
	sansSauvegarde      = []string{"enregistreur", "chaine", "approbateur", "validateur", "deployeur", "relayeur", "approvisionnement", "tsa_interne"}
	partageToujours     = []string{"enveloppe"}
	partageEnProduction = []string{"administrateur_registre", "tresorerie"}
	productionValeur    = "production"
	schemaPartage       = "partage_k_sur_n"
	schemaAucune        = "aucune"
	roleOfficiant       = "officiant"
	roleTemoin          = "temoin"
	roleAuditeur        = "auditeur"
	roleDetenteurPart   = "detenteur_part"
	roleMembre          = "membre"
	usageApprobateur    = "approbateur"
	generationDetenteur = "detenteur"
	classeSansObjet     = "sans_objet"
	resultatException   = "exception"
	sorteIncident       = "incident"
	enregistrementVideo = "video"
	generationPoste     = "poste"
)

func dans(s string, l []string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// VerifierCeremonie exécute CR-1 à CR-12 sur les octets d'un procès-verbal.
func VerifierCeremonie(octets []byte, sch *Schema) *ResultatCeremonie {
	r := &ResultatCeremonie{Statuts: map[string]string{}, Details: map[string][]string{}, Signataires: []string{}}
	for _, id := range idsCR {
		r.Statuts[id] = Reussi
	}
	nonExecutees := func(raison string) *ResultatCeremonie {
		for _, id := range idsCR[1:] {
			r.Statuts[id] = NonExecute
			r.Details[id] = []string{raison}
		}
		return r
	}

	// CR-1 : forme.
	if len(octets) > TailleMaxProcesVerbal {
		r.echec("CR-1", "fichier de %d octets, au plus 1 Mio", len(octets))
		return nonExecutees("prerequis_en_echec")
	}
	pv, err := AnalyserJSONStrict(octets)
	if err != nil {
		r.echec("CR-1", "%v", err)
		return nonExecutees("prerequis_en_echec")
	}
	if m := sch.Valider(pv); len(m) > 0 {
		for _, x := range m {
			r.echec("CR-1", "schéma ceremonie-cles-v0 : %s", x)
		}
		return nonExecutees("prerequis_en_echec")
	}
	dc, err := CondenseCeremonie(pv)
	if err != nil {
		r.echec("CR-1", "forme canonique : %v", err)
		return nonExecutees("prerequis_en_echec")
	}
	r.Digest = Hex0x(dc)

	participants := pv.Get("participants").Arr
	role := map[string]string{}
	adresse := map[string]string{}
	for _, p := range participants {
		role[p.Get("id").Str] = p.Get("role").Str
		adresse[p.Get("id").Str] = p.Get("address").Str
	}
	steps := pv.Get("steps").Arr
	keys := pv.Get("keys").Arr
	findings := pv.Get("findings").Arr
	production := pv.Get("environment").Str == productionValeur

	// CR-2 : participants.
	ids, adrs := map[string]bool{}, map[string]bool{}
	officiants, temoins := 0, 0
	for _, p := range participants {
		id, a := p.Get("id").Str, p.Get("address").Str
		if ids[id] {
			r.echec("CR-2", "identifiant %s en double", id)
		}
		if adrs[a] {
			r.echec("CR-2", "adresse %s en double", a)
		}
		ids[id], adrs[a] = true, true
		switch p.Get("role").Str {
		case roleOfficiant:
			officiants++
		case roleTemoin:
			temoins++
		}
	}
	if len(participants) < 2 {
		r.echec("CR-2", "%d participant(s), au moins deux", len(participants))
	}
	if officiants != 1 {
		r.echec("CR-2", "%d officiant(s), exactement un", officiants)
	}
	if temoins < 1 {
		r.echec("CR-2", "aucun témoin")
	}
	for _, s := range steps {
		if role[s.Get("performed_by").Str] == roleAuditeur {
			r.echec("CR-2", "étape %s exécutée par l'auditeur %s", s.Get("n").Num, s.Get("performed_by").Str)
		}
	}
	for _, k := range keys {
		for _, h := range k.Chemin("backup", "holders").Arr {
			if role[h.Str] == roleAuditeur {
				r.echec("CR-2", "part de %s détenue par l'auditeur %s", k.Get("key_id").Str, h.Str)
			}
		}
	}

	// CR-3 : chronologie.
	debut, okD := AnalyserInstant(pv.Get("started_at").Str)
	fin, okF := AnalyserInstant(pv.Get("ended_at").Str)
	if !okD || !okF {
		r.echec("CR-3", "started_at ou ended_at n'est pas un instant existant (CT-1 §3)")
	} else if debut.After(fin) {
		r.echec("CR-3", "started_at postérieur à ended_at")
	}
	var precedent time.Time
	for i, s := range steps {
		if n, _ := s.Get("n").Entier(); n != int64(i+1) {
			r.echec("CR-3", "steps[%d].n = %d, %d attendu", i, n, i+1)
		}
		at, ok := AnalyserInstant(s.Get("at").Str)
		if !ok {
			r.echec("CR-3", "steps[%d].at n'est pas un instant existant", i)
			continue
		}
		if i > 0 && !precedent.IsZero() && at.Before(precedent) {
			r.echec("CR-3", "steps[%d].at antérieur à l'étape précédente", i)
		}
		if okD && okF && (at.Before(debut) || at.After(fin)) {
			r.echec("CR-3", "steps[%d].at hors de [started_at, ended_at]", i)
		}
		precedent = at
	}

	// CR-4 : étapes.
	for i, s := range steps {
		par := s.Get("performed_by").Str
		if _, ok := role[par]; !ok {
			r.echec("CR-4", "steps[%d].performed_by %s n'est pas un participant", i, par)
		}
		for _, w := range s.Get("witnessed_by").Arr {
			ro, ok := role[w.Str]
			if !ok {
				r.echec("CR-4", "steps[%d] : témoin %s n'est pas un participant", i, w.Str)
			} else if ro != roleTemoin && ro != roleAuditeur {
				r.echec("CR-4", "steps[%d] : %s de rôle %s, témoin ou auditeur attendu", i, w.Str, ro)
			}
			if w.Str == par {
				r.echec("CR-4", "steps[%d] : l'exécutant %s est témoin de sa propre étape", i, par)
			}
		}
		temoinDistinct := false
		for _, w := range s.Get("witnessed_by").Arr {
			temoinDistinct = temoinDistinct || (role[w.Str] == roleTemoin && w.Str != par)
		}
		if !temoinDistinct {
			r.echec("CR-4", "steps[%d] : aucun participant de rôle temoin parmi les témoins", i)
		}
		if s.Get("outcome").Str == resultatException {
			n, _ := s.Get("n").Entier()
			nomme := false
			for _, f := range findings {
				if st, ok := f.Get("step").Entier(); ok && st == n {
					nomme = true
				}
			}
			if !nomme {
				r.echec("CR-4", "étape %d en exception sans constat qui la nomme", n)
			}
		}
	}

	// CR-5 : clés.
	keyIDs := map[string]bool{}
	for i, k := range keys {
		kid := k.Get("key_id").Str
		usage, algo := k.Get("usage").Str, k.Get("algorithm").Str
		if keyIDs[kid] {
			r.echec("CR-5", "key_id %s en double", kid)
		}
		keyIDs[kid] = true
		if !dans(algo, algorithmeParUsage[usage]) {
			r.echec("CR-5", "keys[%d] : algorithme %s pour l'usage %s", i, algo, usage)
		}
		if (k.Get("generated_in").Str == generationDetenteur) != (usage == usageApprobateur) {
			r.echec("CR-5", "keys[%d] : generated_in %s pour l'usage %s", i, k.Get("generated_in").Str, usage)
		}
		for _, x := range controlerEncodageCle(k) {
			r.echec("CR-5", "keys[%d] (%s) : %s", i, kid, x)
		}
	}

	// CR-6 : classes.
	for i, k := range keys {
		usage, classe := k.Get("usage").Str, k.Get("custody_class").Str
		if (classe == classeSansObjet) != (usage == usageApprobateur) {
			r.echec("CR-6", "keys[%d] : classe %s pour l'usage %s", i, classe, usage)
		}
		if production && !dans(classe, classesProduction[usage]) {
			r.echec("CR-6", "keys[%d] : classe %s non admise en production pour l'usage %s (4.3)", i, classe, usage)
		}
	}

	// CR-7 : sauvegarde.
	for i, k := range keys {
		usage := k.Get("usage").Str
		b := k.Get("backup")
		schema := b.Get("scheme").Str
		holders := b.Get("holders").Arr
		switch schema {
		case schemaAucune:
			if !b.Get("k").EstNull() || !b.Get("n").EstNull() || len(holders) != 0 {
				r.echec("CR-7", "keys[%d] : sauvegarde « aucune » avec k, n ou détenteurs", i)
			}
		case schemaPartage:
			kk, okK := b.Get("k").Entier()
			nn, okN := b.Get("n").Entier()
			if !okK || !okN || kk < 2 || kk > nn {
				r.echec("CR-7", "keys[%d] : partage k = %s, n = %s ; 2 ≤ k ≤ n attendu", i, b.Get("k").Num, b.Get("n").Num)
			}
			if okN && int64(len(holders)) != nn {
				r.echec("CR-7", "keys[%d] : %d détenteurs pour n = %d", i, len(holders), nn)
			}
			vus := map[string]bool{}
			for _, h := range holders {
				if vus[h.Str] {
					r.echec("CR-7", "keys[%d] : détenteur %s en double", i, h.Str)
				}
				vus[h.Str] = true
				if role[h.Str] != roleDetenteurPart {
					r.echec("CR-7", "keys[%d] : détenteur %s de rôle %q, detenteur_part attendu", i, h.Str, role[h.Str])
				}
			}
		}
		switch {
		case dans(usage, sansSauvegarde) && schema != schemaAucune:
			r.echec("CR-7", "keys[%d] : aucune sauvegarde admise pour l'usage %s (4.4)", i, usage)
		case dans(usage, partageToujours) && schema != schemaPartage:
			r.echec("CR-7", "keys[%d] : partage exigé pour l'usage %s (4.4)", i, usage)
		case production && dans(usage, partageEnProduction) && schema != schemaPartage:
			r.echec("CR-7", "keys[%d] : partage exigé en production pour l'usage %s (4.4)", i, usage)
		}
	}

	// CR-8 : membres.
	for i, k := range keys {
		if k.Get("usage").Str != usageApprobateur {
			continue
		}
		n := 0
		for _, p := range participants {
			if p.Get("role").Str == roleMembre && p.Get("address").Str == k.Get("address").Chaine() {
				n++
			}
		}
		if n != 1 {
			r.echec("CR-8", "keys[%d] (approbateur) : %d participant(s) membre(s) de cette adresse, un attendu", i, n)
		}
	}
	for _, p := range participants {
		if p.Get("role").Str != roleMembre {
			continue
		}
		n := 0
		for _, k := range keys {
			if k.Get("usage").Str == usageApprobateur && k.Get("address").Chaine() == p.Get("address").Str {
				n++
			}
		}
		if n != 1 {
			r.echec("CR-8", "membre %s : %d clé(s) approbateur à son adresse, une attendue", p.Get("id").Str, n)
		}
	}

	// CR-9 : production.
	if production {
		if pv.Chemin("script", "sha256").EstNull() {
			r.echec("CR-9", "script.sha256 nul en production")
		}
		video := false
		for _, e := range pv.Get("records").Arr {
			video = video || e.Get("kind").Str == enregistrementVideo
		}
		auditeur := false
		for _, p := range participants {
			auditeur = auditeur || p.Get("role").Str == roleAuditeur
		}
		if !video && !auditeur {
			r.echec("CR-9", "production sans enregistrement vidéo ni auditeur")
		}
		poste := false
		for _, k := range keys {
			poste = poste || k.Get("generated_in").Str == generationPoste
		}
		ws := pv.Get("workstation")
		if poste && (!ws.Get("offline").Bool || ws.Get("image_sha256").EstNull()) {
			r.echec("CR-9", "clé générée sur le poste : offline vrai et image_sha256 non nul exigés")
		}
	}

	// CR-10 : constats.
	numeros := map[int64]bool{}
	for _, s := range steps {
		n, _ := s.Get("n").Entier()
		numeros[n] = true
	}
	for i, f := range findings {
		if n, _ := f.Get("n").Entier(); n != int64(i+1) {
			r.echec("CR-10", "findings[%d].n = %d, %d attendu", i, n, i+1)
		}
		if st := f.Get("step"); !st.EstNull() {
			if n, _ := st.Entier(); !numeros[n] {
				r.echec("CR-10", "findings[%d].step = %d n'est le numéro d'aucune étape", i, n)
			}
		}
		if f.Get("kind").Str == sorteIncident && f.Get("resolution").EstNull() {
			r.echec("CR-10", "findings[%d] : incident sans résolution", i)
		}
	}

	// CR-12 : objet (5.1) : forme de purpose_details et ce que l'objet exige.
	objet := pv.Get("purpose").Str
	d := pv.Get("purpose_details")
	nbRole := func(ro string) int64 {
		n := int64(0)
		for _, p := range participants {
			if p.Get("role").Str == ro {
				n++
			}
		}
		return n
	}
	if cle := detailsParObjet[objet]; cle == "" {
		if !d.EstNull() {
			r.echec("CR-12", "purpose_details non nul pour l'objet %s", objet)
		}
	} else if d.EstNull() || d.Get(cle) == nil {
		r.echec("CR-12", "purpose_details de l'objet %s : membre %s attendu", objet, cle)
	} else {
		switch objet {
		case "rotation_urgence":
			a, okA := AnalyserInstant(d.Get("decided_at").Str)
			b, okB := AnalyserInstant(d.Get("revocation_included_at").Str)
			if !okA || !okB {
				r.echec("CR-12", "purpose_details : instant qui n'existe pas")
			} else if a.After(b) {
				r.echec("CR-12", "decided_at postérieur à revocation_included_at")
			}
		case "restauration":
			k, _ := d.Get("k").Entier()
			n, _ := d.Get("n").Entier()
			if k < 2 || k > n {
				r.echec("CR-12", "restauration d'un partage %d sur %d, 2 ≤ k ≤ n attendu", k, n)
			}
			if nbRole(roleDetenteurPart) < k {
				r.echec("CR-12", "%d détenteur(s) de part, au moins k = %d", nbRole(roleDetenteurPart), k)
			}
		case "changement_administrateur":
			req, _ := d.Get("required").Entier()
			if nbRole(roleMembre) < req {
				r.echec("CR-12", "%d membre(s) présent(s), au moins required = %d", nbRole(roleMembre), req)
			}
			gouv := false
			for _, k := range keys {
				gouv = gouv || k.Get("usage").Str == "gouvernance"
			}
			if !gouv {
				r.echec("CR-12", "aucune clé d'usage gouvernance")
			}
		}
	}
	if dans(objet, []string{"creation", "rotation", "rotation_urgence"}) && len(keys) == 0 {
		r.echec("CR-12", "objet %s sans clé", objet)
	}
	if objet == "sauvegarde" {
		partage := false
		for _, k := range keys {
			partage = partage || k.Chemin("backup", "scheme").Str == schemaPartage
		}
		if !partage {
			r.echec("CR-12", "sauvegarde sans clé partagée k sur n")
		}
	}
	if objet == "inscription_membres" {
		app := false
		for _, k := range keys {
			app = app || k.Get("usage").Str == usageApprobateur
		}
		if !app {
			r.echec("CR-12", "inscription de membres sans clé d'approbateur")
		}
	}

	// CR-11 : signatures.
	m := MessageEIP191(dc)
	parParticipant := map[string]int{}
	signataires := map[string]bool{}
	for i, s := range pv.Get("signatures").Arr {
		p := s.Get("participant").Str
		parParticipant[p]++
		a, ok := adresse[p]
		if !ok {
			r.echec("CR-11", "signatures[%d] : %s n'est pas un participant", i, p)
			continue
		}
		rec, err := RecouvrerAdresse(m, s.Get("signature").Str)
		if err != nil {
			r.echec("CR-11", "signatures[%d] (%s) : %v", i, p, err)
			continue
		}
		if rec != a {
			r.echec("CR-11", "signatures[%d] (%s) : adresse recouvrée %s ≠ %s", i, p, rec, a)
			continue
		}
		signataires[a] = true
	}
	// Signataires (5.8) : adresses des participants dont la signature passe CR-11, dans l'ordre de participants, sans doublon.
	for _, p := range participants {
		a := p.Get("address").Str
		if signataires[a] && !dans(a, r.Signataires) {
			r.Signataires = append(r.Signataires, a)
		}
	}
	for _, p := range participants {
		if n := parParticipant[p.Get("id").Str]; n != 1 {
			r.echec("CR-11", "participant %s : %d signature(s), exactement une attendue", p.Get("id").Str, n)
		}
	}
	return r
}

// controlerEncodageCle applique l'encodage de 5.6 et les règles de CR-5 sur
// public_key, fingerprint et address.
func controlerEncodageCle(k *Value) []string {
	var out []string
	algo, usage := k.Get("algorithm").Str, k.Get("usage").Str
	pubV, fpV, adrV := k.Get("public_key"), k.Get("fingerprint"), k.Get("address")
	var pub []byte
	if !pubV.EstNull() {
		b, err := OctetsHex(pubV.Str, 0)
		if err != nil {
			return append(out, "public_key : "+err.Error())
		}
		pub = b
	}
	// fingerprint : SHA-256 de public_key, ou nul avec elle.
	switch {
	case pub == nil && !fpV.EstNull():
		out = append(out, "fingerprint non nul sans public_key")
	case pub != nil && fpV.EstNull():
		out = append(out, "fingerprint nul avec une public_key")
	case pub != nil && fpV.Str != Hex0x(SHA256(pub)):
		out = append(out, fmt.Sprintf("fingerprint %s ≠ SHA-256(public_key) = %s", fpV.Str, Hex0x(SHA256(pub))))
	}
	switch algo {
	case "ed25519":
		if pub == nil || len(pub) != 32 {
			out = append(out, fmt.Sprintf("clé Ed25519 de %d octets, 32 attendus (RFC 8032)", len(pub)))
		}
	case "secp256k1":
		if pub == nil {
			if usage != usageApprobateur {
				out = append(out, "public_key nulle : admise pour une clé d'approbateur seulement")
			}
		} else if a, err := AdresseDeCleNonCompressee(pub); err != nil {
			out = append(out, err.Error())
		} else if adrV.Chaine() != a {
			out = append(out, fmt.Sprintf("address %s ≠ adresse dérivée %s", adrV.Chaine(), a))
		}
		if adrV.EstNull() {
			out = append(out, "address nulle pour une clé secp256k1")
		}
	case "rsa", "ecdsa_p256":
		if pub == nil {
			out = append(out, "public_key nulle")
		} else if cle, err := x509.ParsePKIXPublicKey(pub); err != nil {
			out = append(out, "SubjectPublicKeyInfo illisible : "+err.Error())
		} else {
			switch c := cle.(type) {
			case *rsa.PublicKey:
				if algo != "rsa" {
					out = append(out, "clé RSA déclarée "+algo)
				}
			case *ecdsa.PublicKey:
				if algo != "ecdsa_p256" || c.Curve != elliptic.P256() {
					out = append(out, "clé ECDSA hors P-256 ou déclarée "+algo)
				}
			default:
				out = append(out, "SubjectPublicKeyInfo d'un autre algorithme")
			}
		}
	case "aes256":
		if pub != nil || !fpV.EstNull() {
			out = append(out, "aes256 n'a ni clé publique ni empreinte")
		}
	}
	if algo != "secp256k1" && !adrV.EstNull() {
		out = append(out, "address non nulle hors de secp256k1")
	}
	return out
}
