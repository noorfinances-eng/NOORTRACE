// Console d'approbation (CT-3 révision 0.3, 9.6, 9.7, 13.9 à 13.14) :
// hachage de l'événement retenue (CT-1 §6.1), condensés, empreinte et
// groupes (EX-9.17 à EX-9.19), modèle d'affichage et ses treize contrôles
// (EX-9.15, EX-9.16), requête personal_sign (EX-13.24), vérification de la
// réponse du portefeuille et vote construit (EX-9.21, EX-13.29), découverte
// EIP-6963 (EX-13.22) et fichier de clé chiffré (EX-13.28). Écrit depuis le
// seul texte de CT-3, de CT-1 §5.4 et §6, et du schéma
// console-approbation-v0.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// PrefixeEvenement est P_H (CT-1 §6.1).
var PrefixeEvenement = []byte("noortrace/evenement/v0\n")

// HachageEvenement rend SHA-256(P_H ‖ JCS(E')), E' l'événement privé de
// hash et sig (CT-1 §6.1).
func HachageEvenement(ev *Value) ([]byte, error) {
	if ev == nil || ev.Kind != KindObject {
		return nil, fmt.Errorf("événement absent")
	}
	e := &Value{Kind: KindObject}
	for _, m := range ev.Obj {
		if m.Key != "hash" && m.Key != "sig" {
			e.Obj = append(e.Obj, m)
		}
	}
	c, err := Canonique(e)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(PrefixeEvenement)
	h.Write(c)
	return h.Sum(nil), nil
}

// ------------------------------------------------- condensés et empreintes

// Empreinte rend x[0..8] ‖ « … » ‖ x[56..64] (EX-9.18).
func Empreinte(b []byte) string {
	x := hex.EncodeToString(b)
	return x[:8] + "…" + x[56:]
}

// Groupes rend les 64 chiffres en 8 groupes de 8 séparés par une espace.
func Groupes(b []byte) string {
	x := hex.EncodeToString(b)
	g := make([]string, 8)
	for i := range g {
		g[i] = x[8*i : 8*i+8]
	}
	return strings.Join(g, " ")
}

// Condenses rend $defs/condenses pour l'objet A (EX-9.17 à EX-9.19), et
// D_A.
func Condenses(a *Value) (*Value, []byte, error) {
	j, err := Canonique(a)
	if err != nil {
		return nil, nil, err
	}
	d, _ := CondenseA(a)
	h := CondenseEIP191(d)
	return Objet("a", Copier(a), "jcs", Chaine(string(j)), "d_a", Chaine(Hex0x(d)), "fingerprint", Chaine(Empreinte(d)),
		"groups", Chaine(Groupes(d)), "h", Chaine(Hex0x(h)), "h_fingerprint", Chaine(Empreinte(h)),
		"utf8", Booleen(utf8.Valid(d))), d, nil
}

// RequetePersonalSign rend la requête d'EX-13.24 : la donnée en
// hexadécimal minuscule, puis l'adresse en minuscules.
func RequetePersonalSign(donnees []byte, adresse string) *Value {
	return Objet("method", Chaine("personal_sign"), "params", Tableau(Chaine(Hex0x(donnees)), Chaine(strings.ToLower(adresse))))
}

// ------------------------------------------------- arguments, feuille par feuille

// Feuille est une feuille d'une valeur JSON (EX-9.16).
type Feuille struct {
	Pointeur string
	Valeur   *Value
}

// Feuilles rend les feuilles d'une valeur : scalaires, objets sans membre et
// tableaux vides ; membres d'objet dans l'ordre JCS des noms (unités
// UTF-16), noms échappés selon la RFC 6901 ; éléments de tableau dans
// l'ordre, par indice décimal.
func Feuilles(v *Value, p string) []Feuille {
	switch {
	case v.Kind == KindObject && len(v.Obj) > 0:
		ms := append([]Member(nil), v.Obj...)
		sort.SliceStable(ms, func(i, j int) bool { return ComparerUTF16(ms[i].Key, ms[j].Key) < 0 })
		var out []Feuille
		for _, m := range ms {
			out = append(out, Feuilles(m.Val, p+"/"+echapperJeton(m.Key))...)
		}
		return out
	case v.Kind == KindArray && len(v.Arr) > 0:
		var out []Feuille
		for i, e := range v.Arr {
			out = append(out, Feuilles(e, fmt.Sprintf("%s/%d", p, i))...)
		}
		return out
	}
	return []Feuille{{Pointeur: p, Valeur: v}}
}

// ------------------------------------------------- modèle d'affichage

// SessionConsole est le contexte de session d'un cas de modèle
// (input.session de $defs/cas_modele).
type SessionConsole struct {
	Identite     string
	Entree       string // absente, active, desactivee
	Adresses     []string
	EstDemandeur bool
}

// ModeleAffichage tire de la vue du ticket le modèle d'affichage d'EX-9.4,
// avec les treize contrôles d'EX-9.15 dans leur ordre et les
// avertissements ($defs/modele_affichage).
func ModeleAffichage(vue *Value, s SessionConsole, decision, approbateur, motif *Value, maintenant Instant) *Value {
	req := vue.Get("request")
	ev := vue.Get("retained_event")
	sep := vue.Get("separation")
	interdite := sep.Get("self_approval").S() == "interdite"
	var bloc []string
	ajouter := func(r string) { bloc = append(bloc, r) }

	// 1. état.
	switch vue.Get("state").S() {
	case "ouvert", "seuil_atteint", "verification":
	default:
		ajouter("ticket_clos_aux_votes")
	}
	// 2. événement retenue.
	hachage := ""
	if h, err := HachageEvenement(ev); err == nil {
		hachage = Hex0x(h)
	}
	exe := ev.Get("execution")
	pol := ev.Get("policy")
	evOK := hachage != "" && exe.Get("status").S() == "retenue" && pol.Get("decision").S() == "a_approuver" &&
		pol.Get("ticket").S() == vue.Get("ticket").S() && hachage == ev.Get("hash").S() && hachage == vue.Get("request_hash").S()
	feuilles := Feuilles(req.Get("arguments"), "")
	etats := make([]string, len(feuilles))
	for i := range etats {
		etats[i] = "non_verifiable"
	}
	condenses := Nul()
	if !evOK {
		ajouter("evenement_invalide")
	} else {
		// 3. pièce « arguments ».
		ref := exe.Get("arguments")
		var piece *Value
		if pb := vue.Get("arguments_piece"); pb != nil && !pb.IsNull() {
			octets, err := base64.StdEncoding.Strict().DecodeString(pb.S())
			if err == nil {
				s := sha256.Sum256(octets)
				lg, _ := EntierJSON(ref.Get("length"))
				if Hex0x(s[:]) == ref.Get("sha256").S() && int64(len(octets)) == lg {
					if v, err := ParseJSON(octets); err == nil {
						piece = v
					}
				}
			}
		} else if val := ref.Get("value"); val != nil {
			if c, err := Canonique(val); err == nil {
				s := sha256.Sum256(c)
				lg, _ := EntierJSON(ref.Get("length"))
				if Hex0x(s[:]) == ref.Get("sha256").S() && int64(len(c)) == lg {
					piece = val
				}
			}
		}
		if piece == nil {
			ajouter("piece_invalide")
		}
		// 4. champs liés.
		champs := exe.Get("tool").S() == req.Get("tool_announced").S() &&
			pol.Get("rule").S() == vue.Get("rule").Get("policy_rule").S() &&
			ev.Get("org_id").S() == vue.Get("org_id").S() && ev.Get("journal_id").S() == vue.Get("journal_id").S()
		for _, k := range []string{"launched_by", "on_behalf_of", "scope", "run_id"} {
			if !EgalJSON(ev.Get("delegation").Get(k), req.Get("delegation").Get(k)) {
				champs = false
			}
		}
		if it := ev.Get("intent"); it == nil || it.Kind != KindObject {
			// Intention portée en chaîne (ou nulle) : égalité exigée ; par
			// référence, non vérifiable, sans bloquer.
			if !EgalJSON(it, req.Get("intent")) {
				champs = false
			}
		}
		if !champs {
			ajouter("champ_different")
		}
		// 5. arguments, feuille par feuille (EX-9.16).
		if piece != nil {
			different := false
			for i, f := range feuilles {
				x := Resoudre(f.Pointeur, piece)
				switch {
				case x == nil:
					etats[i] = "non_verifiable"
				case x.Kind == KindString && (strings.Contains(x.Str, "[REDIGE:") || strings.Contains(x.Str, "[PSEUDO:")):
					etats[i] = "non_verifiable"
				case EgalJSON(x, f.Valeur):
					etats[i] = "verifie"
				default:
					etats[i] = "different"
					different = true
				}
			}
			absent := false
			for _, q := range Feuilles(piece, "") {
				if Resoudre(q.Pointeur, req.Get("arguments")) == nil {
					absent = true
				}
			}
			if different {
				ajouter("argument_different")
			}
			if absent {
				ajouter("argument_absent_de_l_affichage")
			}
		}
		// 6. condensés des deux décisions, comparés à digests.
		ca, da, err1 := Condenses(ObjetA("approuve", ev.Get("journal_id").S(), ev.Get("org_id").S(), hachage, pol.Get("ticket").S()))
		cr, dr, err2 := Condenses(ObjetA("refuse", ev.Get("journal_id").S(), ev.Get("org_id").S(), hachage, pol.Get("ticket").S()))
		if err1 == nil && err2 == nil {
			condenses = Objet("approuve", ca, "refuse", cr)
			dg := vue.Get("digests")
			if Hex0x(da) != dg.Get("approuve").S() || Hex0x(dr) != dg.Get("refuse").S() {
				ajouter("empreinte_divergente")
			}
		}
	}
	// 7. jeu figé.
	jeu := vue.Get("approver_set")
	fige := jeu != nil && !jeu.IsNull()
	if !fige {
		ajouter("jeu_non_fige")
	}
	// 8. décision choisie.
	if decision == nil || decision.IsNull() {
		ajouter("decision_absente")
	}
	// 9. adresse attribuée à la session ; 10. membre ; 11. éligible.
	adr := ""
	if approbateur != nil && !approbateur.IsNull() {
		adr = approbateur.S()
	}
	switch {
	case s.Entree == "absente":
		ajouter("identite_inconnue")
	case s.Entree == "desactivee":
		ajouter("identite_desactivee")
	case adr == "" || !contient(s.Adresses, adr):
		ajouter("adresse_non_attribuee")
	case !fige:
		// Jeu non figé : ni appartenance ni éligibilité ne se contrôlent.
	case !contient(chaines(jeu.Get("members")), adr):
		ajouter("hors_jeu")
	case !contient(chaines(vue.Get("eligible")), adr):
		if interdite && contient(chaines(sep.Get("requester_addresses")), adr) {
			ajouter("auto_approbation")
		} else {
			ajouter("recuse")
		}
	}
	// 12. session du demandeur.
	if interdite && s.EstDemandeur {
		ajouter("session_du_demandeur")
	}
	// 13. motif.
	if motif != nil && motif.Kind == KindString && PointsDeCode(motif.Str) > 1024 {
		ajouter("motif_trop_long")
	}

	// Avertissements, dans l'ordre d'EX-9.15.
	var avert []string
	if !condenses.IsNull() && decision != nil && !decision.IsNull() {
		if c := condenses.Get(decision.S()); c != nil && c.Get("utf8").Bool {
			avert = append(avert, "condense_utf8")
		}
	}
	banniere := interdite && !sep.Get("requester_declared").Bool
	if banniere {
		avert = append(avert, "separation_non_verifiable")
	}
	if len(vue.Get("added_members").Arr) > 0 {
		avert = append(avert, "membres_ajoutes")
	}
	for _, a := range chaines(sep.Get("requester_directory_addresses")) {
		if !contient(chaines(sep.Get("requester_addresses")), a) {
			avert = append(avert, "separation_incomplete")
			break
		}
	}

	args := Tableau()
	for i, f := range feuilles {
		args.Arr = append(args.Arr, Objet("pointer", Chaine(f.Pointeur), "value", Copier(f.Valeur), "status", Chaine(etats[i])))
	}
	restant := Nul()
	if dl := vue.Get("deadline"); dl != nil && !dl.IsNull() {
		if t, err := LireInstant(dl.S()); err == nil {
			restant = Entier(int64(t - maintenant))
		}
	}
	// EX-9.15, contrôle 4 : intent_status vaut reference_non_verifiable quand
	// le membre intent de l'événement retenu est un objet, en_clair sinon.
	statutIntention := "en_clair"
	if ev != nil {
		if it := ev.Get("intent"); it != nil && it.Kind == KindObject {
			statutIntention = "reference_non_verifiable"
		}
	}
	return Objet(
		"version", Entier(0),
		"ticket", Copier(vue.Get("ticket")),
		"state", Copier(vue.Get("state")),
		"org_id", Copier(vue.Get("org_id")),
		"journal_id", Copier(vue.Get("journal_id")),
		"tool", Objet("announced", Copier(req.Get("tool_announced")), "original", Copier(req.Get("tool_original")),
			"server_alias", Copier(req.Get("server_alias")), "class", Copier(req.Get("class"))),
		"arguments", args,
		"effects", Copier(vue.Get("effects")),
		"rule", Copier(vue.Get("rule")),
		"opening", Copier(vue.Get("opening")),
		"intent", Copier(req.Get("intent")),
		"intent_status", Chaine(statutIntention),
		"delegation", Copier(req.Get("delegation")),
		"separation_banner", Booleen(banniere),
		"request", Objet("request_hash", Copier(vue.Get("request_hash")), "seq", Copier(ev.Get("seq")), "ts", Copier(ev.Get("ts"))),
		"digests", condenses,
		"decision", nulSiAbsent(decision),
		"approver", nulSiAbsent(approbateur),
		"deadline", Copier(vue.Get("deadline")),
		"remaining_ms", restant,
		"contest", Copier(vue.Get("contest")),
		"approver_set", Copier(vue.Get("approver_set")),
		"effective_required", Copier(vue.Get("effective_required")),
		"votes", Copier(vue.Get("votes")),
		"warnings", TableauChaines(avert),
		"blocking", TableauChaines(bloc),
		"signable", Booleen(len(bloc) == 0),
	)
}

func nulSiAbsent(v *Value) *Value {
	if v == nil {
		return Nul()
	}
	return Copier(v)
}

// ------------------------------------------------- réponse du portefeuille

// codesEIP1193 associe les codes d'EIP-1193 aux raisons de la table de
// 13.14 ; tout autre code, ou l'absence de code, donne erreur_portefeuille.
var codesEIP1193 = map[string]string{
	"4001": "refus_approbateur",
	"4100": "non_autorise",
	"4200": "methode_non_prise_en_charge",
	"4900": "deconnecte",
	"4901": "chaine_deconnectee",
}

var reReponseHex = regexp.MustCompile(`^0x[0-9a-fA-F]*$`)

// IssueReponse est le verdict d'EX-9.21 sur une réponse du portefeuille.
type IssueReponse struct {
	Raison    string // "" si acceptée
	Signature string // forme normalisée, si acceptée
	Recouvree string // adresse recouvrée sur H, "" si la forme est refusée avant
}

// VerifierReponse applique EX-9.21 (pas 1 à 7) et la table de 13.14 à
// l'issue d'une requête de signature envoyée pour (donnees, adresse).
func VerifierReponse(rep *Value, donnees []byte, adresse string) IssueReponse {
	if e := rep.Get("error"); e != nil {
		code := e.Get("code")
		if code != nil && code.Kind == KindNumber {
			if r, ok := codesEIP1193[code.Num]; ok {
				return IssueReponse{Raison: r}
			}
		}
		return IssueReponse{Raison: "erreur_portefeuille"}
	}
	res := rep.Get("result")
	if res == nil || res.Kind != KindString || !reReponseHex.MatchString(res.Str) {
		return IssueReponse{Raison: "reponse_invalide"}
	}
	sigtxt := strings.ToLower(res.Str)
	if len(sigtxt) != 132 {
		return IssueReponse{Raison: "signature_invalide"}
	}
	sig, err := NormaliserSignature(sigtxt)
	if err != nil {
		return IssueReponse{Raison: "signature_invalide"}
	}
	rec, err := AdresseRecouvree(CondenseEIP191(donnees), sig)
	if err != nil {
		return IssueReponse{Raison: "signature_invalide"}
	}
	if rec != strings.ToLower(adresse) {
		return IssueReponse{Raison: "adresse_differente", Recouvree: rec}
	}
	return IssueReponse{Signature: sig.Encoder(), Recouvree: rec}
}

// RequeteVoter construit le corps de voter (EX-9.21 pas 8, EX-12.16).
func RequeteVoter(a *Value, adresse, signature string, motif *Value, session string) *Value {
	return Objet("ticket", Copier(a.Get("ticket")), "approver", Chaine(adresse), "decision", Copier(a.Get("decision")),
		"signature", Chaine(signature), "reason", nulSiAbsent(motif), "session_identity", Chaine(session))
}

// ------------------------------------------------- découverte EIP-6963

var reUUIDv4 = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// AnnonceValide applique EX-13.22 point 2 à une annonce des vecteurs
// ($defs/annonce_eip6963, provider nommé) : uuid de version 4, nom non vide
// d'au plus 64 caractères, icône en URI data:, rdns chaîne.
func AnnonceValide(a *Value) bool {
	info := a.Get("info")
	if info == nil || info.Kind != KindObject {
		return false
	}
	nom := info.Get("name")
	icone := info.Get("icon")
	rdns := info.Get("rdns")
	pv := a.Get("provider")
	return reUUIDv4.MatchString(info.Get("uuid").S()) &&
		nom != nil && nom.Kind == KindString && nom.Str != "" && PointsDeCode(nom.Str) <= 64 &&
		icone != nil && icone.Kind == KindString && strings.HasPrefix(icone.Str, "data:") &&
		rdns != nil && rdns.Kind == KindString && pv != nil && pv.Kind == KindString && pv.Str != ""
}

// Decouvrir applique EX-13.22 points 2 et 3 à une suite d'annonces : la
// liste des fournisseurs dans l'ordre des premières annonces, et les
// annonces écartées (indice, raison), sans aucun choix.
func Decouvrir(annonces []*Value) (*Value, *Value) {
	type four struct {
		uuid, nom, rdns, objet string
		indice                 int
	}
	var liste []*four
	exclus := map[string]bool{}
	rejets := map[int]string{}
	for i, a := range annonces {
		if !AnnonceValide(a) {
			rejets[i] = "annonce_invalide"
			continue
		}
		info := a.Get("info")
		u := info.Get("uuid").S()
		obj := a.Get("provider").S()
		if exclus[u] {
			rejets[i] = "annonce_en_double"
			continue
		}
		k := -1
		for j, f := range liste {
			if f.uuid == u {
				k = j
			}
		}
		switch {
		case k < 0:
			liste = append(liste, &four{u, info.Get("name").S(), info.Get("rdns").S(), obj, i})
		case liste[k].objet == obj:
			// Réannonce par le même objet : sans effet.
		default:
			// Même uuid, autre objet : les deux sont écartés, l'uuid exclu.
			rejets[liste[k].indice] = "annonce_en_double"
			rejets[i] = "annonce_en_double"
			exclus[u] = true
			liste = append(liste[:k:k], liste[k+1:]...)
		}
	}
	fs := Tableau()
	for _, f := range liste {
		fs.Arr = append(fs.Arr, Objet("uuid", Chaine(f.uuid), "name", Chaine(f.nom), "rdns", Chaine(f.rdns), "provider", Chaine(f.objet)))
	}
	idx := make([]int, 0, len(rejets))
	for i := range rejets {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	rs := Tableau()
	for _, i := range idx {
		rs.Arr = append(rs.Arr, Objet("index", Entier(int64(i)), "reason", Chaine(rejets[i])))
	}
	return fs, rs
}

// ------------------------------------------------- fichier de clé

// IssueFichierCle est l'issue d'EX-13.28 (pas 1 à 6 et 9).
type IssueFichierCle struct {
	Raison         string
	Adresse        string // adresse de la clé déchiffrée, "" sinon
	Cle            []byte
	DerivationFbl  bool
	DerivationFait bool
}

var reHexLibre = regexp.MustCompile(`^([0-9a-fA-F]{2})*$`)

func hexLibre(v *Value, n int) ([]byte, bool) {
	if v == nil || v.Kind != KindString || !reHexLibre.MatchString(v.Str) {
		return nil, false
	}
	b, _ := hex.DecodeString(v.Str)
	if n >= 0 && len(b) != n {
		return nil, false
	}
	return b, true
}

func entierBorne(v *Value, min, max int64) (int64, bool) {
	n, ok := EntierJSON(v)
	return n, ok && n >= min && n <= max
}

// LireFichierCle applique EX-13.28 : format (fichier_cle_invalide),
// dérivation admise (fichier_cle_non_pris_en_charge), MAC
// (mot_de_passe_ou_mac), clé dans [1, n − 1] (cle_invalide), adresse
// (adresse_differente) ; avertissement derivation_faible.
func LireFichierCle(f *Value, motDePasse, adresse string) IssueFichierCle {
	invalide := IssueFichierCle{Raison: "fichier_cle_invalide"}
	nonPris := IssueFichierCle{Raison: "fichier_cle_non_pris_en_charge"}
	// 1. format.
	if f == nil || f.Kind != KindObject {
		return invalide
	}
	if v, ok := EntierJSON(f.Get("version")); !ok || v != 3 {
		return invalide
	}
	if id := f.Get("id"); id == nil || id.Kind != KindString {
		return invalide
	}
	cr := f.Get("crypto")
	if cr == nil || cr.Kind != KindObject {
		return invalide
	}
	cp := cr.Get("cipherparams")
	kp := cr.Get("kdfparams")
	if c := cr.Get("cipher"); c == nil || c.Kind != KindString {
		return invalide
	}
	if k := cr.Get("kdf"); k == nil || k.Kind != KindString {
		return invalide
	}
	if cp == nil || cp.Kind != KindObject || kp == nil || kp.Kind != KindObject {
		return invalide
	}
	iv, ok1 := hexLibre(cp.Get("iv"), 16)
	ct, ok2 := hexLibre(cr.Get("ciphertext"), 32)
	mac, ok3 := hexLibre(cr.Get("mac"), 32)
	if !ok1 || !ok2 || !ok3 {
		return invalide
	}
	// 2. dérivation admise.
	if cr.Get("cipher").S() != "aes-128-ctr" {
		return nonPris
	}
	sel, okSel := hexLibre(kp.Get("salt"), -1)
	if !okSel || len(sel) < 16 {
		return nonPris
	}
	if dk, ok := EntierJSON(kp.Get("dklen")); !ok || dk != 32 {
		return nonPris
	}
	var deriver func() ([]byte, error)
	faible := false
	switch cr.Get("kdf").S() {
	case "pbkdf2":
		if kp.Get("prf").S() != "hmac-sha256" {
			return nonPris
		}
		c, ok := entierBorne(kp.Get("c"), 1, 10000000)
		if !ok {
			return nonPris
		}
		faible = c < 262144
		deriver = func() ([]byte, error) { return pbkdf2.Key(sha256.New, motDePasse, sel, int(c), 32) }
	case "scrypt":
		n, okn := entierBorne(kp.Get("n"), 2, 1<<18)
		r, okr := entierBorne(kp.Get("r"), 1, 8)
		p, okp := entierBorne(kp.Get("p"), 1, 4)
		if !okn || !okr || !okp || n&(n-1) != 0 {
			return nonPris
		}
		faible = n < 1<<17
		deriver = func() ([]byte, error) { return Scrypt(motDePasse, sel, int(n), int(r), int(p), 32) }
	default:
		return nonPris
	}
	out := IssueFichierCle{DerivationFbl: faible, DerivationFait: true}
	// 4. dérivation et MAC.
	dk, err := deriver()
	if err != nil {
		return nonPris
	}
	if hex.EncodeToString(Keccak256(append(append([]byte{}, dk[16:32]...), ct...))) != hex.EncodeToString(mac) {
		out.Raison = "mot_de_passe_ou_mac"
		return out
	}
	// 5. déchiffrement AES-128-CTR, clé dans [1, n − 1].
	bloc, _ := aes.NewCipher(dk[:16])
	k := make([]byte, len(ct))
	cipher.NewCTR(bloc, iv).XORKeyStream(k, ct)
	ki := new(big.Int).SetBytes(k)
	if ki.Sign() == 0 || ki.Cmp(secpN) >= 0 {
		out.Raison = "cle_invalide"
		return out
	}
	// 6. adresse.
	a, err := AdresseDePrivee(k)
	if err != nil {
		out.Raison = "cle_invalide"
		return out
	}
	out.Adresse = Hex0x(a)
	out.Cle = k
	if out.Adresse != strings.ToLower(adresse) {
		out.Raison = "adresse_differente"
	}
	return out
}
