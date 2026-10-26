// Annuaire des approbateurs (CT-3 révision 0.3, 13.3 à 13.8) : identité de
// session canonique (EX-13.7), message d'inscription (EX-13.12), défi
// (EX-13.13), vérification d'une inscription (EX-13.15), opérations
// (EX-13.17) et invariants (EX-13.10), contrôles de la console avant un vote
// ou une récusation (EX-13.18), vérification d'un annuaire exporté
// (EX-13.19). Écrit depuis le seul texte de CT-3 et les schémas
// annuaire-approbateurs-v0 et console-service-v0.
//
// L'annuaire est manipulé sous sa forme JSON (*Value), dans l'ordre des
// membres du schéma, pour être confronté tel quel aux vecteurs.

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Schémas de la révision 0.3.
const (
	RefAnnuaire       = "https://noortrace.example/schemas/v0/annuaire-approbateurs.schema.json"
	RefConsole        = "https://noortrace.example/schemas/v0/console-approbation.schema.json"
	RefConsoleService = "https://noortrace.example/schemas/v0/console-service.schema.json"
)

// ------------------------------------------------- identité de session

// IdentiteCanonique dit si une chaîne est une identité de session de la
// forme canonique d'EX-13.7 : « oidc <iss> <sub> » ou « utilisateur
// <domaine> <nom> », trois jetons séparés par une espace, caractères ASCII
// imprimables (U+0021 à U+007E) dans chaque jeton, au plus 256 caractères ;
// <iss> est une URL https:// sans « ? » ni « # » ; <sub> et <nom> de 1 à 255
// caractères, <domaine> de 1 à 128.
func IdentiteCanonique(s string) bool {
	if len(s) > 256 {
		return false
	}
	t := strings.Split(s, " ")
	if len(t) != 3 {
		return false
	}
	for _, j := range t {
		if j == "" {
			return false
		}
		for i := 0; i < len(j); i++ {
			if j[i] < 0x21 || j[i] > 0x7E {
				return false
			}
		}
	}
	switch t[0] {
	case "oidc":
		return strings.HasPrefix(t[1], "https://") && len(t[1]) > len("https://") &&
			!strings.ContainsAny(t[1], "?#") && len(t[2]) <= 255
	case "utilisateur":
		return len(t[1]) <= 128 && len(t[2]) <= 255
	}
	return false
}

// ------------------------------------------------- message d'inscription

// LigneInscription1 et LigneInscription2 sont les deux lignes fixes du
// message d'inscription (EX-13.12).
const (
	LigneInscription1 = "noortrace/inscription/v0"
	LigneInscription2 = "Je lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote."
)

// clesInscription sont les clés des lignes 3 à 10, dans l'ordre.
var clesInscription = []string{"Origine", "Organisation", "Identifiant d'organisation", "Identite", "Adresse", "Emis le", "Expire le", "Nonce"}

// ChampsInscription sont les champs d'un message d'inscription, dans l'ordre
// de ses lignes ($defs/champs_inscription).
type ChampsInscription struct {
	Origin, Org, OrgID, Identity, Address, IssuedAt, ExpiresAt, Nonce string
}

func (ch ChampsInscription) valeurs() []string {
	return []string{ch.Origin, ch.Org, ch.OrgID, ch.Identity, ch.Address, ch.IssuedAt, ch.ExpiresAt, ch.Nonce}
}

// JSON rend les champs sous la forme de $defs/champs_inscription.
func (ch ChampsInscription) JSON() *Value {
	return Objet("origin", Chaine(ch.Origin), "org", Chaine(ch.Org), "org_id", Chaine(ch.OrgID),
		"identity", Chaine(ch.Identity), "address", Chaine(ch.Address), "issued_at", Chaine(ch.IssuedAt),
		"expires_at", Chaine(ch.ExpiresAt), "nonce", Chaine(ch.Nonce))
}

// LireChamps lit $defs/champs_inscription.
func LireChamps(v *Value) ChampsInscription {
	return ChampsInscription{Origin: v.Get("origin").S(), Org: v.Get("org").S(), OrgID: v.Get("org_id").S(),
		Identity: v.Get("identity").S(), Address: v.Get("address").S(), IssuedAt: v.Get("issued_at").S(),
		ExpiresAt: v.Get("expires_at").S(), Nonce: v.Get("nonce").S()}
}

// MessageInscription construit le texte exact d'EX-13.12 : dix lignes
// séparées par LF, sans LF final.
func MessageInscription(ch ChampsInscription) string {
	l := []string{LigneInscription1, LigneInscription2}
	for i, v := range ch.valeurs() {
		l = append(l, clesInscription[i]+": "+v)
	}
	return strings.Join(l, "\n")
}

var (
	reOrigine      = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$`)
	reOrganisation = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	reNonce        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// reIdentifiantEntree est le motif d'un identifiant d'entrée (EX-13.9).
	reIdentifiantEntree = regexp.MustCompile(`^apb-[0-9a-z]+(-[0-9a-z]+)*$`)
)

// valeurChampValide contrôle la grammaire de la valeur de la ligne i
// (0 : origine … 7 : nonce), selon EX-13.12.
func valeurChampValide(i int, v string) bool {
	switch i {
	case 0:
		return len(v) <= 270 && reOrigine.MatchString(v)
	case 1:
		return reOrganisation.MatchString(v)
	case 2:
		return reHex32.MatchString(v)
	case 3:
		return IdentiteCanonique(v)
	case 4:
		return reAdresse.MatchString(v)
	case 5, 6:
		_, err := LireInstant(v)
		return err == nil
	case 7:
		return reNonce.MatchString(v)
	}
	return false
}

// AnalyserMessageInscription analyse un texte selon EX-13.12 : découpage
// sur LF, exactement dix lignes, deux premières lignes à l'identique, chaque
// clé à sa place, chaque valeur dans sa grammaire, puis reconstruction et
// égalité octet pour octet ; chaque caractère est de l'ASCII imprimable ou
// LF. Rend les champs, ou faux (message_invalide).
func AnalyserMessageInscription(txt string) (ChampsInscription, bool) {
	for i := 0; i < len(txt); i++ {
		if (txt[i] < 0x20 || txt[i] > 0x7E) && txt[i] != '\n' {
			return ChampsInscription{}, false
		}
	}
	l := strings.Split(txt, "\n")
	if len(l) != 10 || l[0] != LigneInscription1 || l[1] != LigneInscription2 {
		return ChampsInscription{}, false
	}
	vals := make([]string, 8)
	for i, k := range clesInscription {
		p := k + ": "
		if !strings.HasPrefix(l[i+2], p) {
			return ChampsInscription{}, false
		}
		vals[i] = l[i+2][len(p):]
		if !valeurChampValide(i, vals[i]) {
			return ChampsInscription{}, false
		}
	}
	ch := ChampsInscription{vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7]}
	if MessageInscription(ch) != txt {
		return ChampsInscription{}, false
	}
	return ch, true
}

// PreimageEIP191 rend la préimage EIP-191 version 0x45 d'un message en
// octets : 0x19 ‖ « Ethereum Signed Message:\n » ‖ décimal(L) ‖ message.
func PreimageEIP191(msg []byte) []byte {
	return append([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))), msg...)
}

// ------------------------------------------------- état du service

// Defi est un défi d'inscription connu du service ($defs/defi).
type Defi struct {
	Champs  ChampsInscription
	Utilise bool
}

// EtatAnnuaire est l'annuaire tenu par le service et ses défis en cours.
type EtatAnnuaire struct {
	Doc   *Value
	Defis []*Defi
	Sch   *Schemas
}

func poser(o *Value, cle string, v *Value) {
	for i := range o.Obj {
		if o.Obj[i].Key == cle {
			o.Obj[i].Val = v
			return
		}
	}
	o.Obj = append(o.Obj, Member{Key: cle, Val: v})
}

func (e *EtatAnnuaire) entrees() []*Value { return e.Doc.Get("entries").Arr }

func (e *EtatAnnuaire) entreeParID(id string) *Value {
	for _, x := range e.entrees() {
		if x.Get("id").S() == id {
			return x
		}
	}
	return nil
}

func (e *EtatAnnuaire) entreeParIdentite(s string) *Value {
	for _, x := range e.entrees() {
		if x.Get("session_identity").S() == s {
			return x
		}
	}
	return nil
}

// adresseDansAnnuaire dit si une adresse figure dans une entrée, dans
// quelque état que ce soit (EX-13.10, point 2).
func (e *EtatAnnuaire) adresseDansAnnuaire(a string) bool {
	for _, x := range e.entrees() {
		if adresseDeLEntree(x, a) != nil {
			return true
		}
	}
	return false
}

func adresseDeLEntree(entree *Value, a string) *Value {
	for _, x := range entree.Get("addresses").Arr {
		if x.Get("address").S() == a {
			return x
		}
	}
	return nil
}

// AdresseActive rend l'adresse active d'une entrée, ou "".
func AdresseActive(entree *Value) string {
	for _, x := range entree.Get("addresses").Arr {
		if x.Get("state").S() == "active" {
			return x.Get("address").S()
		}
	}
	return ""
}

func (e *EtatAnnuaire) estAdministrateur(s string) bool {
	return contient(chaines(e.Doc.Get("administrators")), s)
}

func (e *EtatAnnuaire) defiParNonce(n string) *Defi {
	for _, d := range e.Defis {
		if d.Champs.Nonce == n {
			return d
		}
	}
	return nil
}

// noter inscrit une opération acceptée (EX-12.17, EX-13.17) : revision
// incrémentée, élément ajouté à operations, updated_at posé.
func (e *EtatAnnuaire) noter(at Instant, op, by, entree string, adresse, launchedBy, motif *Value) int64 {
	rev, _ := EntierJSON(e.Doc.Get("revision"))
	rev++
	ops := e.Doc.Get("operations")
	// EX-13.37 : administrators est nul pour toute opération d'EX-13.15 et
	// d'EX-13.17.
	ops.Arr = append(ops.Arr, Objet("seq", Entier(rev), "at", Chaine(at.String()), "op", Chaine(op), "by", Chaine(by),
		"entry", Chaine(entree), "address", adresse, "launched_by", launchedBy, "reason", motif, "administrators", Nul()))
	poser(e.Doc, "revision", Entier(rev))
	poser(e.Doc, "updated_at", Chaine(at.String()))
	return rev
}

func reponseAdresse(entree, adresse, etat string, rev int64) *Value {
	return Objet("entry", Chaine(entree), "address", Chaine(adresse), "state", Chaine(etat), "revision", Entier(rev))
}

func reponseEntree(x *Value, rev int64) *Value {
	return Objet("entry", Chaine(x.Get("id").S()), "active", Booleen(x.Get("active").Bool),
		"requester_identities", Copier(x.Get("requester_identities")), "revision", Entier(rev))
}

// Resume rend l'état résumé de chaque entrée ($defs/resume_entree).
func (e *EtatAnnuaire) Resume() *Value {
	t := Tableau()
	for _, x := range e.entrees() {
		ad := Tableau()
		for _, a := range x.Get("addresses").Arr {
			ad.Arr = append(ad.Arr, Objet("address", Chaine(a.Get("address").S()), "state", Chaine(a.Get("state").S())))
		}
		t.Arr = append(t.Arr, Objet("id", Chaine(x.Get("id").S()), "active", Booleen(x.Get("active").Bool),
			"requester_identities", Copier(x.Get("requester_identities")), "addresses", ad))
	}
	return t
}

// ------------------------------------------------- inscription

// ModeInscription règle la vérification d'EX-13.15 : le service applique
// toutes les vérifications ; le rejeu d'un annuaire exporté (EX-13.19,
// point 6) les applique « hors nonce et horloge ».
type ModeInscription int

// Les deux modes.
const (
	ModeService ModeInscription = iota
	ModeRejeu
)

// ResultatInscription est l'issue d'EX-13.15.
type ResultatInscription struct {
	Raison    string // "" si acceptée
	Champs    ChampsInscription
	Signature string // signature normalisée
}

// VerifierInscription applique EX-13.15, dans l'ordre, à la requête reçue à
// l'instant r. En mode service, le défi est marqué présenté à partir du
// pas 4, quel que soit le sort de la requête.
func (e *EtatAnnuaire) VerifierInscription(req *Value, r Instant, mode ModeInscription) ResultatInscription {
	ko := func(raison string) ResultatInscription { return ResultatInscription{Raison: raison} }
	// 1. forme de la requête.
	if len(e.Sch.Valider(RefConsoleService+"#/$defs/requete_inscrire", req)) > 0 {
		return ko("requete_invalide")
	}
	sess := req.Get("session_identity").S()
	adr := req.Get("address").S()
	msg := req.Get("message").S()
	// 2. identité canonique.
	if !IdentiteCanonique(sess) {
		return ko("identite_invalide")
	}
	// 3. message d'EX-13.12.
	ch, ok := AnalyserMessageInscription(msg)
	if !ok {
		return ko("message_invalide")
	}
	var defi *Defi
	if mode == ModeService {
		// 4. nonce connu et non encore présenté ; le défi est présenté dès ici.
		defi = e.defiParNonce(ch.Nonce)
		if defi == nil {
			return ko("nonce_inconnu")
		}
		if defi.Utilise {
			return ko("nonce_deja_utilise")
		}
		defi.Utilise = true
		// 5. Emis le ≤ r < Expire le.
		emis, _ := LireInstant(ch.IssuedAt)
		expire, _ := LireInstant(ch.ExpiresAt)
		if r < emis || r >= expire {
			return ko("inscription_expiree")
		}
	}
	// 6. origine.
	if ch.Origin != e.Doc.Get("console_origin").S() {
		return ko("origine_differente")
	}
	// 7. organisation.
	if ch.Org != e.Doc.Get("org").S() || ch.OrgID != e.Doc.Get("org_id").S() {
		return ko("organisation_differente")
	}
	// 8. identité de la requête et du défi.
	if ch.Identity != sess || (defi != nil && defi.Champs.Identity != sess) {
		return ko("identite_differente")
	}
	// 9. adresse de la requête et du défi.
	if ch.Address != adr || (defi != nil && defi.Champs.Address != adr) {
		return ko("adresse_differente")
	}
	// 10. texte du défi, octet pour octet.
	if defi != nil && msg != MessageInscription(defi.Champs) {
		return ko("message_invalide")
	}
	// 11. signature normalisée (EX-9.3) qui recouvre l'adresse sur le
	// condensé EIP-191 des octets du message.
	sig, err := NormaliserSignature(req.Get("signature").S())
	if err != nil {
		return ko("signature_invalide")
	}
	rec, err := AdresseRecouvree(CondenseEIP191([]byte(msg)), sig)
	if err != nil || rec != adr {
		return ko("signature_invalide")
	}
	// 12. entrée active.
	if x := e.entreeParIdentite(sess); x != nil && !x.Get("active").Bool {
		return ko("identite_desactivee")
	}
	// 13. adresse dans aucune entrée.
	if e.adresseDansAnnuaire(adr) {
		return ko("adresse_deja_attribuee")
	}
	return ResultatInscription{Champs: ch, Signature: sig.Encoder()}
}

// adresseEnAttente construit l'adresse ajoutée par une inscription.
func adresseEnAttente(adr, msg, sig string, ch ChampsInscription, r Instant) *Value {
	return Objet("address", Chaine(adr), "state", Chaine("en_attente"),
		"proof", Objet("message", Chaine(msg), "signature", Chaine(sig), "nonce", Chaine(ch.Nonce),
			"issued_at", Chaine(ch.IssuedAt), "expires_at", Chaine(ch.ExpiresAt), "received_at", Chaine(r.String())),
		"validated_at", Nul(), "validated_by", Nul(), "revoked_at", Nul(), "revoked_by", Nul(),
		"revocation_cause", Nul(), "revocation_reason", Nul(), "replaced_by", Nul())
}

// inscrire applique l'effet d'une inscription acceptée (EX-13.15) ;
// nouvelleEntree donne l'identifiant d'une entrée créée, que la
// spécification laisse au service (EX-13.9). Rend l'entrée.
func (e *EtatAnnuaire) inscrire(req *Value, res ResultatInscription, r Instant, nouvelleEntree string) (string, int64) {
	sess := req.Get("session_identity").S()
	adr := req.Get("address").S()
	x := e.entreeParIdentite(sess)
	if x == nil {
		x = Objet("id", Chaine(nouvelleEntree), "session_identity", Chaine(sess), "external_id", Nul(),
			"display_name", Nul(), "active", Booleen(true), "requester_identities", Tableau(),
			"created_at", Chaine(r.String()), "addresses", Tableau())
		ent := e.Doc.Get("entries")
		ent.Arr = append(ent.Arr, x)
	}
	ad := x.Get("addresses")
	ad.Arr = append(ad.Arr, adresseEnAttente(adr, req.Get("message").S(), res.Signature, res.Champs, r))
	id := x.Get("id").S()
	rev := e.noter(r, "inscrire", sess, id, Chaine(adr), Nul(), Nul())
	return id, rev
}

// ------------------------------------------------- opérations

// IssueOperation est l'issue d'une méthode de l'annuaire.
type IssueOperation struct {
	Accepte bool
	Raison  string
	Reponse *Value // null si refusée
	// NouvelleEntree vaut vrai si une inscription a créé une entrée (son
	// identifiant n'est pas fixé par la spécification).
	NouvelleEntree bool
}

var refRequetes = map[string]string{
	"preparer_inscription": "requete_preparer_inscription",
	"inscrire":             "requete_inscrire",
	"valider":              "requete_valider",
	"revoquer":             "requete_revoquer",
	"desactiver":           "requete_entree",
	"reactiver":            "requete_entree",
	"lier_demandeur":       "requete_demandeur",
	"delier_demandeur":     "requete_demandeur",
}

// Appliquer exécute une méthode du canal de la console sur l'annuaire
// (EX-13.13, EX-13.15, EX-13.17), à l'instant at de l'horloge du service.
// nonce est le nonce que le service tire pour preparer_inscription ;
// idEntree donne l'identifiant d'une entrée que crée une inscription.
func (e *EtatAnnuaire) Appliquer(methode string, req *Value, at Instant, nonce string, idEntree func() string, mode ModeInscription) IssueOperation {
	ko := func(r string) IssueOperation { return IssueOperation{Raison: r, Reponse: Nul()} }
	ref, connu := refRequetes[methode]
	if !connu {
		return ko("requete_invalide")
	}
	if methode == "inscrire" {
		res := e.VerifierInscription(req, at, mode)
		if res.Raison != "" {
			return ko(res.Raison)
		}
		nouvelle := e.entreeParIdentite(req.Get("session_identity").S()) == nil
		id := ""
		if nouvelle {
			id = idEntree()
		}
		id, rev := e.inscrire(req, res, at, id)
		return IssueOperation{Accepte: true, Reponse: reponseAdresse(id, req.Get("address").S(), "en_attente", rev), NouvelleEntree: nouvelle}
	}
	if len(e.Sch.Valider(RefConsoleService+"#/$defs/"+ref, req)) > 0 {
		return ko("requete_invalide")
	}
	sess := req.Get("session_identity").S()
	if !IdentiteCanonique(sess) {
		return ko("identite_invalide")
	}
	adr := req.Get("address").S()
	motif := Copier(req.Get("reason"))
	if motif == nil {
		motif = Nul()
	}
	switch methode {
	case "preparer_inscription":
		if x := e.entreeParIdentite(sess); x != nil && !x.Get("active").Bool {
			return ko("identite_desactivee")
		}
		if e.adresseDansAnnuaire(adr) {
			return ko("adresse_deja_attribuee")
		}
		ttl, _ := EntierJSON(e.Doc.Get("registration_ttl_ms"))
		ch := ChampsInscription{Origin: e.Doc.Get("console_origin").S(), Org: e.Doc.Get("org").S(), OrgID: e.Doc.Get("org_id").S(),
			Identity: sess, Address: adr, IssuedAt: at.String(), ExpiresAt: (at + Instant(ttl)).String(), Nonce: nonce}
		// Un nouveau défi pour la même identité et la même adresse remplace
		// le précédent, dont le nonce devient inconnu (EX-13.13).
		garde := e.Defis[:0]
		for _, d := range e.Defis {
			if !(d.Champs.Identity == sess && d.Champs.Address == adr) {
				garde = append(garde, d)
			}
		}
		e.Defis = append(garde, &Defi{Champs: ch})
		return IssueOperation{Accepte: true, Reponse: Objet("fields", ch.JSON(), "message", Chaine(MessageInscription(ch)))}
	case "valider":
		if !e.estAdministrateur(sess) {
			return ko("non_administrateur")
		}
		x := e.entreeParID(req.Get("entry").S())
		if x == nil {
			return ko("entree_inconnue")
		}
		a := adresseDeLEntree(x, adr)
		if a == nil {
			return ko("adresse_inconnue")
		}
		if x.Get("session_identity").S() == sess {
			return ko("auto_validation")
		}
		if !x.Get("active").Bool {
			return ko("identite_desactivee")
		}
		if a.Get("state").S() != "en_attente" {
			return ko("etat_incompatible")
		}
		for _, p := range x.Get("addresses").Arr {
			if p.Get("state").S() == "active" {
				revoquerAdresse(p, at, sess, "remplacee", Nul(), Chaine(adr))
			}
		}
		poser(a, "state", Chaine("active"))
		poser(a, "validated_at", Chaine(at.String()))
		poser(a, "validated_by", Chaine(sess))
		rev := e.noter(at, "valider", sess, x.Get("id").S(), Chaine(adr), Nul(), Nul())
		return IssueOperation{Accepte: true, Reponse: reponseAdresse(x.Get("id").S(), adr, "active", rev)}
	case "revoquer":
		x := e.entreeParID(req.Get("entry").S())
		if x == nil {
			return ko("entree_inconnue")
		}
		a := adresseDeLEntree(x, adr)
		if a == nil {
			return ko("adresse_inconnue")
		}
		personne := x.Get("session_identity").S() == sess
		if !personne && !e.estAdministrateur(sess) {
			return ko("revocation_non_autorisee")
		}
		if st := a.Get("state").S(); st != "en_attente" && st != "active" {
			return ko("etat_incompatible")
		}
		cause := "administrateur"
		if personne {
			cause = "personne"
		}
		revoquerAdresse(a, at, sess, cause, motif, Nul())
		rev := e.noter(at, "revoquer", sess, x.Get("id").S(), Chaine(adr), Nul(), Copier(motif))
		return IssueOperation{Accepte: true, Reponse: reponseAdresse(x.Get("id").S(), adr, "revoquee", rev)}
	case "desactiver", "reactiver":
		if !e.estAdministrateur(sess) {
			return ko("non_administrateur")
		}
		x := e.entreeParID(req.Get("entry").S())
		if x == nil {
			return ko("entree_inconnue")
		}
		actif := x.Get("active").Bool
		if (methode == "desactiver") != actif {
			return ko("etat_incompatible")
		}
		if methode == "desactiver" {
			poser(x, "active", Booleen(false))
			for _, p := range x.Get("addresses").Arr {
				if st := p.Get("state").S(); st == "en_attente" || st == "active" {
					revoquerAdresse(p, at, sess, "desactivation", Nul(), Nul())
				}
			}
			// Les défis de l'identité sont effacés.
			garde := e.Defis[:0]
			for _, d := range e.Defis {
				if d.Champs.Identity != x.Get("session_identity").S() {
					garde = append(garde, d)
				}
			}
			e.Defis = garde
		} else {
			poser(x, "active", Booleen(true))
		}
		rev := e.noter(at, methode, sess, x.Get("id").S(), Nul(), Nul(), Copier(motif))
		return IssueOperation{Accepte: true, Reponse: reponseEntree(x, rev)}
	case "lier_demandeur", "delier_demandeur":
		if !e.estAdministrateur(sess) {
			return ko("non_administrateur")
		}
		x := e.entreeParID(req.Get("entry").S())
		if x == nil {
			return ko("entree_inconnue")
		}
		lb := req.Get("launched_by").S()
		ri := x.Get("requester_identities")
		if methode == "lier_demandeur" {
			for _, y := range e.entrees() {
				if contient(chaines(y.Get("requester_identities")), lb) {
					return ko("demandeur_deja_lie")
				}
			}
			ri.Arr = append(ri.Arr, Chaine(lb))
		} else {
			k := -1
			for i, v := range ri.Arr {
				if v.S() == lb {
					k = i
				}
			}
			if k < 0 {
				return ko("demandeur_inconnu")
			}
			ri.Arr = append(ri.Arr[:k:k], ri.Arr[k+1:]...)
		}
		rev := e.noter(at, methode, sess, x.Get("id").S(), Nul(), Chaine(lb), Nul())
		return IssueOperation{Accepte: true, Reponse: reponseEntree(x, rev)}
	}
	return ko("requete_invalide")
}

// revoquerAdresse pose l'état revoquee et ses champs (EX-13.17). Le motif
// d'une révocation par la validation d'une autre adresse ou par la
// désactivation de l'entrée n'est pas fixé par le texte : il est laissé nul
// (aucun vecteur ne l'expose).
func revoquerAdresse(a *Value, at Instant, par, cause string, motif, remplacant *Value) {
	poser(a, "state", Chaine("revoquee"))
	poser(a, "revoked_at", Chaine(at.String()))
	poser(a, "revoked_by", Chaine(par))
	poser(a, "revocation_cause", Chaine(cause))
	poser(a, "revocation_reason", motif)
	poser(a, "replaced_by", remplacant)
}

// ------------------------------------------------- contrôles de la console

// ControleVote applique EX-13.18 : la première condition remplie dans
// l'ordre jeu_non_fige, identite_inconnue, identite_desactivee,
// adresse_non_attribuee, hors_jeu, puis session_du_demandeur pour un vote
// seulement ; l'avertissement separation_incomplete porte les adresses que
// l'annuaire attribue au demandeur et que la politique ne déclare pas pour
// lui.
func ControleVote(doc *Value, session, action, adresse string, ticket *Value) (bool, string, *Value) {
	e := &EtatAnnuaire{Doc: doc}
	avert := Tableau()
	pol := chaines(ticket.Get("policy_requester_addresses"))
	manque := []string{}
	for _, a := range chaines(ticket.Get("directory_requester_addresses")) {
		if !contient(pol, a) {
			manque = append(manque, a)
		}
	}
	if len(manque) > 0 {
		avert.Arr = append(avert.Arr, Objet("code", Chaine("separation_incomplete"), "addresses", TableauChaines(manque)))
	}
	refus := func(r string) (bool, string, *Value) { return false, r, avert }
	membres := ticket.Get("members")
	if membres == nil || membres.IsNull() {
		return refus("jeu_non_fige")
	}
	x := e.entreeParIdentite(session)
	if x == nil {
		return refus("identite_inconnue")
	}
	if !x.Get("active").Bool {
		return refus("identite_desactivee")
	}
	if AdresseActive(x) != adresse || adresse == "" {
		return refus("adresse_non_attribuee")
	}
	if !contient(chaines(membres), adresse) {
		return refus("hors_jeu")
	}
	if action == "voter" && ticket.Get("self_approval").S() == "interdite" &&
		contient(chaines(x.Get("requester_identities")), ticket.Get("launched_by").S()) {
		return refus("session_du_demandeur")
	}
	return true, "", avert
}

// ControleCanal applique le contrôle de l'identité de session des méthodes
// tickets, consulter (EX-12.14), voter, recuser (EX-12.16) et retirer
// (EX-12.19) : identite_invalide si session_identity n'est pas canonique
// (EX-12.13), puis les raisons de la méthode dans l'ordre de sa règle ; ""
// sinon. ticket porte launched_by et eligible ; il est nul pour un ticket
// inconnu dans l'organisation, et pour tickets.
func ControleCanal(doc *Value, methode string, req, ticket *Value) string {
	session := req.Get("session_identity")
	if session == nil || session.IsNull() || !IdentiteCanonique(session.S()) {
		return "identite_invalide"
	}
	e := &EtatAnnuaire{Doc: doc}
	x := e.entreeParIdentite(session.S())
	active := ""
	if x != nil && x.Get("active").Bool {
		active = AdresseActive(x)
	}
	admin := contient(chaines(doc.Get("administrators")), session.S())
	refus := "session_non_autorisee"
	inconnu := ticket == nil || ticket.IsNull()
	switch methode {
	case "tickets", "consulter":
		// EX-12.14, point 1 : session de l'organisation (administrateur, ou
		// entrée active) ; tickets n'applique que ce point.
		if !admin && (x == nil || !x.Get("active").Bool) {
			return refus
		}
		if methode == "tickets" {
			return ""
		}
		// Point 2 : ticket inconnu ; point 3 : adresse active membre
		// éligible, ou administrateur.
		if inconnu {
			return "ticket_inconnu"
		}
		if admin || (active != "" && contient(chaines(ticket.Get("eligible")), active)) {
			return ""
		}
	case "voter", "recuser":
		// EX-12.16 : approver est l'adresse active de l'entrée active ; ce
		// contrôle ne dépend pas du ticket et passe avant ticket_inconnu
		// (EX-12.19, dernier alinéa).
		if active != "" && strings.ToLower(req.Get("approver").S()) == active {
			if inconnu {
				return "ticket_inconnu"
			}
			return ""
		}
	case "retirer":
		// EX-12.19 : le contrôle ne se fait que pour un ticket connu.
		if inconnu {
			return "ticket_inconnu"
		}
		// EX-12.19 : le demandeur, ou un administrateur en son nom propre.
		lb := ticket.Get("launched_by").S()
		by := req.Get("by")
		byS := ""
		if by != nil && !by.IsNull() {
			byS = by.S()
		}
		demandeur := byS == lb && x != nil && x.Get("active").Bool && contient(chaines(x.Get("requester_identities")), lb)
		if demandeur || (byS == session.S() && admin) {
			return ""
		}
	default:
		return "methode inconnue : " + methode
	}
	return refus
}

// AdressesAnnuaireDuDemandeur rend les adresses actives que l'annuaire
// attribue aux entrées dont requester_identities contient launchedBy,
// triées (EX-12.15).
func AdressesAnnuaireDuDemandeur(doc *Value, launchedBy string) []string {
	out := []string{}
	for _, x := range doc.Get("entries").Arr {
		if contient(chaines(x.Get("requester_identities")), launchedBy) {
			if a := AdresseActive(x); a != "" {
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------- annuaire exporté

// EcartExport est un écart d'EX-13.19 ; Pointeur vaut nil pour l'écart
// schema.
type EcartExport struct {
	Code     string
	Pointeur *string
}

func ecart(code, ptr string) EcartExport { return EcartExport{Code: code, Pointeur: &ptr} }

// VerifierAnnuaireExporte applique EX-13.19 hors ligne et rend la liste
// complète des écarts, triée par pointeur (unités UTF-16) puis par code ; un
// document non conforme au schéma donne la seule entrée schema.
func VerifierAnnuaireExporte(sch *Schemas, doc *Value) []EcartExport {
	// 1. forme.
	if len(sch.Valider(RefAnnuaire, doc)) > 0 {
		return []EcartExport{{Code: "schema"}}
	}
	var out []EcartExport
	ops := doc.Get("operations").Arr
	entrees := doc.Get("entries").Arr
	// 2. revision, seq, instants, updated_at.
	rev, _ := EntierJSON(doc.Get("revision"))
	if rev != int64(len(ops)) {
		out = append(out, ecart("revision_incoherente", "/revision"))
	}
	var prec Instant
	for j, op := range ops {
		if s, _ := EntierJSON(op.Get("seq")); s != int64(j+1) {
			out = append(out, ecart("revision_incoherente", fmt.Sprintf("/operations/%d/seq", j)))
		}
		t, _ := LireInstant(op.Get("at").S())
		if j > 0 && t < prec {
			out = append(out, ecart("revision_incoherente", fmt.Sprintf("/operations/%d/at", j)))
		}
		prec = t
	}
	maj := doc.Get("updated_at")
	if len(ops) == 0 {
		if !maj.IsNull() {
			out = append(out, ecart("revision_incoherente", "/updated_at"))
		}
	} else if maj.S() != ops[len(ops)-1].Get("at").S() {
		out = append(out, ecart("revision_incoherente", "/updated_at"))
	}
	// 3. unicité des identifiants, des identités, des adresses ; une
	// adresse active par entrée.
	ids, idts, adrs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, x := range entrees {
		if id := x.Get("id").S(); ids[id] {
			out = append(out, ecart("identifiant_double", fmt.Sprintf("/entries/%d/id", i)))
		} else {
			ids[id] = true
		}
		if s := x.Get("session_identity").S(); idts[s] {
			out = append(out, ecart("identite_double", fmt.Sprintf("/entries/%d/session_identity", i)))
		} else {
			idts[s] = true
		}
		actives := 0
		for k, a := range x.Get("addresses").Arr {
			if ad := a.Get("address").S(); adrs[ad] {
				out = append(out, ecart("adresse_double", fmt.Sprintf("/entries/%d/addresses/%d/address", i, k)))
			} else {
				adrs[ad] = true
			}
			if a.Get("state").S() == "active" {
				actives++
			}
		}
		if actives > 1 {
			out = append(out, ecart("deux_adresses_actives", fmt.Sprintf("/entries/%d/addresses", i)))
		}
	}
	// 4. preuves ; 5. auto-validation.
	for i, x := range entrees {
		for k, a := range x.Get("addresses").Arr {
			ptr := fmt.Sprintf("/entries/%d/addresses/%d", i, k)
			if code := verifierPreuve(doc, x, a); code != "" {
				out = append(out, ecart(code, ptr+"/proof"))
			}
			if vb := a.Get("validated_by"); vb != nil && !vb.IsNull() && vb.S() == x.Get("session_identity").S() {
				out = append(out, ecart("auto_validation", ptr+"/validated_by"))
			}
		}
	}
	// 6. rejeu des opérations depuis un annuaire vide.
	if p := rejouerOperations(sch, doc); p != "" {
		out = append(out, ecart("operations_incoherentes", p))
	}
	sort.SliceStable(out, func(a, b int) bool {
		if c := ComparerUTF16(*out[a].Pointeur, *out[b].Pointeur); c != 0 {
			return c < 0
		}
		return out[a].Code < out[b].Code
	})
	return out
}

// verifierPreuve applique EX-13.19 point 4 à une adresse d'une entrée.
func verifierPreuve(doc, entree, a *Value) string {
	p := a.Get("proof")
	msg := p.Get("message").S()
	ch, ok := AnalyserMessageInscription(msg)
	if !ok {
		return "preuve_invalide"
	}
	sig, err := DecoderSignature(p.Get("signature").S())
	if err != nil || !sig.Canonique() {
		return "preuve_invalide"
	}
	rec, err := AdresseRecouvree(CondenseEIP191([]byte(msg)), sig)
	if err != nil || rec != a.Get("address").S() {
		return "preuve_invalide"
	}
	emis, _ := LireInstant(ch.IssuedAt)
	expire, _ := LireInstant(ch.ExpiresAt)
	recu, err := LireInstant(p.Get("received_at").S())
	if err != nil || ch.Origin != doc.Get("console_origin").S() || ch.Org != doc.Get("org").S() ||
		ch.OrgID != doc.Get("org_id").S() || ch.Identity != entree.Get("session_identity").S() ||
		ch.Address != a.Get("address").S() || ch.Nonce != p.Get("nonce").S() ||
		ch.IssuedAt != p.Get("issued_at").S() || ch.ExpiresAt != p.Get("expires_at").S() ||
		recu < emis || recu >= expire {
		return "preuve_discordante"
	}
	return ""
}

// AnnuaireVide rend l'annuaire sans entrée ni opération de la même
// organisation et de la même configuration que doc.
func AnnuaireVide(doc *Value) *Value {
	return Objet("version", Entier(0), "org", Copier(doc.Get("org")), "org_id", Copier(doc.Get("org_id")),
		"console_origin", Copier(doc.Get("console_origin")), "registration_ttl_ms", Copier(doc.Get("registration_ttl_ms")),
		"administrators", Copier(doc.Get("administrators")), "revision", Entier(0), "updated_at", Nul(),
		"entries", Tableau(), "operations", Tableau())
}

// rejouerOperations rejoue operations depuis un annuaire vide (EX-13.19,
// point 6) : une inscription reprend la preuve que l'entrée op.entry porte
// pour op.address et l'identifiant op.entry pour une entrée créée ; les
// autres opérations sont rejouées comme les méthodes d'EX-13.17, les droits
// d'administrateur étant jugés sur la liste en vigueur, qui part du before
// de la première opération changer_administrateurs (sinon de administrators
// du document) et que chaque changer_administrateurs remplace par son after
// (EX-13.37). Rend le pointeur de la première opération qui ne se rejoue
// pas, "/administrators" si le rejeu aboutit à une autre liste, "/entries"
// s'il aboutit à d'autres entrées, ou "".
func rejouerOperations(sch *Schemas, doc *Value) string {
	e := &EtatAnnuaire{Doc: AnnuaireVide(doc), Sch: sch}
	for _, op := range doc.Get("operations").Arr {
		if op.Get("op").S() == "changer_administrateurs" {
			if a := op.Get("administrators"); a != nil && a.Kind == KindObject && a.Get("before") != nil {
				poser(e.Doc, "administrators", Copier(a.Get("before")))
			}
			break
		}
	}
	for j, op := range doc.Get("operations").Arr {
		ptr := fmt.Sprintf("/operations/%d", j)
		if op.Get("op").S() == "changer_administrateurs" {
			// EX-13.37 : by « configuration », entry, address, launched_by et
			// reason nuls ; before égal à la liste en vigueur, after différent.
			a := op.Get("administrators")
			if a == nil || a.Kind != KindObject || op.Get("by").S() != "configuration" ||
				!op.Get("entry").IsNull() || !op.Get("address").IsNull() || !op.Get("launched_by").IsNull() || !op.Get("reason").IsNull() ||
				!EgalJSON(a.Get("before"), e.Doc.Get("administrators")) || EgalJSON(a.Get("after"), a.Get("before")) {
				return ptr
			}
			poser(e.Doc, "administrators", Copier(a.Get("after")))
			continue
		}
		if a := op.Get("administrators"); a == nil || !a.IsNull() {
			return ptr
		}
		at, _ := LireInstant(op.Get("at").S())
		by := op.Get("by").S()
		id := op.Get("entry").S()
		adr := op.Get("address")
		var req *Value
		switch m := op.Get("op").S(); m {
		case "inscrire":
			var preuve *Value
			for _, x := range doc.Get("entries").Arr {
				if x.Get("id").S() == id {
					if a := adresseDeLEntree(x, adr.S()); a != nil {
						preuve = a.Get("proof")
						break
					}
				}
			}
			if preuve == nil {
				return ptr
			}
			// L'identifiant de l'opération doit être celui de l'entrée de
			// l'identité, ou un identifiant nouveau.
			if x := e.entreeParIdentite(by); x != nil {
				if x.Get("id").S() != id {
					return ptr
				}
			} else if e.entreeParID(id) != nil {
				return ptr
			}
			req = Objet("session_identity", Chaine(by), "address", Copier(adr),
				"message", Copier(preuve.Get("message")), "signature", Copier(preuve.Get("signature")))
		case "valider":
			req = Objet("session_identity", Chaine(by), "entry", Chaine(id), "address", Copier(adr))
		case "revoquer":
			req = Objet("session_identity", Chaine(by), "entry", Chaine(id), "address", Copier(adr), "reason", Copier(op.Get("reason")))
		case "desactiver", "reactiver":
			req = Objet("session_identity", Chaine(by), "entry", Chaine(id), "reason", Copier(op.Get("reason")))
		case "lier_demandeur", "delier_demandeur":
			req = Objet("session_identity", Chaine(by), "entry", Chaine(id), "launched_by", Copier(op.Get("launched_by")))
		default:
			return ptr
		}
		is := e.Appliquer(op.Get("op").S(), req, at, "", func() string { return id }, ModeRejeu)
		if !is.Accepte {
			return ptr
		}
	}
	// La liste d'administrateurs du rejeu est celle du document (EX-13.37).
	if !EgalJSON(e.Doc.Get("administrators"), doc.Get("administrators")) {
		return "/administrators"
	}
	// Les entrées rejouées sont confrontées à celles du document ;
	// external_id et display_name, qu'aucune opération ne pose (EX-13.9 :
	// « facultatifs et sans effet »), sont repris du document.
	rejouees := e.Doc.Get("entries").Arr
	doci := doc.Get("entries").Arr
	if len(rejouees) != len(doci) {
		return "/entries"
	}
	for i := range rejouees {
		x := Copier(rejouees[i])
		poser(x, "external_id", Copier(doci[i].Get("external_id")))
		poser(x, "display_name", Copier(doci[i].Get("display_name")))
		if !EgalJSON(x, doci[i]) {
			return "/entries"
		}
	}
	return ""
}
