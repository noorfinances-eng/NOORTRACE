package dossier

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Outils réservés (CT-1 §5.1).
const (
	OutilEchange   = "noortrace.modele.echange"
	OutilDecision  = "noortrace.approbation.decision"
	OutilRotation  = "noortrace.journal.rotation-cle"
	OutilPolitique = "noortrace.journal.politique"
)

// Evt : un événement du dossier (prouvé, voisin, décision d'approbation, ou
// inscription d'une attestation de périmètre).
type Evt struct {
	// Role : désignation dans les détails (« evenement », « voisin
	// précédent »…).
	Role commun.Texte
	V    *jsonv.Valeur
	// C : forme canonique de E' (objet privé de hash et sig), CT-1 §6.1.
	C    []byte
	ErrC error
	// Canonique : l'événement entier a une forme canonique (E-2).
	ErrCanonique error
	// Hash : hachage recalculé (si ErrC est nil).
	Hash [32]byte
}

func nouvelEvt(role commun.Texte, v *jsonv.Valeur) *Evt {
	e := &Evt{Role: role, V: v}
	e.ErrCanonique = jcs.Calculable(v)
	e.C, e.ErrC = jcs.Canonique(v.SansMembres("hash", "sig"))
	if e.ErrC == nil {
		e.Hash = cryptographie.Sha256(cryptographie.PrefixeEvenement, e.C)
	}
	return e
}

// HashOK dit si le hachage a pu être recalculé.
func (e *Evt) HashOK() bool { return e != nil && e.ErrC == nil }

// HashHex rend le hachage recalculé en hexadécimal.
func (e *Evt) HashHex() string { return cryptographie.Hex32(e.Hash) }

// Seq rend `seq` s'il est un entier sûr.
func (e *Evt) Seq() (int64, bool) { return e.V.Membre("seq").Entier() }

// Ts rend `ts` décodé.
func (e *Evt) Ts() (time.Time, bool) { return commun.LireHorodatage(e.V.Membre("ts").S()) }

// Outil rend execution.tool.
func (e *Evt) Outil() string { return e.V.Chemin("execution", "tool").S() }

// Cle rend recorder_key_id.
func (e *Evt) Cle() string { return e.V.Membre("recorder_key_id").S() }

// EstRotation dit si l'événement est une rotation de clé.
func (e *Evt) EstRotation() bool { return e.Outil() == OutilRotation }

// NouvelleCle rend new_key_id d'une rotation.
func (e *Evt) NouvelleCle() string {
	return e.V.Chemin("execution", "arguments", "value", "new_key_id").S()
}

// references rend les références de charge utile de l'événement :
// arguments, result, intent (quand c'est une référence) et context.
func (e *Evt) references() []*jsonv.Valeur {
	var refs []*jsonv.Valeur
	if a := e.V.Chemin("execution", "arguments"); a.EstObjet() {
		refs = append(refs, a)
	}
	if r := e.V.Chemin("execution", "result"); r.EstObjet() {
		refs = append(refs, r)
	}
	if i := e.V.Membre("intent"); i.EstObjet() {
		refs = append(refs, i)
	}
	if c := e.V.Membre("context"); c.EstTableau() {
		for _, x := range c.Elements {
			if x.EstObjet() {
				refs = append(refs, x)
			}
		}
	}
	return refs
}

// resultatEvt : résultat d'une règle sur un événement.
type resultatEvt struct {
	statut commun.Statut
	raison commun.Raison
	detail commun.Texte
}

func ok(fr, en string) resultatEvt { return resultatEvt{commun.Reussi, "", commun.T(fr, en)} }
func ko(fr, en string) resultatEvt { return resultatEvt{commun.Echoue, "", commun.T(fr, en)} }
func ne(r commun.Raison, fr, en string) resultatEvt {
	return resultatEvt{commun.NonExecute, r, commun.T(fr, en)}
}

// agregerEvts agrège les résultats d'une règle sur plusieurs événements et
// forme le détail « role : détail ; role : détail ».
func agregerEvts(id string, evts []*Evt, res []resultatEvt, controles ...int) commun.Verification {
	var rs []commun.Resultat
	var fr, en []string
	for i, r := range res {
		rs = append(rs, commun.Resultat{Statut: r.statut, Raison: r.raison})
		if !r.detail.Vide() {
			fr = append(fr, evts[i].Role.Fr+" : "+r.detail.Fr)
			en = append(en, evts[i].Role.En+": "+r.detail.En)
		}
	}
	st, ra := commun.Agreger(rs)
	return commun.Nouvelle(id, st, ra, commun.T(strings.Join(fr, " ; "), strings.Join(en, "; ")), controles...)
}

// --- E-1 -------------------------------------------------------------------

func regleE1(e *Evt) resultatEvt {
	if err := schema.Valider(schema.Evenement, e.V); err != nil {
		return ko("contraire au schéma evenement-v0 ("+err.Error()+")", "does not follow the evenement-v0 schema ("+err.Error()+")")
	}
	if _, okTs := e.Ts(); !okTs {
		return ko("ts n'est pas une date existante", "ts is not an existing date")
	}
	// org_id et journal_id non nuls (CT-1 §3, révision 0.5) : le schéma
	// admet 32 octets nuls, le vérificateur les refuse.
	if e.V.Membre("org_id").S() == zero32 || e.V.Membre("journal_id").S() == zero32 {
		return ko("org_id ou journal_id nul (32 octets nuls)", "null org_id or journal_id (32 zero bytes)")
	}
	if a := e.V.Membre("approval"); a.EstObjet() {
		if _, okAt := commun.LireHorodatage(a.Membre("at").S()); !okAt {
			return ko("approval.at n'est pas une date existante", "approval.at is not an existing date")
		}
	}
	return resultatEvt{statut: commun.Reussi}
}

// --- E-3 -------------------------------------------------------------------

func estReference(v *jsonv.Valeur) bool {
	return v.EstObjet() && v.Membre("sha256").EstChaine() && v.A("length") && v.Membre("redacted").EstBooleen()
}

// LanceurJournal : delegation.launched_by d'un événement du journal sur
// lui-même (rotation de clé, changement de politique ; CT-1 §5.3, E-3).
const LanceurJournal = "noortrace-enregistreur"

// tableauVide dit si la valeur est un tableau sans élément (une valeur
// absente ou d'un autre genre ne l'est pas, CT-1 §5.3).
func tableauVide(v *jsonv.Valeur) bool { return v.EstTableau() && len(v.Elements) == 0 }

// entierPositif dit si la valeur est un entier ≥ 0 de l'intervalle sûr.
func entierPositif(v *jsonv.Valeur) bool {
	n, ok := v.Entier()
	return ok && n >= 0
}

// regleE3 applique la règle exacte de E-3 (CT-1 §5.3, révision 0.5 ; CT-6
// EX-5.17) : la sorte se lit sur execution.tool ; un nom en « noortrace. »
// hors des quatre noms réservés met E-3 en échec et aucune autre règle ne
// s'applique ; sinon chaque règle de la sorte doit tenir, et une valeur
// absente, ou d'un autre genre que celui que la règle nomme, ne la tient
// pas.
func regleE3(e *Evt) resultatEvt {
	outil := e.Outil()
	exe := e.V.Membre("execution")
	polV := e.V.Chemin("policy", "decision")
	pol, polChaine := polV.Str()
	statut, statutChaine := exe.Membre("status").Str()
	res, dur, err := exe.Membre("result"), exe.Membre("duration_ms"), exe.Membre("is_error")
	ap := e.V.Membre("approval")
	effets := e.V.Membre("effects")
	nuls := func() bool { return res.EstNul() && dur.EstNul() && err.EstNul() }
	reponse := func() bool { return estReference(res) && entierPositif(dur) && err.EstBooleen() }
	var ecarts []string
	ajoute := func(s string) { ecarts = append(ecarts, s) }
	reservee := strings.HasPrefix(outil, "noortrace.")
	switch {
	case !exe.Membre("tool").EstChaine():
		ajoute("execution.tool n'est pas une chaîne : sorte illisible")
	case reservee && outil != OutilEchange && outil != OutilDecision && outil != OutilRotation && outil != OutilPolitique:
		// Nom réservé inconnu : aucune autre règle ne s'applique.
		ajoute("nom réservé « noortrace. » inconnu : " + outil)
	case !reservee:
		// 1. Appel d'outil.
		if !polChaine || (pol != "autorise" && pol != "a_approuver" && pol != "refuse") {
			ajoute("policy.decision d'un appel d'outil hors de { autorise, a_approuver, refuse }")
		}
		if !ap.EstNul() && pol != "a_approuver" {
			ajoute("approval non nul sans policy.decision = a_approuver")
		}
		decisionAp, _ := ap.Membre("decision").Str()
		switch {
		case !statutChaine:
			ajoute("execution.status illisible")
		case statut == "retenue":
			if pol != "a_approuver" || !ap.EstNul() {
				ajoute("appel retenu sans policy.decision = a_approuver et approval nul")
			}
		case statut == "executee":
			if !(pol == "autorise" || (pol == "a_approuver" && ap.EstObjet() && decisionAp == "approuve")) {
				ajoute("appel exécuté sans policy.decision = autorise, ni a_approuver avec approval.decision = approuve")
			}
		case statut == "refusee":
			if !(pol == "refuse" || (pol == "a_approuver" && ap.EstObjet() && (decisionAp == "refuse" || decisionAp == "expire"))) {
				ajoute("appel refusé sans policy.decision = refuse, ni a_approuver avec approval.decision = refuse ou expire")
			}
		default:
			ajoute("execution.status inconnu")
		}
		switch statut {
		case "executee":
			if !reponse() {
				ajoute("appel exécuté sans result (référence), duration_ms (entier ≥ 0) ou is_error (booléen)")
			}
		case "retenue", "refusee":
			if !nuls() {
				ajoute("appel " + statut + " avec result, duration_ms ou is_error non nul")
			}
			if !tableauVide(effets) {
				ajoute("appel " + statut + " avec des effets : un appel non relayé n'a pas d'effet")
			}
		}
	case outil == OutilEchange:
		// 2. Échange avec le modèle.
		if pol != "sans_objet" || !polChaine {
			ajoute("policy.decision ≠ sans_objet")
		}
		if !ap.EstNul() {
			ajoute("approval non nul pour un échange avec le modèle")
		}
		if statut != "executee" || !statutChaine {
			ajoute("status ≠ executee")
		}
		if !reponse() {
			ajoute("result (référence), duration_ms (entier ≥ 0) ou is_error (booléen) manquant")
		}
	default:
		// 3. Décision d'approbation, rotation de clé, changement de
		// politique.
		if pol != "sans_objet" || !polChaine {
			ajoute("policy.decision ≠ sans_objet")
		}
		if statut != "executee" || !statutChaine {
			ajoute("status ≠ executee")
		}
		if !nuls() {
			ajoute("result, duration_ms ou is_error non nul")
		}
		if !e.V.Membre("intent").EstNul() {
			ajoute("intent non nul")
		}
		if !exe.Membre("arguments").A("value") {
			ajoute("arguments sans valeur en ligne")
		}
		lanceur, _ := e.V.Chemin("delegation", "launched_by").Str()
		switch outil {
		case OutilDecision:
			// arguments.value a la même forme canonique que l'objet signé
			// A construit depuis l'événement (CT-1 §6.3), pour tout
			// événement que E-3 contrôle ; effets vides.
			if !ap.EstObjet() {
				ajoute("approval n'est pas un objet pour une décision")
			} else {
				ca, errA := jcs.Canonique(objetA(ap, e.V.Membre("org_id").S(), e.V.Membre("journal_id").S()))
				cv, errV := jcs.Canonique(exe.Chemin("arguments", "value"))
				if errA != nil || errV != nil || !bytes.Equal(ca, cv) {
					ajoute("arguments.value n'a pas la forme canonique de A = { decision, journal_id, org_id, request_hash, ticket } de la décision")
				}
			}
			if !tableauVide(effets) {
				ajoute("décision d'approbation avec des effets (ils sont déclarés par l'appel relayé)")
			}
		case OutilRotation:
			if !ap.EstNul() {
				ajoute("approval non nul pour un événement du journal")
			}
			if lanceur != LanceurJournal {
				ajoute("delegation.launched_by ≠ " + LanceurJournal)
			}
			nk := e.NouvelleCle()
			attendu := jsonv.NouvelObjet(
				jsonv.Membre{Nom: "system", Valeur: jsonv.NouvelleChaine("noortrace")},
				jsonv.Membre{Nom: "action", Valeur: jsonv.NouvelleChaine("ecriture")},
				jsonv.Membre{Nom: "object", Valeur: jsonv.NouvelleChaine("cle:" + nk)},
				jsonv.Membre{Nom: "amount", Valeur: &jsonv.Valeur{Genre: jsonv.Nul}},
				jsonv.Membre{Nom: "currency", Valeur: &jsonv.Valeur{Genre: jsonv.Nul}},
			)
			if !effets.EstTableau() || len(effets.Elements) != 1 || !jsonv.Egales(effets.Elements[0], attendu) || !exe.Chemin("arguments", "value", "new_key_id").EstChaine() {
				ajoute("effects différent de l'effet de rotation (CT-1 §8, règle 4)")
			}
		case OutilPolitique:
			if !ap.EstNul() {
				ajoute("approval non nul pour un événement du journal")
			}
			if lanceur != LanceurJournal {
				ajoute("delegation.launched_by ≠ " + LanceurJournal)
			}
			val := exe.Chemin("arguments", "value")
			pv, okPV := val.Membre("policy_version").Str()
			_, okH := cryptographie.LireHex(val.Membre("policy_sha256").S(), 32)
			n := utf8.RuneCountInString(pv)
			if !val.EstObjet() || val.Doublon || len(val.Noms()) != 2 || !okPV || n < 1 || n > 128 || !val.Membre("policy_sha256").EstChaine() || !okH {
				ajoute("arguments.value n'est pas { policy_version (1 à 128 caractères), policy_sha256 (32 octets) }")
			}
		}
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, ", ")
		return ko("champs incohérents avec la sorte de l'événement : "+s, "fields inconsistent with the kind of event: "+s)
	}
	return resultatEvt{statut: commun.Reussi}
}

// --- E-4 -------------------------------------------------------------------

func regleE4(e *Evt) resultatEvt {
	redige := false
	for _, r := range e.references() {
		if r.Membre("redacted").EstBooleen() && r.Membre("redacted").Bool {
			redige = true
		}
	}
	// policy.redaction doit être une chaîne non vide au sens de CT-1 §3
	// (révision 0.5) : null, "" et une chaîne de blancs ne suffisent pas.
	if r, okR := e.V.Chemin("policy", "redaction").Str(); redige && (!okR || !commun.ChaineNonVide(r)) {
		return ko("référence rédigée sans policy.redaction qui soit une chaîne non vide", "redacted reference without a policy.redaction that is a non-empty string")
	}
	return resultatEvt{statut: commun.Reussi}
}

// --- E-5 -------------------------------------------------------------------

func regleE5(e *Evt) resultatEvt {
	a := e.V.Membre("approval")
	if a.EstNul() {
		return resultatEvt{statut: commun.Reussi}
	}
	if !a.EstObjet() || !a.Membre("approvers").EstTableau() || !a.Membre("signatures").EstTableau() {
		return ko("approval illisible", "unreadable approval")
	}
	na, ns := len(a.Membre("approvers").Elements), len(a.Membre("signatures").Elements)
	if na != ns {
		return ko(fmt.Sprintf("%d approbateur(s) pour %d signature(s)", na, ns), fmt.Sprintf("%d approver(s) for %d signature(s)", na, ns))
	}
	if !a.Membre("ticket").EstChaine() || a.Membre("ticket").S() != e.V.Chemin("policy", "ticket").S() || !e.V.Chemin("policy", "ticket").EstChaine() {
		return ko("approval.ticket différent de policy.ticket", "approval.ticket differs from policy.ticket")
	}
	return resultatEvt{statut: commun.Reussi}
}

// --- E-6 -------------------------------------------------------------------

// Pieces : pièces fournies à part (EX-4.6).
type Pieces struct {
	Repertoire string
	// Lues : nombre de pièces lues (inputs.pieces.files).
	Lues int
	lues map[string]bool
}

func (a *Analyse) regleE6(e *Evt) (resultatEvt, *Defaut) {
	var ecarts []string
	for _, r := range e.references() {
		sha := r.Membre("sha256").S()
		lng, _ := r.Membre("length").Entier()
		if r.A("value") {
			c, err := jcs.Canonique(r.Membre("value"))
			if err != nil {
				ecarts = append(ecarts, "valeur en ligne sans forme canonique")
				continue
			}
			h := cryptographie.Sha256(c)
			if cryptographie.Hex32(h) != sha || int64(len(c)) != lng {
				ecarts = append(ecarts, fmt.Sprintf("valeur en ligne : SHA-256 %s, longueur %d, référence %s, %d", cryptographie.Hex32(h), len(c), sha, lng))
			}
		}
		if a.pieces == nil || !strings.HasPrefix(sha, "0x") || len(sha) != 66 {
			continue
		}
		nom := sha[2:]
		chemin := filepath.Join(a.pieces.Repertoire, nom)
		if !entree.Existe(chemin) {
			continue
		}
		l := entree.Lire(chemin, entree.LimitePiece)
		switch l.Etat {
		case entree.TropGrand:
			return resultatEvt{}, &Defaut{"taille_depassee", commun.T("pièce "+nom+" de plus de 1 Gio", "piece "+nom+" larger than 1 GiB")}
		case entree.Illisible, entree.Absent:
			return resultatEvt{}, &Defaut{"entree_illisible", commun.T("pièce "+nom+" illisible", "piece "+nom+" unreadable")}
		}
		if !a.pieces.lues[nom] {
			a.pieces.lues[nom] = true
			a.pieces.Lues++
		}
		if cryptographie.Hex32(l.Sha256) != sha || int64(len(l.Octets)) != lng {
			ecarts = append(ecarts, fmt.Sprintf("pièce %s : SHA-256 %s, longueur %d", nom, cryptographie.Hex32(l.Sha256), len(l.Octets)))
		}
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, ", ")
		return ko(s, s), nil
	}
	return resultatEvt{statut: commun.Reussi}, nil
}

// --- E-7 -------------------------------------------------------------------

func regleE7(e *Evt) resultatEvt {
	if !e.HashOK() {
		return ne(commun.PrerequisEnEchec, "forme canonique non calculable (E-2)", "canonical form not computable (E-2)")
	}
	declare := e.V.Membre("hash").S()
	if declare != e.HashHex() {
		return ko("hash recalculé "+e.HashHex()+" différent de hash "+declare, "recomputed hash "+e.HashHex()+" differs from hash "+declare)
	}
	return ok("hash "+e.HashHex(), "hash "+e.HashHex())
}

// --- E-8 (signature d'un événement) ----------------------------------------

func (a *Analyse) regleE8(e *Evt) resultatEvt {
	kid := e.Cle()
	cle, trouvee := a.Cles[kid]
	if !trouvee {
		return ko("clé "+kid+" absente de cles.json", "key "+kid+" missing from cles.json")
	}
	if !e.HashOK() {
		return ne(commun.PrerequisEnEchec, "forme canonique non calculable (E-2)", "canonical form not computable (E-2)")
	}
	sig, okSig := cryptographie.LireHex(e.V.Membre("sig").S(), 64)
	if !okSig || !cryptographie.VerifierEd25519(cle.Octets, append(append([]byte{}, cryptographie.PrefixeSignatureEvenement...), e.C...), sig) {
		return ko("signature invalide sous "+kid, "invalid signature under "+kid)
	}
	return ok("signature valide sous "+kid, "valid signature under "+kid)
}

// --- E-9 -------------------------------------------------------------------

// condenseApprobation rend D_A = SHA-256(P_A ‖ JCS(A)) (CT-1 §6.3).
func condenseApprobation(e *Evt, ap *jsonv.Valeur) ([32]byte, *jsonv.Valeur, error) {
	A := objetA(ap, e.V.Membre("org_id").S(), e.V.Membre("journal_id").S())
	c, err := jcs.Canonique(A)
	if err != nil {
		return [32]byte{}, A, err
	}
	return cryptographie.Sha256(cryptographie.PrefixeApprobation, c), A, nil
}

// objetA construit A = { decision, journal_id, org_id, request_hash, ticket }.
func objetA(ap *jsonv.Valeur, org, journal string) *jsonv.Valeur {
	copie := func(nom string) *jsonv.Valeur {
		if v := ap.Membre(nom); v != nil {
			return v
		}
		return &jsonv.Valeur{Genre: jsonv.Nul}
	}
	return jsonv.NouvelObjet(
		jsonv.Membre{Nom: "decision", Valeur: copie("decision")},
		jsonv.Membre{Nom: "journal_id", Valeur: jsonv.NouvelleChaine(journal)},
		jsonv.Membre{Nom: "org_id", Valeur: jsonv.NouvelleChaine(org)},
		jsonv.Membre{Nom: "request_hash", Valeur: copie("request_hash")},
		jsonv.Membre{Nom: "ticket", Valeur: copie("ticket")},
	)
}

func regleE9(e *Evt) resultatEvt {
	ap := e.V.Membre("approval")
	if ap.EstNul() {
		return resultatEvt{statut: commun.Reussi}
	}
	if !ap.EstObjet() {
		return ko("approval illisible", "unreadable approval")
	}
	// approvers et signatures sont des tableaux (CT-1 §5.3) : un autre
	// genre (null compris) ne porte aucune signature vérifiable, et E-9
	// échoue au lieu de réussir sur zéro signature.
	if !ap.Membre("approvers").EstTableau() || !ap.Membre("signatures").EstTableau() {
		return ko("approval.approvers ou approval.signatures n'est pas un tableau", "approval.approvers or approval.signatures is not an array")
	}
	d, _, err := condenseApprobation(e, ap)
	if err != nil {
		return ko("objet signé A sans forme canonique", "signed object A without canonical form")
	}
	// E-9 parcourt toutes les signatures (CT-1 §11.4, révision 0.5 ; CT-6
	// EX-5.19) : une signature sans approvers[i] la met en échec, en plus de
	// E-5 ; un approbateur sans signature relève de E-5 seule.
	adr, sigs := ap.Membre("approvers").Elements, ap.Membre("signatures").Elements
	for i := range sigs {
		if i >= len(adr) {
			return ko(fmt.Sprintf("signatures[%d] sans approvers[%d]", i, i), fmt.Sprintf("signatures[%d] without approvers[%d]", i, i))
		}
		s, okS := cryptographie.LireHex(sigs[i].S(), 65)
		if !okS {
			return ko(fmt.Sprintf("signatures[%d] illisible", i), fmt.Sprintf("signatures[%d] unreadable", i))
		}
		rec, err := cryptographie.RecouvrerEIP191(d, s)
		if err != nil {
			return ko(fmt.Sprintf("signatures[%d] : %v", i, err), fmt.Sprintf("signatures[%d]: %v", i, err))
		}
		if cryptographie.Hex(rec[:]) != adr[i].S() {
			return ko(fmt.Sprintf("signatures[%d] recouvre %s, et non %s", i, cryptographie.Hex(rec[:]), adr[i].S()),
				fmt.Sprintf("signatures[%d] recovers %s, not %s", i, cryptographie.Hex(rec[:]), adr[i].S()))
		}
	}
	return resultatEvt{statut: commun.Reussi}
}

// --- E-10 ------------------------------------------------------------------

func (a *Analyse) regleE10(e *Evt) resultatEvt {
	if !e.EstRotation() {
		return resultatEvt{statut: commun.Reussi}
	}
	val := e.V.Chemin("execution", "arguments", "value")
	if !val.EstObjet() {
		return ko("annonce de rotation illisible", "unreadable rotation announcement")
	}
	var ecarts []string
	if val.Membre("old_key_id").S() != e.Cle() {
		ecarts = append(ecarts, "old_key_id ≠ recorder_key_id")
	}
	if val.Membre("valid_from").S() != e.V.Membre("ts").S() {
		ecarts = append(ecarts, "valid_from ≠ ts")
	}
	if val.Membre("org_id").S() != e.V.Membre("org_id").S() || val.Membre("journal_id").S() != e.V.Membre("journal_id").S() {
		ecarts = append(ecarts, "org_id ou journal_id ≠ ceux de l'événement")
	}
	nk := val.Membre("new_key_id").S()
	if nk == "" || nk == val.Membre("old_key_id").S() {
		ecarts = append(ecarts, "new_key_id vide ou égal à old_key_id")
	}
	pub, okPub := cryptographie.LireHex(val.Membre("new_public_key").S(), 32)
	cs, okCs := cryptographie.LireHex(val.Membre("counter_sig").S(), 64)
	R := val.SansMembres("counter_sig")
	cR, err := jcs.Canonique(R)
	if !okPub || !okCs || err != nil || !cryptographie.VerifierEd25519(pub, append(append([]byte{}, cryptographie.PrefixeRotation...), cR...), cs) {
		ecarts = append(ecarts, "counter_sig invalide sous new_public_key")
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, ", ")
		return ko(s, s)
	}
	if !a.ClesExploitables {
		return ne(commun.PrerequisEnEchec, "cles.json inexploitable (E-8)", "cles.json unusable (E-8)")
	}
	ts, okTs := e.Ts()
	if c, okN := a.Cles[nk]; !okN || !okTs || c.Hex != val.Membre("new_public_key").S() || !c.Debut.Equal(ts) {
		ecarts = append(ecarts, "cles.json : clé "+nk+" absente, autre clé publique ou valid_from ≠ ts")
	}
	if c, okA := a.Cles[e.Cle()]; !okA || !okTs || c.Fin == nil || !c.Fin.Equal(ts) {
		ecarts = append(ecarts, "cles.json : valid_to de "+e.Cle()+" ≠ ts")
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, ", ")
		return ko(s, s)
	}
	return ok("rotation "+e.Cle()+" → "+nk, "rotation "+e.Cle()+" → "+nk)
}

// --- E-11 ------------------------------------------------------------------

func (a *Analyse) regleE11(e *Evt) resultatEvt {
	if !a.ClesExploitables {
		return ne(commun.PrerequisEnEchec, "cles.json inexploitable (E-8)", "cles.json unusable (E-8)")
	}
	c, trouvee := a.Cles[e.Cle()]
	if !trouvee {
		return ne(commun.PrerequisEnEchec, "clé absente de cles.json (échec porté par E-8)", "key missing from cles.json (failure carried by E-8)")
	}
	ts, okTs := e.Ts()
	if !okTs {
		return ko("ts illisible", "unreadable ts")
	}
	if ts.Before(c.Debut) || (c.Fin != nil && ts.After(*c.Fin)) {
		return ko("ts "+e.V.Membre("ts").S()+" hors de la validité de "+e.Cle(), "ts "+e.V.Membre("ts").S()+" outside the validity of "+e.Cle())
	}
	return resultatEvt{statut: commun.Reussi}
}
