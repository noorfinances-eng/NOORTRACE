package rapport

import (
	"fmt"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/ots"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
)

// Provenances d'une clé (EX-6.8).
const (
	ProvAncres   = "ancres"
	ProvRegistre = "registre"
	ProvDossier  = "dossier"
)

// Approbation : valeurs de F3 (contrôle 7 réussi).
type Approbation struct {
	Decision     string
	Approbateurs []string
	Required     int64
	Size         int64
}

// DonneesEnonce : valeurs de l'énoncé d'un verdict valide ou incomplet
// (EX-6.8, EX-6.11).
type DonneesEnonce struct {
	Seq       int64
	Hash      string
	JournalID string
	OrgID     string
	// Precedent, Suivant : seq des voisins, nil pour un voisin nul.
	Precedent, Suivant     *int64
	PeriodStart, PeriodEnd int64
	PeriodHash             string
	CleEvenement           string
	CleManifeste           string
	ProvEvenement          string
	ProvManifeste          string
	// Approbation : nil si le contrôle 7 n'a pas réussi.
	Approbation *Approbation
	// F4, F5, F6 : propositions des contrôles 4, 5 et 8 réussis (sans
	// « ; » de tête), ou vides.
	F4, F5, F6 commun.Texte
	// FK, FP : fragments FK et FP (sans « ; » de tête), ou vides.
	FK, FP commun.Texte
	// NonExecutes : contrôles non exécutés (4, 5, 7, 8 pour F7).
	NonExecutes map[int]bool
}

// TexteProvenance : texte de la colonne « Une clé, cas mixte » d'EX-6.8.
func TexteProvenance(p string) commun.Texte {
	switch p {
	case ProvAncres:
		return commun.T("fournie par le fichier d'ancres", "given by the anchors file")
	case ProvRegistre:
		return commun.T("inscrite au registre", "registered in the registry")
	}
	return commun.T("déclarée par le dossier", "declared by the dossier")
}

func provenanceCommune(p string, pluriel bool) commun.Texte {
	switch {
	case p == ProvAncres && pluriel:
		return commun.T("clés fournies par le fichier d'ancres", "keys given by the anchors file")
	case p == ProvAncres:
		return commun.T("clé fournie par le fichier d'ancres", "given by the anchors file")
	case p == ProvRegistre && pluriel:
		return commun.T("clés inscrites au registre", "keys registered in the registry")
	case p == ProvRegistre:
		return commun.T("clé inscrite au registre", "registered in the registry")
	case pluriel:
		return commun.T("clés déclarées par le dossier", "keys declared by the dossier")
	}
	return commun.T("clé déclarée par le dossier", "declared by the dossier")
}

// Enonce construit l'énoncé d'un verdict valide ou incomplet (EX-6.8).
func ConstruireEnonce(d DonneesEnonce) commun.Texte {
	fr := fmt.Sprintf("L'événement seq %d (hachage %s) du journal %s de l'organisation %s", d.Seq, d.Hash, d.JournalID, d.OrgID)
	en := fmt.Sprintf("Event seq %d (hash %s) of journal %s of organisation %s", d.Seq, d.Hash, d.JournalID, d.OrgID)
	// F1
	var vFr, vEn string
	switch {
	case d.Precedent != nil && d.Suivant != nil:
		vFr = fmt.Sprintf("chaîné à ses voisins seq %d et %d", *d.Precedent, *d.Suivant)
		vEn = fmt.Sprintf("chained to its neighbours seq %d and %d", *d.Precedent, *d.Suivant)
	case d.Precedent != nil:
		vFr = fmt.Sprintf("chaîné à son voisin précédent seq %d (le dossier ne fournit pas de suivant)", *d.Precedent)
		vEn = fmt.Sprintf("chained to its previous neighbour seq %d (the dossier gives no next event)", *d.Precedent)
	case d.Suivant != nil:
		vFr = fmt.Sprintf("premier événement du journal, chaîné à son voisin suivant seq %d", *d.Suivant)
		vEn = fmt.Sprintf("the first event of the journal, chained to its next neighbour seq %d", *d.Suivant)
	default:
		vFr = "premier événement du journal, sans voisin dans le dossier"
		vEn = "the first event of the journal, with no neighbour in the dossier"
	}
	ps, pe := commun.FormaterSecondes(d.PeriodStart), commun.FormaterSecondes(d.PeriodEnd)
	fr += fmt.Sprintf(" est bien formé, %s et inclus dans la période du %s au %s close par le manifeste %s", vFr, ps, pe, d.PeriodHash)
	en += fmt.Sprintf(" is well-formed, %s and included in the period from %s to %s closed by manifest %s", vEn, ps, pe, d.PeriodHash)
	// F2
	if d.CleEvenement == d.CleManifeste {
		p := provenanceCommune(d.ProvEvenement, false)
		fr += fmt.Sprintf(" ; l'événement est signé, comme le manifeste, par la clé d'enregistreur %s, %s", d.CleEvenement, p.Fr)
		en += fmt.Sprintf("; the event is signed, like the manifest, by recorder key %s, %s", d.CleEvenement, p.En)
	} else {
		var p commun.Texte
		if d.ProvEvenement == d.ProvManifeste {
			p = provenanceCommune(d.ProvEvenement, true)
		} else {
			p1, p2 := TexteProvenance(d.ProvEvenement), TexteProvenance(d.ProvManifeste)
			p = commun.T(fmt.Sprintf("clé %s %s, clé %s %s", d.CleEvenement, p1.Fr, d.CleManifeste, p2.Fr),
				fmt.Sprintf("key %s %s, key %s %s", d.CleEvenement, p1.En, d.CleManifeste, p2.En))
		}
		fr += fmt.Sprintf(" ; l'événement est signé par la clé d'enregistreur %s et le manifeste par la clé %s, %s", d.CleEvenement, d.CleManifeste, p.Fr)
		en += fmt.Sprintf("; the event is signed by recorder key %s and the manifest by key %s, %s", d.CleEvenement, d.CleManifeste, p.En)
	}
	// F3
	if a := d.Approbation; a != nil {
		nb := len(a.Approbateurs)
		sigFr := commun.Pluriel(nb, "1 signature", fmt.Sprintf("%d signatures", nb))
		sigEn := sigFr
		listeFr := commun.JoindreListe(a.Approbateurs, ", ", " et ")
		listeEn := commun.JoindreListe(a.Approbateurs, ", ", " and ")
		switch a.Decision {
		case "approuve":
			fr += fmt.Sprintf(" ; l'événement a été approuvé par %s (%s, seuil de %d sur %d du jeu déclaré par le dossier)", listeFr, sigFr, a.Required, a.Size)
			en += fmt.Sprintf("; the event was approved by %s (%s, threshold %d of %d of the set declared by the dossier)", listeEn, sigEn, a.Required, a.Size)
		case "refuse":
			fr += fmt.Sprintf(" ; l'événement porte un refus signé par %s (%s, seuil de %d sur %d du jeu déclaré par le dossier)", listeFr, sigFr, a.Required, a.Size)
			en += fmt.Sprintf("; the event carries a refusal signed by %s (%s, threshold %d of %d of the set declared by the dossier)", listeEn, sigEn, a.Required, a.Size)
		case "expire":
			fr += fmt.Sprintf(" ; l'événement porte une demande d'approbation expirée sans signature (seuil de %d sur %d du jeu déclaré par le dossier)", a.Required, a.Size)
			en += fmt.Sprintf("; the event carries an approval request that expired without signature (threshold %d of %d of the set declared by the dossier)", a.Required, a.Size)
		}
	}
	// F4, F5, F6, FK, FP
	for _, f := range []commun.Texte{d.F4, d.F5, d.F6, d.FK, d.FP} {
		if !f.Vide() {
			fr += " ; " + f.Fr
			en += "; " + f.En
		}
	}
	// F7
	avecFK := !d.FK.Vide()
	var eFr, eEn []string
	n4, n5 := d.NonExecutes[4], d.NonExecutes[5]
	switch {
	case n4 && n5 && avecFK:
		eFr, eEn = append(eFr, "la date de son manifeste (contrôles 4 et 5)"), append(eEn, "the date of its manifest (controls 4 and 5)")
	case n4 && n5:
		eFr, eEn = append(eFr, "sa date (contrôles 4 et 5)"), append(eEn, "its date (controls 4 and 5)")
	case n4 && avecFK:
		eFr, eEn = append(eFr, "un horodatage de son manifeste par une autorité (contrôle 4)"), append(eEn, "a time-stamp of its manifest by an authority (control 4)")
	case n4:
		eFr, eEn = append(eFr, "un horodatage par une autorité (contrôle 4)"), append(eEn, "a time-stamp by an authority (control 4)")
	case n5 && avecFK:
		eFr, eEn = append(eFr, "un ancrage de son manifeste dans Bitcoin (contrôle 5)"), append(eEn, "an anchoring of its manifest in Bitcoin (control 5)")
	case n5:
		eFr, eEn = append(eFr, "un ancrage dans Bitcoin (contrôle 5)"), append(eEn, "an anchoring in Bitcoin (control 5)")
	}
	if d.NonExecutes[7] {
		eFr, eEn = append(eFr, "une approbation (contrôle 7)"), append(eEn, "an approval (control 7)")
	}
	if d.NonExecutes[8] {
		eFr, eEn = append(eFr, "son inscription au registre (contrôle 8)"), append(eEn, "its registration in the registry (control 8)")
	}
	if len(eFr) > 0 {
		fr += " ; ce dossier ne prouve rien sur " + commun.JoindreListe(eFr, ", sur ", " ni sur ")
		en += "; this dossier proves nothing about " + commun.JoindreListe(eEn, ", ", " or ")
	}
	return commun.T(fr+".", en+".")
}

// EnonceInvalide construit l'énoncé d'un verdict invalide (EX-6.9).
func EnonceInvalide(echecs, bloquantes []string) commun.Texte {
	var fr, en string
	if len(echecs) > 0 {
		fr = "Dossier invalide : vérification(s) en échec : " + commun.ListeIDs(echecs)
		en = "Invalid dossier: failed check(s): " + commun.ListeIDs(echecs)
		if len(bloquantes) > 0 {
			fr += " ; vérification(s) non exécutée(s) sans raison admise : " + commun.ListeIDs(bloquantes)
			en += "; check(s) not run without an admitted reason: " + commun.ListeIDs(bloquantes)
		}
	} else {
		fr = "Dossier invalide : vérification(s) non exécutée(s) sans raison admise : " + commun.ListeIDs(bloquantes)
		en = "Invalid dossier: check(s) not run without an admitted reason: " + commun.ListeIDs(bloquantes)
	}
	return commun.T(fr+" ; le vérificateur n'affirme rien sur cet événement.", en+"; the verifier asserts nothing about this event.")
}

// ControleNonExecute : un contrôle non exécuté et sa raison, pour la borne.
type ControleNonExecute struct {
	Numero int
	Raison commun.Raison
}

// Borne construit la borne d'EX-6.12, ou nil si aucun contrôle n'est non
// exécuté.
func Borne(nonExecutes []ControleNonExecute) *commun.Texte {
	if len(nonExecutes) == 0 {
		return nil
	}
	var fr, en []string
	for _, c := range nonExecutes {
		fr = append(fr, fmt.Sprintf("contrôle %d non exécuté (%s)", c.Numero, c.Raison))
		en = append(en, fmt.Sprintf("control %d not run (%s)", c.Numero, c.Raison))
	}
	t := commun.T("verdict borné : "+strings.Join(fr, ", "), "bounded verdict: "+strings.Join(en, ", "))
	return &t
}

// DonneesFK : valeurs du fragment FK (EX-6.16).
type DonneesFK struct {
	TreeSize       int64
	CheckpointHash string
	KeyID          string
	// Provenance : provenance de la clé du point (EX-6.8).
	Provenance string
	// Jeton : faits du jeton du point (K-7 réussie), avec T11 : T-11 a
	// réussi sur ce jeton.
	Jeton *horodatage.Faits
	// Bitcoin : faits de la preuve du point (K-9 réussie) et point de
	// contrôle Bitcoin du réviseur.
	Bitcoin *ots.Faits
	// Registre : faits de l'ancre du point (K-8 réussie, inclusion prouvée,
	// contrôle 8 réussi) et chain_id du fichier d'ancres.
	Registre *registre.FaitsAncrePoint
	ChainID  string
}

// tsu rend le nom de l'unité d'horodatage (EX-9.20).
func tsu(f *horodatage.Faits) string {
	if f.TsuSubjectCN != nil {
		return *f.TsuSubjectCN
	}
	return f.TsuCertificateSha256
}

func cadre(f string) string {
	if f == "zertes" {
		return "ZertES"
	}
	return "eIDAS"
}

// FragmentFK construit FK (EX-6.16) ; il rend un texte vide si aucune
// clause d'ancre n'est fournie.
func FragmentFK(d DonneesFK) commun.Texte {
	if d.Jeton == nil && d.Bitcoin == nil && d.Registre == nil {
		return commun.Texte{}
	}
	p := TexteProvenance(d.Provenance)
	fr := fmt.Sprintf("l'événement est couvert par le point de contrôle du journal de taille %d de sa période (empreinte %s, signé par la clé d'enregistreur %s, %s), préfixe prouvé de ce manifeste", d.TreeSize, d.CheckpointHash, d.KeyID, p.Fr)
	en := fmt.Sprintf("the event is covered by the journal checkpoint of size %d of its period (digest %s, signed by recorder key %s, %s), a proven prefix of this manifest", d.TreeSize, d.CheckpointHash, d.KeyID, p.En)
	if j := d.Jeton; j != nil {
		if j.UpperBound != nil {
			fr += fmt.Sprintf(", horodaté au plus tard le %s UTC selon %s (unité %s)", *j.UpperBound, j.Authority, tsu(j))
			en += fmt.Sprintf(", time-stamped no later than %s UTC according to %s (unit %s)", *j.UpperBound, j.Authority, tsu(j))
		} else {
			fr += fmt.Sprintf(", horodaté au plus tard le %s UTC, à la précision près de la politique %s, que le jeton n'indique pas selon %s (unité %s)", j.GenTime, j.Policy, j.Authority, tsu(j))
			en += fmt.Sprintf(", time-stamped no later than %s UTC, within the accuracy of policy %s, not stated in the token according to %s (unit %s)", j.GenTime, j.Policy, j.Authority, tsu(j))
		}
		if j.Qualified != nil {
			fr += fmt.Sprintf(" (horodatage qualifié %s selon le réviseur (%s))", cadre(j.Qualified.Framework), j.Qualified.Source)
			en += fmt.Sprintf(" (%s qualified time-stamp according to the reviewer (%s))", cadre(j.Qualified.Framework), j.Qualified.Source)
		}
	}
	if b := d.Bitcoin; b != nil {
		fr += fmt.Sprintf(", antérieur à la création du bloc Bitcoin %d (%s, réseau %s) sous %d blocs rattachés au point de contrôle Bitcoin %d du réviseur", b.RetainedHeight, b.BlockHash, b.Network, b.Confirmations, b.Checkpoint.Height)
		en += fmt.Sprintf(", earlier than the creation of Bitcoin block %d (%s, %s network) under %d blocks connected to the reviewer's Bitcoin checkpoint %d", b.RetainedHeight, b.BlockHash, b.Network, b.Confirmations, b.Checkpoint.Height)
		if b.Network == "regtest" {
			fr += " (réseau d'essai, sans valeur probante)"
			en += " (test network, no evidential value)"
		}
	}
	if r := d.Registre; r != nil {
		bt := ""
		if r.BlockTime != nil {
			bt = *r.BlockTime
		}
		fr += fmt.Sprintf(", ancré au registre %s au bloc %d (heure déclarée par le bloc : %s UTC) par AttestationRegistry %s", d.ChainID, r.BlockNumber, bt, r.Contract)
		en += fmt.Sprintf(", anchored in registry %s in block %d (time declared by the block: %s UTC) by AttestationRegistry %s", d.ChainID, r.BlockNumber, bt, r.Contract)
	}
	switch {
	case d.Jeton != nil:
		fr += " ; une réécriture postérieure à cet instant serait détectée"
		en += "; a rewrite after that instant would be detected"
	case d.Bitcoin != nil:
		fr += " ; une réécriture postérieure à la création de ce bloc serait détectée"
		en += "; a rewrite after that block was created would be detected"
	default:
		fr += " ; une réécriture postérieure à l'inclusion de cette ancre serait détectée"
		en += "; a rewrite after that anchor was included would be detected"
	}
	return commun.T(fr, en)
}

// DonneesFP : valeurs du fragment FP (EX-6.19).
type DonneesFP struct {
	Retenue bool
	// IDs, IDsEnEchec : `{ids}` d'une attestation non retenue.
	IDs         []string
	IDsEnEchec  bool
	Digest      string
	From        string
	Until       string
	Signataires []string
	Required    int64
	Size        int64
	// Inscription : « reussie », « partie_absente » ou « ancre_absente ».
	Inscription string
	SeqI        int64
	CleI        string
	ProvI       string
	// MemeVersion : AT-7 a réussi.
	MemeVersion bool
	Exceptions  int
}

// FragmentFP construit FP (EX-6.19).
func FragmentFP(d DonneesFP) commun.Texte {
	if !d.Retenue {
		ids := commun.ListeIDs(d.IDs)
		if d.IDsEnEchec {
			return commun.T("l'attestation de périmètre jointe n'est pas retenue (vérification(s) en échec : "+ids+")",
				"the attached perimeter attestation is not retained (failed check(s): "+ids+")")
		}
		return commun.T("l'attestation de périmètre jointe n'est pas retenue (vérification(s) non exécutée(s) : "+ids+")",
			"the attached perimeter attestation is not retained (check(s) not run: "+ids+")")
	}
	nb := len(d.Signataires)
	sig := commun.Pluriel(nb, "1 signature", fmt.Sprintf("%d signatures", nb))
	fr := fmt.Sprintf("le périmètre de capture est déclaré, non prouvé, par l'attestation %s valable du %s au %s, signée par %s (%s, seuil de %d sur %d du jeu déclaré par le dossier)",
		d.Digest, d.From, d.Until, commun.JoindreListe(d.Signataires, ", ", " et "), sig, d.Required, d.Size)
	en := fmt.Sprintf("the capture perimeter is declared, not proven, by attestation %s valid from %s to %s, signed by %s (%s, threshold %d of %d of the set declared by the dossier)",
		d.Digest, d.From, d.Until, commun.JoindreListe(d.Signataires, ", ", " and "), sig, d.Required, d.Size)
	switch d.Inscription {
	case "reussie":
		p := TexteProvenance(d.ProvI)
		fr += fmt.Sprintf(", inscrite au journal par l'événement seq %d (clé %s %s)", d.SeqI, d.CleI, p.Fr)
		en += fmt.Sprintf(", recorded in the journal by event seq %d (key %s %s)", d.SeqI, d.CleI, p.En)
		if d.MemeVersion {
			fr += " sous une version de politique de même nom que celle de cet événement"
			en += " under a policy version with the same name as this event's"
		} else {
			fr += ", sans preuve qu'elle était en vigueur pour cet événement (version de politique différente)"
			en += ", with no proof that it was in force for this event (different policy version)"
		}
	case "ancre_absente":
		fr += ", dont l'inscription jointe n'est pas signée par la clé de l'événement prouvé (ni sa date ni son rang ne sont établis)"
		en += ", whose attached inscription is not signed by the proven event's key (neither its date nor its rank is established)"
	default:
		fr += ", non inscrite au journal (ni sa date ni son rang ne sont établis)"
		en += ", not recorded in the journal (neither its date nor its rank is established)"
	}
	switch d.Exceptions {
	case 0:
		fr += ", et qui ne déclare aucune exception de capture"
		en += ", and which declares no capture exception"
	case 1:
		fr += ", et qui déclare 1 exception de capture"
		en += ", and which declares 1 capture exception"
	default:
		fr += fmt.Sprintf(", et qui déclare %d exceptions de capture", d.Exceptions)
		en += fmt.Sprintf(", and which declares %d capture exceptions", d.Exceptions)
	}
	return commun.T(fr, en)
}
