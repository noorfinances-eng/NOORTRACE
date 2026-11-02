package rapport

import (
	"fmt"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

// Libellés des huit contrôles (CT-6 §8.4).
var LibellesControles = map[int]commun.Texte{
	1: commun.T("hachage canonique de l'événement", "canonical hash of the event"),
	2: commun.T("chaînage avec les voisins", "chaining with the neighbours"),
	3: commun.T("inclusion dans la racine du manifeste", "inclusion in the manifest root"),
	4: commun.T("jeton d'horodatage RFC 3161 sur periodHash", "RFC 3161 time-stamp token on periodHash"),
	5: commun.T("preuve OpenTimestamps et en-têtes Bitcoin", "OpenTimestamps proof and Bitcoin headers"),
	6: commun.T("signatures de l'enregistreur", "recorder signatures"),
	7: commun.T("signatures des approbateurs et seuil", "approver signatures and threshold"),
	8: commun.T("inclusion au registre, bloc certifié par un quorum", "registry inclusion, quorum-certified block"),
}

// LibellesVerifications : libellés des vérifications (CT-6 §8.4 : tables
// 9.5, 10.4, 11.4, 12.4 et AT- ; résumés traduits de CT-1 §11.4).
var LibellesVerifications = map[string]commun.Texte{
	"D-1":  commun.T("dossier.json conforme à son schéma ; event égal à evenement.json", "dossier.json follows its schema; event equals evenement.json"),
	"D-2":  commun.T("SHA-256 de chaque partie présente égal à l'index ; parties absentes avec raison", "SHA-256 of each present part equals the index; absent parts with a reason"),
	"E-1":  commun.T("chaque événement conforme à evenement-v0", "each event follows evenement-v0"),
	"E-2":  commun.T("forme canonique calculable", "canonical form computable"),
	"E-3":  commun.T("nom d'outil réservé et champs cohérents avec la sorte de l'événement", "reserved tool name and fields consistent with the kind of event"),
	"E-4":  commun.T("référence rédigée accompagnée de policy.redaction", "redacted reference accompanied by policy.redaction"),
	"E-5":  commun.T("approvers et signatures de même longueur ; ticket égal à policy.ticket", "approvers and signatures of the same length; ticket equals policy.ticket"),
	"E-6":  commun.T("références en ligne et pièces fournies : sha256 et length", "inline references and pieces given: sha256 and length"),
	"E-7":  commun.T("hash recalculé depuis l'objet égal à hash", "hash recomputed from the object equals hash"),
	"E-8":  commun.T("cles.json exploitable ; signature Ed25519 de chaque événement", "cles.json usable; Ed25519 signature of each event"),
	"E-9":  commun.T("adresse recouvrée de chaque signature d'approbateur", "address recovered from each approver signature"),
	"E-10": commun.T("événement de rotation de clé cohérent et contresigné", "key rotation event consistent and countersigned"),
	"E-11": commun.T("ts dans la validité de la clé qui signe", "ts within the validity of the signing key"),
	"C-1":  commun.T("voisins : seq consécutifs, ts non décroissants, même journal", "neighbours: consecutive seq, non-decreasing ts, same journal"),
	"C-2":  commun.T("prev_hash égal au hash recalculé du précédent", "prev_hash equals the recomputed hash of the previous event"),
	"C-3":  commun.T("clé des voisins cohérente avec les rotations", "neighbours' key consistent with rotations"),
	"M-1":  commun.T("leaf_hash = SHA-256(00 ‖ hash recalculé)", "leaf_hash = SHA-256(00 ‖ recomputed hash)"),
	"M-2":  commun.T("chemin d'audit jusqu'à la racine (RFC 9162 §2.1.3.2)", "audit path up to the root (RFC 9162 §2.1.3.2)"),
	"M-3":  commun.T("chemin cohérent avec le manifeste", "path consistent with the manifest"),
	"P-1":  commun.T("manifeste conforme ; période d'une heure ; count ; journal", "manifest follows its schema; one-hour period; count; journal"),
	"P-2":  commun.T("événement dans la période", "event within the period"),
	"P-3":  commun.T("voisins cohérents avec la période", "neighbours consistent with the period"),
	"P-4":  commun.T("racine nulle si et seulement si count = 0", "null root if and only if count = 0"),
	"P-5":  commun.T("periodHash signé par la clé du manifeste ; continuité", "periodHash signed by the manifest key; continuity"),
	"A-1":  commun.T("approbations.json présent si et seulement si approval non nul", "approbations.json present if and only if approval is not null"),
	"A-2":  commun.T("événements de décision cohérents avec l'approbation", "decision events consistent with the approval"),
	"A-3":  commun.T("approbateurs distincts, membres du jeu, au seuil", "distinct approvers, members of the set, at the threshold"),
	"A-4":  commun.T("request_hash = hash recalculé de l'événement de demande (status retenue) quand il est dans le dossier", "request_hash = recomputed hash of the request event (status retenue) when it is in the dossier"),
	"K-1":  commun.T("partie points-de-controle.json conforme et cohérente avec le manifeste", "points-de-controle.json part conforming and consistent with the manifest"),
	"K-2":  commun.T("checkpointHash recalculé égal à checkpoint_hash", "recomputed checkpointHash equals checkpoint_hash"),
	"K-3":  commun.T("signature du point sous la clé déclarée", "checkpoint signature under the declared key"),
	"K-4":  commun.T("le point couvre l'événement", "the checkpoint covers the event"),
	"K-5":  commun.T("preuve de cohérence vers la racine du manifeste", "consistency proof towards the manifest root"),
	"K-6":  commun.T("last_hash égal au hash recalculé de l'événement last_seq", "last_hash equals the recomputed hash of the last_seq event"),
	"K-7":  commun.T("jeton RFC 3161 du point (T-1 à T-11)", "RFC 3161 token of the checkpoint (T-1 to T-11)"),
	"K-8":  commun.T("référence au registre du point", "registry reference of the checkpoint"),
	"K-9":  commun.T("preuve OpenTimestamps du point (O-1 à O-7)", "OpenTimestamps proof of the checkpoint (O-1 to O-7)"),
	"AT-1": commun.T("forme de l'attestation de périmètre", "form of the perimeter attestation"),
	"AT-2": commun.T("condensé de l'attestation", "attestation digest"),
	"AT-3": commun.T("signatures de l'attestation", "attestation signatures"),
	"AT-4": commun.T("signataires membres du jeu déclaré, seuil", "signers in the declared set, threshold"),
	"AT-5": commun.T("organisation, journal et validité de l'attestation", "organisation, journal and validity of the attestation"),
	"AT-6": commun.T("inscription de l'attestation au journal", "attestation recorded in the journal"),
	"AT-7": commun.T("politique en vigueur pour l'événement", "policy in force for the event"),
	"T-1":  commun.T("structure du jeton", "token structure"),
	"T-2":  commun.T("empreinte = periodHash", "imprint = periodHash"),
	"T-3":  commun.T("attributs signés", "signed attributes"),
	"T-4":  commun.T("certificat signataire identifié", "signer certificate identified"),
	"T-5":  commun.T("algorithmes admis", "admitted algorithms"),
	"T-6":  commun.T("signature", "signature"),
	"T-7":  commun.T("chemin de certification jusqu'à une autorité de l'ancre, à genTime", "certification path to an anchor authority, at genTime"),
	"T-8":  commun.T("usage horodatage du certificat signataire", "time-stamping usage of the signer certificate"),
	"T-9":  commun.T("contenu de TSTInfo", "TSTInfo content"),
	"T-10": commun.T("révocation", "revocation"),
	"T-11": commun.T("statut qualifié déclaré par l'ancre", "qualified status declared by the anchor"),
	"O-1":  commun.T("format", "format"),
	"O-2":  commun.T("empreinte = periodHash", "file digest = periodHash"),
	"O-3":  commun.T("opérations", "operations"),
	"O-4":  commun.T("attestation Bitcoin contre l'en-tête", "Bitcoin attestation against the header"),
	"O-5":  commun.T("chaîne d'en-têtes rattachée au point de contrôle", "header chain connected to the checkpoint"),
	"O-6":  commun.T("profondeur", "depth"),
	"O-7":  commun.T("présence d'une attestation Bitcoin", "presence of a Bitcoin attestation"),
	"R-1":  commun.T("parties conformes et appariées", "parts well-formed and matched"),
	"R-2":  commun.T("jeu de validateurs de l'ancre", "validator set of the anchor"),
	"R-3":  commun.T("cohérence de validateurs.json", "consistency of validateurs.json"),
	"R-4":  commun.T("identifiant de chaîne", "chain identifier"),
	"R-5":  commun.T("signatures et quorum", "signatures and quorum"),
	"R-6":  commun.T("hachage du bloc", "block hash"),
	"R-7":  commun.T("racine des reçus", "receipts root"),
	"R-8":  commun.T("contrat émetteur", "emitting contract"),
	"R-9":  commun.T("événement et valeurs de la période", "event and period values"),
	"R-10": commun.T("inscriptions", "registrations"),
	"R-11": commun.T("ancre d'un point de contrôle du journal", "anchor of a journal checkpoint"),
	"N-3":  commun.T("clés d'enregistreur", "recorder keys"),
	"N-4":  commun.T("clé de chaîne", "chain key"),
}

func etiquette(fr, en, langue string) string {
	e := fr
	if langue == "en" {
		e = en
	}
	return fmt.Sprintf("%-14s: ", e)
}

func statutAffiche(s commun.Statut, langue string) string {
	switch {
	case s == commun.Reussi && langue == "en":
		return "[passed]"
	case s == commun.Reussi:
		return "[réussi]"
	case s == commun.Echoue && langue == "en":
		return "[FAILED]"
	case s == commun.Echoue:
		return "[ÉCHEC]"
	case langue == "en":
		return "[not run]"
	}
	return "[non exécuté]"
}

func colonne(s string, largeur int) string {
	n := len([]rune(s))
	if n >= largeur {
		return s + " "
	}
	return s + strings.Repeat(" ", largeur-n)
}

// InfosLisibles : lignes de tête que le rapport JSON ne porte pas sous
// cette forme.
type InfosLisibles struct {
	Verificateur string
	Repertoire   string
}

// Lisible écrit le rapport lisible d'EX-8.6.
func Lisible(r *Rapport, info InfosLisibles, detail bool) string {
	l := r.Language
	en := l == "en"
	var b strings.Builder
	ligne := func(s string) { b.WriteString(s + "\n") }
	if en {
		ligne("Offline verification of a NOORTRACE evidence dossier (format v0, CT-1 and CT-6)")
	} else {
		ligne("Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)")
	}
	ligne(etiquette("Vérificateur", "Verifier", l) + info.Verificateur)
	ligne(etiquette("Répertoire", "Directory", l) + info.Repertoire)
	if r.Inputs.Dossier.IndexSha256 != nil {
		ligne(etiquette("Index", "Index", l) + "dossier.json, SHA-256 " + *r.Inputs.Dossier.IndexSha256)
	}
	if a := r.Inputs.Anchors; a != nil {
		ligne(etiquette("Ancres", "Anchors", l) + a.Path + ", SHA-256 " + a.Sha256)
	} else if en {
		ligne(etiquette("", "Anchors", l) + "no anchors file")
	} else {
		ligne(etiquette("Ancres", "", l) + "aucun fichier d'ancres")
	}
	if h := r.Inputs.BitcoinHeaders; h != nil {
		ligne(etiquette("En-têtes", "Headers", l) + h.Path + ", SHA-256 " + h.Sha256)
	}
	if p := r.Inputs.Pieces; p != nil {
		if en {
			ligne(etiquette("", "Pieces", l) + fmt.Sprintf("%s, %d piece(s) read", p.Path, p.Files))
		} else {
			ligne(etiquette("Pièces", "", l) + fmt.Sprintf("%s, %d pièce(s) lue(s)", p.Path, p.Files))
		}
	}
	if s := r.Inputs.SecondManifest; s != nil {
		ligne(etiquette("2e manifeste", "2nd manifest", l) + s.Path + ", SHA-256 " + s.Sha256)
	}
	if e := r.Event; e != nil {
		outil := "null"
		if e.Tool != nil {
			outil = *e.Tool
		}
		if en {
			ligne(etiquette("", "Event", l) + fmt.Sprintf("seq %d, hash %s, ts %s, tool %s", e.Seq, e.Hash, e.Ts, outil))
		} else {
			ligne(etiquette("Événement", "", l) + fmt.Sprintf("seq %d, hash %s, ts %s, outil %s", e.Seq, e.Hash, e.Ts, outil))
		}
	}
	if r.OrgID != nil && r.JournalID != nil {
		ligne(etiquette("Journal", "Journal", l) + "org_id " + *r.OrgID + ", journal_id " + *r.JournalID)
	}
	if p := r.Period; p != nil {
		a := " à "
		if en {
			a = " to "
		}
		ligne(etiquette("Période", "Period", l) + commun.FormaterSecondes(p.PeriodStart) + a + commun.FormaterSecondes(p.PeriodEnd) + ", periodHash " + p.PeriodHash)
	}
	if p := r.Lisible.LignePoint; p != nil {
		ligne(etiquette("Pt de contrôle", "Checkpoint", l) + p.Langue(l))
	}
	if p := r.Lisible.LignePerimetre; p != nil {
		ligne(etiquette("Périmètre", "Perimeter", l) + p.Langue(l))
	}
	if en {
		ligne("Architecture controls:")
	} else {
		ligne("Contrôles de l'architecture :")
	}
	for _, c := range r.Controls {
		resume := c.ResumeBilingue.Langue(l)
		lib := LibellesControles[c.Number].Langue(l)
		if c.Status == commun.NonExecute && c.Reason != nil {
			if en {
				resume = fmt.Sprintf("not run (%s): %s", *c.Reason, resume)
			} else {
				resume = fmt.Sprintf("non exécuté (%s) : %s", *c.Reason, resume)
			}
		}
		ligne("  " + colonne(statutAffiche(c.Status, l), 14) + fmt.Sprintf("%d  %s — %s", c.Number, lib, resume))
	}
	var liste []Verification
	for _, v := range r.Checks {
		if detail || v.Status != commun.Reussi {
			liste = append(liste, v)
		}
	}
	if len(liste) > 0 {
		switch {
		case detail && en:
			ligne("Checks:")
		case detail:
			ligne("Vérifications :")
		case en:
			ligne("Checks not passed:")
		default:
			ligne("Vérifications non réussies :")
		}
		for _, v := range liste {
			ctrl := make([]string, len(v.Controls))
			for i, c := range v.Controls {
				ctrl[i] = fmt.Sprint(c)
			}
			st := statutAffiche(v.Status, l)
			if v.Status == commun.Echoue && strings.HasPrefix(v.ID, "AT-") {
				if en {
					st += " (no effect on the verdict)"
				} else {
					st += " (sans effet sur le verdict)"
				}
			}
			ligne("  " + colonne(st, 14) + colonne(v.ID, 5) + "[" + strings.Join(ctrl, ", ") + "] " + LibellesVerifications[v.ID].Langue(l))
			d := v.DetailBilingue.Langue(l)
			if v.Status == commun.NonExecute && v.Reason != nil {
				if d == "" {
					d = string(*v.Reason)
				} else {
					d += " (" + string(*v.Reason) + ")"
				}
			}
			if d != "" {
				ligne(strings.Repeat(" ", 22) + d)
			}
		}
	}
	if len(r.Warnings) > 0 {
		if en {
			ligne("Warnings:")
		} else {
			ligne("Avertissements :")
		}
		for _, w := range r.Warnings {
			c := ""
			if w.Check != nil {
				c = "(" + *w.Check + ") "
			}
			ligne("  " + w.ID + " " + c + w.DetailBilingue.Langue(l))
		}
	}
	if len(r.AbsentParts) > 0 {
		var parts []string
		for _, p := range r.AbsentParts {
			raison := ""
			if p.Reason != nil {
				raison = " (" + *p.Reason + ")"
			}
			parts = append(parts, p.File+raison)
		}
		if en {
			ligne("Absent parts: " + strings.Join(parts, ", "))
		} else {
			ligne("Parties absentes : " + strings.Join(parts, ", "))
		}
	}
	if bb := r.Lisible.BorneBilingue; bb != nil {
		ligne(etiquette("Borne", "Bound", l) + bb.Langue(l))
	}
	switch r.Verdict {
	case "valide":
		if en {
			ligne(etiquette("", "Result", l) + "VALID — no failed check, no check left unrun without an admitted reason")
		} else {
			ligne(etiquette("Résultat", "", l) + "VALIDE — aucune vérification en échec, aucune vérification non exécutée sans raison admise")
		}
	case "invalide":
		var fr, eng string
		if len(r.FailedChecks) > 0 {
			fr = "INVALIDE — vérification(s) en échec : " + commun.ListeIDs(r.FailedChecks)
			eng = "INVALID — failed check(s): " + commun.ListeIDs(r.FailedChecks)
			if len(r.BlockingUnexecuted) > 0 {
				fr += " ; vérification(s) non exécutée(s) sans raison admise : " + commun.ListeIDs(r.BlockingUnexecuted)
				eng += "; check(s) not run without an admitted reason: " + commun.ListeIDs(r.BlockingUnexecuted)
			}
		} else {
			fr = "INVALIDE — vérification(s) non exécutée(s) sans raison admise : " + commun.ListeIDs(r.BlockingUnexecuted)
			eng = "INVALID — check(s) not run without an admitted reason: " + commun.ListeIDs(r.BlockingUnexecuted)
		}
		ligne(etiquette("Résultat", "Result", l) + commun.T(fr, eng).Langue(l))
	case "incomplet":
		var n []string
		for _, c := range r.Lisible.ExigesNonReussis {
			n = append(n, fmt.Sprint(c))
		}
		ligne(etiquette("Résultat", "Result", l) + commun.T("INCOMPLET — contrôle(s) exigé(s) non réussi(s) : "+strings.Join(n, ", "), "INCOMPLETE — required control(s) not passed: "+strings.Join(n, ", ")).Langue(l))
	}
	if en {
		ligne(etiquette("", "Statement", l) + r.Statement.En)
	} else {
		ligne(etiquette("Énoncé", "", l) + r.Statement.Fr)
	}
	return b.String()
}
