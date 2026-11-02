package dossier

import (
	"fmt"
	"strings"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Attestation : la partie attestation-perimetre.json déclarée présente
// (CT-1 §11.2, CT-6 §5.5, CT-7 §7).
type Attestation struct {
	Partie *Partie
	V      *jsonv.Valeur
	// Digest : D_P recalculé (AT-2), valable si DigestOK.
	Digest   [32]byte
	DigestOK bool
	// Retenue : l'attestation est retenue (EX-6.19).
	Retenue bool
	// IDs : `{ids}` de 5.5 ; IDsEnEchec dit si ce sont des AT- en échec.
	IDs        []string
	IDsEnEchec bool
	// Signataires : adresses recouvrées (AT-3).
	Signataires []string
	// Inscription (AT-6 réussie) : événement d'inscription.
	Inscription *Evt
	// Avertissements AV-AT-1 à AV-AT-3.
	Avertissements []commun.Avertissement
}

func (a *Analyse) verificationsAT(p *Partie) {
	at := &Attestation{Partie: p}
	a.Attestation = at
	ev := a.Evenement
	att := func() *jsonv.Valeur { return at.V.Chemin("signed", "attestation") }
	// AT-1
	at1 := func() commun.Verification {
		echec := func(fr, en string) commun.Verification {
			return commun.Nouvelle("AT-1", commun.Echoue, "", commun.T(fr, en), 7)
		}
		switch {
		case p.Lecture.Etat == entree.TropGrand:
			return echec("attestation-perimetre.json dépasse 4 Mio", "attestation-perimetre.json exceeds 4 MiB")
		case p.Lecture.Etat != entree.Lu:
			return echec("attestation-perimetre.json absent ou illisible", "attestation-perimetre.json missing or unreadable")
		case !p.Exploitable():
			return echec("attestation-perimetre.json n'est pas un objet JSON", "attestation-perimetre.json is not a JSON object")
		}
		v := p.Valeur
		if err := schema.Valider(schema.Dossier+"#/$defs/attestation_perimetre", v); err != nil {
			return echec("contraire au schéma ("+err.Error()+")", "does not follow the schema ("+err.Error()+")")
		}
		P := v.Chemin("signed", "attestation")
		if _, err := jcs.Canonique(P); err != nil {
			return echec("attestation sans forme canonique JCS v0", "attestation without JCS v0 canonical form")
		}
		de, ok1 := commun.LireHorodatage(P.Chemin("validity", "from").S())
		a2, ok2 := commun.LireHorodatage(P.Chemin("validity", "until").S())
		_, ok3 := commun.LireHorodatage(P.Membre("issued_at").S())
		if !ok1 || !ok2 || !ok3 {
			return echec("date inexistante dans l'attestation", "non-existing date in the attestation")
		}
		if de.After(a2) {
			return echec("validity.from postérieur à validity.until", "validity.from after validity.until")
		}
		if a2.Sub(de) > 366*24*time.Hour {
			return echec("validité de plus de 366 jours", "validity longer than 366 days")
		}
		journaux := map[string]bool{}
		for _, j := range P.Membre("journals").Elements {
			id := j.Membre("journal_id").S()
			if journaux[id] {
				return echec("journal_id en double dans journals", "duplicate journal_id in journals")
			}
			journaux[id] = true
		}
		agents := map[string]bool{}
		for _, ag := range P.Membre("agents").Elements {
			if !journaux[ag.Membre("journal_id").S()] {
				return echec("agent dont le journal_id n'est pas dans journals", "agent whose journal_id is not in journals")
			}
			if agents[ag.Membre("agent_id").S()] {
				return echec("agent_id en double", "duplicate agent_id")
			}
			agents[ag.Membre("agent_id").S()] = true
		}
		sigs := map[string]bool{}
		for _, s := range P.Membre("signatories").Elements {
			if sigs[s.Membre("address").S()] {
				return echec("adresse en double dans signatories", "duplicate address in signatories")
			}
			sigs[s.Membre("address").S()] = true
		}
		if ins := v.Membre("inscription"); ins.EstObjet() {
			doc, err := cryptographie.Base64Canonique(ins.Membre("policy_document").S())
			if err != nil {
				return echec("policy_document : "+err.Error(), "policy_document: "+err.Error())
			}
			if len(doc) > 2097152 {
				return echec("policy_document de plus de 2 097 152 octets", "policy_document larger than 2,097,152 bytes")
			}
		}
		at.V = v
		return commun.Nouvelle("AT-1", commun.Reussi, "", commun.Texte{}, 7)
	}()
	a.ajouter(at1)
	ok1 := at1.Statut == commun.Reussi
	// AT-2
	if !ok1 {
		a.ajouter(prerequis("AT-2", "AT-1 en échec", "AT-1 failed", 7))
	} else {
		c, _ := jcs.Canonique(att())
		at.Digest = cryptographie.Keccak256(cryptographie.PrefixeAttestation, c)
		at.DigestOK = true
		d := cryptographie.Hex32(at.Digest)
		if d != at.V.Chemin("signed", "digest").S() {
			a.ajouter(commun.Nouvelle("AT-2", commun.Echoue, "", commun.T("D_P recalculé "+d+" ≠ digest "+at.V.Chemin("signed", "digest").S(), "recomputed D_P "+d+" ≠ digest "+at.V.Chemin("signed", "digest").S()), 7))
		} else {
			a.ajouter(commun.Nouvelle("AT-2", commun.Reussi, "", commun.T("D_P "+d, "D_P "+d), 7))
		}
	}
	// AT-3
	if !ok1 {
		a.ajouter(prerequis("AT-3", "AT-1 en échec", "AT-1 failed", 7))
	} else {
		var ecarts, recouvrees []string
		for i, s := range at.V.Chemin("signed", "signatures").Elements {
			sig, _ := cryptographie.LireHex(s.Membre("signature").S(), 65)
			adr, err := cryptographie.RecouvrerEIP191(at.Digest, sig)
			if err != nil {
				ecarts = append(ecarts, fmt.Sprintf("signatures[%d] : %v", i, err))
				continue
			}
			r := cryptographie.Hex(adr[:])
			recouvrees = append(recouvrees, r)
			if r != s.Membre("address").S() {
				ecarts = append(ecarts, fmt.Sprintf("signatures[%d] recouvre %s, et non %s", i, r, s.Membre("address").S()))
			}
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, " ; ")
			a.ajouter(commun.Nouvelle("AT-3", commun.Echoue, "", commun.T(s, s), 7))
		} else {
			at.Signataires = recouvrees
			s := strings.Join(recouvrees, ", ")
			a.ajouter(commun.Nouvelle("AT-3", commun.Reussi, "", commun.T("adresses recouvrées : "+s, "recovered addresses: "+s), 7))
		}
	}
	// AT-4
	if !a.reussie("AT-3") {
		a.ajouter(prerequis("AT-4", "AT-3 non réussie", "AT-3 not passed", 7))
	} else {
		P := att()
		jeu := at.V.Membre("approver_set")
		dans := func(liste *jsonv.Valeur, champ, adr string) bool {
			for _, x := range liste.Elements {
				v := x
				if champ != "" {
					v = x.Membre(champ)
				}
				if v.S() == adr {
					return true
				}
			}
			return false
		}
		req, _ := jeu.Chemin("threshold", "required").Entier()
		taille, _ := jeu.Chemin("threshold", "size").Entier()
		var ecarts []string
		vus := map[string]bool{}
		membres := 0
		for _, s := range at.V.Chemin("signed", "signatures").Elements {
			adr := s.Membre("address").S()
			if vus[adr] {
				ecarts = append(ecarts, "signataire en double "+adr)
			}
			vus[adr] = true
			if !dans(P.Membre("signatories"), "address", adr) {
				ecarts = append(ecarts, adr+" absent de signatories")
			}
			if !dans(jeu.Membre("members"), "", adr) {
				ecarts = append(ecarts, adr+" absent du jeu déclaré")
			} else {
				membres++
			}
		}
		if int64(len(vus)) < req {
			ecarts = append(ecarts, fmt.Sprintf("%d signataire(s) pour un seuil de %d", len(vus), req))
		}
		if req > taille || taille != int64(len(jeu.Membre("members").Elements)) {
			ecarts = append(ecarts, "required > size, ou size ≠ nombre de members")
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, " ; ")
			a.ajouter(commun.Nouvelle("AT-4", commun.Echoue, "", commun.T(s, s), 7))
		} else {
			a.ajouter(commun.Nouvelle("AT-4", commun.Reussi, "", commun.T(fmt.Sprintf("%d signataire(s) membre(s), seuil de %d sur %d", membres, req, taille), fmt.Sprintf("%d member signer(s), threshold %d of %d", membres, req, taille)), 7))
			if pa := a.Dossier.Partie(PApprobations); pa.Exploitable() && enveloppeApprobations(pa.Valeur) {
				js := pa.Valeur.Membre("approver_set")
				if !memeEnsemble(js.Membre("members"), jeu.Membre("members")) || !jsonv.Egales(js.Membre("threshold"), jeu.Membre("threshold")) {
					at.Avertissements = append(at.Avertissements, commun.Avertissement{ID: "AV-AT-2", Verification: "AT-4", Detail: commun.T(
						"jeu d'approbateurs de l'attestation différent de celui de approbations.json (attestation : "+jeu.Membre("source").S()+" ; approbations.json : "+js.Membre("source").S()+")",
						"approver set of the attestation differs from that of approbations.json (attestation: "+jeu.Membre("source").S()+"; approbations.json: "+js.Membre("source").S()+")")})
				}
			}
		}
	}
	// AT-5
	switch {
	case !ok1:
		a.ajouter(prerequis("AT-5", "AT-1 en échec", "AT-1 failed", 7))
	case !a.evenementExploitableAT():
		a.ajouter(prerequis("AT-5", "evenement.json inexploitable (E-1, E-2)", "evenement.json unusable (E-1, E-2)", 7))
	default:
		P := att()
		de, _ := commun.LireHorodatage(P.Chemin("validity", "from").S())
		fin, _ := commun.LireHorodatage(P.Chemin("validity", "until").S())
		ts, okTs := ev.Ts()
		var ecarts []string
		if P.Chemin("org", "org_id").S() != ev.V.Membre("org_id").S() {
			ecarts = append(ecarts, "org_id de l'attestation ≠ celui de l'événement")
		}
		trouve := false
		for _, j := range P.Membre("journals").Elements {
			if j.Membre("journal_id").S() == ev.V.Membre("journal_id").S() {
				trouve = true
			}
		}
		if !trouve {
			ecarts = append(ecarts, "journal de l'événement absent de journals")
		}
		if !okTs || ts.Before(de) || ts.After(fin) {
			ecarts = append(ecarts, "ts de l'événement hors de la validité de l'attestation")
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, ", ")
			a.ajouter(commun.Nouvelle("AT-5", commun.Echoue, "", commun.T(s, s), 7))
		} else {
			a.ajouter(commun.Nouvelle("AT-5", commun.Reussi, "", commun.Texte{}, 7))
		}
	}
	// AT-6
	a.ajouter(a.at6(at))
	// AT-7
	v6 := a.statut["AT-6"]
	switch {
	case v6.Statut == commun.NonExecute && v6.Raison == commun.PartieAbsente:
		a.ajouter(commun.Nouvelle("AT-7", commun.NonExecute, commun.PartieAbsente, commun.T("aucune inscription jointe", "no inscription attached"), 6))
	case v6.Statut != commun.Reussi:
		a.ajouter(prerequis("AT-7", "AT-6 non réussie", "AT-6 not passed", 6))
	default:
		ve := ev.V.Chemin("code", "policy_version").S()
		vi := at.Inscription.V.Chemin("execution", "arguments", "value", "policy_version").S()
		if ve == vi {
			a.ajouter(commun.Nouvelle("AT-7", commun.Reussi, "", commun.T("même version de politique ("+ve+")", "same policy version ("+ve+")"), 6))
		} else {
			a.ajouter(commun.Nouvelle("AT-7", commun.NonExecute, commun.PieceHorsDossier, commun.T("version de politique de l'événement ("+ve+") différente de celle de l'inscription ("+vi+")", "policy version of the event ("+ve+") differs from that of the inscription ("+vi+")"), 6))
			at.Avertissements = append(at.Avertissements, commun.Avertissement{ID: "AV-AT-3", Verification: "AT-7", Detail: commun.T(
				"version de politique de l'événement ("+ve+") différente de celle de l'inscription ("+vi+")",
				"policy version of the event ("+ve+") differs from that of the inscription ("+vi+")")})
		}
	}
	// Attestation retenue (EX-6.19) et {ids} (5.5).
	retenue := true
	for _, id := range []string{"AT-1", "AT-2", "AT-3", "AT-4", "AT-5"} {
		if !a.reussie(id) {
			retenue = false
		}
	}
	if v6 := a.statut["AT-6"]; !(v6.Statut == commun.Reussi || (v6.Statut == commun.NonExecute && (v6.Raison == commun.PartieAbsente || v6.Raison == commun.AncreAbsente))) {
		retenue = false
	}
	at.Retenue = retenue
	if !retenue {
		for _, id := range []string{"AT-1", "AT-2", "AT-3", "AT-4", "AT-5", "AT-6", "AT-7"} {
			if a.statut[id].Statut == commun.Echoue {
				at.IDs = append(at.IDs, id)
			}
		}
		at.IDsEnEchec = len(at.IDs) > 0
		if !at.IDsEnEchec {
			for _, id := range []string{"AT-1", "AT-2", "AT-3", "AT-4", "AT-5", "AT-6"} {
				if v := a.statut[id]; v.Statut == commun.NonExecute && v.Raison == commun.PrerequisEnEchec {
					at.IDs = append(at.IDs, id)
				}
			}
		}
		if len(at.IDs) > 0 {
			ids := strings.Join(at.IDs, ", ")
			av := commun.Avertissement{ID: "AV-AT-1", Verification: at.IDs[0]}
			if at.IDsEnEchec {
				av.Detail = commun.T("attestation de périmètre non retenue : "+ids+" en échec ; elle ne change ni les statuts ni le verdict", "perimeter attestation not retained: "+ids+" failed; it changes neither the statuses nor the verdict")
			} else {
				av.Detail = commun.T("attestation de périmètre non retenue : "+ids+" non exécutée(s) ; elle ne change ni les statuts ni le verdict", "perimeter attestation not retained: "+ids+" not run; it changes neither the statuses nor the verdict")
			}
			at.Avertissements = append(at.Avertissements, av)
		}
	}
}

func memeEnsemble(a, b *jsonv.Valeur) bool {
	ea, eb := map[string]bool{}, map[string]bool{}
	for _, x := range a.Elements {
		ea[x.S()] = true
	}
	for _, x := range b.Elements {
		eb[x.S()] = true
	}
	if len(ea) != len(eb) {
		return false
	}
	for k := range ea {
		if !eb[k] {
			return false
		}
	}
	return true
}

func (a *Analyse) at6(at *Attestation) commun.Verification {
	if !a.reussie("AT-1") {
		return prerequis("AT-6", "AT-1 en échec", "AT-1 failed", 6)
	}
	ins := at.V.Membre("inscription")
	if !ins.EstObjet() {
		return commun.Nouvelle("AT-6", commun.NonExecute, commun.PartieAbsente, commun.T("inscription nulle : attestation non inscrite au journal", "null inscription: attestation not recorded in the journal"), 6)
	}
	if !a.reussie("AT-2") {
		return prerequis("AT-6", "AT-2 non réussie", "AT-2 not passed", 6)
	}
	if !a.evenementExploitableAT() || !a.ClesExploitables {
		return prerequis("AT-6", "evenement.json (E-1, E-2) ou cles.json (E-8) inexploitable", "evenement.json (E-1, E-2) or cles.json (E-8) unusable", 6)
	}
	ev := a.Evenement
	e := nouvelEvt(commun.T("inscription", "inscription"), ins.Membre("event"))
	var ecarts []string
	ajoute := func(r resultatEvt, regle string) {
		if r.statut != commun.Reussi {
			ecarts = append(ecarts, regle+" : "+r.detail.Fr)
		}
	}
	ajoute(regleE1(e), "E-1")
	if e.ErrCanonique != nil {
		ecarts = append(ecarts, "E-2 : forme canonique non calculable")
	}
	ajoute(regleE3(e), "E-3")
	ajoute(regleE4(e), "E-4")
	ajoute(regleE5(e), "E-5")
	sauve := a.pieces
	a.pieces = nil
	r6, _ := a.regleE6(e)
	a.pieces = sauve
	ajoute(r6, "E-6")
	ajoute(regleE7(e), "E-7")
	ajoute(a.regleE11(e), "E-11")
	ajoute(a.regleE8(e), "signature")
	if e.Outil() != OutilPolitique {
		ecarts = append(ecarts, "execution.tool ≠ noortrace.journal.politique")
	}
	if e.V.Membre("org_id").S() != ev.V.Membre("org_id").S() || e.V.Membre("journal_id").S() != ev.V.Membre("journal_id").S() {
		ecarts = append(ecarts, "org_id ou journal_id différent de celui de l'événement prouvé")
	}
	doc, _ := cryptographie.Base64Canonique(ins.Membre("policy_document").S())
	if cryptographie.Hex32(cryptographie.Sha256(doc)) != e.V.Chemin("execution", "arguments", "value", "policy_sha256").S() {
		ecarts = append(ecarts, "SHA-256 du document de politique ≠ policy_sha256")
	}
	if dv, err := jsonv.Analyser(doc); err != nil || !dv.EstObjet() || aDoublon(dv) || !dv.Membre("perimeter").EstObjet() || dv.Chemin("perimeter", "attestation_digest").S() != cryptographie.Hex32(at.Digest) || !dv.Chemin("perimeter", "attestation_digest").EstChaine() {
		ecarts = append(ecarts, "document de politique sans perimeter.attestation_digest égal à D_P")
	}
	si, _ := e.Seq()
	se, _ := ev.Seq()
	if si > se || (si == se && (!e.HashOK() || !ev.HashOK() || e.Hash != ev.Hash)) {
		ecarts = append(ecarts, "inscription de rang postérieur à l'événement prouvé")
	}
	ti, ok1 := e.Ts()
	te, ok2 := ev.Ts()
	if !ok1 || !ok2 || ti.After(te) {
		ecarts = append(ecarts, "inscription d'instant postérieur à l'événement prouvé")
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("AT-6", commun.Echoue, "", commun.T(s, s), 6)
	}
	if e.Cle() != ev.Cle() {
		return commun.Nouvelle("AT-6", commun.NonExecute, commun.AncreAbsente, commun.T("inscription signée par "+e.Cle()+", et non par la clé de l'événement prouvé "+ev.Cle()+" : rien ne la relie au journal", "inscription signed by "+e.Cle()+", not by the proven event's key "+ev.Cle()+": nothing ties it to the journal"), 6)
	}
	at.Inscription = e
	return commun.Nouvelle("AT-6", commun.Reussi, "", commun.T(fmt.Sprintf("inscription seq %d, hash %s", si, e.HashHex()), fmt.Sprintf("inscription seq %d, hash %s", si, e.HashHex())), 6)
}

// evenementExploitableAT : « evenement.json exploitable » au sens d'AT-5 et
// d'AT-6 (CT-1 §11.4, révision 0.4) : l'événement prouvé passe E-1 et E-2.
func (a *Analyse) evenementExploitableAT() bool {
	return a.Evenement != nil && regleE1(a.Evenement).statut == commun.Reussi && a.Evenement.ErrCanonique == nil
}

// aDoublon dit si un document JSON porte un nom de membre en double.
func aDoublon(v *jsonv.Valeur) bool {
	if v == nil {
		return false
	}
	if v.Doublon {
		return true
	}
	for _, m := range v.Membres {
		if aDoublon(m.Valeur) {
			return true
		}
	}
	for _, e := range v.Elements {
		if aDoublon(e) {
			return true
		}
	}
	return false
}

// CanauxCapture rend l'union des canaux de capture, dans l'ordre d'EX-6.20.
func (at *Attestation) CanauxCapture() []string {
	ordre := []string{"mandataire_mcp", "passerelle", "icap", "miroir", "sdk", "opentelemetry"}
	vus := map[string]bool{}
	for _, ag := range at.V.Chemin("signed", "attestation", "agents").Elements {
		for _, c := range ag.Membre("capture_channels").Elements {
			vus[c.S()] = true
		}
	}
	var out []string
	for _, c := range ordre {
		if vus[c] {
			out = append(out, c)
		}
	}
	return out
}
