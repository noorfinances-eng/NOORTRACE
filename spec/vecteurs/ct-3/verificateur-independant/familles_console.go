// Famille console/ de l'annexe A (A.11, vérifications CS-1 à CS-9) et
// épreuve de lecture de la console (EX-A.17) : modèle d'affichage, requête
// personal_sign, réponse du portefeuille et vote construit, découverte
// EIP-6963, fichier de clé chiffré. Chaque attendu est recalculé depuis le
// texte de CT-3 0.3 (9.6, 9.7, 13.9 à 13.14) par console.go.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Familles de la révision 0.3.
const (
	FamConsole                = "console"
	FamAcceptationConsole     = "acceptation-console"
	MotDePasseFichierCle      = "noortrace/vecteurs/ct3/console/mot-de-passe"
	PrefixeSignatureEvenement = "noortrace/signature-evenement/v0\n"
)

// lireCT1 lit un fichier des vecteurs CT-1 (journal-valide), à côté de ct-3.
func (c *Contexte) lireCT1(rel string) (*Value, bool) {
	src, err := os.ReadFile(filepath.Join(c.Racine, "..", "ct-1", "journal-valide", rel))
	if err != nil {
		return nil, false
	}
	v, err := ParseJSON(src)
	return v, err == nil
}

func evenementCT1(evs *Value, seq int64) *Value {
	for _, e := range evs.Arr {
		if s, ok := EntierJSON(e.Get("seq")); ok && s == seq {
			return e
		}
	}
	return nil
}

func familleConsole(c *Contexte) {
	const f = FamConsole
	k := c.Consts
	evsCT1, okCT1 := c.lireCT1("evenements.json")
	piecesCT1, _ := c.lireCT1("pieces.json")
	clesCT1, _ := c.lireCT1("cles.json")

	// ---- modeles/ (CS-1 à CS-4).
	bloquants := map[string]bool{}
	avertis := map[string]bool{}
	intentionParReference, effetNonResolu := false, false
	hachesSeq := map[int64][]string{}
	type chainage struct{ fic, prev string }
	chaines10 := []chainage{}
	for _, fic := range c.fichiers("console/modeles/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		in := cas.Get("input")
		vue := in.Get("view")
		se := in.Get("session")
		s := SessionConsole{Identite: se.Get("session_identity").S(), Entree: se.Get("entry").S(), Adresses: chaines(se.Get("addresses")), EstDemandeur: se.Get("is_requester").Bool}
		now, err := LireInstant(in.Get("now").S())
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		m := ModeleAffichage(vue, s, in.Get("decision"), in.Get("approver"), in.Get("reason"), now)
		exp := cas.Get("expected")
		for _, mb := range m.Obj {
			fond := "CT-3 EX-9.4, EX-9.15 à EX-9.19 ($defs/modele_affichage)"
			switch mb.Key {
			case "blocking":
				fond = "CT-3 EX-9.15 : « Chaque contrôle en échec ajoute sa raison […] à la liste blocking du modèle d'affichage, dans l'ordre des contrôles »"
			case "arguments":
				fond = "CT-3 EX-9.16 : arguments, feuille par feuille"
			case "digests":
				fond = "CT-3 EX-9.17 à EX-9.19 ; EX-9.15 point 2 : « le modèle n'a pas de condensés »"
			case "warnings":
				fond = "CT-3 EX-9.15 : avertissements « dans cet ordre : condense_utf8 ; separation_non_verifiable ; membres_ajoutes ; separation_incomplete »"
			}
			c.R.ComparerJSON(f, fic, mb.Key, exp.Get(mb.Key), mb.Val, fond)
		}
		c.R.Comparer(f, fic, "membres du modèle", membresDe(exp), membresDe(m), "CT-3 $defs/modele_affichage")
		for _, b := range chaines(m.Get("blocking")) {
			bloquants[b] = true
		}
		for _, a := range chaines(m.Get("warnings")) {
			avertis[a] = true
		}
		ev := vue.Get("retained_event")
		// EX-12.14 : chaque membre listé dans unresolved est nul dans la vue,
		// et son pointeur désigne le résultat.
		for i, ef := range vue.Get("effects").Arr {
			for _, u := range ef.Get("unresolved").Arr {
				mb := u.Get("member").S()
				c.R.Exiger(f, fic, fmt.Sprintf("effects/%d : %s non résolu, valeur nulle", i, mb), ef.Get(mb) != nil && ef.Get(mb).IsNull(), "non nul", "CT-3 EX-12.14 : « la valeur d'un tel membre est null dans la vue »")
				c.R.Exiger(f, fic, fmt.Sprintf("effects/%d : pointeur vers le résultat", i), strings.HasPrefix(u.Get("pointer").S(), "/result"), u.Get("pointer").S(), "CT-3 EX-12.14 : « dont le pointeur désigne le résultat (/result/…) »")
				effetNonResolu = true
			}
		}
		if m.Get("intent_status").S() == "reference_non_verifiable" {
			intentionParReference = true
		}
		if sq, ok := EntierJSON(ev.Get("seq")); ok {
			hachesSeq[sq] = append(hachesSeq[sq], ev.Get("hash").S())
			if it := ev.Get("intent"); it != nil && it.Kind == KindObject {
				c.R.Comparer(f, fic, "ticket et seq de l'intention par référence", "apr-0902 10", vue.Get("ticket").S()+" "+fmt.Sprint(sq), "CT-3 EX-A.15 : « ticket apr-0902, événement seq 10 »")
				chaines10 = append(chaines10, chainage{fic, ev.Get("prev_hash").S()})
			}
		}
		// Le ticket apr-2201 : événement seq 5 et pièce de CT-1, lus tels quels.
		if vue.Get("ticket").S() == "apr-2201" && ev.Get("ts").S() == "2026-11-05T09:12:09.904Z" && okCT1 {
			if e5 := evenementCT1(evsCT1, 5); e5 != nil && vue.Get("request_hash").S() == e5.Get("hash").S() {
				c.R.ComparerJSON(f, fic, "retained_event = CT-1 journal-valide seq 5", e5, ev, "CT-3 EX-A.15 : « le ticket apr-2201 des vecteurs de CT-1 (événement seq 5 et pièce de journal-valide, lus et jamais réécrits) »")
			}
			if pb := vue.Get("arguments_piece"); pb != nil && !pb.IsNull() && piecesCT1 != nil {
				ref := e5Ref(evsCT1)
				if octets, err := base64.StdEncoding.DecodeString(pb.S()); err == nil {
					sum := sha256.Sum256(octets)
					if Hex0x(sum[:]) == ref {
						for _, p := range piecesCT1.Get("pieces").Arr {
							if p.Get("sha256").S() == ref {
								c.R.Comparer(f, fic, "arguments_piece = pièce de CT-1 journal-valide", p.Get("texte").S(), string(octets), "CT-3 EX-A.15")
							}
						}
					}
				}
			}
		}
		// Événement scellé par la clé de test rec-test-01 de CT-1.
		if vue.Get("arguments_piece").IsNull() && clesCT1 != nil {
			c.R.Exiger(f, fic, "sig de l'événement retenue (Ed25519, clé rec-test-01 de CT-1)", sigEvenementValide(ev, clesCT1), "signature refusée", "CT-3 EX-A.15 : « événement retenue construit par le générateur et scellé par la clé de test rec-test-01 de CT-1 » ; CT-1 §6.2")
			c.R.Comparer(f, fic, "journal_id = journal-approbations (A.2)", k.JournalID, ev.Get("journal_id").S(), "CT-3 EX-A.15 : « une demande de journal-approbations »")
		}
	}
	if c.Spec != "" {
		if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/vue_ticket -->"); err == nil {
			if cas, ok := c.lire("console/modeles/apr-2201-approuve.json"); ok {
				c.R.ComparerJSON(f, "console/modeles/apr-2201-approuve.json", "input.view = vue d'exemple d'EX-12.15", ex, cas.Get("input").Get("view"), "CT-3 EX-12.15 : réponse pour le ticket apr-2201")
				s := SessionConsole{Identite: "oidc " + EmetteurA10 + " approbateur-1", Entree: "active", Adresses: []string{k.Comptes[1]}}
				now, _ := LireInstant("2026-11-05T09:25:00.000Z")
				m := ModeleAffichage(ex, s, Chaine("approuve"), Chaine(k.Comptes[1]), Chaine("Constat et facture concordants"), now)
				const fic = "CT-3 EX-12.15 (exemple)"
				c.R.Comparer(f, fic, "blocking", "[]", Compact(m.Get("blocking")), "CT-3 EX-12.15 : « les treize contrôles d'EX-9.15 passent : blocking est vide »")
				c.R.Comparer(f, fic, "remaining_ms", "2829904", Compact(m.Get("remaining_ms")), "CT-3 EX-12.15 : « remaining_ms vaut 2 829 904 »")
				c.R.Comparer(f, fic, "empreinte affichée", "a57cbdad…64f7df7c", m.Get("digests").Get("approuve").Get("fingerprint").S(), "CT-3 EX-12.15, EX-9.18")
				m3 := ModeleAffichage(ex, SessionConsole{Identite: "oidc " + EmetteurA10 + " u.martin", Entree: "active", Adresses: []string{k.Comptes[3]}, EstDemandeur: true},
					Chaine("approuve"), Chaine(k.Comptes[3]), Nul(), now)
				c.R.Comparer(f, fic, "compte 3, session du demandeur", "[\"auto_approbation\",\"session_du_demandeur\"]", Compact(m3.Get("blocking")), "CT-3 EX-12.15 : « Le compte 3, adresse du demandeur, recevrait auto_approbation, et sa session session_du_demandeur »")
				// Exemple d'EX-9.16 : amount 21500.00 en clair.
				v2 := Copier(ex)
				poser(v2.Get("request").Get("arguments"), "amount", Chaine("21500.00"))
				m2 := ModeleAffichage(v2, s, Chaine("approuve"), Chaine(k.Comptes[1]), Nul(), now)
				c.R.Comparer(f, "CT-3 EX-9.16 (exemple)", "blocking", "[\"argument_different\"]", Compact(m2.Get("blocking")), "CT-3 EX-9.16 : « Avec amount \"21500.00\" en clair, /amount devient different et blocking vaut [\"argument_different\"] »")
				etats := []string{}
				for _, a := range m.Get("arguments").Arr {
					etats = append(etats, a.Get("pointer").S()+" "+a.Get("status").S())
				}
				c.R.Comparer(f, "CT-3 EX-9.16 (exemple)", "feuilles", "/amount verifie, /beneficiary_iban non_verifiable, /claim_id verifie, /currency verifie", strings.Join(etats, ", "), "CT-3 EX-9.16 : « Les feuilles sont, dans l'ordre : /amount verifie, /beneficiary_iban non_verifiable, /claim_id verifie, /currency verifie »")
				dA := m.Get("digests")
				c.R.Comparer(f, "CT-3 EX-9.17 (exemple)", "D_approuve", "0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c", dA.Get("approuve").Get("d_a").S(), "CT-3 EX-9.17")
				c.R.Comparer(f, "CT-3 EX-9.17 (exemple)", "H_approuve", "0xe9f3d8812e1fc736cd7957efb20093bfb3655c6568fc56e6133b2cc41d2cf6ea", dA.Get("approuve").Get("h").S(), "CT-3 EX-9.17")
				c.R.Comparer(f, "CT-3 EX-9.17 (exemple)", "D_refuse", "0xd2cace7b1eded2643785e99e2f5316ee6cb4fad6ea468426d30d76538ccab300", dA.Get("refuse").Get("d_a").S(), "CT-3 EX-9.17")
				c.R.Comparer(f, "CT-3 EX-9.17 (exemple)", "H_refuse", "0xde5123ed1281dbf3fa4f923b14c96db3481c460e7ed324b2943fffbec2f04811", dA.Get("refuse").Get("h").S(), "CT-3 EX-9.17")
				c.R.Comparer(f, "CT-3 EX-9.18 (exemple)", "groupes(D_approuve)", "a57cbdad 280b5cb2 e9f6ee87 b85d8bc0 5e76a596 6377e7d5 80465194 64f7df7c", dA.Get("approuve").Get("groups").S(), "CT-3 EX-9.18")
				c.R.Comparer(f, "CT-3 EX-9.18 (exemple)", "empreinte(H_approuve)", "e9f3d881…1d2cf6ea", dA.Get("approuve").Get("h_fingerprint").S(), "CT-3 EX-9.18")
				c.R.Comparer(f, "CT-3 EX-9.18 (exemple)", "empreinte(D_refuse)", "d2cace7b…8ccab300", dA.Get("refuse").Get("fingerprint").S(), "CT-3 EX-9.18")
			}
		} else {
			c.R.Erreur("spécification : %v", err)
		}
	}
	for _, b := range []string{"evenement_invalide", "piece_invalide", "champ_different", "argument_different", "argument_absent_de_l_affichage",
		"empreinte_divergente", "ticket_clos_aux_votes", "jeu_non_fige", "decision_absente", "identite_inconnue", "identite_desactivee",
		"adresse_non_attribuee", "hors_jeu", "auto_approbation", "session_du_demandeur", "recuse", "motif_trop_long"} {
		c.R.Exiger(f, "console/modeles/", "raison exercée : "+b, bloquants[b], "absente", "CT-3 EX-A.15 : modeles/")
	}
	for _, a := range []string{"separation_non_verifiable", "membres_ajoutes", "separation_incomplete"} {
		c.R.Exiger(f, "console/modeles/", "avertissement exercé : "+a, avertis[a], "absent", "CT-3 EX-A.15 : modeles/")
	}
	c.R.Exiger(f, "console/modeles/", "cas exercé : intention portée par une référence", intentionParReference, "absent", "CT-3 EX-A.15 : « une intention que l'événement porte par une référence »")
	c.R.Exiger(f, "console/modeles/", "cas exercé : effet tiré du résultat (unresolved)", effetNonResolu, "absent", "CT-3 EX-A.15 : « un effet dont object est tiré du résultat »")
	for _, ch := range chaines10 {
		c.R.Exiger(f, ch.fic, "événement seq 10 chaîné à un événement seq 9 des modèles", contient(hachesSeq[9], ch.prev), ch.prev, "CT-3 EX-A.15 : « événement seq 10 chaîné au précédent »")
	}

	// ---- requetes/ (CS-3, CS-5).
	sigCT1 := map[string]string{}
	if okCT1 {
		if e6 := evenementCT1(evsCT1, 6); e6 != nil {
			ap := e6.Get("approval")
			sigs := chaines(ap.Get("signatures"))
			for i, a := range chaines(ap.Get("approvers")) {
				if i < len(sigs) {
					sigCT1[a] = sigs[i]
				}
			}
		}
	}
	for _, fic := range c.fichiers("console/requetes/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		in := cas.Get("input")
		exp := cas.Get("expected")
		a := in.Get("a")
		cd, dA, err := Condenses(a)
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		n, _ := EntierJSON(in.Get("account"))
		adr := k.Comptes[int(n)]
		c.R.Comparer(f, fic, "approver = adresse du compte", adr, in.Get("approver").S(), "CT-3 A.11 : « input.account est l'indice du compte de A.2 qui signe »")
		c.R.ComparerJSON(f, fic, "digests", exp.Get("digests"), cd, "CT-3 EX-9.17 à EX-9.19")
		c.R.Comparer(f, fic, "preimage", exp.Get("preimage").S(), Hex0x(PreimageEIP191(dA)), "CT-3 13.9, pas 5 : « préimage de 60 octets : 0x19, les 25 octets de Ethereum Signed Message:\\n, les 2 octets 32, puis les 32 octets de D_A »")
		c.R.ComparerJSON(f, fic, "request", exp.Get("request"), RequetePersonalSign(dA, in.Get("approver").S()), "CT-3 EX-13.24")
		sig, err := SignerMessage(k.Prives[adr], dA)
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		c.R.Comparer(f, fic, "signature (RFC 6979, clé du compte)", exp.Get("signature").S(), sig, "CT-3 A.11 : « expected.signature la signature RFC 6979 de ce compte sur H »")
		if a.Get("ticket").S() == "apr-2201" && a.Get("decision").S() == "approuve" && sigCT1[adr] != "" {
			c.R.Comparer(f, fic, "signature = celle des vecteurs de CT-1 (seq 6)", sigCT1[adr], exp.Get("signature").S(), "CT-3 EX-A.15 : « dont les signatures sur D_approuve sont celles des vecteurs de CT-1 »")
		}
		switch a.Get("ticket").S() {
		case "apr-0001":
			c.R.Comparer(f, fic, "D_A cité par EX-A.15", "0xce13c3f15c3eab4c81a4735828741b0acf205a46e59d6894ed2e7589b5777d0d", Hex0x(dA), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "H cité par EX-A.15", "0x9079b529368f08023b43a2b61a7ab9f92c3c42a28cefe10dfc161b48835ca728", cd.Get("h").S(), "CT-3 EX-A.15")
			if v, ok := c.lire("decisions/valides/approbation-2-sur-3.json"); ok {
				ap := v.Get("remise").Get("approval")
				ctx := v.Get("context")
				a2 := ObjetA(ap.Get("decision").S(), ctx.Get("journal_id").S(), ctx.Get("org_id").S(), ap.Get("request_hash").S(), ap.Get("ticket").S())
				c.R.ComparerJSON(f, fic, "A = celui de decisions/valides/approbation-2-sur-3.json", a2, a, "CT-3 EX-A.15 : « le compte 1 sur le ticket apr-0001 de decisions/valides/approbation-2-sur-3.json »")
			}
		case "apr-2201":
			c.R.Comparer(f, fic, "journal_id = CT-1", "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164", a.Get("journal_id").S(), "CT-3 EX-9.17")
		}
		if strings.HasPrefix(a.Get("ticket").S(), "apr-c0-") {
			rh := Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/demande/console-zero"))
			c.R.Comparer(f, fic, "request_hash = SHA-256(\"noortrace/vecteurs/ct3/demande/console-zero\")", rh, a.Get("request_hash").S(), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "request_hash cité par EX-A.15", "0xd3620aa8af23a0d83931eb2db11403b2947430cbd89c3387781bce95ab06823b", rh, "CT-3 EX-A.15")
			kmin := 0
			for i := 1; i <= 100000 && kmin == 0; i++ {
				d, _ := CondenseA(ObjetA("approuve", k.JournalID, k.OrgID, rh, fmt.Sprintf("apr-c0-%d", i)))
				if d[0] == 0 {
					kmin = i
				}
			}
			c.R.Comparer(f, fic, "ticket apr-c0-<k>, plus petit k ≥ 1 à premier octet nul", fmt.Sprintf("apr-c0-%d", kmin), a.Get("ticket").S(), "CT-3 EX-A.15 : « ticket apr-c0-<k> pour le plus petit entier k ≥ 1 qui donne un premier octet nul : k = 542 »")
			c.R.Comparer(f, fic, "k cité par EX-A.15", "542", fmt.Sprint(kmin), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "D_A cité par EX-A.15", "0x00d9060ac22cf499a79777dfeb7fa339783ac23f12571712c02663d9acdca5c7", Hex0x(dA), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "décision et journal", "approuve "+k.JournalID, a.Get("decision").S()+" "+a.Get("journal_id").S(), "CT-3 EX-A.15 : « décision approuve, journal-approbations »")
		}
		if strings.HasSuffix(fic, "/apr-2201-approuve-compte-1.json") && c.Spec != "" {
			if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/requete_signature -->"); err == nil {
				c.R.ComparerJSON(f, fic, "request = exemple d'EX-13.24", ex, exp.Get("request"), "CT-3 EX-13.24")
			}
			c.R.Comparer(f, fic, "préimage citée en 13.9", "0x19457468657265756d205369676e6564204d6573736167653a0a3332a57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c", exp.Get("preimage").S(), "CT-3 13.9 : « la préimage du pas 5 est, en hexadécimal, … »")
			if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/requete_voter -->"); err == nil {
				c.R.Comparer(f, fic, "signature = celle de la requête voter de 12.9", ex.Get("signature").S(), exp.Get("signature").S(), "CT-3 EX-13.24 : « la signature attendue est celle de la requête voter de 12.9 »")
			}
		}
	}

	// ---- reponses/ (CS-6, CS-7).
	raisonsRep := map[string]int{}
	for _, fic := range c.fichiers("console/reponses/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		in := cas.Get("input")
		exp := cas.Get("expected")
		dA, err := CondenseA(in.Get("a"))
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		is := VerifierReponse(in.Get("response"), dA, in.Get("approver").S())
		issue, vote := "accepte", Nul()
		if is.Raison != "" {
			issue = "refuse"
		} else {
			vote = RequeteVoter(in.Get("a"), in.Get("approver").S(), is.Signature, in.Get("reason"), in.Get("session_identity").S())
		}
		raisonsRep[is.Raison]++
		fond := "CT-3 EX-9.21 et table de 13.14 (EX-13.29)"
		c.R.Comparer(f, fic, "outcome", exp.Get("outcome").S(), issue, fond)
		c.R.Comparer(f, fic, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(is.Raison)), fond)
		c.R.Comparer(f, fic, "signature", Compact(exp.Get("signature")), Compact(nulOuChaine(is.Signature)), "CT-3 EX-9.21 pas 5 (normalisation d'EX-9.3)")
		c.R.Comparer(f, fic, "recovered", Compact(exp.Get("recovered")), Compact(nulOuChaine(is.Recouvree)), "CT-3 EX-9.21 pas 6 et 7")
		c.R.ComparerJSON(f, fic, "vote", exp.Get("vote"), vote, "CT-3 EX-9.21 pas 8, EX-12.16")
		if strings.HasSuffix(fic, "/s-haut-normalisee.json") && c.Spec != "" {
			if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/cas_reponse -->"); err == nil {
				c.R.ComparerJSON(f, fic, "égal à l'exemple d'EX-9.21", ex, cas, "CT-3 EX-9.21")
			}
			if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/requete_voter -->"); err == nil {
				c.R.ComparerJSON(f, fic, "vote = requête voter de 12.9", ex, vote, "CT-3 EX-12.16")
			}
		}
		if strings.HasSuffix(fic, "/signature-de-la-chaine.json") {
			c.R.Comparer(f, fic, "adresse citée par EX-9.21", "0x58047c881cfdadf1b8d785b79b29c5cc784ede6e", is.Recouvree, "CT-3 EX-9.21 : « recouvre, sur H, 0x58047c881cfdadf1b8d785b79b29c5cc784ede6e »")
			// La signature du compte 1 sur la chaîne « 0x… » de D_A (66 octets).
			s, _ := SignerMessage(k.Prives[k.Comptes[1]], []byte(Hex0x(dA)))
			c.R.Comparer(f, fic, "result = signature du compte 1 sur la chaîne 0x… de D_A", s, in.Get("response").Get("result").S(), "CT-3 EX-9.7, EX-9.21")
		}
	}
	for _, r := range []string{"", "refus_approbateur", "non_autorise", "methode_non_prise_en_charge", "deconnecte", "chaine_deconnectee", "reponse_invalide", "signature_invalide", "adresse_differente"} {
		nom := r
		if r == "" {
			nom = "acceptée"
		}
		c.R.Exiger(f, "console/reponses/", "issue exercée : "+nom, raisonsRep[r] > 0, "absente", "CT-3 EX-A.15 : reponses/")
	}
	c.R.Exiger(f, "console/reponses/", "erreur_portefeuille : un autre code et une erreur sans code", raisonsRep["erreur_portefeuille"] >= 2, fmt.Sprint(raisonsRep["erreur_portefeuille"]), "CT-3 EX-A.15 : « un autre code, une erreur sans code »")

	// ---- decouverte/ (CS-8).
	vuesDec := map[string]bool{}
	for _, fic := range c.fichiers("console/decouverte/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		an := cas.Get("input").Get("announcements").Arr
		fs, rs := Decouvrir(an)
		exp := cas.Get("expected")
		c.R.ComparerJSON(f, fic, "providers", exp.Get("providers"), fs, "CT-3 EX-13.22 points 2 à 4 : « La liste est affichée dans l'ordre des premières annonces »")
		c.R.ComparerJSON(f, fic, "rejected", exp.Get("rejected"), rs, "CT-3 EX-13.22 points 2 et 3 (annonce_invalide, annonce_en_double)")
		if len(an) == 0 {
			vuesDec["aucune"] = true
		}
		if len(an) == 1 && len(fs.Arr) == 1 {
			vuesDec["une"] = true
		}
		for _, r := range rs.Arr {
			vuesDec[r.Get("reason").S()] = true
		}
	}
	for _, x := range []string{"aucune", "une", "annonce_invalide", "annonce_en_double"} {
		c.R.Exiger(f, "console/decouverte/", "cas exercé : "+x, vuesDec[x], "absent", "CT-3 EX-A.15 : decouverte/")
	}

	// ---- fichiers-cle/ (CS-9).
	raisonsFC := map[string]bool{}
	for _, fic := range c.fichiers("console/fichiers-cle/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		in := cas.Get("input")
		ks := in.Get("keystore")
		is := LireFichierCle(ks, in.Get("password").S(), in.Get("approver").S())
		exp := cas.Get("expected")
		issue := "accepte"
		if is.Raison != "" {
			issue = "refuse"
		}
		raisonsFC[is.Raison] = true
		avert := Tableau()
		if is.DerivationFait && is.DerivationFbl {
			avert.Arr = append(avert.Arr, Chaine("derivation_faible"))
		}
		fond := "CT-3 EX-13.28"
		c.R.Comparer(f, fic, "outcome", exp.Get("outcome").S(), issue, fond)
		c.R.Comparer(f, fic, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(is.Raison)), fond)
		c.R.Comparer(f, fic, "address", Compact(exp.Get("address")), Compact(nulOuChaine(is.Adresse)), "CT-3 EX-13.28 points 5 et 6")
		c.R.ComparerJSON(f, fic, "warnings", exp.Get("warnings"), avert, "CT-3 EX-13.28 point 9 : « derivation_faible quand c < 262 144 […] ou n < 2^17 »")
		id := cas.Get("id").S()
		if id == "pbkdf2-valide" || id == "scrypt-valide" {
			nom := strings.TrimSuffix(id, "-valide")
			cr := ks.Get("crypto")
			sel := Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/console/fichier-cle/" + nom + "/sel"))
			iv := Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/console/fichier-cle/" + nom + "/iv")[:16])
			c.R.Comparer(f, fic, "salt = SHA-256(…/fichier-cle/"+nom+"/sel)", sel, "0x"+cr.Get("kdfparams").Get("salt").S(), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "iv = 16 premiers octets de SHA-256(…/fichier-cle/"+nom+"/iv)", iv, "0x"+cr.Get("cipherparams").Get("iv").S(), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "id = UUID tiré de SHA-256(…/fichier-cle/"+nom+"/uuid)", uuidEtiquette("noortrace/vecteurs/ct3/console/fichier-cle/"+nom+"/uuid"), ks.Get("id").S(), "CT-3 EX-A.15 : « 16 premiers octets, bits de version 4 et de variante posés »")
			c.R.Comparer(f, fic, "mot de passe", MotDePasseFichierCle, in.Get("password").S(), "CT-3 EX-A.15")
			c.R.Comparer(f, fic, "clé déchiffrée = clé du compte 1", Hex0x(k.Prives[k.Comptes[1]]), Hex0x(is.Cle), "CT-3 EX-A.15 : « clé du compte 1 »")
			if nom == "pbkdf2" {
				c.R.Comparer(f, fic, "c", "1024", Compact(cr.Get("kdfparams").Get("c")), "CT-3 EX-A.15 : « c = 1 024 »")
				if c.Spec != "" {
					if ex, err := blocJSON(c.Spec, "<!-- schema: console-approbation/fichier_cle -->"); err == nil {
						c.R.ComparerJSON(f, fic, "keystore = exemple d'EX-13.28", ex, ks, "CT-3 EX-13.28 (exemple)")
					}
				}
			} else {
				kp := cr.Get("kdfparams")
				c.R.Comparer(f, fic, "n, r, p", "1024 8 1", Compact(kp.Get("n"))+" "+Compact(kp.Get("r"))+" "+Compact(kp.Get("p")), "CT-3 EX-A.15 : « n = 1 024, r = 8, p = 1 »")
			}
		}
	}
	for _, r := range []string{"", "mot_de_passe_ou_mac", "fichier_cle_non_pris_en_charge", "fichier_cle_invalide", "cle_invalide", "adresse_differente"} {
		nom := r
		if r == "" {
			nom = "accepté"
		}
		c.R.Exiger(f, "console/fichiers-cle/", "issue exercée : "+nom, raisonsFC[r], "absente", "CT-3 EX-A.15 : fichiers-cle/")
	}
}

func membresDe(v *Value) string {
	var k []string
	for _, m := range v.Obj {
		k = append(k, m.Key)
	}
	return strings.Join(k, ",")
}

// e5Ref rend le sha256 de la référence des arguments de l'événement seq 5
// de CT-1.
func e5Ref(evs *Value) string {
	if e := evenementCT1(evs, 5); e != nil {
		return e.Get("execution").Get("arguments").Get("sha256").S()
	}
	return ""
}

// uuidEtiquette rend l'UUID de version 4 tiré des 16 premiers octets de
// SHA-256 d'une étiquette, bits de version et de variante posés.
func uuidEtiquette(e string) string {
	b := SHA256Etiquette(e)[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	x := fmt.Sprintf("%x", b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// sigEvenementValide vérifie sig d'un événement : Ed25519 sur
// P_S ‖ JCS(E') (CT-1 §6.2), clé de recorder_key_id lue dans cles.json de
// CT-1.
func sigEvenementValide(ev, cles *Value) bool {
	var pub []byte
	for _, k := range cles.Get("keys").Arr {
		if k.Get("key_id").S() == ev.Get("recorder_key_id").S() {
			pub, _ = DecoderHex(k.Get("public_key").S())
		}
	}
	sig, err := DecoderHex(ev.Get("sig").S())
	if len(pub) != ed25519.PublicKeySize || err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	e := &Value{Kind: KindObject}
	for _, m := range ev.Obj {
		if m.Key != "hash" && m.Key != "sig" {
			e.Obj = append(e.Obj, m)
		}
	}
	cn, err := Canonique(e)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, append([]byte(PrefixeSignatureEvenement), cn...), sig)
}

// ------------------------------------------------- épreuve de lecture

var reRegle = regexp.MustCompile(`^EX-([0-9]+|A)\.[0-9]+$`)

func familleAcceptationConsole(c *Contexte) {
	const f = FamAcceptationConsole
	const fic = "acceptation-console-attendu.json"
	d, ok := c.lire(fic)
	if !ok {
		return
	}
	attendus := map[string]struct {
		sections  string
		questions []string
	}{
		"approbateur": {"9,13", []string{"Comment vous inscrivez-vous ?", "Comment signez-vous depuis la console avec votre portefeuille ?", "Que vérifiez-vous avant de signer ?", "Que faites-vous si l'empreinte diffère ?"}},
		"integrateur": {"7.4,9,12,13", []string{"Quels messages la page, le portefeuille et le service échangent-ils, dans quel ordre, et avec quel contenu exact ?", "Que refuse la console, et à quel moment ?"}},
	}
	vus := map[string]bool{}
	for _, r := range d.Get("roles").Arr {
		role := r.Get("role").S()
		vus[role] = true
		at := attendus[role]
		c.R.Comparer(f, fic, role+" : sections reçues", at.sections, strings.Join(chaines(r.Get("sections")), ","), "CT-3 EX-A.17 (table des rôles)")
		qs := []string{}
		for _, q := range r.Get("questions").Arr {
			qs = append(qs, q.Get("question").S())
			for _, e := range q.Get("elements").Arr {
				for _, regle := range chaines(e.Get("rules")) {
					existe := reRegle.MatchString(regle) && c.Spec != "" && strings.Contains(c.Spec, "**"+regle+"**")
					c.R.Exiger(f, fic, fmt.Sprintf("%s %s : règle %s définie dans CT-3", role, q.Get("id").S(), regle), existe, "introuvable", "CT-3 EX-A.17 : « la règle qui fonde chacun »")
				}
			}
		}
		c.R.Comparer(f, fic, role+" : questions", strings.Join(at.questions, " | "), strings.Join(qs, " | "), "CT-3 EX-A.17 (table des rôles)")
	}
	c.R.Exiger(f, fic, "deux rôles, approbateur et integrateur", vus["approbateur"] && vus["integrateur"] && len(d.Get("roles").Arr) == 2, Compact(d.Get("roles")), "CT-3 EX-A.17")
	for _, x := range []string{"acceptation-console/consigne.md", "acceptation-console/gabarit-reponse.md"} {
		_, err := os.Stat(filepath.Join(c.Racine, x))
		c.R.Exiger(f, x, "présent", err == nil, fmt.Sprint(err), "CT-3 EX-A.17 : « questions de acceptation-console/consigne.md » ; A.3")
	}
	_, err := os.Stat(filepath.Join(c.Racine, "acceptation-console", fic))
	c.R.Exiger(f, fic, "hors du répertoire remis aux lecteurs", os.IsNotExist(err), "présent dans acceptation-console/", "CT-3 A.3 : « la grille de l'épreuve, hors du répertoire que les lecteurs reçoivent »")
	if src, err := os.ReadFile(filepath.Join(c.Racine, "acceptation-console", "consigne.md")); err == nil {
		for role, at := range attendus {
			for _, q := range at.questions {
				c.R.Exiger(f, "acceptation-console/consigne.md", role+" : question « "+q+" »", strings.Contains(strings.Join(strings.Fields(string(src)), " "), q), "absente", "CT-3 EX-A.17 : « répondent par écrit aux questions de acceptation-console/consigne.md »")
			}
		}
	}
	c.R.HorsPerimetre(f, "acceptation-console/consigne.md", "contenu de la consigne", "texte libre (EX-A.17), non recalculable ; seules les questions y sont cherchées")
}
