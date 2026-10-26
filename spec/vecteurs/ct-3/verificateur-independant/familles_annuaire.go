// Famille annuaire/ de l'annexe A (A.10, vérifications AN-1 à AN-9) :
// messages d'inscription, vérification d'une inscription, séparation des
// domaines, traces d'opérations, contrôles de la console avant un vote,
// annuaires exportés. Chaque attendu est recalculé depuis le texte de CT-3
// 0.3 (13.3 à 13.8) par annuaire.go.

package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// FamAnnuaire est la famille annuaire/.
const FamAnnuaire = "annuaire"

// Constantes propres à la famille (A.10).
const (
	OrigineConsoleA10   = "https://console.assureur-demo.example"
	EmetteurA10         = "https://idp.assureur-demo.example"
	InstantBaseAnnuaire = "2026-11-10T08:00:00.000Z"
	TTLInscriptionA10   = 600000
)

// nonceA10 rend le nonce d'inscription k de A.10 : 16 premiers octets de
// SHA-256(UTF-8("noortrace/vecteurs/ct3/inscription/nonce/<k>")), en
// hexadécimal minuscule.
func nonceA10(k int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("noortrace/vecteurs/ct3/inscription/nonce/%d", k)))
	return fmt.Sprintf("%x", s[:16])
}

// indiceNonce cherche k ∈ [1, max] dont le nonce de A.10 est n.
func indiceNonce(n string, max int) int {
	for k := 1; k <= max; k++ {
		if nonceA10(k) == n {
			return k
		}
	}
	return 0
}

func (c *Contexte) etatAnnuaire(rel string) (*EtatAnnuaire, bool) {
	v, ok := c.lire("annuaire/" + rel)
	if !ok {
		return nil, false
	}
	return &EtatAnnuaire{Doc: v, Sch: c.Sch}, true
}

func nulOuChaine(s string) *Value {
	if s == "" {
		return Nul()
	}
	return Chaine(s)
}

func familleAnnuaire(c *Contexte) {
	const f = FamAnnuaire
	k := c.Consts
	// Signatures d'inscription acceptées : reproduites par la clé du compte
	// (A.10 : « de vraies signatures EIP-191 des comptes de A.2 »).
	reproduire := func(fic, grandeur, msg, adr, sig string) {
		prive := k.Prives[adr]
		if prive == nil {
			c.R.Exiger(f, fic, grandeur+" : adresse d'un compte de A.2", false, adr, "CT-3 A.10")
			return
		}
		s, err := SignerMessage(prive, []byte(msg))
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			return
		}
		c.R.Comparer(f, fic, grandeur+" : signature RFC 6979 du compte", sig, s, "CT-3 A.10 : « Les signatures sont de vraies signatures EIP-191 des comptes de A.2 » ; EX-13.12 (personal_sign sur les octets ASCII du texte)")
	}
	nonces := map[string]bool{}
	raisonsInscription := map[string]bool{}

	// ---- annuaires de départ.
	ref, okRef := c.lire("annuaire/annuaires/reference.json")
	if okRef && c.Spec != "" {
		if ex, err := blocJSON(c.Spec, "<!-- schema: annuaire-approbateurs -->"); err == nil {
			c.R.ComparerJSON(f, "annuaire/annuaires/reference.json", "égal à l'annuaire d'exemple de 13.4", ex, ref, "CT-3 EX-A.12 : « l'annuaire d'exemple de 13.4, octet pour octet la même valeur JSON »")
		} else {
			c.R.Erreur("spécification : %v", err)
		}
	}
	if okRef {
		if ex, ok := c.lire("annuaire/exports/reference.json"); ok {
			c.R.ComparerJSON(f, "annuaire/exports/reference.json", "égal à annuaires/reference.json", ref, ex, "CT-3 EX-A.13 : « exports/ : l'annuaire de référence sans écart »")
		}
		for _, x := range ref.Get("entries").Arr {
			for _, a := range x.Get("addresses").Arr {
				p := a.Get("proof")
				reproduire("annuaire/annuaires/reference.json", "preuve de "+a.Get("address").S(), p.Get("message").S(), a.Get("address").S(), p.Get("signature").S())
				nonces[p.Get("nonce").S()] = true
			}
		}
		c.R.Comparer(f, "annuaire/annuaires/reference.json", "console_origin", OrigineConsoleA10, ref.Get("console_origin").S(), "CT-3 A.10 : origine de la console")
		c.R.Comparer(f, "annuaire/annuaires/reference.json", "registration_ttl_ms", fmt.Sprint(TTLInscriptionA10), Compact(ref.Get("registration_ttl_ms")), "CT-3 A.10 : « registration_ttl_ms 600 000 »")
		c.R.Comparer(f, "annuaire/annuaires/reference.json", "org_id", k.OrgID, ref.Get("org_id").S(), "CT-3 A.2")
		if vide, ok := c.lire("annuaire/annuaires/vide.json"); ok {
			c.R.ComparerJSON(f, "annuaire/annuaires/vide.json", "annuaire sans entrée, administrateur admin-1", AnnuaireVide(ref), vide, "CT-3 EX-A.12 : « annuaire sans entrée, administrateur admin-1 »")
		}
	}
	if okRef {
		c.R.Comparer(f, "annuaire/annuaires/reference.json", "administrators (A.10)", "oidc "+EmetteurA10+" admin-1", strings.Join(chaines(ref.Get("administrators")), ","), "CT-3 A.10 : « … admin-1 (administrateur, sans adresse) »")
	}

	// ---- messages.json (AN-1, AN-2).
	if d, ok := c.lire("annuaire/messages.json"); ok {
		const fic = "annuaire/messages.json"
		comptes := map[string]bool{}
		for _, cas := range d.Get("cases").Arr {
			id := fic + " " + cas.Get("id").S()
			msg := cas.Get("message").S()
			if fl := cas.Get("fields"); fl != nil && !fl.IsNull() {
				ch := LireChamps(fl)
				c.R.Comparer(f, id, "texte construit depuis les champs", msg, MessageInscription(ch), "CT-3 EX-13.12")
			}
			exp := cas.Get("expected")
			ch, valide := AnalyserMessageInscription(msg)
			champs := Nul()
			if valide {
				champs = ch.JSON()
				if contient([]string{k.Comptes[1], k.Comptes[2], k.Comptes[3], k.Comptes[4]}, ch.Address) {
					comptes[ch.Address] = true
				}
			}
			c.R.Comparer(f, id, "valid", Compact(exp.Get("valid")), fmt.Sprint(valide), "CT-3 EX-13.12 : analyse stricte, « aucune variante […] n'est admise (message_invalide) »")
			c.R.ComparerJSON(f, id, "fields", exp.Get("fields"), champs, "CT-3 EX-13.12")
			c.R.Comparer(f, id, "length", Compact(exp.Get("length")), fmt.Sprint(len(msg)), "CT-3 EX-13.12 : octets ASCII du message")
			c.R.Comparer(f, id, "personal_sign_data", exp.Get("personal_sign_data").S(), Hex0x([]byte(msg)), "CT-3 EX-13.12 et 13.5 : « 0x suivi des 516 octets du texte en hexadécimal minuscule »")
			c.R.Comparer(f, id, "eip191_digest", exp.Get("eip191_digest").S(), Hex0x(CondenseEIP191([]byte(msg))), "CT-3 EX-13.12 : « préimage 0x19 ‖ \"Ethereum Signed Message:\\n\" ‖ décimal(L) ‖ message »")
			c.R.Comparer(f, id, "preimage_length", Compact(exp.Get("preimage_length")), fmt.Sprint(len(PreimageEIP191([]byte(msg)))), "CT-3 EX-13.12, EX-13.16 point 1")
		}
		for i := 1; i <= 4; i++ {
			c.R.Exiger(f, fic, fmt.Sprintf("message du compte %d", i), comptes[k.Comptes[i]], "absent", "CT-3 EX-A.13 : « les messages des comptes 1 à 4 de l'annuaire de référence »")
		}
		couvertureMessages(c, d)
	}
	if c.Spec != "" {
		ex := ChampsInscription{Origin: OrigineConsoleA10, Org: "assureur-demo", OrgID: k.OrgID, Identity: "oidc " + EmetteurA10 + " approbateur-1",
			Address: k.Comptes[1], IssuedAt: InstantBaseAnnuaire, ExpiresAt: "2026-11-10T08:10:00.000Z", Nonce: "dbcddc22164b049171cc7a6cda847ff2"}
		m := MessageInscription(ex)
		c.R.Comparer(f, "CT-3 EX-13.12 (exemple)", "longueur du texte", "516", fmt.Sprint(len(m)), "CT-3 EX-13.12 : « Le texte fait 516 octets »")
		c.R.Comparer(f, "CT-3 EX-13.12 (exemple)", "longueur de la préimage", "545", fmt.Sprint(len(PreimageEIP191([]byte(m)))), "CT-3 EX-13.12 : « sa préimage EIP-191 fait 545 octets »")
		c.R.Comparer(f, "CT-3 EX-13.12 (exemple)", "condensé EIP-191", "0xaf9b14a62489fc34643813436d932180470bbfa1cb197aea3de5fe54f871c5ef", Hex0x(CondenseEIP191([]byte(m))), "CT-3 EX-13.12")
		c.R.Comparer(f, "CT-3 EX-13.12 (exemple)", "nonce de l'exemple = nonce k = 1 de A.10", "dbcddc22164b049171cc7a6cda847ff2", nonceA10(1), "CT-3 A.10 : nonce d'inscription k")
	}

	// ---- inscriptions.json (AN-3, AN-4, AN-7).
	if d, ok := c.lire("annuaire/inscriptions.json"); ok {
		const fic = "annuaire/inscriptions.json"
		var formes struct{ sHaut, v01, v29, v37, l64, emis, expire bool }
		for _, cas := range d.Get("cases").Arr {
			id := fic + " " + cas.Get("id").S()
			e, ok := c.etatAnnuaire(d.Get("annuaire").S())
			if !ok {
				continue
			}
			for _, df := range cas.Get("challenges").Arr {
				ch := LireChamps(df.Get("fields"))
				e.Defis = append(e.Defis, &Defi{Champs: ch, Utilise: df.Get("used").Bool})
				nonces[ch.Nonce] = true
			}
			r, err := LireInstant(cas.Get("received_at").S())
			if err != nil {
				c.R.Erreur("%s : %v", id, err)
				continue
			}
			req := cas.Get("request")
			exp := cas.Get("expected")
			res := e.VerifierInscription(req, r, ModeService)
			entree, sig := "", ""
			nouvelle := false
			if res.Raison == "" {
				nouvelle = e.entreeParIdentite(req.Get("session_identity").S()) == nil
				if nouvelle {
					entree = identifiantA10(e)
					c.R.Comparer(f, id, "entry (entrée créée)", Compact(exp.Get("entry")), Compact(Chaine(entree)), "CT-3 A.10 : identifiant d'une entrée créée (apb- et le nombre d'entrées augmenté de un)")
					c.R.Exiger(f, id, "identifiant d'entrée nouveau et de la forme apb-…", reIdentifiantEntree.MatchString(entree) && e.entreeParID(entree) == nil, entree, "CT-3 EX-13.9 : « unique et jamais réattribué »")
				}
				entree, _ = e.inscrire(req, res, r, entree)
				sig = res.Signature
				reproduire(id, "signature gardée dans la preuve", req.Get("message").S(), req.Get("address").S(), sig)
			}
			raisonsInscription[res.Raison] = true
			fond := "CT-3 EX-13.15 : « dans cet ordre (la première raison qui s'applique est rendue) »"
			c.R.Comparer(f, id, "accepted", Compact(exp.Get("accepted")), fmt.Sprint(res.Raison == ""), fond)
			c.R.Comparer(f, id, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(res.Raison)), fond)
			if !nouvelle {
				c.R.Comparer(f, id, "entry", Compact(exp.Get("entry")), Compact(nulOuChaine(entree)), "CT-3 EX-13.15 (effet)")
			}
			c.R.Comparer(f, id, "signature (normalisée, EX-9.3)", Compact(exp.Get("signature")), Compact(nulOuChaine(sig)), "CT-3 EX-13.15 : « la signature normalisée »")
			// Formes exigées par EX-A.13.
			if b, err := DecoderHex(req.Get("signature").S()); err == nil {
				switch {
				case len(b) == 64:
					formes.l64 = formes.l64 || res.Raison == "signature_invalide"
				case len(b) == 65 && b[64] == 29:
					formes.v29 = formes.v29 || res.Raison == "signature_invalide"
				case len(b) == 65 && b[64] == 37:
					formes.v37 = formes.v37 || res.Raison == "signature_invalide"
				case len(b) == 65 && (b[64] == 0 || b[64] == 1):
					formes.v01 = formes.v01 || res.Raison == ""
				case len(b) == 65:
					if s, err := DecoderSignature(req.Get("signature").S()); err == nil && s.S.Cmp(secpDemiN) > 0 {
						formes.sHaut = formes.sHaut || res.Raison == ""
					}
				}
			}
			if ch, ok := AnalyserMessageInscription(req.Get("message").S()); ok {
				if ch.IssuedAt == r.String() && res.Raison == "" {
					formes.emis = true
				}
				if ch.ExpiresAt == r.String() && res.Raison == "inscription_expiree" {
					formes.expire = true
				}
			}
		}
		fond := "CT-3 EX-A.13 : inscriptions.json"
		c.R.Exiger(f, fic, "s haut accepté et gardé normalisé", formes.sHaut, "absent", fond)
		c.R.Exiger(f, fic, "v = 0 ou 1 accepté et gardé normalisé", formes.v01, "absent", fond)
		c.R.Exiger(f, fic, "v = 29 refusé (signature_invalide)", formes.v29, "absent", fond)
		c.R.Exiger(f, fic, "v = 37 refusé (signature_invalide)", formes.v37, "absent", fond)
		c.R.Exiger(f, fic, "signature de 64 octets refusée (signature_invalide)", formes.l64, "absent", fond)
		c.R.Exiger(f, fic, "réception à « Emis le » exactement : acceptée", formes.emis, "absent", fond)
		c.R.Exiger(f, fic, "réception à « Expire le » exactement : inscription_expiree", formes.expire, "absent", fond)
	}

	// ---- domaines.json (AN-5).
	if d, ok := c.lire("annuaire/domaines.json"); ok {
		const fic = "annuaire/domaines.json"
		genres := map[string]bool{}
		for _, cas := range d.Get("cases").Arr {
			id := fic + " " + cas.Get("id").S()
			genre := cas.Get("kind").S()
			genres[genre] = true
			sig, err := NormaliserSignature(cas.Get("signature").S())
			if err != nil {
				c.R.Exiger(f, id, "signature de forme admise", false, err.Error(), "CT-3 EX-9.3")
				continue
			}
			var m []byte
			if genre == "inscription_comme_vote" {
				dA, err := CondenseA(cas.Get("A"))
				if err != nil {
					c.R.Erreur("%s : %v", id, err)
					continue
				}
				m = CondenseEIP191(dA)
			} else {
				m = CondenseEIP191([]byte(cas.Get("message").S()))
			}
			rec, _ := AdresseRecouvree(m, sig)
			raison := ""
			if rec != cas.Get("claimed_address").S() {
				raison = "signature_invalide"
			}
			exp := cas.Get("expected")
			c.R.Comparer(f, id, "recovered", exp.Get("recovered").S(), rec, "CT-3 EX-13.16 point 2")
			c.R.Comparer(f, id, "reason", exp.Get("reason").S(), raison, "CT-3 EX-13.16 point 2 : signature_invalide")
			if c.Spec != "" {
				attendu := map[string]string{"inscription_comme_vote": "0xfac296ad1fc770d69ff4d1f69b67efbba7ae46f9", "vote_comme_inscription": "0x8768051a828bb4301030920c9b69759b08e64bde"}[genre]
				c.R.Comparer(f, id, "adresse recouvrée citée par EX-13.16", attendu, rec, "CT-3 EX-13.16 point 2 : « recouvre 0xfac296ad… » ; « recouvre 0x8768051a… »")
			}
			if genre == "inscription_comme_vote" && okRef {
				p := ref.Get("entries").Arr[0].Get("addresses").Arr[0].Get("proof")
				c.R.Comparer(f, id, "signature = preuve du compte 1 de l'annuaire de référence", p.Get("signature").S(), cas.Get("signature").S(), "CT-3 EX-A.13 : « la signature d'inscription d'exemple »")
			}
		}
		c.R.Exiger(f, fic, "inscription présentée comme vote", genres["inscription_comme_vote"], "absent", "CT-3 EX-A.13 : domaines.json")
		c.R.Exiger(f, fic, "vote présenté comme inscription", genres["vote_comme_inscription"], "absent", "CT-3 EX-A.13 : domaines.json")
	}

	// ---- traces (AN-6, AN-7).
	for _, fic := range c.fichiers("annuaire/traces/*.json") {
		tr, ok := c.lire(fic)
		if !ok {
			continue
		}
		e, ok := c.etatAnnuaire(tr.Get("initial").S())
		if !ok {
			continue
		}
		for n, pas := range tr.Get("steps").Arr {
			id := fmt.Sprintf("%s pas %d (%s)", fic, n+1, pas.Get("method").S())
			at, err := LireInstant(pas.Get("at").S())
			if err != nil {
				c.R.Erreur("%s : %v", id, err)
				continue
			}
			exp := pas.Get("expected")
			nonce := ""
			if ch := pas.Get("challenges").Arr; len(ch) > 0 {
				nonce = ch[0].S()
				nonces[nonce] = true
			}
			attribue := ""
			is := e.Appliquer(pas.Get("method").S(), pas.Get("request"), at, nonce, func() string {
				attribue = identifiantA10(e)
				return attribue
			}, ModeService)
			fond := "CT-3 EX-13.13, EX-13.15, EX-13.17 (ordre des vérifications et effets) ; EX-12.17"
			raisonsInscription[is.Raison] = raisonsInscription[is.Raison] || pas.Get("method").S() == "inscrire"
			if is.NouvelleEntree {
				// L'identifiant recalculé (A.10) est comparé avec la réponse ci-dessous.
				nb := 0
				for _, x := range e.entrees() {
					if x.Get("id").S() == attribue {
						nb++
					}
				}
				c.R.Exiger(f, id, "identifiant d'entrée nouveau et de la forme apb-…", reIdentifiantEntree.MatchString(attribue) && nb == 1, attribue, "CT-3 EX-13.9 : « unique et jamais réattribué »")
			}
			if is.Accepte && pas.Get("method").S() == "inscrire" {
				q := pas.Get("request")
				x := e.entreeParIdentite(q.Get("session_identity").S())
				sig := adresseDeLEntree(x, q.Get("address").S()).Get("proof").Get("signature").S()
				reproduire(fic, fmt.Sprintf("pas %d : signature gardée dans la preuve", n+1), q.Get("message").S(), q.Get("address").S(), sig)
			}
			c.R.Comparer(f, id, "accepted", Compact(exp.Get("accepted")), fmt.Sprint(is.Accepte), fond)
			c.R.Comparer(f, id, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(is.Raison)), fond)
			c.R.ComparerJSON(f, id, "response", exp.Get("response"), is.Reponse, "CT-3 12.9 ($defs/reponse_* de console-service-v0), EX-13.12, EX-13.13")
			c.R.Comparer(f, id, "revision", Compact(exp.Get("revision")), Compact(e.Doc.Get("revision")), "CT-3 EX-12.17 : « Une opération acceptée incrémente revision »")
			c.R.ComparerJSON(f, id, "entries (état résumé)", exp.Get("entries"), e.Resume(), "CT-3 EX-13.10, EX-13.17")
		}
		if tr.Get("id").S() == "annuaire-de-reference" && okRef {
			fin := Copier(e.Doc)
			for i, x := range fin.Get("entries").Arr {
				if i < len(ref.Get("entries").Arr) {
					poser(x, "display_name", Copier(ref.Get("entries").Arr[i].Get("display_name")))
				}
			}
			c.R.ComparerJSON(f, fic, "état final = annuaires/reference.json (noms affichés mis à part)", ref, fin, "CT-3 EX-A.13 et 13.4 : « l'annuaire de l'organisation des vecteurs après neuf opérations »")
		}
	}
	for _, r := range []string{"requete_invalide", "identite_invalide", "message_invalide", "nonce_inconnu", "nonce_deja_utilise", "inscription_expiree",
		"origine_differente", "organisation_differente", "identite_differente", "adresse_differente", "signature_invalide", "identite_desactivee", "adresse_deja_attribuee"} {
		c.R.Exiger(f, "annuaire/inscriptions.json, traces/", "raison d'EX-13.15 exercée : "+r, raisonsInscription[r], "absente", "CT-3 EX-A.13 : « chaque raison d'EX-13.15 au moins une fois »")
	}

	// ---- controles-vote.json (AN-8).
	if d, ok := c.lire("annuaire/controles-vote.json"); ok {
		const fic = "annuaire/controles-vote.json"
		doc, ok := c.lire("annuaire/" + d.Get("annuaire").S())
		vues := map[string]bool{}
		if ok {
			for _, cas := range d.Get("cases").Arr {
				id := fic + " " + cas.Get("id").S()
				t := cas.Get("ticket")
				permis, raison, avert := ControleVote(doc, cas.Get("session_identity").S(), cas.Get("action").S(), cas.Get("address").S(), t)
				exp := cas.Get("expected")
				fond := "CT-3 EX-13.18 : « la fonction de contrôle […] rend la première dans cet ordre »"
				c.R.Comparer(f, id, "allowed", Compact(exp.Get("allowed")), fmt.Sprint(permis), fond)
				c.R.Comparer(f, id, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(raison)), fond)
				c.R.ComparerJSON(f, id, "warnings", exp.Get("warnings"), avert, "CT-3 EX-13.18 : avertissement separation_incomplete")
				vues[raison] = true
				if permis && len(avert.Arr) > 0 {
					vues["separation_incomplete"] = true
				}
				c.R.ComparerJSON(f, id, "directory_requester_addresses = adresses de l'annuaire du demandeur",
					t.Get("directory_requester_addresses"), TableauChaines(AdressesAnnuaireDuDemandeur(doc, t.Get("launched_by").S())),
					"CT-3 EX-12.15 : « les adresses actives que l'annuaire attribue aux entrées dont requester_identities contient le launched_by du ticket, triées »")
			}
		}
		for _, r := range []string{"jeu_non_fige", "identite_inconnue", "identite_desactivee", "adresse_non_attribuee", "hors_jeu", "session_du_demandeur", "", "separation_incomplete"} {
			nom := r
			if r == "" {
				nom = "vote autorisé"
			}
			c.R.Exiger(f, fic, "cas exercé : "+nom, vues[r], "absent", "CT-3 EX-A.13 : controles-vote.json")
		}
	}

	// ---- controles-canal.json (AN-10).
	if d, ok := c.lire("annuaire/controles-canal.json"); ok {
		const fic = "annuaire/controles-canal.json"
		doc, ok := c.lire("annuaire/" + d.Get("annuaire").S())
		vues := map[string]bool{}
		defs := map[string]string{
			"tickets":   RefConsoleService + "#/$defs/requete_tickets",
			"consulter": RefConsole + "#/$defs/requete_consulter",
			"voter":     RefConsole + "#/$defs/requete_voter",
			"recuser":   RefConsoleService + "#/$defs/requete_recuser",
			"retirer":   RefConsoleService + "#/$defs/requete_retirer",
		}
		if ok {
			for _, cas := range d.Get("cases").Arr {
				id := fic + " " + cas.Get("id").S()
				m := cas.Get("method").S()
				req := cas.Get("request")
				exp := cas.Get("expected")
				raison := ControleCanal(doc, m, req, cas.Get("ticket"))
				if raison != "identite_invalide" {
					c.R.Exiger(f, id, "requête conforme au schéma de la méthode", len(c.Sch.Valider(defs[m], req)) == 0, "non conforme", "CT-3 EX-12.14, EX-12.16, EX-12.19 (corps de la requête)")
				}
				c.R.Comparer(f, id, "reason", Compact(exp.Get("reason")), Compact(nulOuChaine(raison)),
					"CT-3 EX-12.14 (ordre des refus de tickets et consulter), EX-12.16, EX-12.19 (identite_invalide d'abord ; ordre face à ticket_inconnu)")
				if m == "tickets" {
					c.R.Exiger(f, id, "ticket nul pour tickets", cas.Get("ticket").IsNull(), "non nul", "CT-3 $defs/fichier_controles_canal")
				}
				r := raison
				if r == "" {
					r = "passe"
				}
				vues[m+" "+r] = true
			}
		}
		for _, m := range []string{"tickets", "consulter", "voter", "recuser", "retirer"} {
			for _, r := range []string{"passe", "session_non_autorisee"} {
				c.R.Exiger(f, fic, "cas exercé : "+m+" "+r, vues[m+" "+r], "absent", "CT-3 EX-12.19 et A.10 : controles-canal.json")
			}
		}
		for _, m := range []string{"consulter", "voter", "retirer"} {
			c.R.Exiger(f, fic, "cas exercé : "+m+" ticket_inconnu", vues[m+" ticket_inconnu"], "absent", "CT-3 EX-A.13 : controles-canal.json, ticket inconnu")
		}
		c.R.Exiger(f, fic, "cas exercé : identite_invalide", vues["consulter identite_invalide"] || vues["retirer identite_invalide"] || vues["voter identite_invalide"] || vues["recuser identite_invalide"], "absent", "CT-3 EX-12.19 et A.10 : controles-canal.json")
	}

	// ---- exports (AN-9).
	if d, ok := c.lire("annuaire/exports/attendu.json"); ok {
		codes := map[string]bool{}
		// EX-A.13 : recopie d'administrators sans écart, liste changée sans
		// opération, liste différente de celle du rejeu (EX-13.37).
		recopieSansEcart, pointeurs := false, map[string]bool{}
		for _, cas := range d.Get("cases").Arr {
			fe := "annuaire/exports/" + cas.Get("file").S()
			doc, ok := c.lire(fe)
			if !ok {
				continue
			}
			ecarts := VerifierAnnuaireExporte(c.Sch, doc)
			if len(ecarts) == 0 {
				if ops := doc.Get("operations"); ops != nil {
					for _, op := range ops.Arr {
						if op.Get("op").S() == "changer_administrateurs" {
							recopieSansEcart = true
						}
					}
				}
			}
			for _, x := range ecarts {
				if x.Pointeur != nil && strings.HasPrefix(cas.Get("file").S(), "administrateurs-") {
					pointeurs[*x.Pointeur] = true
				}
			}
			t := Tableau()
			for _, x := range ecarts {
				codes[x.Code] = true
				p := Nul()
				if x.Pointeur != nil {
					p = Chaine(*x.Pointeur)
				}
				t.Arr = append(t.Arr, Objet("code", Chaine(x.Code), "pointer", p))
			}
			c.R.ComparerJSON(f, fe, "errors", cas.Get("errors"), t, "CT-3 EX-13.19 : « Les écarts sont rapportés comme ceux de A.4 (liste complète, triée par pointeur puis par code ; une non-conformité au schéma donne une seule erreur schema) »")
		}
		for _, code := range []string{"schema", "revision_incoherente", "operations_incoherentes", "identifiant_double", "identite_double", "adresse_double", "deux_adresses_actives", "preuve_invalide", "preuve_discordante", "auto_validation"} {
			c.R.Exiger(f, "annuaire/exports/attendu.json", "code exercé : "+code, codes[code], "absent", "CT-3 EX-A.13 : « un cas par code d'EX-13.19 »")
		}
		c.R.Exiger(f, "annuaire/exports/attendu.json", "cas exercé : recopie d'administrators sans écart", recopieSansEcart, "absent", "CT-3 EX-A.13 : « la recopie d'un nouveau réglage administrators suivie d'une opération du nouvel administrateur (sans écart) »")
		for _, ptr := range []string{"/operations/1", "/administrators"} {
			c.R.Exiger(f, "annuaire/exports/attendu.json", "cas exercé : administrateurs, "+ptr, pointeurs[ptr], "absent", "CT-3 EX-A.13 : « une liste d'administrateurs changée sans opération (/operations/1) et une liste qui diffère de celle du rejeu (/administrators) »")
		}
	}

	// ---- nonces de A.10.
	for n := range nonces {
		c.R.Exiger(f, "annuaire/", "nonce "+n+" = nonce k de A.10", indiceNonce(n, 1000) > 0, "aucun k ≤ 1000", "CT-3 A.10 : « 16 premiers octets de SHA-256(UTF-8(\"noortrace/vecteurs/ct3/inscription/nonce/<k>\")) »")
	}
}

// couvertureMessages vérifie la liste des textes refusés qu'EX-A.13 exige
// de messages.json, chacun reconnu à sa propriété.
func couvertureMessages(c *Contexte, d *Value) {
	type prop struct {
		nom string
		ok  func(string) bool
	}
	lignes := func(m string) []string { return strings.Split(m, "\n") }
	ligne := func(m string, i int) string {
		l := lignes(m)
		if i < len(l) {
			return l[i]
		}
		return ""
	}
	valeur := func(m string, i int) string {
		l := ligne(m, i)
		if j := strings.Index(l, ": "); j >= 0 {
			return l[j+2:]
		}
		return ""
	}
	props := []prop{
		{"CR LF", func(m string) bool { return strings.Contains(m, "\r\n") }},
		{"LF final", func(m string) bool { return strings.HasSuffix(m, "\n") }},
		{"onze lignes", func(m string) bool { return len(lignes(m)) == 11 && !strings.HasSuffix(m, "\n") }},
		{"première ligne changée d'un caractère", func(m string) bool {
			return ligne(m, 0) != LigneInscription1 && len(ligne(m, 0)) == len(LigneInscription1)
		}},
		{"deuxième ligne changée d'un caractère", func(m string) bool {
			return ligne(m, 1) != LigneInscription2 && len(ligne(m, 1)) == len(LigneInscription2)
		}},
		{"clé en autre casse", func(m string) bool {
			return strings.HasPrefix(strings.ToLower(ligne(m, 2)), "origine: ") && !strings.HasPrefix(ligne(m, 2), "Origine: ")
		}},
		{"espace double après « : »", func(m string) bool { return strings.Contains(m, ":  ") }},
		{"caractère accentué", func(m string) bool {
			for _, r := range m {
				if r > 0x7E {
					return true
				}
			}
			return false
		}},
		{"adresse en casse EIP-55", func(m string) bool { v := valeur(m, 6); return len(v) == 42 && v != strings.ToLower(v) }},
		{"nonce de 31 chiffres", func(m string) bool { return len(valeur(m, 9)) == 31 }},
		{"nonce de 33 chiffres", func(m string) bool { return len(valeur(m, 9)) == 33 }},
		{"instant sans millisecondes", func(m string) bool { v := valeur(m, 7); return len(v) == 20 && strings.HasSuffix(v, "Z") }},
		{"identité de quatre jetons", func(m string) bool { return len(strings.Split(valeur(m, 5), " ")) == 4 }},
	}
	for _, p := range props {
		vu := false
		for _, cas := range d.Get("cases").Arr {
			m := cas.Get("message").S()
			if _, ok := AnalyserMessageInscription(m); !ok && p.ok(m) {
				vu = true
			}
		}
		c.R.Exiger(FamAnnuaire, "annuaire/messages.json", "texte refusé : "+p.nom, vu, "absent", "CT-3 EX-A.13 : messages.json, textes refusés")
	}
}

// identifiantA10 rend l'identifiant de la prochaine entrée créée selon la
// convention des vecteurs (CT-3 A.10) : « apb- » suivi, sur 4 chiffres
// décimaux complétés de zéros, du nombre d'entrées augmenté de un.
func identifiantA10(e *EtatAnnuaire) string {
	return fmt.Sprintf("apb-%04d", len(e.entrees())+1)
}
