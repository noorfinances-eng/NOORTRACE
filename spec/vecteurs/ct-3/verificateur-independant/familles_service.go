// Familles de l'annexe A qui portent sur le service et le noyau : traces de
// tickets (A.6), remises (A.7), normalisation des signatures (A.8).

package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// signatureConnue est une signature valide relevée dans les vecteurs, avec
// l'objet A qu'elle signe et l'adresse qu'elle recouvre.
type signatureConnue struct {
	Origine   string
	A         *Value
	Signature string // forme canonique
	Adresse   string
}

// ------------------------------------------------------------- tickets

func lireServiceDeTrace(tr *Value) *Service {
	s := &Service{
		OrgID: tr.Get("org_id").S(), JournalID: tr.Get("journal_id").S(),
		PV: tr.Get("policy_version").S(), Charges: map[string]bool{},
	}
	s.Charges[s.PV] = true
	s.E, _ = EntierJSON(tr.Get("expire_after_ms"))
	js := tr.Get("approver_set")
	s.Source = js.Get("source").S()
	s.Epingle = strings.ToLower(js.Get("set").S()) // EX-8.1 : jeu épinglé par la politique
	if s.Source == "statique" {
		l := &Lecture{Statique: true}
		rq, _ := EntierJSON(js.Get("threshold").Get("required"))
		sz, _ := EntierJSON(js.Get("threshold").Get("size"))
		l.Seuil = Seuil{Required: rq, Size: sz}
		for _, m := range js.Get("members").Arr {
			l.Membres = append(l.Membres, strings.ToLower(m.Str))
		}
		sort.Strings(l.Membres)
		s.Statique = l
	}
	sep := tr.Get("separation")
	s.AutoAppr = sep.Get("self_approval").S()
	for _, id := range sep.Get("identities").Arr {
		s.Identites = append(s.Identites, Identite{LaunchedBy: id.Get("launched_by").S(), Adresses: chaines(id.Get("addresses"))})
	}
	s.MaxOuverts, _ = EntierJSON(tr.Get("service").Get("max_open_tickets"))
	s.Administrateurs = chaines(tr.Get("service").Get("administrators")) // EX-7.15, 10.3
	return s
}

// indiceEtiquette cherche k ∈ [1, max] tel que SHA-256(UTF-8(prefixe + k))
// = h.
func indiceEtiquette(prefixe, h string, max int) int {
	for k := 1; k <= max; k++ {
		s := sha256.Sum256([]byte(fmt.Sprintf("%s%d", prefixe, k)))
		if Hex0x(s[:]) == h {
			return k
		}
	}
	return 0
}

func (c *Contexte) controlerConstantesPas(fic string, n int, kind string, d *Value) {
	const f = FamTickets
	k := c.Consts
	v := fmt.Sprintf("%s pas %d", fic, n)
	switch kind {
	case "jeu_lu":
		j := d.Get("jeu")
		if j == nil || j.IsNull() {
			return
		}
		h, ok := EntierJSON(j.Get("height"))
		if ok {
			c.R.Comparer(f, v, "jeu.block_hash", j.Get("block_hash").S(), Hex0x(SHA256Etiquette(fmt.Sprintf("noortrace/vecteurs/ct3/bloc/%d", h))), "CT-3 A.2 : « Hachage du bloc h : SHA-256(UTF-8(\"noortrace/vecteurs/ct3/bloc/<h>\")) »")
		}
		c.R.Comparer(f, v, "jeu.registry", j.Get("registry").S(), k.Registre, "CT-3 A.2 : registre de test")
		c.R.Comparer(f, v, "jeu.chain_id", Compact(j.Get("chain_id")), "2124", "CT-3 A.2 : chain_id 2124")
		set := j.Get("set").S()
		c.R.Exiger(f, v, "jeu.set est le jeu de test 1 ou 2", set == k.Jeux[1] || set == k.Jeux[2], set, "CT-3 A.2 : jeu de test n")
	case "ouvrir":
		rh := d.Get("request_hash").S()
		kk := indiceEtiquette("noortrace/vecteurs/ct3/demande/", rh, 1000)
		c.R.Exiger(f, v, "request_hash = SHA-256(\"noortrace/vecteurs/ct3/demande/<k>\")", kk > 0, rh+" : aucun k ≤ 1000", "CT-3 A.2 : « Hachage d'une demande k »")
	case "acquitter", "consommer", "expiration":
		hv := d.Get("hash")
		seq, ok := EntierJSON(d.Get("seq"))
		if hv == nil || hv.IsNull() || !ok {
			return
		}
		att := Hex0x(SHA256Etiquette(fmt.Sprintf("noortrace/vecteurs/ct3/evenement/%d", seq)))
		c.R.Comparer(f, v, "hash = SHA-256(\"noortrace/vecteurs/ct3/evenement/<seq>\")", hv.Str, att, "CT-3 A.2 : « Hachage d'un événement seq : SHA-256(UTF-8(\"noortrace/vecteurs/ct3/evenement/<seq>\")) »")
	}
}

func etatsJSON(s *Service) *Value {
	o := Objet()
	for _, t := range s.Tickets {
		o.Obj = append(o.Obj, Member{Key: t.ID, Val: Chaine(t.Etat)})
	}
	return o
}

func remisesJSON(rs []*Remise) *Value {
	t := Tableau()
	for _, r := range rs {
		t.Arr = append(t.Arr, r.JSON())
	}
	return t
}

func fenetresTriees(f []*Fenetre) *Value {
	c := append([]*Fenetre(nil), f...)
	sort.SliceStable(c, func(i, j int) bool { return c[i].Ticket < c[j].Ticket })
	return fenetresJSON(c)
}

func familleTickets(c *Contexte) []signatureConnue {
	const f = FamTickets
	var connues []signatureConnue
	fond := map[string]string{
		"tickets":   "CT-3 table 7.5 (T1 à T21), minuteurs d'EX-7.7, décompte d'EX-7.27",
		"accepted":  "CT-3 EX-7.8, EX-9.10, table 12.8",
		"reason":    "CT-3 EX-7.8, EX-9.10, table 12.8",
		"response":  "CT-3 EX-7.16 et EX-12.6 (evaluer), 12.4 (ouvrir), 12.5 (acquitter), 12.6 (consommer, expiration)",
		"remises":   "CT-3 12.5, EX-7.28, EX-7.11, EX-8.8",
		"windows":   "CT-3 EX-5.4 à EX-5.6, EX-4.12, T11",
		"evaluated": "",
	}
	for _, fic := range c.fichiers("tickets/*.json") {
		tr, ok := c.lire(fic)
		if !ok {
			continue
		}
		c.R.Comparer(f, fic, "org_id", tr.Get("org_id").S(), c.Consts.OrgID, "CT-3 A.2 : organisation de toutes les familles")
		c.R.Comparer(f, fic, "journal_id", tr.Get("journal_id").S(), c.Consts.JournalID, "CT-3 A.2 : journal de toutes les familles")
		s := lireServiceDeTrace(tr)
		for n, pas := range tr.Get("steps").Arr {
			in := pas.Get("input")
			kind := in.Get("kind").S()
			d := in.Get("data")
			at, err := LireInstant(in.Get("at").S())
			if err != nil {
				c.R.Erreur("%s pas %d : %v", fic, n+1, err)
				continue
			}
			c.controlerConstantesPas(fic, n+1, kind, d)
			res := s.Traiter(kind, at, d)
			if kind == "voter" && res.Accepte {
				t := s.ticket(d.Get("ticket").S())
				v := t.Votes[len(t.Votes)-1]
				connues = append(connues, signatureConnue{Origine: fmt.Sprintf("%s pas %d", fic, n+1),
					A: ObjetA(v.Decision, s.JournalID, s.OrgID, t.RequestHash, t.ID), Signature: v.Signature, Adresse: v.Approbateur})
			}
			if kind == "evaluer" && d.Get("evaluation") != nil {
				c.R.HorsPerimetre(f, fmt.Sprintf("%s pas %d", fic, n+1), "data.evaluation", "sortie d'EVALUER fournie par la trace (A.6), sans les règles qui la produiraient")
				c.coherenceEvaluation(fmt.Sprintf("%s pas %d", fic, n+1), d)
			}
			exp := pas.Get("expected")
			v := fmt.Sprintf("%s pas %d (%s %s)", fic, n+1, kind, in.Get("at").S())
			rep := res.Reponse
			if rep == nil {
				rep = Nul()
			}
			raison := Nul()
			if res.Raison != "" {
				raison = Chaine(res.Raison)
			}
			c.R.ComparerJSON(f, v, "tickets", exp.Get("tickets"), etatsJSON(s), fond["tickets"])
			c.R.ComparerJSON(f, v, "accepted", exp.Get("accepted"), Booleen(res.Accepte), fond["accepted"])
			c.R.ComparerJSON(f, v, "reason", exp.Get("reason"), raison, fond["reason"])
			fr := fond["response"]
			if kind == "charger" {
				// A.6 : l'entrée charger d'une trace ne porte que policy_version ;
				// la réponse attendue se réduit à { policy_version } (12.2 donne
				// policy_sha256 et approval_candidates au message complet).
				fr = "CT-3 A.6 : « la réponse à charger d'une trace est { policy_version } »"
			}
			c.R.ComparerJSON(f, v, "response", exp.Get("response"), rep, fr)
			c.R.ComparerJSON(f, v, "remises", exp.Get("remises"), remisesJSON(s.pas), fond["remises"])
			c.R.ComparerJSON(f, v, "windows", exp.Get("windows"), fenetresTriees(s.Fenetres), fond["windows"])
			for _, a := range s.Avertissements {
				c.R.Note("%s : %s", v, a)
			}
			s.Avertissements = nil
		}
		// Identifiants des tickets : motif d'EX-7.1, compteur de A.6.
		for i, t := range s.Tickets {
			c.R.Comparer(f, fic, "identifiant du ticket "+fmt.Sprint(i+1), fmt.Sprintf("apr-%04d", i+1), t.ID, "CT-3 EX-A.6 : « les identifiants sont apr-0001, apr-0002, … dans l'ordre des réservations »")
		}
	}
	// EX-A.7 : chaque trace exigée est présente.
	exigees := []string{"approuve-sans-contestation", "refuse-seuil", "expire-sans-vote", "vote-remplace",
		"contestation-sans-objection", "contestation-objection-levee", "contestation-objection-maintenue",
		"contestation-refus-anterieur", "contestation-apres-echeance", "separation-auto-approbation",
		"separation-auto-permise", "seuil-inatteignable", "recusation", "jeu-change-membre-retire", "jeu-reassigne",
		"jeu-illisible", "jeu-statique", "signature-hors-jeu", "reemission-en-attente", "retrait",
		"acquittement-temporaire", "deja-decide", "reservation-abandonnee", "plafond", "fenetre-ouvrante",
		"fenetre-politique-changee", "politique-changee", "jeu-change-pendant-contestation", "recusation-refus-maintenu",
		"jeu-seuil-abaisse", "ordre-des-raisons-de-vote", "retrait-administrateur", "deja-decide-autre-demande",
		"acquittements-noyau", "expiration-noyau", "retenir-double-reemission"}
	for _, e := range exigees {
		_, err := os.Stat(filepath.Join(c.Racine, "tickets", e+".json"))
		c.R.Exiger(f, "tickets/"+e+".json", "trace présente", err == nil, "absente", "CT-3 EX-A.7")
	}
	return connues
}

// coherenceEvaluation contrôle ce que la spécification fixe d'une sortie
// d'EVALUER fournie par une trace, sans connaître les règles : contest_ms
// et opening nuls hors a_approuver (6.2 : « c et o vont au ticket créé »),
// et, pour un ticket ouvrant, la portée K = (policy_version en vigueur,
// nom de la règle, outil annoncé, launched_by, valeurs) d'EX-5.2 avec une chaîne
// policy.rule sans marque (EX-5.3 : condition VRAI, hors fenêtre).
func (c *Contexte) coherenceEvaluation(v string, d *Value) {
	const f = FamTickets
	ev := d.Get("evaluation")
	req := d.Get("request")
	dec := ev.Get("decision").S()
	if dec != "a_approuver" {
		c.R.Exiger(f, v, "evaluation : contest_ms et opening nuls hors a_approuver", ev.Get("contest_ms").IsNull() && ev.Get("opening").IsNull(), Compact(ev), "CT-3 6.2 et $defs/evaluation : « contest_ms et opening ne sont non nuls que pour a_approuver »")
		return
	}
	_, okc := EntierJSON(ev.Get("contest_ms"))
	c.R.Exiger(f, v, "evaluation : contest_ms entier pour a_approuver", okc, Compact(ev.Get("contest_ms")), "CT-3 6.2 : « c := P.default.contest_ms si C est vide, P.rules[i*].contest_ms sinon »")
	o := ev.Get("opening")
	if o == nil || o.IsNull() {
		return
	}
	sc := o.Get("scope")
	ok := sc.Get("policy_version").S() == req.Get("code").Get("policy_version").S() &&
		sc.Get("tool").S() == req.Get("tool_announced").S() &&
		sc.Get("launched_by").S() == req.Get("delegation").Get("launched_by").S() &&
		sc.Get("rule").S() == ev.Get("rule").S() && !strings.Contains(ev.Get("rule").S(), " [")
	if ok {
		for _, p := range sc.Get("values").Arr {
			if p.Kind != KindString {
				ok = false
			}
		}
	}
	c.R.Exiger(f, v, "evaluation : portée du ticket ouvrant (EX-5.2)", ok, Compact(o), "CT-3 EX-5.2 : « K = (policy_version en vigueur, r.name, d.tool_announced, d.delegation.launched_by, v_1, …, v_n) » ; EX-5.3")
}

// ------------------------------------------------------------- décisions

var verifParRaison = map[string]string{
	"remise_mal_formee": "SG-1", "ticket_inconnu": "SG-2", "request_hash_different": "SG-2",
	"ticket_deja_decide": "SG-3", "echeance_depassee": "SG-4", "signature_invalide": "SG-5",
	"approbateur_double": "SG-6", "approbateur_hors_jeu": "SG-6", "seuil_different_du_jeu": "SG-6",
	"expire_avec_signatures": "SG-6", "seuil_non_atteint": "SG-6",
	"auto_approbation": "SG-7",
}

func familleDecisions(c *Contexte) []signatureConnue {
	const f = FamDecisions
	var connues []signatureConnue
	raisons := map[string]bool{}
	var parChaine, approuvePourRefuse, sHaut, ecritureEcheance, autreJournal bool
	paires := map[string]bool{} // paires de vérifications voisines en échec (EX-A.8)
	valides := c.fichiers("decisions/valides/*.json")
	invalides := c.fichiers("decisions/invalides/*.json")
	for _, fic := range append(valides, invalides...) {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		ctx, err := LireContexteNoyau(cas.Get("context"))
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		rem := cas.Get("remise")
		res, raison := VerifierRemise(c.Sch, ctx, rem)
		exp := cas.Get("expected")
		c.R.Comparer(f, fic, "expected.result", exp.Get("result").S(), res, "CT-3 EX-9.11 (SG-1 à SG-7, dans l'ordre) ; CT-2 EX-7.5")
		c.R.Comparer(f, fic, "expected.reason", Compact(exp.Get("reason")), Compact(chaineOuNulle(raison)), "CT-3 EX-9.11 : « la raison de la première vérification en échec » ; table de 9.4")
		chk := Nul()
		if raison != "" {
			chk = Chaine(verifParRaison[raison])
		}
		c.R.Comparer(f, fic, "check", Compact(cas.Get("check")), Compact(chk), "CT-3 A.7 : « check est la vérification SG- visée (null pour un cas valide) »")
		raisons[raison] = true
		if res == "refuse" {
			echecs := EchecsRemise(c.Sch, ctx, rem)
			for i := 0; i+1 < len(VerificationsSG); i++ {
				a, b := VerificationsSG[i].ID, VerificationsSG[i+1].ID
				if echecs[a] != "" && echecs[b] != "" && verifParRaison[raison] == a {
					paires[a+"/"+b] = true
				}
			}
		}
		ap := rem.Get("approval")
		if ap == nil || ap.Kind != KindObject {
			continue
		}
		rh, tk, dec := ap.Get("request_hash").S(), ap.Get("ticket").S(), ap.Get("decision").S()
		for i, sig := range chaines(ap.Get("signatures")) {
			appr := chaines(ap.Get("approvers"))
			if i >= len(appr) {
				break
			}
			s, err := DecoderSignature(sig)
			if err != nil {
				continue
			}
			a := ObjetA(dec, ctx.JournalID, ctx.OrgID, rh, tk)
			if res == "scelle" {
				connues = append(connues, signatureConnue{Origine: fic, A: a, Signature: sig, Adresse: appr[i]})
			}
			if raison != "signature_invalide" {
				continue
			}
			// EX-A.8 : formes particulières de signature invalide.
			if !s.Canonique() && s.S.Cmp(secpDemiN) > 0 {
				if adr, err := AdresseVote(a, s); err == nil && adr == appr[i] {
					sHaut = true
				}
			}
			if d, err := CondenseA(a); err == nil {
				if adr, err := AdresseRecouvree(CondenseEIP191([]byte(Hex0x(d))), s); err == nil && adr == appr[i] {
					parChaine = true
				}
			}
			if dec == "refuse" {
				if adr, err := AdresseVote(ObjetA("approuve", ctx.JournalID, ctx.OrgID, rh, tk), s); err == nil && adr == appr[i] {
					approuvePourRefuse = true
				}
			}
			for _, j := range []string{"journal-sinistres", "journal-principal", "journal-demo", "journal-approbations-2", "autre-journal"} {
				jid := Hex0x(Keccak256([]byte(j)))
				if jid == ctx.JournalID {
					continue
				}
				if adr, err := AdresseVote(ObjetA(dec, jid, ctx.OrgID, rh, tk), s); err == nil && adr == appr[i] {
					autreJournal = true
				}
			}
		}
		if raison == "echeance_depassee" {
			for _, r := range ctx.Retenues {
				if r.Hash == rh && ctx.EcritureA == r.Ts+Instant(ctx.ExpireAfterMs) {
					ecritureEcheance = true
				}
			}
		}
		if strings.HasSuffix(fic, "ct1-apr-2201.json") {
			c.verifierCasCT1(fic, cas)
		}
	}
	fond := "CT-3 EX-A.8"
	for _, r := range []string{"remise_mal_formee", "ticket_inconnu", "request_hash_different", "ticket_deja_decide", "echeance_depassee", "signature_invalide", "approbateur_hors_jeu", "approbateur_double", "seuil_different_du_jeu", "expire_avec_signatures", "seuil_non_atteint", "auto_approbation"} {
		c.R.Exiger(f, "decisions/invalides", "au moins un cas de raison "+r, raisons[r], "aucun", fond)
	}
	for i := 0; i+1 < len(VerificationsSG); i++ {
		a, b := VerificationsSG[i].ID, VerificationsSG[i+1].ID
		c.R.Exiger(f, "decisions/invalides", "un cas où "+a+" et "+b+" échouent, refusé par "+a+" (ordre d'EX-9.11)", paires[a+"/"+b], "aucun",
			fond+" : « un cas pour chaque paire de vérifications voisines en échec (ordre-sg1-sg2 à ordre-sg6-sg7) »")
	}
	c.R.Exiger(f, "decisions/invalides", "signature produite sur la chaîne « 0x… » de D_A (EX-9.7)", parChaine, "aucune", fond)
	c.R.Exiger(f, "decisions/invalides", "signature approuve présentée dans une remise refuse", approuvePourRefuse, "aucune", fond)
	c.R.Exiger(f, "decisions/invalides", "signature à s haut", sHaut, "aucune", fond)
	c.R.Exiger(f, "decisions/invalides", "write_at égal à l'échéance (echeance_depassee)", ecritureEcheance, "aucune", fond)
	if autreJournal {
		c.R.Exiger(f, "decisions/invalides", "signature d'un autre journal", true, "", fond)
	} else {
		c.R.HorsPerimetre(f, "decisions/invalides", "signature d'un autre journal", "journal de la signature non retrouvé parmi les journaux nommés par CT-1 et CT-3 ; le refus signature_invalide est, lui, recalculé")
	}
	return connues
}

func chaineOuNulle(s string) *Value {
	if s == "" {
		return Nul()
	}
	return Chaine(s)
}

// verifierCasCT1 confronte le cas repris de CT-1 (EX-A.8) à l'événement
// seq 6 de spec/vecteurs/ct-1/journal-valide/evenements.json et à
// l'exemple de remise de CT-3 §12.5.
func (c *Contexte) verifierCasCT1(fic string, cas *Value) {
	const f = FamDecisions
	rem := cas.Get("remise")
	at := cas.Get("context").Get("write_at").S()
	ap := Copier(rem.Get("approval"))
	reason := ap.Obj[len(ap.Obj)-1]
	ap.Obj = append(ap.Obj[:len(ap.Obj)-1], Member{Key: "at", Val: Chaine(at)}, reason)
	src, err := os.ReadFile(filepath.Join(c.Racine, "..", "ct-1", "journal-valide", "evenements.json"))
	if err != nil {
		c.R.HorsPerimetre(f, fic, "approval + at = CT-1 journal-valide seq 6", "vecteurs CT-1 introuvables à côté de ct-3")
	} else if evs, err := ParseJSON(src); err == nil {
		var ev *Value
		for _, e := range evs.Arr {
			if s, ok := EntierJSON(e.Get("seq")); ok && s == 6 {
				ev = e
			}
		}
		if ev == nil {
			c.R.Erreur("CT-1 journal-valide : seq 6 absent")
		} else {
			c.R.ComparerJSON(f, fic, "approval + at = CT-1 journal-valide seq 6", ev.Get("approval"), ap, "CT-3 EX-A.8 : « dont approval augmenté de at doit être égal, clé pour clé, à celui de spec/vecteurs/ct-1/journal-valide/evenements.json, seq 6 »")
			c.R.Comparer(f, fic, "org_id = CT-1 seq 6", ev.Get("org_id").S(), cas.Get("context").Get("org_id").S(), "CT-3 A.2 (cas repris de CT-1)")
			c.R.Comparer(f, fic, "journal_id = CT-1 seq 6", ev.Get("journal_id").S(), cas.Get("context").Get("journal_id").S(), "CT-3 A.2 (cas repris de CT-1)")
		}
	}
	if c.Spec != "" {
		if ex, err := blocJSON(c.Spec, "<!-- schema: ticket/remise -->"); err == nil {
			c.R.ComparerJSON(f, fic, "remise égale à l'exemple de CT-3 §12.5", ex, rem, "CT-3 12.5 : « C'est la décision du ticket apr-2201 des vecteurs de CT-1 […] (cas decisions/valides/ de l'annexe A.7) »")
		}
		c.R.Comparer(f, fic, "approval.at (§12.5)", "2026-11-05T09:31:47.250Z", at, "CT-3 12.5 : « ajouter at (2026-11-05T09:31:47.250Z) à approval »")
	}
}

// ------------------------------------------------------------ signatures

func familleSignatures(c *Contexte, connues []signatureConnue) {
	const f = FamSignatures
	d, ok := c.lire("signatures/normalisation.json")
	if !ok {
		return
	}
	index := map[string]signatureConnue{}
	for _, k := range connues {
		index[k.Signature] = k
	}
	m0 := CondenseEIP191(SHA256Etiquette("noortrace/vecteurs/ct3/verificateur/message-de-controle"))
	formes := map[string]bool{}
	for _, cas := range d.Get("cases").Arr {
		id := "signatures/normalisation.json " + cas.Get("id").S()
		in := cas.Get("signature").S()
		n, err := NormaliserSignature(in)
		obt, raison := Nul(), Nul()
		if err != nil {
			raison = Chaine("signature_invalide")
		} else {
			obt = Chaine(n.Encoder())
		}
		c.R.ComparerJSON(f, id, "expected", cas.Get("expected"), obt, "CT-3 EX-9.3 (normalisation sans la clé)")
		c.R.ComparerJSON(f, id, "reason", cas.Get("reason"), raison, "CT-3 EX-9.3 : « Toute autre valeur de v est refusée (signature_invalide) »")
		b, _ := DecoderHex(in)
		switch {
		case len(b) != 65:
			formes[fmt.Sprintf("longueur %d", len(b))] = true
		default:
			s := new(big.Int).SetBytes(b[32:64])
			haut := s.Cmp(secpDemiN) > 0
			v := int(b[64])
			switch {
			case haut && (v == 27 || v == 28):
				formes[fmt.Sprintf("s haut v=%d", v)] = true
			case !haut && (v == 27 || v == 28):
				formes["canonique"] = true
			default:
				formes[fmt.Sprintf("v=%d", v)] = true
			}
		}
		if err != nil {
			continue
		}
		// « Chaque forme normalisée recouvre la même adresse que la forme
		// d'entrée » (A.8) ; sur le D_A de la remise ou du vote où la forme
		// canonique figure, sinon sur un message de contrôle.
		brute, _ := DecoderSignature(in)
		if k, ok := index[n.Encoder()]; ok {
			da, _ := CondenseA(k.A)
			m := CondenseEIP191(da)
			a1, e1 := AdresseRecouvree(m, brute)
			a2, e2 := AdresseRecouvree(m, n)
			c.R.Exiger(f, id, "entrée et forme normalisée recouvrent l'approbateur ("+k.Origine+")", e1 == nil && e2 == nil && a1 == k.Adresse && a2 == k.Adresse, a1+" / "+a2+" / "+k.Adresse, "CT-3 A.8, EX-9.3")
		} else {
			a1, e1 := AdresseRecouvree(m0, brute)
			a2, e2 := AdresseRecouvree(m0, n)
			c.R.Exiger(f, id, "entrée et forme normalisée recouvrent la même adresse", e1 == nil && e2 == nil && a1 == a2, a1+" / "+a2, "CT-3 A.8, EX-9.3")
		}
	}
	for _, fo := range []string{"canonique", "s haut v=27", "s haut v=28", "v=0", "v=1", "v=29", "longueur 64"} {
		c.R.Exiger(f, "signatures/normalisation.json", "cas « "+fo+" » présent", formes[fo], "absent", "CT-3 A.8 : « Au moins : forme canonique inchangée ; s haut et v = 27 ; s haut et v = 28 ; v = 0 ; v = 1 ; v = 29 (refusée) ; longueur de 64 octets (refusée) »")
	}
	// Reproduction des signatures valides par les clés de A.2 (RFC 6979) :
	// la spécification exige de vraies signatures des comptes (A.6), pas un
	// nonce déterministe ; une signature valide non reproduite est hors
	// périmètre, jamais discordante.
	vues := map[string]bool{}
	for _, k := range connues {
		if vues[k.Signature+k.Origine] {
			continue
		}
		vues[k.Signature+k.Origine] = true
		prive := c.Consts.Prives[k.Adresse]
		if prive == nil {
			c.R.HorsPerimetre(f, k.Origine, "reproduction de la signature de "+k.Adresse, "clé privée inconnue")
			continue
		}
		sig, err := SignerA(prive, k.A)
		if err == nil && sig == k.Signature {
			c.R.Comparer(f, k.Origine, "signature de "+k.Adresse+" reproduite (RFC 6979)", k.Signature, sig, "CT-3 A.6 : « de vraies signatures EIP-191 des comptes de A.2 sur D_A (9.1) »")
		} else {
			c.R.HorsPerimetre(f, k.Origine, "reproduction de la signature de "+k.Adresse, "signature valide (recouvrée) mais non reproduite par RFC 6979")
		}
	}
}
