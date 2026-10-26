// Familles de vecteurs (CT-5 annexe A.4) : constantes, requetes, reponses,
// ots, planification, reprise, cout. Chaque valeur attendue est recalculée
// et confrontée ; une disposition non reconnue est une erreur.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VerifierVecteurs parcourt les familles sous la racine des vecteurs CT-5.
func VerifierVecteurs(racine string) *Rapport {
	rap := &Rapport{Racine: racine, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}, Details: []string{}}
	familleConstantes(rap, racine)
	familleRequetes(rap, racine)
	familleReponses(rap, racine)
	familleOts(rap, racine)
	famillePlanification(rap, racine)
	familleReprise(rap, racine)
	familleCout(rap, racine)
	familleCompletude(rap, racine)
	return rap
}

// --- completude (AN-61, EX-10.7) ------------------------------------------------------------

func familleCompletude(rap *Rapport, racine string) {
	const fam = "completude"
	doc := lireJSON(rap, filepath.Join(racine, "completude", "completude.json"))
	if doc == nil {
		return
	}
	for _, c := range casDe(rap, "completude.json", doc) {
		id := chaineOu(c, "?", "id")
		in := c.Get("input")
		var journaux []JournalPublie
		if js := in.Get("journals"); js != nil && js.Kind == KindArray {
			for _, j := range js.Arr {
				jp := JournalPublie{OrgID: chaineOu(j, "", "org_id"), JournalID: chaineOu(j, "", "journal_id")}
				if ps := j.Get("points"); ps != nil && ps.Kind == KindArray {
					for _, p := range ps.Arr {
						jp.Points = append(jp.Points, PointPublie{CheckpointHash: chaineOu(p, "", "checkpoint_hash"), CheckpointTs: chaineOu(p, "", "checkpoint_ts")})
					}
				}
				journaux = append(journaux, jp)
			}
		}
		var ancres []AncreCapturee
		if as := in.Get("anchors"); as != nil && as.Kind == KindArray {
			for _, a := range as.Arr {
				ancres = append(ancres, AncreCapturee{Fingerprint: chaineOu(a, "", "fingerprint"), DocType: chaineOu(a, "", "doc_type"), BlockNumber: entierOu(a, 0, "block_number"), LogIndex: entierOu(a, 0, "log_index"), Issuer: chaineOu(a, "", "issuer")})
			}
		}
		r, err := VerifierCompletude(journaux, ancres, chainesDe(in, "issuers"), entierOu(in, -1, "from_block"), entierOu(in, 0, "to_block"))
		if err != nil {
			rap.Erreur("completude/%s : %s", id, err.Error())
			continue
		}
		obtenu := vObj("complete", vBool(r.Complet), "orphans", vChaines(r.Orphelines), "out_of_order", vChaines(r.HorsOrdre), "attached", vInt(int64(r.Rattachees)))
		rap.Comparer(fam, id, "AN-61 : complétude au registre", canon(c.Get("expected")), canon(obtenu))
	}
}

func lireJSON(rap *Rapport, chemin string) *Value {
	b, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("%s : %s", chemin, err.Error())
		return nil
	}
	v, err := ParseJSON(b)
	if err != nil {
		rap.Erreur("%s : %s", chemin, err.Error())
		return nil
	}
	return v
}

func lireOctets(rap *Rapport, chemin string) []byte {
	b, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("%s : %s", chemin, err.Error())
		return nil
	}
	return b
}

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

func octetsHex(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil
}

// comparerObjets confronte chaque membre de l'objet attendu au membre de même
// nom de l'objet obtenu ; les clés nommées dans horsPerimetre sont énoncées
// sans être recalculées.
func comparerObjets(rap *Rapport, famille, vecteur, prefixeGrandeur string, attendu, obtenu *Value, horsPerimetre map[string]string) {
	for _, m := range attendu.Obj {
		grandeur := prefixeGrandeur + m.Key
		if note, ok := horsPerimetre[m.Key]; ok {
			rap.HorsPerimetre(famille, vecteur, grandeur, Rendu(m.Val), note)
			continue
		}
		o := obtenu.Get(m.Key)
		if o == nil {
			rap.Comparer(famille, vecteur, grandeur, Rendu(m.Val), "(absent)")
			continue
		}
		rap.ComparerValeurs(famille, vecteur, grandeur, m.Val, o)
	}
}

func casDe(rap *Rapport, fichier string, doc *Value) []*Value {
	c := doc.Get("cases")
	if c == nil || c.Kind != KindArray {
		rap.Erreur("%s : liste cases attendue", fichier)
		return nil
	}
	return c.Arr
}

// --- constantes (A.2) ------------------------------------------------------------

func familleConstantes(rap *Rapport, racine string) {
	const fam = "constantes"
	doc := lireJSON(rap, filepath.Join(racine, "constantes.json"))
	if doc == nil {
		return
	}
	ref := doc.Get("reference_journal")
	nom := chaineOu(ref, "", "name")
	orgID := chaineOu(ref, "", "org_id")
	journalID := chaineOu(ref, "", "journal_id")
	rap.Comparer(fam, "reference_journal", "org_id = keccak256(\"assureur-demo\") (CT-1 §13)", orgID, JournalIDOf("assureur-demo"))
	rap.Comparer(fam, "reference_journal", "journal_id = keccak256(name)", journalID, JournalIDOf(nom))
	if ps := ref.Get("periods"); ps != nil {
		for _, p := range ps.Arr {
			id := fmt.Sprintf("periode %d", entierOu(p, 0, "index"))
			rap.Comparer(fam, id, "anchor_fingerprint", chaineOu(p, "", "anchor_fingerprint"), EmpreinteAncre(orgID, journalID, chaineOu(p, "", "period_hash")))
			rap.Comparer(fam, id, "period_end = period_start + 3600", fmt.Sprint(entierOu(p, 0, "period_end")), fmt.Sprint(entierOu(p, 0, "period_start")+DureePeriode))
		}
	}
	var hashK2, hashP1 string
	if ks := ref.Get("checkpoints"); ks != nil {
		for _, m := range ks.Obj {
			h := chaineOu(m.Val, "", "checkpoint_hash")
			rap.Comparer(fam, "point "+m.Key, "anchor_fingerprint", chaineOu(m.Val, "", "anchor_fingerprint"), EmpreinteAncre(orgID, journalID, h))
			if m.Key == "K2" {
				hashK2 = h
			}
		}
	}
	if ps := ref.Get("periods"); ps != nil && len(ps.Arr) > 0 {
		hashP1 = chaineOu(ps.Arr[0], "", "period_hash")
	}
	vj := doc.Get("vectors_journal")
	rap.Comparer(fam, "vectors_journal", "journal_id = keccak256(name)", chaineOu(vj, "", "journal_id"), JournalIDOf(chaineOu(vj, "", "name")))
	// EX-A.2 : les periodHash du journal des vecteurs sont ceux des manifestes de spec/vecteurs/ct-1 (lus, jamais réécrits).
	cheminAttendu := filepath.Join(racine, "..", "ct-1", "manifestes", "attendu.json")
	if b, err := os.ReadFile(cheminAttendu); err != nil {
		// EX-A.2 : entrée obligatoire, comme les preuves de ct-6 ; son absence est une erreur.
		rap.Erreur("constantes : %s illisible, periodHash du journal des vecteurs non recoupés (EX-A.2)", cheminAttendu)
	} else if att, err := ParseJSON(b); err != nil {
		rap.Erreur("%s : %s", cheminAttendu, err.Error())
	} else {
		var lus []string
		journalLu := ""
		if ps := att.Get("periodes"); ps != nil && ps.Kind == KindArray {
			for _, p := range ps.Arr {
				lus = append(lus, chaineOu(p, "", "period_hash"))
				if journalLu == "" {
					journalLu = chaineOu(p, "", "period_meta", "journalId")
				}
			}
		}
		rap.Comparer(fam, "vectors_journal", "period_hashes = periodHash des manifestes de ct-1 (EX-A.2)", strings.Join(chainesDe(vj, "period_hashes"), " "), strings.Join(lus, " "))
		rap.Comparer(fam, "vectors_journal", "journal_id = journal_id des manifestes de ct-1 (EX-A.2)", chaineOu(vj, "", "journal_id"), journalLu)
	}
	rap.Comparer(fam, "doc_types", "period = keccak256(\"noortrace/periode/v0\")", chaineOu(doc, "", "doc_types", "period"), DocTypePeriode)
	rap.Comparer(fam, "doc_types", "checkpoint = keccak256(\"noortrace/point-de-controle/v0\")", chaineOu(doc, "", "doc_types", "checkpoint"), DocTypePointDeControle)
	lab := doc.Get("labels")
	rap.Comparer(fam, "labels.ct1_example_nonce", "nonce", chaineOu(lab, "", "ct1_example_nonce", "nonce"), HexNonce(NonceDepuisEtiquette(chaineOu(lab, "", "ct1_example_nonce", "label"))))
	ex := lab.Get("examples")
	if hashK2 != "" && hashP1 != "" && ex != nil {
		rap.Comparer(fam, "labels.examples", "point_k2_first_attempt_nonce", chaineOu(ex, "", "point_k2_first_attempt_nonce"), HexNonce(NonceDepuisEtiquette(EtiquetteNonceTsa("journal-principal", "point", hashK2, 1))))
		rap.Comparer(fam, "labels.examples", "period_1_first_attempt_nonce", chaineOu(ex, "", "period_1_first_attempt_nonce"), HexNonce(NonceDepuisEtiquette(EtiquetteNonceTsa("journal-principal", "periode", hashP1, 1))))
		rap.Comparer(fam, "labels.examples", "point_k2_minimal_ots_nonce", chaineOu(ex, "", "point_k2_minimal_ots_nonce"), hex0x(OctetsDepuisEtiquette("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2", 16)))
		pk := ex.Get("point_k2_pending_ots")
		nonce := OctetsDepuisEtiquette(EtiquetteNonceOts("journal-principal", "point", hashK2), 16)
		rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "nonce", chaineOu(pk, "", "nonce"), hex0x(nonce))
		k2, _ := octetsHex(hashK2)
		if e, err := EngagementOts(k2, nonce); err == nil {
			rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "commitment", chaineOu(pk, "", "commitment"), hex0x(e))
		}
		rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "alice", chaineOu(pk, "", "alice"), hex0x(OctetsDepuisEtiquette(EtiquetteCalendrier("alice", "journal-principal", "point", hashK2), 16)))
		rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "bob", chaineOu(pk, "", "bob"), hex0x(OctetsDepuisEtiquette(EtiquetteCalendrier("bob", "journal-principal", "point", hashK2), 16)))
		if b := lireOctets(rap, filepath.Join(racine, "ots", "point-k2-en-attente.ots")); b != nil {
			rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "size", fmt.Sprint(entierOu(pk, 0, "size")), fmt.Sprint(len(b)))
			rap.Comparer(fam, "labels.examples.point_k2_pending_ots", "sha256", chaineOu(pk, "", "sha256"), SHA256Hex(b))
		}
	}
	for _, p := range doc.Get("trace_providers").Arr {
		role := chaineOu(p, "", "role")
		rap.Comparer(fam, "trace_providers."+chaineOu(p, "", "id"), "role admis (4.4)", "true", fmt.Sprint(dans(role, Roles)))
	}
}

// --- requetes (EX-5.1, AN-5, AN-6) --------------------------------------------------

func nonceDe(v *Value) *big.Int {
	if v == nil {
		return nil
	}
	switch v.Kind {
	case KindString:
		n := new(big.Int)
		if strings.HasPrefix(v.Str, "0x") {
			if _, ok := n.SetString(v.Str[2:], 16); ok {
				return n
			}
			return nil
		}
		if _, ok := n.SetString(v.Str, 10); ok {
			return n
		}
	case KindNumber:
		n := new(big.Int)
		if _, ok := n.SetString(v.Num, 10); ok {
			return n
		}
	}
	return nil
}

func familleRequetes(rap *Rapport, racine string) {
	const fam = "requetes"
	dir := filepath.Join(racine, "requetes")
	doc := lireJSON(rap, filepath.Join(dir, "requetes.json"))
	if doc != nil {
		for _, c := range casDe(rap, "requetes.json", doc) {
			id := chaineOu(c, "?", "id")
			in := c.Get("input")
			ex := c.Get("expected")
			nonce := NonceDepuisEtiquette(chaineOu(in, "", "nonce_label"))
			der, err := ConstruireRequete(chaineOu(in, "", "digest"), nonce, ptrChaine(in, "policy_oid"), booleenOu(in, false, "cert_req"))
			if err != nil {
				rap.Comparer(fam, id, "construction", "requête construite", "refus : "+err.Error())
				continue
			}
			obtenu := vObj("nonce", vStr(HexNonce(nonce)), "der", vStr(hex0x(der)), "size", vInt(int64(len(der))), "sha256", vStr(SHA256Hex(der)))
			if f, ok := chaineDe(ex, "file"); ok {
				if b := lireOctets(rap, filepath.Join(dir, f)); b != nil {
					obtenu.Obj = append(obtenu.Obj, Member{Key: "file", Val: vStr(f)})
					rap.Comparer(fam, id, "octets du fichier "+f, hex0x(der), hex0x(b))
				}
			}
			comparerObjets(rap, fam, id, "", ex, obtenu, nil)
			if r, err := LireRequete(der); err != nil {
				rap.Comparer(fam, id, "relecture", "requête relue", "refus : "+err.Error())
			} else {
				rap.Comparer(fam, id, "relecture : digest, policy_oid, nonce", Rendu(vObj("digest", in.Get("digest"), "policy_oid", in.Get("policy_oid"), "nonce", vStr(HexNonce(nonce)))), Rendu(vObj("digest", vStr(r.Digest), "policy_oid", vStrOuNul(r.PolicyOID), "nonce", vStr(HexNonce(r.Nonce)))))
			}
		}
	}
	refus := lireJSON(rap, filepath.Join(dir, "refusees.json"))
	if refus != nil {
		for _, c := range casDe(rap, "refusees.json", refus) {
			id := chaineOu(c, "?", "id")
			in := c.Get("input")
			ex := c.Get("expected")
			var err error
			if d, ok := chaineDe(in, "der"); ok {
				b, _ := octetsHex(d)
				_, err = LireRequete(b)
			} else {
				_, err = ConstruireRequete(chaineOu(in, "", "digest"), nonceDe(in.Get("nonce")), ptrChaine(in, "policy_oid"), booleenOu(in, false, "cert_req"))
			}
			obtenu := vObj("refused", vBool(err != nil))
			if e, ok := err.(*ErreurAncrage); ok {
				obtenu.Obj = append(obtenu.Obj, Member{Key: "rule", Val: vStr(e.Regle)}, Member{Key: "message", Val: vStr(e.Msg)})
			} else if err != nil {
				obtenu.Obj = append(obtenu.Obj, Member{Key: "rule", Val: vNull()}, Member{Key: "message", Val: vStr(err.Error())})
			}
			comparerObjets(rap, fam, id, "", ex, obtenu, nil)
		}
	}
}

// --- reponses (EX-5.10 à EX-5.12, AN-8 à AN-11) -----------------------------------------

func familleReponses(rap *Rapport, racine string) {
	const fam = "reponses"
	dir := filepath.Join(racine, "reponses")
	doc := lireJSON(rap, filepath.Join(dir, "reponses.json"))
	if doc == nil {
		return
	}
	var politiques []string
	if !estNul(doc, "provider", "accepted_policies") {
		politiques = chainesDe(doc, "provider", "accepted_policies")
	}
	fr := Fraicheur{MaxResponseDelayS: entierOu(doc, 60, "freshness", "max_response_delay_s"), ClockToleranceS: entierOu(doc, 120, "freshness", "clock_tolerance_s")}
	retry := Reprise{InitialMs: nombreOu(doc, 5000, "retry", "initial_ms"), Factor: nombreOu(doc, 2, "retry", "factor"), MaxMs: nombreOu(doc, 300000, "retry", "max_ms"), JitterMs: entierOu(doc, 250, "retry", "jitter_ms")}
	for _, c := range casDe(rap, "reponses.json", doc) {
		id := chaineOu(c, "?", "id")
		in := c.Get("input")
		ex := c.Get("expected")
		requete := lireOctets(rap, filepath.Join(dir, chaineOu(in, "", "request")))
		if requete == nil {
			continue
		}
		rap.Comparer(fam, id, "request_sha256", chaineOu(in, "", "request_sha256"), SHA256Hex(requete))
		var reponse []byte
		if f, ok := chaineDe(in, "response"); ok {
			if reponse = lireOctets(rap, filepath.Join(dir, f)); reponse == nil {
				continue
			}
			rap.Comparer(fam, id, "response_sha256", chaineOu(in, "", "response_sha256"), SHA256Hex(reponse))
		}
		h := in.Get("http")
		http := HTTP{Status: ptrEntier(h, "status"), ContentType: ptrChaine(h, "content_type"), BodySize: ptrEntier(h, "body_size"), RetryAfterS: ptrEntier(h, "retry_after_s")}
		passes := map[string]bool{}
		for _, t := range chainesDe(in, "checks_passed") {
			passes[t] = true
		}
		tardives := entierOu(in, 0, "late_responses_before")
		res, err := EvaluerReponse(requete, reponse, http, chaineOu(in, "", "sent_at"), chaineOu(in, "", "received_at"), politiques, fr, tardives, passes)
		if err != nil {
			rap.Erreur("reponses/%s : %s", id, err.Error())
			continue
		}
		obtenu := vObj("outcome", vStr(res.Outcome), "error_code", vStrOuNul(res.ErrorCode), "class", vStrOuNul(res.Class), "critical", vBool(res.Critical), "warnings", vChaines(res.Warnings), "pki_status", vIntOuNul(res.PKIStatus), "failure_info", vStrOuNul(res.FailureInfo), "nonce_in_response", vStrOuNul(res.NonceInResponse), "imprint_matches", vBoolOuNul(res.ImprintMatches), "token_sha256", vStrOuNul(res.TokenSHA256), "token_size", vIntOuNul(res.TokenSize), "gen_time", vStrOuNul(res.GenTime), "upper_bound", vStrOuNul(res.UpperBound))
		if res.AccuracyS != nil {
			obtenu.Obj = append(obtenu.Obj, Member{Key: "accuracy_s", Val: vNum(*res.AccuracyS)})
		} else {
			obtenu.Obj = append(obtenu.Obj, Member{Key: "accuracy_s", Val: vNull()})
		}
		// jeton extrait : le fichier .der attendu porte les mêmes octets
		if f, ok := chaineDe(ex, "token"); ok {
			if b := lireOctets(rap, filepath.Join(dir, f)); b != nil && res.Token != nil && bytes.Equal(b, res.Token) {
				obtenu.Obj = append(obtenu.Obj, Member{Key: "token", Val: vStr(f)})
			} else if b != nil {
				obtenu.Obj = append(obtenu.Obj, Member{Key: "token", Val: vStr("(jeton extrait différent de " + f + ")")})
			}
		} else if res.Token == nil {
			obtenu.Obj = append(obtenu.Obj, Member{Key: "token", Val: vNull()})
		} else {
			obtenu.Obj = append(obtenu.Obj, Member{Key: "token", Val: vStr("(jeton extrait sans fichier attendu)")})
		}
		// attente de reprise d'EX-8.9 pour une première reprise, gigue nulle
		if res.Class != nil && *res.Class == "transitoire" {
			delai, raison := CalculerAttente(http.Status, http.RetryAfterS, tardives+1, false, retry, 0)
			obtenu.Obj = append(obtenu.Obj, Member{Key: "retry", Val: vObj("delay_ms", vNum(delai), "reason", vStr(raison))})
		} else {
			obtenu.Obj = append(obtenu.Obj, Member{Key: "retry", Val: vNull()})
		}
		comparerObjets(rap, fam, id, "", ex, obtenu, map[string]string{"openssl_verify": "verdict d'OpenSSL (openssl ts -verify), confronté par confrontation/"})
	}
}

// --- ots (EX-6.2 à EX-6.7, EX-8.11) ------------------------------------------------------

func branchesDe(rap *Rapport, id string, c *Value) ([][]*Branche, []string) {
	var reponses [][]*Branche
	var uris []string
	bs := c.Get("branches")
	if bs == nil {
		return nil, nil
	}
	for _, b := range bs.Arr {
		var ops []Operation
		for _, o := range chainesOps(b) {
			ops = append(ops, o)
		}
		uri := chaineOu(b, "", "uri")
		uris = append(uris, uri)
		var finale *Branche
		switch chaineOu(b, "", "attestation") {
		case "en_attente":
			finale = &Branche{Attestation: &Attestation{Genre: "en_attente", URI: uri}}
		default:
			rap.Erreur("ots/%s : attestation %q non prise en charge", id, chaineOu(b, "", "attestation"))
			return nil, nil
		}
		reponses = append(reponses, Chemin(ops, []*Branche{finale}))
	}
	return reponses, uris
}

func chainesOps(b *Value) []Operation {
	var ops []Operation
	l := b.Get("ops")
	if l == nil {
		return nil
	}
	for _, o := range l.Arr {
		arg, _ := octetsHex(chaineOu(o, "", "argument"))
		switch chaineOu(o, "", "op") {
		case "prepend":
			ops = append(ops, Operation{Op: OpPrepend, Argument: arg})
		case "append":
			ops = append(ops, Operation{Op: OpAppend, Argument: arg})
		case "sha256":
			ops = append(ops, Operation{Op: OpSHA256})
		}
	}
	return ops
}

func verificationsOts(octets []byte, digest string) *Value {
	o := vObj()
	p, err := LireOts(octets)
	if err != nil {
		o.Obj = append(o.Obj, Member{Key: "O-1", Val: vStr("echoue")})
		return o
	}
	o.Obj = append(o.Obj, Member{Key: "O-1", Val: vStr("reussi")})
	if hex0x(p.Empreinte) == digest {
		o.Obj = append(o.Obj, Member{Key: "O-2", Val: vStr("reussi")})
	} else {
		o.Obj = append(o.Obj, Member{Key: "O-2", Val: vStr("echoue")})
	}
	defaut, attestations, _ := Executer(p)
	if defaut == "" {
		o.Obj = append(o.Obj, Member{Key: "O-3", Val: vStr("reussi")})
	} else {
		o.Obj = append(o.Obj, Member{Key: "O-3", Val: vStr("echoue")})
	}
	bitcoin := false
	for _, a := range attestations {
		if a.Genre == "bitcoin" {
			bitcoin = true
		}
	}
	if bitcoin {
		o.Obj = append(o.Obj, Member{Key: "O-7", Val: vStr("reussi")}, Member{Key: "O-7_reason", Val: vNull()})
	} else {
		o.Obj = append(o.Obj, Member{Key: "O-7", Val: vStr("non_execute")}, Member{Key: "O-7_reason", Val: vStr("partie_absente")})
	}
	return o
}

func familleOts(rap *Rapport, racine string) {
	const fam = "ots"
	dir := filepath.Join(racine, "ots")
	doc := lireJSON(rap, filepath.Join(dir, "ots.json"))
	if doc != nil {
		for _, c := range casDe(rap, "ots.json", doc) {
			id := chaineOu(c, "?", "id")
			digest := chaineOu(c, "", "digest")
			empreinte, _ := octetsHex(digest)
			nonce, _ := octetsHex(chaineOu(c, "", "nonce"))
			reponses, uris := branchesDe(rap, id, c)
			if reponses == nil {
				continue
			}
			octets, err := ConstruireOts(empreinte, nonce, reponses)
			if err != nil {
				rap.Erreur("ots/%s : %s", id, err.Error())
				continue
			}
			obtenu := vObj("size", vInt(int64(len(octets))), "sha256", vStr(SHA256Hex(octets)))
			if e, err := EngagementOts(empreinte, nonce); err == nil {
				obtenu.Obj = append(obtenu.Obj, Member{Key: "commitment", Val: vStr(hex0x(e))})
			}
			fichier := lireOctets(rap, filepath.Join(dir, chaineOu(c, "", "file")))
			if fichier != nil {
				rap.Comparer(fam, id, "octets du fichier "+chaineOu(c, "", "file"), hex0x(fichier), hex0x(octets))
				if etat, err := EtatPreuve(fichier); err == nil {
					obtenu.Obj = append(obtenu.Obj, Member{Key: "state", Val: vStr(etat)})
				}
				obtenu.Obj = append(obtenu.Obj, Member{Key: "expected_checks", Val: verificationsOts(fichier, digest)})
				if p, err := LireOts(fichier); err == nil {
					_, atts, _ := Executer(p)
					var lues []string
					for _, a := range atts {
						if a.Genre == "en_attente" {
							lues = append(lues, a.URI)
						}
					}
					sort.Strings(uris)
					sort.Strings(lues)
					rap.Comparer(fam, id, "URI des attestations en attente relues", strings.Join(uris, " "), strings.Join(lues, " "))
				}
			}
			for _, m := range c.Obj {
				switch m.Key {
				case "size", "sha256", "commitment", "state":
					if o := obtenu.Get(m.Key); o != nil {
						rap.ComparerValeurs(fam, id, m.Key, m.Val, o)
					}
				case "expected_checks":
					if o := obtenu.Get(m.Key); o != nil {
						comparerObjets(rap, fam, id, "expected_checks.", m.Val, o, nil)
					}
				}
			}
		}
	}
	man := lireJSON(rap, filepath.Join(dir, "mise-a-niveau.json"))
	if man != nil {
		id := "mise-a-niveau"
		avant := lireOctets(rap, filepath.Join(dir, chaineOu(man, "", "before", "file")))
		apres := lireOctets(rap, filepath.Join(dir, chaineOu(man, "", "after", "file")))
		der, _ := octetsHex(chaineOu(man, "", "response", "der"))
		if avant == nil || apres == nil || der == nil {
			return
		}
		rap.Comparer(fam, id, "before.size", fmt.Sprint(entierOu(man, 0, "before", "size")), fmt.Sprint(len(avant)))
		rap.Comparer(fam, id, "before.sha256", chaineOu(man, "", "before", "sha256"), SHA256Hex(avant))
		rap.Comparer(fam, id, "after.size", fmt.Sprint(entierOu(man, 0, "after", "size")), fmt.Sprint(len(apres)))
		rap.Comparer(fam, id, "after.sha256", chaineOu(man, "", "after", "sha256"), SHA256Hex(apres))
		rap.Comparer(fam, id, "response.size", fmt.Sprint(entierOu(man, 0, "response", "size")), fmt.Sprint(len(der)))
		rap.Comparer(fam, id, "response.sha256", chaineOu(man, "", "response", "sha256"), SHA256Hex(der))
		etatAvant, err1 := EtatPreuve(avant)
		etatApres, err2 := EtatPreuve(apres)
		if err1 != nil || err2 != nil {
			rap.Erreur("ots/mise-a-niveau : preuve illisible")
			return
		}
		rap.Comparer(fam, id, "before.state", chaineOu(man, "", "before", "state"), etatAvant)
		rap.Comparer(fam, id, "after.state", chaineOu(man, "", "after", "state"), etatApres)
		branches, err := LireReponseCalendrier(der)
		if err != nil {
			rap.Erreur("ots/mise-a-niveau : réponse du calendrier illisible : %s", err.Error())
			return
		}
		fusion, err := FusionnerOts(avant, chaineOu(man, "", "calendar"), branches)
		if err != nil {
			rap.Erreur("ots/mise-a-niveau : fusion impossible : %s", err.Error())
			return
		}
		etatFusion, _ := EtatPreuve(fusion)
		obtenu := vObj("state_before", vStr(etatAvant), "state_after", vStr(etatFusion), "merged_sha256", vStr(SHA256Hex(fusion)), "merged_equals_after", vBool(bytes.Equal(fusion, apres)))
		comparerObjets(rap, fam, id, "expected.", man.Get("expected"), obtenu, nil)
	}
}

// --- planification (EX-8.16) -----------------------------------------------------------

func canon(v *Value) string {
	if v == nil {
		return "null"
	}
	return CanoniqueOuRendu(v)
}

func famillePlanification(rap *Rapport, racine string) {
	const fam = "planification"
	dir := filepath.Join(racine, "planification")
	entrees, err := os.ReadDir(dir)
	if err != nil {
		rap.Erreur("%s : %s", dir, err.Error())
		return
	}
	for _, e := range entrees {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		trace := lireJSON(rap, filepath.Join(dir, e.Name()))
		if trace == nil {
			continue
		}
		if tid, ok := chaineDe(trace, "id"); ok {
			rap.Comparer(fam, id, "id de la trace = nom du fichier", id, tid)
		}
		rejeu, err := RejouerTrace(trace, nil)
		if err != nil {
			rap.Erreur("planification/%s : %s", id, err.Error())
			continue
		}
		confronterTrace(rap, fam, id, trace, rejeu)
		invariants, err := VerifierInvariants(trace, rejeu)
		if err != nil {
			rap.Erreur("planification/%s : invariants : %s", id, err.Error())
			continue
		}
		rapporterInvariants(rap, fam, id, invariants)
	}
}

// rapporterInvariants confronte chaque invariant de la section 8.11 à sa
// valeur attendue (aucun écart) et détaille les écarts.
func rapporterInvariants(rap *Rapport, fam, id string, invariants []Invariant) {
	for _, inv := range invariants {
		obtenu := "aucun écart"
		if n := len(inv.Ecarts); n > 0 {
			obtenu = fmt.Sprintf("%d écart(s) : %s", n, strings.Join(inv.Ecarts, " ; "))
		}
		rap.Comparer(fam, id, inv.Regle+" : "+inv.Objet, "aucun écart", obtenu)
		for _, e := range inv.Ecarts {
			rap.Detail("%s/%s %s : %s", fam, id, inv.Regle, e)
		}
	}
}

func confronterTrace(rap *Rapport, fam, id string, trace *Value, rejeu *Rejeu) {
	attendues := trace.Get("expected")
	if attendues == nil || attendues.Kind != KindArray {
		rap.Erreur("%s/%s : expected attendu", fam, id)
		return
	}
	rap.Comparer(fam, id, "nombre d'actions", fmt.Sprint(len(attendues.Arr)), fmt.Sprint(len(rejeu.Actions)))
	n := len(attendues.Arr)
	if len(rejeu.Actions) > n {
		n = len(rejeu.Actions)
	}
	ecarts := 0
	for i := 0; i < n; i++ {
		var a, b *Value
		if i < len(attendues.Arr) {
			a = attendues.Arr[i]
		}
		if i < len(rejeu.Actions) {
			b = rejeu.Actions[i]
		}
		if !rap.Comparer(fam, id, fmt.Sprintf("action[%d]", i), canon(a), canon(b)) {
			ecarts++
			if ecarts >= 5 {
				rap.Note("%s/%s : confrontation des actions arrêtée après cinq écarts", fam, id)
				break
			}
		}
		// request_sha256 et request_size : requête reconstruite depuis le détail attendu (EX-A.6)
		if a != nil && chaineOu(a, "", "action") == "envoyer_rfc3161" {
			d := a.Get("detail")
			nonce := nonceDe(d.Get("nonce"))
			if der, err := ConstruireRequete(chaineOu(d, "", "digest"), nonce, ptrChaine(d, "policy_oid"), true); err == nil {
				rap.Comparer(fam, id, fmt.Sprintf("action[%d].request_sha256 et request_size (requête reconstruite)", i), Rendu(vObj("request_sha256", d.Get("request_sha256"), "request_size", d.Get("request_size"))), Rendu(vObj("request_sha256", vStr(SHA256Hex(der)), "request_size", vInt(int64(len(der))))))
			} else {
				rap.Comparer(fam, id, fmt.Sprintf("action[%d].request_sha256 (requête reconstruite)", i), chaineOu(d, "", "request_sha256"), "refus : "+err.Error())
			}
		}
	}
	queue := trace.Get("queue_after")
	if queue == nil || queue.Kind != KindArray {
		rap.Erreur("%s/%s : queue_after attendu", fam, id)
		return
	}
	rap.Comparer(fam, id, "nombre de demandes de queue_after", fmt.Sprint(len(queue.Arr)), fmt.Sprint(len(rejeu.File)))
	m := len(queue.Arr)
	if len(rejeu.File) > m {
		m = len(rejeu.File)
	}
	for i := 0; i < m; i++ {
		var a, b *Value
		if i < len(queue.Arr) {
			a = queue.Arr[i]
		}
		if i < len(rejeu.File) {
			b = rejeu.File[i].Valeur()
		}
		rap.Comparer(fam, id, fmt.Sprintf("queue_after[%d]", i), canon(a), canon(b))
	}
}

// --- reprise (EX-8.12, AN-33) -------------------------------------------------------------

func familleReprise(rap *Rapport, racine string) {
	const fam = "reprise"
	dir := filepath.Join(racine, "reprise")
	entrees, err := os.ReadDir(dir)
	if err != nil {
		rap.Erreur("%s : %s", dir, err.Error())
		return
	}
	for _, e := range entrees {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".avant.ndjson") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".avant.ndjson")
		avant := lireOctets(rap, filepath.Join(dir, e.Name()))
		apres := lireOctets(rap, filepath.Join(dir, id+".apres.ndjson"))
		trace := lireJSON(rap, filepath.Join(racine, "planification", id+".json"))
		if avant == nil || apres == nil || trace == nil {
			continue
		}
		fichier := LireFile(string(avant))
		rap.Comparer(fam, id, "file avant : lignes toutes lisibles", "0 erreur(s), tronquée : false", fmt.Sprintf("%d erreur(s), tronquée : %v", len(fichier.Erreurs), fichier.Tronquee))
		// Fichiers de file d'époques successives (EX-8.5, EX-8.12) : relus dans l'ordre des
		// époques, la dernière ligne d'un id fait foi à travers eux ; leur relecture est la file avant.
		var epoques []string
		for n := 1; ; n++ {
			nom := fmt.Sprintf("%s.epoque-%d.ndjson", id, n)
			if _, err := os.Stat(filepath.Join(dir, nom)); err != nil {
				break
			}
			epoques = append(epoques, nom)
		}
		if len(epoques) > 0 {
			parID := map[string]*Demande{}
			var ordre []string
			for _, nom := range epoques {
				b := lireOctets(rap, filepath.Join(dir, nom))
				if b == nil {
					continue
				}
				f := LireFile(string(b))
				rap.Comparer(fam, id, nom+" : lignes toutes lisibles", "0 erreur(s), tronquée : false", fmt.Sprintf("%d erreur(s), tronquée : %v", len(f.Erreurs), f.Tronquee))
				for _, d := range f.Demandes {
					if _, ok := parID[d.ID]; !ok {
						ordre = append(ordre, d.ID)
					}
					parID[d.ID] = d
				}
			}
			lignesAvant := lignesDe(string(avant))
			rap.Comparer(fam, id, "relecture des fichiers d'époques : nombre de demandes = file avant", fmt.Sprint(len(lignesAvant)), fmt.Sprint(len(ordre)))
			for i := 0; i < len(ordre) && i < len(lignesAvant); i++ {
				rap.Comparer(fam, id, fmt.Sprintf("relecture des époques [%d] = avant[%d]", i, i), lignesAvant[i], LigneFile(parID[ordre[i]]))
			}
		}
		qb := trace.Get("queue_before")
		lignesAvant := lignesDe(string(avant))
		if qb != nil && qb.Kind == KindArray {
			rap.Comparer(fam, id, "file avant : nombre de lignes = queue_before", fmt.Sprint(len(qb.Arr)), fmt.Sprint(len(lignesAvant)))
			for i := 0; i < len(qb.Arr) && i < len(lignesAvant); i++ {
				rap.Comparer(fam, id, fmt.Sprintf("avant[%d] = JCS(queue_before[%d])", i, i), canon(qb.Arr[i]), lignesAvant[i])
			}
		}
		rejeu, err := RejouerTrace(trace, fichier.Demandes)
		if err != nil {
			rap.Erreur("reprise/%s : %s", id, err.Error())
			continue
		}
		lignesApres := lignesDe(string(apres))
		rap.Comparer(fam, id, "file après : nombre de lignes = file finale rejouée depuis la file avant", fmt.Sprint(len(lignesApres)), fmt.Sprint(len(rejeu.File)))
		for i := 0; i < len(lignesApres) || i < len(rejeu.File); i++ {
			a, b := "(absente)", "(absente)"
			if i < len(lignesApres) {
				a = lignesApres[i]
			}
			if i < len(rejeu.File) {
				b = LigneFile(rejeu.File[i])
			}
			rap.Comparer(fam, id, fmt.Sprintf("apres[%d]", i), a, b)
		}
		ids := map[string]int{}
		doubles := 0
		for _, l := range lignesApres {
			if v, err := ParseJSON([]byte(l)); err == nil {
				k := chaineOu(v, "", "id")
				ids[k]++
				if ids[k] > 1 {
					doubles++
				}
			}
		}
		rap.Comparer(fam, id, "file après : une seule demande par id", "0 doublon(s)", fmt.Sprintf("%d doublon(s)", doubles))
		qa := trace.Get("queue_after")
		if qa != nil && qa.Kind == KindArray {
			rap.Comparer(fam, id, "file après : nombre de lignes = queue_after", fmt.Sprint(len(qa.Arr)), fmt.Sprint(len(lignesApres)))
			for i := 0; i < len(qa.Arr) && i < len(lignesApres); i++ {
				rap.Comparer(fam, id, fmt.Sprintf("apres[%d] = JCS(queue_after[%d])", i, i), canon(qa.Arr[i]), lignesApres[i])
			}
		}
	}
}

func lignesDe(texte string) []string {
	var out []string
	for _, l := range strings.Split(texte, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// --- cout (section 12) ---------------------------------------------------------------------

func familleCout(rap *Rapport, racine string) {
	const fam = "cout"
	doc := lireJSON(rap, filepath.Join(racine, "cout", "cout.json"))
	if doc == nil {
		return
	}
	for _, c := range casDe(rap, "cout.json", doc) {
		id := chaineOu(c, "?", "id")
		in := c.Get("input")
		cas := CasCout{
			Journals:                  entierOu(in, 0, "journals"),
			HoursPerYear:              entierOu(in, 0, "hours_per_year"),
			CheckpointIntervalS:       entierOu(in, 0, "checkpoint_interval_s"),
			Rfc3161CheckpointInterval: entierOu(in, 0, "rfc3161_checkpoint_interval_s"),
			ActivityRatio:             nombreOu(in, 0, "activity_ratio"),
			ProviderRole:              chaineOu(in, "", "checkpoints_provider_role"),
			CountersignIdle:           booleenOu(in, false, "countersign_idle"),
			RegistryCheckpoints:       chaineOu(in, "", "registry_checkpoints"),
			UnitPriceQualified:        nombreOu(in, 0, "unit_price_qualified"),
			UnitPriceSecondRank:       nombreOu(in, 0, "unit_price_second_rank"),
			SubscriptionFee:           nombreOu(in, 0, "subscription_fee"),
			SubscriptionQuota:         ptrNombre(in, "subscription_quota"),
			BillableRetryRatio:        nombreOu(in, 0, "billable_retry_ratio"),
		}
		r, err := Cout(cas)
		if err != nil {
			rap.Erreur("cout/%s : %s", id, err.Error())
			continue
		}
		obtenu := vObj("qualified_tokens_per_journal", vNum(r.QualifiedTokensPerJournal), "second_rank_tokens_per_journal", vNum(r.SecondRankTokensPerJournal), "registry_anchors_per_journal", vNum(r.RegistryAnchorsPerJournal), "gas_upper_bound_per_journal", vNum(r.GasUpperBoundPerJournal), "cost_per_journal", vNum(r.CostPerJournal), "cost_total", vNum(r.CostTotal))
		comparerObjets(rap, fam, id, "", c.Get("expected"), obtenu, nil)
	}
	// AN-59 : avec a = 1 (ou countersign_idle vrai, qui vaut a = 1), N_q, N_s
	// et N_a égalent N_h fois les comptages par heure d'EX-4.11 (table de 4.6),
	// recalculés ici par CompterJetons et non par la formule de coût.
	for _, c := range casDe(rap, "cout.json", doc) {
		in := c.Get("input")
		if !(nombreOu(in, 0, "activity_ratio") == 1 || booleenOu(in, false, "countersign_idle")) {
			continue
		}
		id := chaineOu(c, "?", "id")
		cfg := &Config{CheckpointIntervalS: entierOu(in, 60, "checkpoint_interval_s"), CheckpointsIntervalS: entierOu(in, 300, "rfc3161_checkpoint_interval_s"), ProviderRole: chaineOu(in, "", "checkpoints_provider_role"), RegistryCheckpoints: chaineOu(in, "", "registry_checkpoints"), OtsEnabled: true}
		cp, err := CompterJetons(cfg)
		if err != nil {
			rap.Erreur("cout/%s : %s", id, err.Error())
			continue
		}
		H := entierOu(in, 0, "hours_per_year")
		ex := c.Get("expected")
		rap.Comparer(fam, id, "AN-59 : N_q, N_s, N_a = N_h × comptages par heure d'EX-4.11 (table de 4.6, a = 1)",
			Rendu(vObj("N_q", ex.Get("qualified_tokens_per_journal"), "N_s", ex.Get("second_rank_tokens_per_journal"), "N_a", ex.Get("registry_anchors_per_journal"))),
			Rendu(vObj("N_q", vInt(H*cp.QualifiedTokens), "N_s", vInt(H*(cp.Tokens-cp.QualifiedTokens)), "N_a", vInt(H*cp.RegistryAnchorsMax))))
	}
}
