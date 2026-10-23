package main

// Approbation vue du frontal MCP (CT-2 version 0.3) : résultats rendus par
// l'enregistreur (EX-4.49), réponse d'evaluer (EX-7.16), codes d'EX-4.24,
// confrontés aux exemples imprimés par la spécification (testdata/spec,
// blocs recopiés sans retouche).

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func texteSpec(t *testing.T, nom string) string {
	t.Helper()
	return strings.TrimSuffix(string(lireSpec(t, nom)), "\n")
}

// EX-4.49 : les deux objets imprimés, octet pour octet, pour la version
// 0.1.0 et un hôte de l'ère moderne ; l'ère héritée retire resultType.
func TestResultatsEX449(t *testing.T) {
	if got, want := SerialiserOrdre(RefusPolitique(true)), texteSpec(t, "ex-4-49-refus.json"); got != want {
		t.Errorf("refus par la politique :\n obtenu  %s\n attendu %s", got, want)
	}
	if got, want := SerialiserOrdre(SignalApprobation("apr-1192", "en_attente", true)), texteSpec(t, "ex-4-49-signal.json"); got != want {
		t.Errorf("signal :\n obtenu  %s\n attendu %s", got, want)
	}
	herite := SignalApprobation("apr-1192", "refuse", false)
	if herite.Has("resultType") || herite.Has("structuredContent") || chaineDe(herite.Get("content").Arr[0], "text") != "noortrace: appel soumis a approbation ; ticket=apr-1192 ; state=refuse" {
		t.Errorf("signal, ère héritée : %s", SerialiserOrdre(herite))
	}
	if got := TexteSignal("<ticket>", "<state>"); got != "noortrace: appel soumis a approbation ; ticket=<ticket> ; state=<state>" {
		t.Errorf("gabarit du texte : %s", got)
	}
}

// Annexe A pas 5 : la ligne rendue en mode erreur, 359 octets, est la ligne
// JSON-RPC du signal du ticket apr-1192, id de la requête de l'hôte.
func TestSignalAnnexeA(t *testing.T) {
	ligne := texteSpec(t, "annexe-a-signal-attente.jsonl")
	if len(ligne) != 359 {
		t.Errorf("longueur %d, l'annexe A dit 359 octets", len(ligne))
	}
	req := LireRequeteHote(lireSpec(t, "annexe-a-hote-requete.jsonl"), "ligne")
	rep := valeurSpec(t, "annexe-a-reponse-evaluer.json")
	issue, raison := IssueReponseEvaluer(rep)
	if issue != IssueNouveau || raison != "" {
		t.Fatalf("réponse de l'annexe A : %s %s", issue, raison)
	}
	v, s := versionHote(nil, &LigneTranscription{Val: req.Msg})
	if v != VersionModerne {
		t.Fatalf("ère de la requête de l'annexe A : %q (%s)", v, s)
	}
	if got := LigneResultat(req.IDTexte, ResultatAttendu(issue, rep, true)); got != ligne {
		t.Errorf("ligne rendue :\n obtenu  %s\n attendu %s", got, ligne)
	}
}

// EX-7.16 : les six combinaisons, et des réponses invalides.
func TestReponsesEvaluer(t *testing.T) {
	ap := func(dec string) string {
		return `{"decision":"` + dec + `","ticket":"apr-1","request_hash":"0x00","threshold":{"required":1,"size":1},"approvers":[],"signatures":[],"reason":null,"at":"2026-11-01T00:00:00.000Z"}`
	}
	js := `{"threshold":{"required":1,"size":1},"members":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"],"source":"jeu statique de la politique p"}`
	valides := map[string]string{
		`{"rule":null,"decision":"autorise","ticket":null,"ticket_state":null,"approval":null,"approver_set":null}`:                           IssueRelais,
		`{"rule":"r","decision":"refuse","ticket":null,"ticket_state":null,"approval":null,"approver_set":null}`:                              IssueRefus,
		`{"rule":"r","decision":"a_approuver","ticket":"apr-1","ticket_state":"nouveau","approval":null,"approver_set":` + js + `}`:           IssueNouveau,
		`{"rule":"r","decision":"a_approuver","ticket":"apr-1","ticket_state":"en_attente","approval":null,"approver_set":null}`:              IssueEnAttente,
		`{"rule":"r","decision":"autorise","ticket":"apr-1","ticket_state":"approuve","approval":` + ap("approuve") + `,"approver_set":null}`: IssueRelaisApprouv,
		`{"rule":"r","decision":"refuse","ticket":"apr-1","ticket_state":"expire","approval":` + ap("expire") + `,"approver_set":null}`:       IssueRefusTicket,
	}
	for txt, want := range valides {
		if got, raison := IssueReponseEvaluer(doit(t, txt)); got != want {
			t.Errorf("%s : %s (%s), attendu %s", txt, got, raison, want)
		}
	}
	for _, txt := range []string{
		`{"rule":"r","decision":"a_approuver","ticket":"apr-1","ticket_state":"nouveau","approval":null,"approver_set":null}`,               // approver_set manquant pour nouveau
		`{"rule":"r","decision":"a_approuver","ticket":"apr-1","ticket_state":"en_attente","approval":null,"approver_set":` + js + `}`,      // approver_set hors de nouveau
		`{"rule":"r","decision":"a_approuver","ticket":null,"ticket_state":"en_attente","approval":null,"approver_set":null}`,               // ticket nul, état non nul
		`{"rule":"r","decision":"autorise","ticket":"apr-1","ticket_state":"approuve","approval":` + ap("refuse") + `,"approver_set":null}`, // décision différente
		`{"rule":"r","decision":"autorise","ticket":"apr-1","ticket_state":"approuve","approval":null,"approver_set":null}`,                 // approval absent
		`{"rule":"r","decision":"refuse","ticket":"apr-1","ticket_state":"en_attente","approval":null,"approver_set":null}`,                 // hors table
		`{"rule":"r","decision":"autorise","ticket":null,"ticket_state":null,"approval":null}`,                                              // membre absent
		`{"rule":null,"decision":"a_approuver","ticket":"apr-1","ticket_state":"en_attente","approval":null,"approver_set":null}`,           // rule nulle pour a_approuver
	} {
		if got, raison := IssueReponseEvaluer(doit(t, txt)); got != "" || raison == "" {
			t.Errorf("%s : accepté (%s)", txt, got)
		}
	}
}

// EX-4.24 (version 0.3) : codes de la table de 4.4 et codes standard admis ;
// plages héritée et réservée, anciens codes, 100 à 599 et -31015 refusés.
func TestCodesEX424(t *testing.T) {
	for _, c := range []int64{-31010, -31011, -31012, -31013, -31014, -31016, -31017, -32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022} {
		if ok, r := CodeAdmisEX424(c); !ok {
			t.Errorf("%d refusé : %s", c, r)
		}
	}
	for _, c := range []int64{-31015, -32015, -32010, -32017, -32000, -32019, -32001, -32050, -32099, -32002, -32042, 100, 408, 599, -31018, -31009} {
		if ok, _ := CodeAdmisEX424(c); ok {
			t.Errorf("%d admis", c)
		}
	}
	if _, ok := MessagesErreurs[CodeNonAttribue]; ok {
		t.Error("-31015 a un message : il n'est pas attribué (table de 4.4)")
	}
	if len(MessagesErreurs) != 7 {
		t.Errorf("%d codes dans la table, attendu 7 (-31010 à -31017 sauf -31015)", len(MessagesErreurs))
	}
}

// Annexe A pas 5 et 12 (version 0.3) : message ouvrir (EX-7.18) et consommer
// (EX-7.20) du ticket apr-1192, recalculés depuis les événements imprimés et
// la pièce « arguments » du pas 4 ; décision 693 s après la retenue.
func TestOuvrirEtConsommerAnnexeA(t *testing.T) {
	seq2, seq4 := valeurSpec(t, "annexe-a-seq2.json"), valeurSpec(t, "annexe-a-seq4.json")
	if chaineDe(seq2, "execution", "status") != "retenue" || chaineDe(seq2, "policy", "ticket") != "apr-1192" {
		t.Fatalf("seq 2 : %s %s", chaineDe(seq2, "execution", "status"), chaineDe(seq2, "policy", "ticket"))
	}
	h := chaineDe(seq2, "hash")
	if s, _ := entierDe(seq2, "seq"); s != 2 || !strings.HasPrefix(h, "0x793a") || !strings.HasSuffix(h, "1bd6") || chaineDe(seq2, "ts") != "2026-11-03T13:41:07.218Z" {
		t.Errorf("ouvrir : request_seq %d, request_hash %s, request_ts %s", s, h, chaineDe(seq2, "ts"))
	}
	req := valeurSpec(t, "annexe-a-hote-requete.jsonl")
	p, _, err := PieceRedigeeJSON(politiqueSpec(t), "arguments", "sap.payments.create", req.Get("params").Get("arguments"))
	if err != nil {
		t.Fatal(err)
	}
	const imprime = "eyJhbW91bnQiOiI3NDAwLjAwIiwiYmVuZWZpY2lhcnlfaWJhbiI6IltSRURJR0U6aWJhbl0iLCJjbGFpbV9pZCI6IjIwMjYtNzc4MTIiLCJjdXJyZW5jeSI6IkNIRiJ9"
	if got := base64.StdEncoding.EncodeToString(p.Octets); got != imprime || len(p.Octets) != 96 {
		t.Errorf("arguments_piece : %s (%d octets)", got, len(p.Octets))
	}
	h4 := chaineDe(seq4, "hash")
	if !strings.HasPrefix(h4, "0x8e2f") || !strings.HasSuffix(h4, "5ca6") || chaineDe(seq4, "approval", "ticket") != "apr-1192" {
		t.Errorf("consommer : hash %s, ticket %s", h4, chaineDe(seq4, "approval", "ticket"))
	}
	t2, _ := time.Parse(time.RFC3339Nano, chaineDe(seq2, "ts"))
	ta, _ := time.Parse(time.RFC3339Nano, chaineDe(seq4, "approval", "at"))
	if d := ta.Sub(t2).Seconds(); int(d) != 693 {
		t.Errorf("décision %v s après la retenue, l'annexe A dit 693 s", d)
	}
}
