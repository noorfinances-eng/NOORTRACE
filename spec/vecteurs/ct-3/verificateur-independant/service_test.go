package main

import (
	"fmt"
	"testing"
)

// Scénario construit ici, sans les vecteurs : jeu statique des comptes 1 à 3,
// seuil 2, demandeur détenant le compte 3, votes signés par les clés
// dérivées du mnémonique (A.2).
func TestServiceScenarioStatique(t *testing.T) {
	k, err := CalculerConstantes()
	if err != nil {
		t.Fatal(err)
	}
	membres := []string{k.Comptes[1], k.Comptes[2], k.Comptes[3]}
	s := &Service{OrgID: k.OrgID, JournalID: k.JournalID, PV: "p1", Charges: map[string]bool{"p1": true}, E: 3600000,
		Source: "statique", Statique: &Lecture{Statique: true, Seuil: Seuil{2, 3}, Membres: membres}, AutoAppr: "interdite",
		Identites: []Identite{{LaunchedBy: "dem", Adresses: []string{k.Comptes[3]}}}, MaxOuverts: 5}
	at := func(m int) Instant {
		i, _ := LireInstant("2026-11-12T09:00:00.000Z")
		return i + Instant(m)*60000
	}
	req := `{"tool_announced":"x","tool_original":"x","server_alias":"s","arguments":{"a":1.50},"class":"ecriture","delegation":{"launched_by":"dem","on_behalf_of":null,"scope":"s","run_id":"r1"},"intent":null,"code":{"model":null,"prompt_version":null,"policy_version":"p1","recorder":"0"},"context":[]}`
	ev := `{"request":` + req + `,"evaluation":{"rule":"regle","decision":"a_approuver","contest_ms":0,"opening":null}}`
	res := s.Traiter("evaluer", at(0), valeur(t, ev))
	if !res.Accepte || res.Reponse.Get("ticket_state").S() != "nouveau" || res.Reponse.Get("ticket").S() != "apr-0001" {
		t.Fatalf("evaluer : %+v %s", res, Compact(res.Reponse))
	}
	// Même clé malgré un autre run_id et un nombre écrit autrement (JCS
	// intégral, EX-7.3).
	ev2 := `{"request":` + `{"tool_announced":"x","tool_original":"x","server_alias":"s","arguments":{"a":1.5},"class":"ecriture","delegation":{"launched_by":"dem","on_behalf_of":null,"scope":"s","run_id":"r2"},"intent":"i","code":{"model":null,"prompt_version":null,"policy_version":"p1","recorder":"0"},"context":[]}` + `,"evaluation":{"rule":"regle","decision":"a_approuver","contest_ms":0,"opening":null}}`
	if r := s.Traiter("evaluer", at(0), valeur(t, ev2)); r.Reponse.Get("ticket").S() != "apr-0001" {
		t.Fatalf("ré-émission non reconnue : %s", Compact(r.Reponse))
	}
	rh := Hex0x(SHA256Etiquette("demande"))
	res = s.Traiter("ouvrir", at(1), valeur(t, fmt.Sprintf(`{"ticket":"apr-0001","request_hash":%q,"request_seq":5,"request_ts":%q}`, rh, at(1).String())))
	if res.Reponse.Get("state").S() != "ouvert" {
		t.Fatalf("ouvrir : %s", Compact(res.Reponse))
	}
	vote := func(compte int, dec string, m int) Resultat {
		adr := k.Comptes[compte]
		sig, err := SignerA(k.Prives[adr], ObjetA(dec, k.JournalID, k.OrgID, rh, "apr-0001"))
		if err != nil {
			t.Fatal(err)
		}
		return s.Traiter("voter", at(m), valeur(t, fmt.Sprintf(`{"ticket":"apr-0001","approver":%q,"decision":%q,"signature":%q,"reason":"motif %d","session_identity":null}`, adr, dec, sig, compte)))
	}
	if r := vote(3, "approuve", 2); r.Raison != "auto_approbation" {
		t.Errorf("compte 3 : %+v", r)
	}
	if r := vote(2, "approuve", 3); !r.Accepte {
		t.Errorf("compte 2 : %+v", r)
	}
	if r := vote(2, "approuve", 4); r.Raison != "vote_identique" {
		t.Errorf("vote identique : %+v", r)
	}
	if r := vote(1, "approuve", 5); !r.Accepte || len(s.pas) != 1 {
		t.Fatalf("compte 1 : %+v, remises %d", r, len(s.pas))
	}
	rem := s.pas[0]
	if rem.ID != "apr-0001/1" || listeChaines(rem.Approbateurs) != listeChaines([]string{k.Comptes[2], k.Comptes[1]}) || rem.Motif.S() != "motif 1" || rem.Source != "jeu statique de la politique p1" {
		t.Errorf("remise : %s", Compact(rem.JSON()))
	}
	// Le noyau accepte la remise (SG-1 à SG-7).
	sch := schemasTest(t)
	ctx := &ContexteNoyau{OrgID: k.OrgID, JournalID: k.JournalID, Decides: map[string]bool{}, ExpireAfterMs: 3600000, EcritureA: at(6)}
	ctx.Retenues = append(ctx.Retenues, RetenueNoyau{Seq: 5, Ticket: "apr-0001", Hash: rh, Ts: at(1), LaunchedBy: "dem"})
	if r, raison := VerifierRemise(sch, ctx, rem.JSON()); r != "scelle" {
		t.Errorf("remise refusée : %s", raison)
	}
	// SG-7 (CT-2 EX-7.5) : le compte 1, déclaré pour le demandeur « dem »,
	// a signé ; refus sous « interdite », scellement sous « permise » ou
	// quand l'adresse est déclarée pour un autre demandeur.
	ctx.Separation = &Separation{AutoApprobation: "interdite", Identites: []Identite{{LaunchedBy: "dem", Adresses: []string{k.Comptes[1]}}}}
	if r, raison := VerifierRemise(sch, ctx, rem.JSON()); r != "refuse" || raison != "auto_approbation" {
		t.Errorf("SG-7 sous interdite : %s %s", r, raison)
	}
	ctx.Separation.AutoApprobation = "permise"
	if r, raison := VerifierRemise(sch, ctx, rem.JSON()); r != "scelle" {
		t.Errorf("SG-7 sous permise : %s", raison)
	}
	ctx.Separation = &Separation{AutoApprobation: "interdite", Identites: []Identite{{LaunchedBy: "dem ", Adresses: []string{k.Comptes[1]}}}}
	if r, raison := VerifierRemise(sch, ctx, rem.JSON()); r != "scelle" {
		t.Errorf("SG-7, launched_by différent d'un octet : %s", raison)
	}
	ctx.Separation = nil
	ctx.EcritureA = at(61) // échéance : request_ts + E (SG-4, inégalité stricte)
	if _, raison := VerifierRemise(sch, ctx, rem.JSON()); raison != "echeance_depassee" {
		t.Errorf("écriture à l'échéance : %s", raison)
	}
	// SG-4 et SG-7 en échec : SG-4 l'emporte (ordre d'EX-9.11), et
	// EchecsRemise les rend toutes deux.
	ctx.Separation = &Separation{AutoApprobation: "interdite", Identites: []Identite{{LaunchedBy: "dem", Adresses: []string{k.Comptes[1]}}}}
	if _, raison := VerifierRemise(sch, ctx, rem.JSON()); raison != "echeance_depassee" {
		t.Errorf("SG-4 avant SG-7 : %s", raison)
	}
	if e := EchecsRemise(sch, ctx, rem.JSON()); e["SG-4"] != "echeance_depassee" || e["SG-7"] != "auto_approbation" || len(e) != 2 {
		t.Errorf("échecs : %v", e)
	}
	res = s.Traiter("acquitter", at(6), valeur(t, fmt.Sprintf(`{"remise_id":"apr-0001/1","ticket":"apr-0001","result":"scelle","reason":null,"seq":6,"hash":%q,"at":%q,"decision":"approuve","held":false,"approval":%s}`, rh, at(6).String(), Compact(rem.Approval(at(6))))))
	if res.Reponse.Get("state").S() != "approuve" {
		t.Fatalf("acquitter : %s", Compact(res.Reponse))
	}
	// Une seule ré-émission reçoit approuve (EX-7.17).
	r1 := s.Traiter("evaluer", at(7), valeur(t, ev))
	r2 := s.Traiter("evaluer", at(7), valeur(t, ev))
	if r1.Reponse.Get("ticket_state").S() != "approuve" || r1.Reponse.Get("approval").Get("at").S() != at(6).String() || r2.Reponse.Get("ticket_state").S() != "en_attente" {
		t.Errorf("ré-émissions : %s / %s", Compact(r1.Reponse), Compact(r2.Reponse))
	}
	s.Traiter("consommer", at(8), valeur(t, fmt.Sprintf(`{"ticket":"apr-0001","seq":7,"hash":%q}`, rh)))
	if r := s.Traiter("evaluer", at(9), valeur(t, ev)); r.Reponse.Get("ticket").S() != "apr-0002" {
		t.Errorf("après consommation : %s", Compact(r.Reponse))
	}
}

// Un vote reçu à l'instant de l'échéance arrive après elle (EX-7.7).
func TestEcheanceAvantVote(t *testing.T) {
	k, _ := CalculerConstantes()
	s := &Service{OrgID: k.OrgID, JournalID: k.JournalID, PV: "p", Charges: map[string]bool{"p": true}, E: 1000,
		Source: "statique", Statique: &Lecture{Statique: true, Seuil: Seuil{1, 1}, Membres: []string{k.Comptes[1]}}, MaxOuverts: 1}
	req := `{"tool_announced":"x","tool_original":"x","server_alias":"s","arguments":{},"class":"lecture","delegation":{"launched_by":"d","on_behalf_of":null,"scope":"s","run_id":null},"intent":null,"code":{"model":null,"prompt_version":null,"policy_version":"p","recorder":"0"},"context":[]}`
	s.Traiter("evaluer", 0, valeur(t, `{"request":`+req+`,"evaluation":{"rule":"r","decision":"a_approuver","contest_ms":0,"opening":null}}`))
	rh := Hex0x(SHA256Etiquette("d"))
	s.Traiter("ouvrir", 10, valeur(t, fmt.Sprintf(`{"ticket":"apr-0001","request_hash":%q,"request_seq":1,"request_ts":%q}`, rh, Instant(10).String())))
	sig, _ := SignerA(k.Prives[k.Comptes[1]], ObjetA("approuve", k.JournalID, k.OrgID, rh, "apr-0001"))
	r := s.Traiter("voter", 1010, valeur(t, fmt.Sprintf(`{"ticket":"apr-0001","approver":%q,"decision":"approuve","signature":%q,"reason":null,"session_identity":null}`, k.Comptes[1], sig)))
	if r.Raison != "ticket_clos_aux_votes" || len(s.pas) != 1 || s.pas[0].Decision != "expire" || s.pas[0].Motif.S() != "echeance atteinte sans decision" {
		t.Errorf("%+v %v", r, s.pas)
	}
}
