// Tests des règles de CT-5 écrites par les deux derniers compléments du
// 2026-11-16 : clé retenue par l'ancre d'une période antérieure non finale
// (EX-9.4), ancre d'un point retenue par celle d'un point antérieur de sa
// période (EX-9.4), remplacement d'une ancre de point en reprise encore à
// envoyer (EX-9.5), alerte ots_give_up dès le passage en_attente d'une
// soumission tardive (EX-8.11), et les deux invariants qu'AN-36 gagne. Un
// test par règle, sur les traces publiées qui l'exercent (ignoré quand elles
// sont absentes) ou sur leurs actions attendues altérées ici.

package main

import (
	"strings"
	"testing"
)

// actionDe rend la première action de nom, d'instant et de sorte donnés.
func actionDe(t *testing.T, actions []*Value, instant, nom, sorte, etat string) (int, *Value) {
	t.Helper()
	for i, a := range actions {
		if chaineOu(a, "", "t") != instant || chaineOu(a, "", "action") != nom || !strings.HasPrefix(chaineOu(a, "", "request_id"), sorte+":") {
			continue
		}
		if etat != "" && chaineOu(a.Get("detail"), "", "state") != etat && chaineOu(a.Get("detail"), "", "reason") != etat {
			continue
		}
		return i, a
	}
	t.Fatalf("aucune action %s de %s (%s) à %s", nom, sorte, etat, instant)
	return 0, nil
}

// inserer insère après l'action i une écriture de la file vers l'état donné.
func inserer(t *testing.T, rejeu *Rejeu, i int, instant, id, etat string) {
	t.Helper()
	v, err := ParseJSON([]byte(`{"t":"` + instant + `","action":"ecrire_file","request_id":"` + id + `","detail":{"state":"` + etat + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	l := append([]*Value{}, rejeu.Actions[:i+1]...)
	l = append(l, v)
	rejeu.Actions = append(l, rejeu.Actions[i+1:]...)
}

// EX-9.4 (complément du 2026-11-16, une ancre de période qui attend retient
// sa clé) : « La clé d'une ancre est libre quand elle n'a aucune ancre en vol
// (envoyee) et qu'aucune ancre de période d'une période antérieure de la même
// clé [...] n'est dans un état non final ; sinon l'ancre est retenue. Une
// ancre retenue attend [...] à sa création, à l'échéance de sa reprise et
// quand la clé se libère ». Trace registre-periode-retient-la-cle : l'ancre
// de K5 ne part pas à l'échec de l'ancre de la période 1, celle de K6 et
// celle de la période 2 attendent ; elles partent après son reçu.
func TestCleRetenueParLaPeriodeAnterieureEX94(t *testing.T) {
	trace := chargerTrace(t, "registre-periode-retient-la-cle")
	exigerActionsAttendues(t, trace, actionsDesAncres)
	rejouerEtConfronter(t, trace)
}

// EX-9.5 (complément du 2026-11-16, l'ancre d'un point en reprise) : « Une
// ancre de point a_reprendre après un échec signalé (EX-8.10) est encore à
// envoyer, comme une ancre a_envoyer, quand aucune de ses tentatives n'a pu
// être admise par un nœud [...]. À l'admission d'un point plus récent de la
// même période et du même journal, elle passe remplacee (replaced_by) » ;
// une ancre dont une tentative est close recu_absent ne l'est pas. Trace
// registre-points-en-reprise : l'ancre de K2 (noeud_injoignable) est
// remplacée par celle de K3 à 13:54 ; celle de K3 (recu_absent) ne l'est pas
// par celle de K4.
func TestRemplacementAncreEnRepriseEX95(t *testing.T) {
	trace := chargerTrace(t, "registre-points-en-reprise")
	attendues := trace.Get("expected").Arr
	_, k2 := actionDe(t, attendues, "2026-11-03T13:53:00.000Z", "envoyer_registre", "ancre_registre_point", "")
	_, k3 := actionDe(t, attendues, "2026-11-03T13:54:00.000Z", "ecrire_file", "ancre_registre_point", "a_envoyer")
	_, k4 := actionDe(t, attendues, "2026-11-03T14:00:00.250Z", "ecrire_file", "ancre_registre_point", "a_envoyer")
	idK2, idK3, idK4 := chaineOu(k2, "", "request_id"), chaineOu(k3, "", "request_id"), chaineOu(k4, "", "request_id")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatalf("rejeu refusé : %s", err.Error())
	}
	remplaceeK2, remplaceeK3 := false, false
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "action") != "remplacer" {
			continue
		}
		par := chaineOu(a.Get("detail"), "", "replaced_by")
		switch chaineOu(a, "", "request_id") {
		case idK2:
			remplaceeK2 = par == idK3 && chaineOu(a, "", "t") == "2026-11-03T13:54:00.000Z"
		case idK3:
			remplaceeK3 = true
		}
	}
	if !remplaceeK2 {
		t.Error("l'ancre a_reprendre de K2 (noeud_injoignable) n'est pas remplacée par celle de K3 à 13:54:00")
	}
	if remplaceeK3 {
		t.Error("l'ancre a_reprendre de K3 (recu_absent) est remplacée")
	}
	for _, d := range rejeu.File {
		if d.ID == idK2 && (d.State != "remplacee" || d.ReplacedBy == nil || *d.ReplacedBy != idK3 || d.DueAt != nil) {
			t.Errorf("ancre de K2 finale : état %s, attendu remplacee par K3, sans due_at", d.State)
		}
		if d.ID == idK4 && d.State == "remplacee" {
			t.Error("l'ancre de K4 est remplacée")
		}
	}
}

// EX-9.4 (complément du 2026-11-16, l'ordre des ancres des points d'une
// période) : « L'ancre d'un point ne part pas tant que l'ancre d'un point
// antérieur de la même période et du même journal (checkpoint_ts plus petit,
// puis l'ordre de la file) n'a ni son reçu (obtenue) ni un autre état final
// [...] : elle est retenue ». Trace registre-points-en-reprise : l'ancre de
// K4 attend (attente_nonce) à 14:00:00.250, la clé sans ancre en vol, et ne
// part qu'au reçu de celle de K3.
func TestAncreRetenueParUnPointAnterieurEX94(t *testing.T) {
	trace := chargerTrace(t, "registre-points-en-reprise")
	attendues := trace.Get("expected").Arr
	_, k4 := actionDe(t, attendues, "2026-11-03T14:00:00.250Z", "ecrire_file", "ancre_registre_point", "a_envoyer")
	idK4 := chaineOu(k4, "", "request_id")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatalf("rejeu refusé : %s", err.Error())
	}
	attente, envoi := false, ""
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "request_id") != idK4 {
			continue
		}
		if chaineOu(a, "", "action") == "programmer" && chaineOu(a.Get("detail"), "", "reason") == "attente_nonce" && chaineOu(a, "", "t") == "2026-11-03T14:00:00.250Z" {
			attente = true
		}
		if chaineOu(a, "", "action") == "envoyer_registre" && envoi == "" {
			envoi = chaineOu(a, "", "t")
		}
	}
	if !attente {
		t.Error("à 14:00:00.250, l'ancre de K4 n'attend pas (attente_nonce) celle de K3")
	}
	if envoi != "2026-11-03T14:04:02.000Z" {
		t.Errorf("ancre de K4 envoyée à %q, attendue au reçu de celle de K3 (14:04:02)", envoi)
	}
	rejouerEtConfronter(t, trace)
}

// EX-8.11 (complément du 2026-11-16, soumission aboutie au-delà de l'âge
// d'abandon) : « l'alerte ots_give_up est levée dès ce passage, une fois par
// demande depuis le dernier démarrage (après l'action stocker, avant
// l'écriture en_attente) [...] ; cette première mise à niveau reste
// programmée à now + upgrade.first_after_s, et c'est à sa réponse sans
// attestation Bitcoin que la cadence passe à une fois par jour, sans
// nouvelle alerte » (trace redemarrage-ots-abandon-soumission-tardive).
func TestAlerteAbandonSoumissionTardiveEX811(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ots-abandon-soumission-tardive")
	rejeu := exigerActionsAttendues(t, trace, func(a *Value) bool {
		return strings.HasPrefix(chaineOu(a, "", "request_id"), "ots_")
	})
	alertes := 0
	for _, a := range rejeu.Actions {
		if actionNommee("alerter")(a) && chaineOu(a.Get("detail"), "", "code") == "ots_give_up" {
			alertes++
		}
	}
	if alertes != 1 {
		t.Errorf("%d alerte(s) ots_give_up, une seule attendue", alertes)
	}
	rejouerEtConfronter(t, trace)
}

// AN-36, deuxième invariant (A.4, complément du 2026-11-16) : à chaque
// ecrire_file qui fait passer une ancre au registre à envoyee depuis un autre
// état, « aucune ancre de période de même org_id et journal_id et de
// period_start plus petit n'est dans un état non final ». Actions attendues
// de registre-periode-retient-la-cle, auxquelles est ajoutée l'écriture
// envoyee de l'ancre de K5 (période 2) à 14:01:01, l'ancre de la période 1
// étant a_reprendre.
func TestAN36CleRetenue(t *testing.T) {
	trace := chargerTrace(t, "registre-periode-retient-la-cle")
	rejeu := rejeuPublie(t, trace)
	if e := ecartsDe(t, trace, rejeu, "AN-36"); len(e) != 0 {
		t.Fatalf("AN-36 sur la trace publiée : %v", e)
	}
	_, k5 := actionDe(t, rejeu.Actions, "2026-11-03T14:01:00.000Z", "ecrire_file", "ancre_registre_point", "a_envoyer")
	i, _ := actionDe(t, rejeu.Actions, "2026-11-03T14:01:01.000Z", "programmer", "ancre_registre_periode", "backoff")
	inserer(t, rejeu, i, "2026-11-03T14:01:01.000Z", chaineOu(k5, "", "request_id"), "envoyee")
	e := ecartsDe(t, trace, rejeu, "AN-36")
	if len(e) != 1 || !strings.Contains(e[0], "période antérieure") {
		t.Fatalf("AN-36 : ancre de K5 envoyée alors que l'ancre de la période 1 est a_reprendre, écarts %v (un attendu)", e)
	}
}

// AN-36, troisième invariant (A.4, complément du 2026-11-16) : « si c'est
// l'ancre d'un point, aucune ancre d'un point antérieur de même org_id,
// journal_id et period_start (checkpoint_ts plus petit, puis l'ordre de la
// file) n'est dans un état non final ». Actions attendues de
// registre-points-en-reprise, auxquelles est ajoutée l'écriture envoyee de
// l'ancre de K4 à 14:00:00.250, l'ancre de K3 étant a_reprendre.
func TestAN36PointsAnterieurs(t *testing.T) {
	trace := chargerTrace(t, "registre-points-en-reprise")
	rejeu := rejeuPublie(t, trace)
	if e := ecartsDe(t, trace, rejeu, "AN-36"); len(e) != 0 {
		t.Fatalf("AN-36 sur la trace publiée : %v", e)
	}
	i, k4 := actionDe(t, rejeu.Actions, "2026-11-03T14:00:00.250Z", "programmer", "ancre_registre_point", "attente_nonce")
	inserer(t, rejeu, i, "2026-11-03T14:00:00.250Z", chaineOu(k4, "", "request_id"), "envoyee")
	e := ecartsDe(t, trace, rejeu, "AN-36")
	if len(e) != 1 || !strings.Contains(e[0], "point antérieur") {
		t.Fatalf("AN-36 : ancre de K4 envoyée alors que l'ancre de K3 est a_reprendre, écarts %v (un attendu)", e)
	}
}
