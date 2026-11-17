// Tests des règles de CT-5 précisées en dernier par les compléments du
// 2026-11-16 : ordre des ancres d'une clé de chaîne et ancre de la période
// après celles de ses points (EX-9.4, EX-8.4 règle 2, EX-8.12 point 6),
// alerte du refus définitif de l'ancre d'une période (EX-8.10), origine de
// l'âge d'abandon OpenTimestamps (EX-8.11), et les invariants qui s'en
// déduisent (AN-33, AN-36, AN-37). Un test par règle, sur les traces publiées
// qui l'exercent (ignoré quand elles sont absentes) ou sur une trace publiée
// altérée ici.

package main

import (
	"strings"
	"testing"
)

// actionsDesAncres retient les actions des ancres au registre.
func actionsDesAncres(a *Value) bool {
	return strings.HasPrefix(chaineOu(a, "", "request_id"), "ancre_registre_")
}

// rejeuPublie rend, sans rejouer le planificateur, les actions attendues
// d'une trace (copies) et sa file finale publiée, pour vérifier un invariant
// sur la trace elle-même.
func rejeuPublie(t *testing.T, trace *Value) *Rejeu {
	t.Helper()
	rejeu := &Rejeu{}
	for _, a := range trace.Get("expected").Arr {
		copie, err := ParseJSON([]byte(canon(a)))
		if err != nil {
			t.Fatal(err)
		}
		rejeu.Actions = append(rejeu.Actions, copie)
	}
	for _, v := range trace.Get("queue_after").Arr {
		d, err := DemandeDe(v)
		if err != nil {
			t.Fatal(err)
		}
		rejeu.File = append(rejeu.File, d)
	}
	return rejeu
}

// ecartsDe rend les écarts d'un invariant sur un rejeu.
func ecartsDe(t *testing.T, trace *Value, rejeu *Rejeu, regle string) []string {
	t.Helper()
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range invariants {
		if inv.Regle == regle {
			return inv.Ecarts
		}
	}
	t.Fatalf("%s absent des invariants", regle)
	return nil
}

// EX-9.4 (complément du 2026-11-16, ordre des ancres d'une clé) : quand la
// clé se libère, et après la passe du démarrage, part la première des ancres
// qui attendent, par period_start, puis, dans une période, ses points par
// checkpoint_ts, puis la période ; l'ordre de la file ne départage que les
// égalités. Traces registre-ordre-des-points (au reçu de K3, K4 part avant
// K5, qui la précède dans la file), redemarrage-a-envoyer-cle-libre et
// registre-indisponible-cloture (l'ancre du point de clôture avant celle de
// la période).
func TestOrdreDesAncresDuneCleEX94(t *testing.T) {
	for _, nom := range []string{"registre-ordre-des-points", "redemarrage-a-envoyer-cle-libre", "registre-indisponible-cloture"} {
		t.Run(nom, func(t *testing.T) {
			trace := chargerTrace(t, nom)
			exigerActionsAttendues(t, trace, actionNommee("envoyer_registre"))
			rejouerEtConfronter(t, trace)
		})
	}
}

// EX-9.4 (complément du 2026-11-16) : « Si cette première est une ancre de
// période qui attend encore le reçu d'une ancre de point de sa période [...],
// rien ne part de la clé » (trace registre-periode-apres-point-de-cloture :
// l'ancre de K4 en échec transitoire, la clé libre, l'ancre de la période ne
// part qu'au reçu de celle de K4).
func TestPeriodeBloqueeAuxDepartsEX94(t *testing.T) {
	trace := chargerTrace(t, "registre-periode-apres-point-de-cloture")
	exigerActionsAttendues(t, trace, actionsDesAncres)
	rejouerEtConfronter(t, trace)
}

// EX-9.4 (complément du 2026-11-16) : « à sa création ou à l'échéance de sa
// reprise, l'ancre de la période attend alors comme derrière une ancre en vol
// (attente_nonce) ». Trace redemarrage-ancres-a-reprendre, à laquelle la file
// relue ajoute l'ancre a_reprendre d'un point de la même période, due à
// 14:00:07 : à 14:00:06, la clé est libre, mais l'ancre de la période attend ;
// l'ancre du point part à 14:00:07, celle de la période à son reçu.
func TestPeriodeBloqueeAReprendreEX94(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ancres-a-reprendre")
	qb := trace.Get("queue_before")
	var periode *Value
	for _, v := range qb.Arr {
		if chaineOu(v, "", "kind") == "ancre_registre_periode" {
			periode = v
		}
	}
	if periode == nil {
		t.Fatal("aucune ancre de période dans queue_before")
	}
	point, err := ParseJSON([]byte(canon(periode)))
	if err != nil {
		t.Fatal(err)
	}
	hash := "0x" + strings.Repeat("5a", 32)
	fixer(t, point, "id", vStr("ancre_registre_point:"+hash))
	fixer(t, point, "kind", vStr("ancre_registre_point"))
	fixer(t, point, "created_at", vStr("2026-11-03T13:55:00.000Z"))
	fixer(t, point, "due_at", vStr("2026-11-03T14:00:07.000Z"))
	fixer(t, point, "subject.kind", vStr("point"))
	fixer(t, point, "subject.hash", vStr(hash))
	fixer(t, point, "subject.declared_at", vStr("2026-11-03T13:55:00.000Z"))
	fixer(t, point, "subject.tree_size", vInt(5))
	att := point.Get("attempts").Arr[0]
	fixer(t, att, "correlation_id", vStr(IdentifiantCorrelation("ancre_registre_point", hash, 1)))
	fixer(t, att, "started_at", vStr("2026-11-03T13:55:00.000Z"))
	fixer(t, att, "next_at", vStr("2026-11-03T14:00:07.000Z"))
	qb.Arr = append([]*Value{point}, qb.Arr...)
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatalf("rejeu refusé : %s", err.Error())
	}
	idPeriode := chaineOu(periode, "", "id")
	idPoint := "ancre_registre_point:" + hash
	attente, pointParti := false, false
	for _, a := range rejeu.Actions {
		id := chaineOu(a, "", "request_id")
		switch {
		case id == idPeriode && chaineOu(a, "", "action") == "programmer" && chaineOu(a.Get("detail"), "", "reason") == "attente_nonce" && chaineOu(a, "", "t") == "2026-11-03T14:00:06.000Z":
			attente = true
		case id == idPeriode && chaineOu(a, "", "action") == "envoyer_registre" && !pointParti:
			t.Errorf("ancre de la période envoyée à %s avant celle de son point", chaineOu(a, "", "t"))
		case id == idPoint && chaineOu(a, "", "action") == "envoyer_registre":
			pointParti = true
		}
	}
	if !attente {
		t.Error("à 14:00:06, l'ancre de la période n'attend pas (attente_nonce) le reçu de l'ancre de son point")
	}
	if !pointParti {
		t.Error("l'ancre du point n'est pas repartie à l'échéance de sa reprise")
	}
	if e := ecartsDe(t, trace, rejeu, "AN-36"); len(e) != 0 {
		t.Errorf("AN-36 : %v", e)
	}
}

// EX-8.10 (complément du 2026-11-16) : le refus définitif de l'ancre d'une
// période lève l'alerte prestataires_epuises critique après la ligne
// anchor_retry, une fois par ancre depuis le démarrage ; aucune gigue n'est
// consommée (trace registre-refus-ancre-periode : deux refus, une alerte,
// puis noeud_injoignable avec k = 3 et la première gigue).
func TestRefusAncrePeriodeEX810(t *testing.T) {
	trace := chargerTrace(t, "registre-refus-ancre-periode")
	rejeu := exigerActionsAttendues(t, trace, func(a *Value) bool {
		return actionsDesAncres(a) || actionNommee("alerter")(a)
	})
	alertes := 0
	for _, a := range rejeu.Actions {
		if actionNommee("alerter")(a) && chaineOu(a.Get("detail"), "", "code") == "prestataires_epuises" {
			alertes++
		}
	}
	if alertes != 1 {
		t.Errorf("%d alerte(s) prestataires_epuises, une seule attendue", alertes)
	}
	rejouerEtConfronter(t, trace)
}

// EX-8.11 (complément du 2026-11-16, origine de l'âge d'abandon) : l'âge
// d'abandon d'une preuve OpenTimestamps en attente court depuis created_at
// de la demande, au démarrage comme en marche (trace
// redemarrage-ots-abandon-origine : ots_give_up et mise à niveau quotidienne).
func TestAgeAbandonOtsEX811(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ots-abandon-origine")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return strings.HasPrefix(chaineOu(a, "", "request_id"), "ots_")
	})
	rejouerEtConfronter(t, trace)
}

// AN-33 (complément du 2026-11-16) : la reprise d'une soumission
// OpenTimestamps relue a_reprendre avec une tentative en_cours est l'une des
// quatre écritures du démarrage hors de la table (a_reprendre → a_reprendre,
// suivie de programmer immediat, EX-8.12) ; une réécriture a_reprendre sans
// cette reprise n'est pas admise (trace redemarrage-ots-a-reprendre-en-cours,
// raison de l'action programmer altérée).
func TestAN33SoumissionRelueEnCours(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ots-a-reprendre-en-cours")
	rejeu := rejouerEtConfronter(t, trace)
	if e := ecartsDe(t, trace, rejeu, "AN-33"); len(e) != 0 {
		t.Fatalf("AN-33 sur la trace publiée : %v", e)
	}
	debut := chaineOu(trace.Get("inputs").Arr[0], "", "t")
	altere := false
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "t") == debut && strings.HasPrefix(chaineOu(a, "", "request_id"), "ots_") && chaineOu(a, "", "action") == "programmer" && chaineOu(a.Get("detail"), "", "reason") == "immediat" {
			fixer(t, a, "detail.reason", vStr("backoff_altere"))
			altere = true
			break
		}
	}
	if !altere {
		t.Fatal("aucune action programmer immediat au démarrage")
	}
	if e := ecartsDe(t, trace, rejeu, "AN-33"); len(e) == 0 {
		t.Error("AN-33 : réécriture a_reprendre de la soumission sans reprise immédiate, aucun écart signalé")
	}
}

// AN-37 et A.4 (complément du 2026-11-16) : le vérificateur établit qu'une
// reponse_ots s'applique par la tentative ouverte (soumettre_ots,
// mettre_a_niveau_ots, ligne en_cours de queue_before ; fermée par la réponse
// suivante ou, pour une soumission, par le démarrage), sans lire l'action
// rejeter_reponse : sur la trace ots-preuve-absente, les actions
// rejeter_reponse effacées et une attente faussée d'une milliseconde, l'écart
// est signalé.
func TestAN37SansActionRejet(t *testing.T) {
	trace := chargerTrace(t, "ots-preuve-absente")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e := ecartsDe(t, trace, rejeu, "AN-37"); len(e) != 0 {
		t.Fatalf("AN-37 sur la trace publiée : %v", e)
	}
	fausse := false
	for i, a := range rejeu.Actions {
		if chaineOu(a, "", "action") != "rejeter_reponse" || !strings.HasPrefix(chaineOu(a, "", "request_id"), "ots_") {
			continue
		}
		fixer(t, a, "action", vStr("retiree_pour_le_test"))
		if fausse {
			continue
		}
		for _, b := range rejeu.Actions[i:] {
			if chaineOu(b, "", "action") == "programmer" && chaineOu(b, "", "request_id") == chaineOu(a, "", "request_id") {
				fixer(t, b, "detail.next_at", vStr(Iso(mustMs(t, chaineOu(b.Get("detail"), "", "next_at"))+1)))
				fausse = true
				break
			}
		}
	}
	if !fausse {
		t.Fatal("aucun rejet de soumission suivi d'une action programmer")
	}
	if e := ecartsDe(t, trace, rejeu, "AN-37"); len(e) == 0 {
		t.Error("AN-37 : attente faussée d'une soumission dont le rejet n'est pas une action, aucun écart signalé")
	}
}

// AN-36, EX-8.4 règle 2 et EX-9.4 (complément du 2026-11-16) : à chaque
// ecrire_file qui fait passer une ancre de période à envoyee, aucune ancre de
// point de même journal et même period_start n'est dans un état non final
// (trace registre-periode-apres-point-de-cloture : la ligne obtenue de
// l'ancre de K4 altérée en a_reprendre, l'écart est signalé). L'invariant est
// vérifié sur les actions attendues de la trace et sa file finale publiée,
// sans rejouer le planificateur.
func TestAN36PeriodeApresSesPoints(t *testing.T) {
	trace := chargerTrace(t, "registre-periode-apres-point-de-cloture")
	rejeu := rejeuPublie(t, trace)
	if e := ecartsDe(t, trace, rejeu, "AN-36"); len(e) != 0 {
		t.Fatalf("AN-36 sur la trace publiée : %v", e)
	}
	altere := false
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "action") == "ecrire_file" && strings.HasPrefix(chaineOu(a, "", "request_id"), "ancre_registre_point:0x804585ae") && chaineOu(a.Get("detail"), "", "state") == "obtenue" {
			fixer(t, a, "detail.state", vStr("a_reprendre"))
			altere = true
		}
	}
	if !altere {
		t.Fatal("aucune ligne obtenue de l'ancre du point de clôture")
	}
	if e := ecartsDe(t, trace, rejeu, "AN-36"); len(e) == 0 {
		t.Error("AN-36 : ancre de la période envoyée alors que l'ancre de son point de clôture n'est pas finale, aucun écart signalé")
	}
}

// AN-41 et EX-8.11 (complément du 2026-11-16, origine de l'âge d'abandon) :
// au-delà de give_up_after_s comptés depuis created_at, la mise à niveau est
// reprogrammée un jour plus tard, et à interval_s avant ; sur la trace
// redemarrage-ots-abandon-origine, la mise à niveau quotidienne ramenée à
// interval_s est signalée. L'invariant est vérifié sur les actions attendues
// de la trace, sans rejouer le planificateur.
func TestAN41AgeAbandonDepuisCreation(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ots-abandon-origine")
	rejeu := rejeuPublie(t, trace)
	if e := ecartsDe(t, trace, rejeu, "AN-41"); len(e) != 0 {
		t.Fatalf("AN-41 sur la trace publiée : %v", e)
	}
	altere := false
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "action") != "programmer" || chaineOu(a.Get("detail"), "", "reason") != "mise_a_niveau" {
			continue
		}
		at := mustMs(t, chaineOu(a, "", "t"))
		if mustMs(t, chaineOu(a.Get("detail"), "", "next_at"))-at == 86400*1000 {
			fixer(t, a, "detail.next_at", vStr(Iso(at+1800*1000)))
			altere = true
		}
	}
	if !altere {
		t.Fatal("aucune mise à niveau quotidienne dans la trace")
	}
	if e := ecartsDe(t, trace, rejeu, "AN-41"); len(e) == 0 {
		t.Error("AN-41 : mise à niveau à interval_s au-delà de give_up_after_s depuis la création, aucun écart signalé")
	}
}
