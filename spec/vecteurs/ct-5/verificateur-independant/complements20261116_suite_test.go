// Tests des règles que les compléments du 2026-11-16 de CT-5 ont ajoutées ou
// précisées après les sept premières traces de ces compléments (ordre du
// démarrage, réponses qui ne s'appliquent pas, OpenTimestamps, registre, clé
// de chaîne, ordre des minuteries) : un test par règle, sur les traces
// publiées qui l'exercent (ignoré quand elles sont absentes) ou sur des
// entrées construites ici.

package main

import (
	"math"
	"strings"
	"testing"
)

// exigerActionsAttendues rejoue une trace et exige, à leur place, les actions
// attendues que filtre retient ; rend le rejeu.
func exigerActionsAttendues(t *testing.T, trace *Value, filtre func(*Value) bool) *Rejeu {
	t.Helper()
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatalf("rejeu refusé : %s", err.Error())
	}
	ecarts := 0
	for i, a := range trace.Get("expected").Arr {
		if !filtre(a) {
			continue
		}
		obtenu := "(absente)"
		if i < len(rejeu.Actions) {
			obtenu = canon(rejeu.Actions[i])
		}
		if canon(a) != obtenu {
			t.Errorf("action %d\nattendu %s\nobtenu  %s", i, canon(a), obtenu)
			if ecarts++; ecarts >= 3 {
				t.FailNow()
			}
		}
	}
	return rejeu
}

// evenement rend un filtre des lignes journaliser d'un événement donné.
func evenement(nom string) func(*Value) bool {
	return func(a *Value) bool {
		return chaineOu(a, "", "action") == "journaliser" && chaineOu(a.Get("detail"), "", "event") == nom
	}
}

// actionNommee rend un filtre des actions d'un nom donné.
func actionNommee(noms ...string) func(*Value) bool {
	return func(a *Value) bool { return dans(chaineOu(a, "", "action"), noms) }
}

// EX-8.11 (complément du 2026-11-16) : moins de min_responses réponses
// valables, quelle que soit l'attestation : tentative close
// reponses_insuffisantes, action rejeter_reponse (classe transitoire), ligne
// anchor_response_rejected (provider nul), puis a_reprendre et programmer
// backoff (trace ots-reponses-insuffisantes).
func TestReponsesInsuffisantesEX811(t *testing.T) {
	trace := chargerTrace(t, "ots-reponses-insuffisantes")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return actionNommee("rejeter_reponse")(a) || evenement("anchor_response_rejected")(a)
	})
	rejouerEtConfronter(t, trace)
}

// EX-8.9 (complément du 2026-11-16) : relue au démarrage, la série d'une
// soumission OpenTimestamps compte les échecs que la ligne porte. Entrées
// construites depuis redemarrage-ots-soumission-envoyee : la soumission est
// relue a_reprendre avec deux échecs reponses_insuffisantes ; l'échec suivant
// a k = 3.
func TestSerieSoumissionRelueEX89(t *testing.T) {
	trace := copieValeur(t, chargerTrace(t, "redemarrage-ots-soumission-envoyee"))
	ots := trace.Get("queue_before").Arr[2]
	if !strings.HasPrefix(chaineOu(ots, "", "id"), "ots_periode:") {
		t.Fatalf("queue_before[2] : soumission attendue, %s", chaineOu(ots, "", "id"))
	}
	fixer(t, ots, "state", vStr("a_reprendre"))
	fixer(t, ots, "due_at", vStr("2026-11-03T14:00:20.000Z"))
	fixer(t, ots, "attempts.1.outcome", vStr("echec_transitoire"))
	fixer(t, ots, "attempts.1.error_code", vStr("reponses_insuffisantes"))
	fixer(t, ots, "attempts.1.detail", vStr("1 calendrier(s) ; moins de 2 reponses valables"))
	fixer(t, ots, "attempts.1.next_at", vStr("2026-11-03T14:00:20.000Z"))
	entrees := trace.Get("inputs").Arr
	if chaineOu(entrees[1], "", "type") != "reponse_ots" || entierOu(entrees[1].Get("data"), 0, "calendars_answered") >= 2 {
		t.Fatal("inputs[1] : réponse insuffisante des calendriers attendue")
	}
	fixer(t, trace, "inputs", vArr(entrees[0], entrees[1]))
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ProjeterConfiguration(trace.Get("config"))
	g := entiersDe(trace, "jitter_ms")[0]
	attendu := Iso(mustMs(t, "2026-11-03T14:00:31.000Z") + int64(math.Min(cfg.Retry.MaxMs, cfg.Retry.InitialMs*math.Pow(cfg.Retry.Factor, 2))) + g)
	progs := actionsDe(rejeu, "programmer", chaineOu(ots, "", "id"))
	if len(progs) == 0 {
		t.Fatal("aucune action programmer pour la soumission")
	}
	dernier := progs[len(progs)-1].Get("detail")
	if chaineOu(dernier, "", "next_at") != attendu || chaineOu(dernier, "", "reason") != "backoff" {
		t.Errorf("reprise programmée à %s (%s), attendu %s (backoff, k = 3)", chaineOu(dernier, "", "next_at"), chaineOu(dernier, "", "reason"), attendu)
	}
}

func mustMs(t *testing.T, s string) int64 {
	t.Helper()
	v, err := Ms(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// EX-8.11 (complément du 2026-11-16) : une réponse sans preuve écrite
// (proof_sha256 nul) n'est jamais promue : à la soumission, preuve_absente,
// rejet et attente comme reponses_insuffisantes ; à la mise à niveau, la
// preuve reste en_attente (trace ots-preuve-absente).
func TestPreuveAbsenteEX811(t *testing.T) {
	trace := chargerTrace(t, "ots-preuve-absente")
	exigerActionsAttendues(t, trace, actionNommee("rejeter_reponse", "stocker"))
	rejouerEtConfronter(t, trace)
}

// EX-8.5, règle 2 (complément du 2026-11-16) : une réponse des calendriers
// qui ne s'applique pas est consignée demande_inconnue, tentative_close ou
// demande_close, avec attempt (attempts_total), attempt_id, provider nul et
// kept (trace ots-preuve-absente).
func TestReponseOtsHorsTentativeEX85(t *testing.T) {
	trace := chargerTrace(t, "ots-preuve-absente")
	exigerActionsAttendues(t, trace, evenement("anchor_response_rejected"))
}

// EX-8.12 (complément du 2026-11-16) : une soumission relue a_reprendre qui
// porte une tentative en_cours se reprend comme une soumission envoyee ;
// EX-8.3, AN-34 : la réécriture a_reprendre → a_reprendre suivie de
// programmer immediat est admise (trace redemarrage-ots-a-reprendre-en-cours).
func TestOtsAReprendreEnCoursEX812(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ots-a-reprendre-en-cours")
	rejouerEtConfronter(t, trace)
}

// EX-8.5, règles 1 et 2 (complément du 2026-11-16) : une réponse RFC 3161
// qui ne s'applique pas est consignée demande_inconnue (rien de gardé),
// tentative_inconnue (jeton gardé, borne nulle), tentative_close ou
// demande_close (trace reponses-hors-tentative).
func TestReponseRfc3161HorsTentativeEX85(t *testing.T) {
	trace := chargerTrace(t, "reponses-hors-tentative")
	exigerActionsAttendues(t, trace, evenement("anchor_response_rejected"))
	rejouerEtConfronter(t, trace)
}

// 8.5, règle 2 (complément du 2026-11-16) : la borne d'une pièce n'est
// genTime plus la précision que si le jeton passe les étapes 3 à 6 d'EX-5.10
// pour la tentative qu'il désigne, nulle sinon (trace
// jeton-tardif-avertissements).
func TestBornePieceEX85(t *testing.T) {
	trace := chargerTrace(t, "jeton-tardif-avertissements")
	exigerActionsAttendues(t, trace, actionNommee("stocker"))
}

// EX-5.10 (complément du 2026-11-16) : status 0 ou 1 sans TimeStampToken :
// reponse_illisible ; PKIFailureInfo hors des huit valeurs : statut_2 ;
// précision hors de la plage d'un instant : verification_T-7 (traces
// reponses-hors-tentative et jeton-tardif-avertissements).
func TestClassementEX510(t *testing.T) {
	for _, nom := range []string{"reponses-hors-tentative", "jeton-tardif-avertissements"} {
		t.Run(nom, func(t *testing.T) {
			trace := chargerTrace(t, nom)
			exigerActionsAttendues(t, trace, actionNommee("rejeter_reponse"))
			rejouerEtConfronter(t, trace)
		})
	}
}

// EX-8.10 (complément du 2026-11-16) : un reçu ou un échec du registre ne
// s'applique qu'à une ancre dont une tentative est en cours ; sinon
// anchor_duplicate_ignored avec state, ou reason demande_inconnue (traces
// registre-renvois et reponses-hors-tentative).
func TestEvenementsRegistreIgnoresEX810(t *testing.T) {
	for _, nom := range []string{"registre-renvois", "reponses-hors-tentative"} {
		t.Run(nom, func(t *testing.T) {
			exigerActionsAttendues(t, chargerTrace(t, nom), evenement("anchor_duplicate_ignored"))
		})
	}
}

// EX-8.10 (complément du 2026-11-16) : un échec signalé par le registre
// (hors empreinte_squattee) ne renvoie pas l'ancre aussitôt : ligne
// anchor_retry de mode reprise, a_reprendre, programmer backoff à l'attente
// d'EX-8.9 ; à l'échéance, renvoi si la clé est libre (trace
// registre-renvois).
func TestEchecRegistreAReprendreEX810(t *testing.T) {
	trace := chargerTrace(t, "registre-renvois")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return evenement("anchor_retry")(a) || (actionNommee("programmer")(a) && strings.HasPrefix(chaineOu(a, "", "request_id"), "ancre_registre_"))
	})
	rejouerEtConfronter(t, trace)
}

// EX-8.16 (complément du 2026-11-16) : deux minuteries de même échéance : les
// minuteries de période d'abord, dans l'ordre d'armement, puis celles des
// demandes dans l'ordre de la file (trace minuteries-simultanees).
func TestOrdreMinuteriesEX816(t *testing.T) {
	rejouerEtConfronter(t, chargerTrace(t, "minuteries-simultanees"))
}

// EX-8.16 (complément du 2026-11-16) : les minuteries de période de deux
// journaux se déclenchent dans l'ordre d'armement, quel que soit le journal
// (trace minuteries-deux-journaux : à 13:55, échéance 11 du premier journal,
// point_manquant, échéance 11 du second).
func TestMinuteriesDeuxJournauxEX816(t *testing.T) {
	trace := chargerTrace(t, "minuteries-deux-journaux")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return strings.HasPrefix(chaineOu(a, "", "t"), "2026-11-03T13:55:00")
	})
	rejouerEtConfronter(t, trace)
}

// EX-8.12, ordre du démarrage (complément du 2026-11-16) : passe dans l'ordre
// de la file ; une ancre a_envoyer n'attend le nonce que si sa clé est
// occupée ; départs après la passe (traces redemarrage-a-envoyer-cle-libre et
// redemarrage-ordre-de-la-file).
func TestOrdreDemarrageEX812(t *testing.T) {
	for _, nom := range []string{"redemarrage-a-envoyer-cle-libre", "redemarrage-ordre-de-la-file"} {
		t.Run(nom, func(t *testing.T) {
			trace := chargerTrace(t, nom)
			debut := chaineOu(trace.Get("inputs").Arr[0], "", "t")
			exigerActionsAttendues(t, trace, func(a *Value) bool { return chaineOu(a, "", "t") == debut })
			rejouerEtConfronter(t, trace)
		})
	}
}

// EX-8.12 et EX-4.13 (complément du 2026-11-16) : une ancre au registre
// a_reprendre garde son due_at au démarrage et repart à max(due_at, t)
// (trace redemarrage-ancres-a-reprendre).
func TestAncresAReprendreEX812(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-ancres-a-reprendre")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return strings.HasPrefix(chaineOu(a, "", "request_id"), "ancre_registre_")
	})
	rejouerEtConfronter(t, trace)
}

// EX-8.10 (complément du 2026-11-16) : au reçu, le délai d'inclusion court
// depuis la création de l'ancre, attente du nonce comprise (trace
// registre-inclusion-apres-attente) ; AN-40 le vérifie : sans l'alerte,
// l'invariant signale l'écart.
func TestInclusionLateDepuisCreationEX810(t *testing.T) {
	trace := chargerTrace(t, "registre-inclusion-apres-attente")
	rejeu := exigerActionsAttendues(t, trace, func(a *Value) bool {
		return actionNommee("alerter")(a) && chaineOu(a.Get("detail"), "", "code") == "inclusion_late"
	})
	rejouerEtConfronter(t, trace)
	retiree := false
	for i := len(rejeu.Actions) - 1; i >= 0 && !retiree; i-- {
		a := rejeu.Actions[i]
		if chaineOu(a, "", "action") == "alerter" && chaineOu(a.Get("detail"), "", "code") == "inclusion_late" {
			fixer(t, a, "detail.code", vStr("retiree_pour_le_test"))
			retiree = true
		}
	}
	if !retiree {
		t.Fatal("aucune alerte inclusion_late à retirer")
	}
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range invariants {
		if inv.Regle == "AN-40" && len(inv.Ecarts) == 0 {
			t.Error("AN-40 : inclusion tardive depuis la création sans alerte, aucun écart signalé")
		}
	}
}

// EX-9.4 (complément du 2026-11-16) : la clé de chaîne d'une ancre est celle
// du journal de son sujet ; deux journaux libres font partir chacun leur
// ancre (trace registre-cle-par-journal).
func TestCleParJournalEX94(t *testing.T) {
	trace := chargerTrace(t, "registre-cle-par-journal")
	exigerActionsAttendues(t, trace, actionNommee("envoyer_registre"))
	rejouerEtConfronter(t, trace)
}

// EX-8.12 (complément du 2026-11-16) : une demande de jeton recréée obtenue
// s'applique comme à sa promotion (EX-4.4) : les demandes non finales qui
// servent une échéance ouverte inférieure à sa plus grande échéance sont
// closes remplacee, avec checkpoint_anchor_late (trace
// redemarrage-jeton-recree-couvrant).
func TestRecreeeCouvranteEX812(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-jeton-recree-couvrant")
	exigerActionsAttendues(t, trace, func(a *Value) bool {
		return actionNommee("remplacer")(a) || evenement("checkpoint_anchor_late")(a)
	})
	rejouerEtConfronter(t, trace)
}

// AN-37 et EX-8.9 (complément du 2026-11-16) : l'attente après le rejet d'une
// soumission OpenTimestamps (reponses_insuffisantes ou preuve_absente) suit
// la série de la soumission, gigue comprise ; une attente faussée est
// signalée (trace ots-preuve-absente).
func TestAttenteSoumissionAN37(t *testing.T) {
	trace := chargerTrace(t, "ots-preuve-absente")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	fausse := false
	for i, a := range rejeu.Actions {
		if chaineOu(a, "", "action") == "rejeter_reponse" && strings.HasPrefix(chaineOu(a, "", "request_id"), "ots_") {
			for _, b := range rejeu.Actions[i:] {
				if chaineOu(b, "", "action") == "programmer" && chaineOu(b, "", "request_id") == chaineOu(a, "", "request_id") {
					fixer(t, b, "detail.next_at", vStr(Iso(mustMs(t, chaineOu(b.Get("detail"), "", "next_at"))+1)))
					fausse = true
					break
				}
			}
			break
		}
	}
	if !fausse {
		t.Fatal("aucun rejet de soumission suivi d'une action programmer")
	}
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range invariants {
		if inv.Regle == "AN-37" && len(inv.Ecarts) == 0 {
			t.Error("AN-37 : attente de la soumission faussée d'une milliseconde, aucun écart signalé")
		}
	}
}
