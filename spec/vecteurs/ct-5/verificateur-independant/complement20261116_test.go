// Tests des règles que les compléments du 2026-11-16 de CT-5 ajoutent ou
// précisent et que le module applique : un test par règle, sur les traces
// publiées qui l'exercent (ignoré quand elles sont absentes) ou sur des
// entrées construites ici quand aucune trace ne l'exerce.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// actionsDe rend les actions d'un rejeu de nom donné pour une demande.
func actionsDe(r *Rejeu, action, requestID string) []*Value {
	var l []*Value
	for _, a := range r.Actions {
		if chaineOu(a, "", "action") == action && chaineOu(a, "", "request_id") == requestID {
			l = append(l, a)
		}
	}
	return l
}

// copieValeur rend une copie profonde d'une valeur JSON.
func copieValeur(t *testing.T, v *Value) *Value {
	t.Helper()
	c, err := ParseJSON([]byte(Rendu(v)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// EX-9.7 et EX-8.4, règle 2 (complément du 2026-11-16) : l'ancre de la
// période refusée empreinte_squattee ne libère pas jeton_periode, qui reste
// attente_registre sans requête RFC 3161 ; registry_pending est écrit à
// chaque examen et l'alerte levée une fois (trace empreinte-squattee).
func TestAncrePeriodeRefuseeEX97(t *testing.T) {
	trace := chargerTrace(t, "empreinte-squattee")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1"
	if n := len(actionsDe(rejeu, "envoyer_rfc3161", id)); n != 0 {
		t.Errorf("%d requête(s) RFC 3161 sur periodHash après le refus de son ancre, aucune attendue", n)
	}
	rejouerEtConfronter(t, trace)
}

// EX-8.4, règle 2, et EX-9.7 (complément du 2026-11-16) : le refus de l'ancre
// de la période n'abandonne pas le repli de clôture, engagé squat_wait_s après
// la clôture tant que jeton_periode est attente_registre
// (trace empreinte-squattee-repli).
func TestRepliApresRefusEX84(t *testing.T) {
	trace := chargerTrace(t, "empreinte-squattee-repli")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	repli := false
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "action") == "journaliser" && chaineOu(a, "", "detail", "event") == "checkpoint_closing_fallback" {
			repli = true
		}
	}
	if !repli {
		t.Error("aucun repli de clôture après le refus de l'ancre de la période")
	}
	rejouerEtConfronter(t, trace)
}

// EX-8.10 (complément du 2026-11-16) : une passe rejoue au plus quatre
// échéances d'une minuterie périodique par demande ; au quatrième rejeu, la
// minuterie est reposée à sa première échéance postérieure à l'instant de
// l'entrée ; pour le renvoi d'une ancre, la ligne anchor_retry porte
// missed_deadlines (trace registre-saut-horloge : 35 échéances sautées).
func TestRejeuxBornesParPasseEX810(t *testing.T) {
	trace := chargerTrace(t, "registre-saut-horloge")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	manquees := int64(-1)
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "detail", "event") == "anchor_retry" {
			manquees = entierOu(a, -1, "detail", "missed_deadlines")
		}
	}
	if manquees != 35 {
		t.Errorf("missed_deadlines %d, attendu 35", manquees)
	}
	rejouerEtConfronter(t, trace)
}

// EX-8.12 (complément du 2026-11-16) : au démarrage, les demandes couvrantes
// sont les demandes de jeton obtenue relues de la période ; un repli de
// clôture obtenu, sans échéance, compte pour n_T et clôt une demande non
// finale qui sert une échéance ouverte inférieure, même sans jeton de période
// obtenu ; window_s est la borne de son jeton moins D_k de la plus petite
// échéance close.
func TestCouvrantesReluesEX812(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-echeance-remplacee")
	qb := trace.Get("queue_before").Arr
	k2, err := DemandeDe(qb[3])
	if err != nil {
		t.Fatal(err)
	}
	if k2.Kind != "jeton_point" || k2.State != "obtenue" {
		t.Fatalf("file de départ inattendue : %s %s", k2.Kind, k2.State)
	}
	k2.Deadlines = []int64{}
	qb[3] = k2.Valeur()
	entrees, err := ParseJSON([]byte(`[{"t":"2026-11-03T13:53:04.500Z","type":"demarrage","data":{}},{"t":"2026-11-03T13:53:05.000Z","type":"arret","data":{}}]`))
	if err != nil {
		t.Fatal(err)
	}
	remplacerMembre(trace, "inputs", entrees)
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	k1 := "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4"
	r := actionsDe(rejeu, "remplacer", k1)
	if len(r) != 1 || chaineOu(r[0], "", "detail", "replaced_by") != k2.ID {
		t.Fatalf("jeton de K1 non clos par le repli obtenu : %d action(s) remplacer", len(r))
	}
	for _, a := range actionsDe(rejeu, "journaliser", k1) {
		if chaineOu(a, "", "detail", "event") == "checkpoint_anchor_late" {
			// borne 13:53:04 moins D_1 = 13:05:00
			if w := entierOu(a, -1, "detail", "window_s"); w != 2884 {
				t.Errorf("window_s %d, attendu 2884", w)
			}
		}
	}
	// La trace publiée (jeton_point couvrant de D_9 et D_10) reste reproduite.
	rejouerEtConfronter(t, chargerTrace(t, "redemarrage-echeance-remplacee"))
}

// EX-8.9 (complément du 2026-11-16) : en cours de marche, une tentative en
// échec permanent chez un prestataire interrompt la série d'échecs
// transitoires : l'échec transitoire suivant chez ce prestataire a k = 1.
func TestSerieInterrompueEnMarcheEX89(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-releve")
	qb := trace.Get("queue_before").Arr
	jeton, err := DemandeDe(qb[1])
	if err != nil {
		t.Fatal(err)
	}
	if jeton.Kind != "jeton_periode" || len(jeton.Attempts) != 2 {
		t.Fatalf("file de départ inattendue : %s, %d tentatives", jeton.Kind, len(jeton.Attempts))
	}
	jeton.Attempts = jeton.Attempts[:1]
	jeton.AttemptsTotal = ptrI(1)
	jeton.State = "a_reprendre"
	jeton.DueAt = ptrS("2026-11-03T14:00:30.000Z")
	qb[1] = jeton.Valeur()
	h := jeton.Subject.Hash
	permanente := func(t string, n int) string {
		return fmt.Sprintf(`{"t":"%s","type":"reponse_rfc3161","data":{"request_id":"jeton_periode:%s","attempt":%d,"transport":"reponse","http_status":200,"pki_status":2,"failure_info":"unacceptedPolicy","retry_after_s":null,"nonce_in_response":null,"imprint_matches":null,"checks_passed":[],"gen_time":null,"accuracy_s":null,"token_sha256":null,"token_size":null}}`, t, h, n)
	}
	delai := fmt.Sprintf(`{"t":"2026-11-03T14:05:40.000Z","type":"reponse_rfc3161","data":{"request_id":"jeton_periode:%s","attempt":4,"transport":"delai","http_status":null,"pki_status":null,"failure_info":null,"retry_after_s":null,"nonce_in_response":null,"imprint_matches":null,"checks_passed":[],"gen_time":null,"accuracy_s":null,"token_sha256":null,"token_size":null}}`, h)
	texte := `[{"t":"2026-11-03T14:00:20.000Z","type":"demarrage","data":{}},{"t":"2026-11-03T14:00:30.000Z","type":"tic","data":{}},` + permanente("2026-11-03T14:00:31.000Z", 2) + `,` + permanente("2026-11-03T14:00:32.000Z", 3) + `,{"t":"2026-11-03T14:05:32.000Z","type":"tic","data":{}},` + delai + `,{"t":"2026-11-03T14:06:00.000Z","type":"arret","data":{}}]`
	entrees, err := ParseJSON([]byte(texte))
	if err != nil {
		t.Fatal(err)
	}
	remplacerMembre(trace, "inputs", entrees)
	remplacerMembre(trace, "jitter_ms", vArr(vInt(0)))
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	var obtenu string
	for _, a := range rejeu.Actions {
		if chaineOu(a, "", "action") == "programmer" && chaineOu(a, "", "t") == "2026-11-03T14:05:40.000Z" {
			obtenu = chaineOu(a, "", "detail", "next_at")
		}
	}
	// k = 1 : 5 s (la série du principal, k = 1 relu, est interrompue par
	// l'échec permanent de la tentative 2)
	if obtenu != "2026-11-03T14:05:45.000Z" {
		t.Errorf("reprise après la tentative 4 programmée à %q, attendu 2026-11-03T14:05:45.000Z (k = 1)", obtenu)
	}
	remplacerMembre(trace, "queue_after", vArr())
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range invariants {
		if inv.Regle == "AN-37" && len(inv.Ecarts) > 0 {
			t.Errorf("AN-37 : %v", inv.Ecarts)
		}
	}
}

// EX-4.13 (complément du 2026-11-16) : au démarrage, la reprise d'une demande
// a_reprendre dont due_at dépasse l'instant courant plus retry.max_ms est
// ramenée à cette borne (programmer, raison backoff, puis ligne réécrite) ;
// la mise à niveau d'une preuve OpenTimestamps en_attente n'est pas bornée
// (trace redemarrage-due-at-borne).
func TestBorneDueAtAuDemarrageEX413(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-due-at-borne")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "jeton_point:0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4"
	p := actionsDe(rejeu, "programmer", id)
	if len(p) == 0 || chaineOu(p[0], "", "detail", "next_at") != "2026-11-03T13:48:00.000Z" || chaineOu(p[0], "", "detail", "reason") != "backoff" {
		t.Errorf("reprise non bornée à t + retry.max_ms (13:48:00, backoff)")
	}
	rejouerEtConfronter(t, trace)
	// Une preuve OpenTimestamps en_attente garde sa mise à niveau lointaine.
	ots := chargerTrace(t, "redemarrage-jeton-sans-acquisition")
	entrees, err := ParseJSON([]byte(`[{"t":"2026-11-03T14:05:00.000Z","type":"demarrage","data":{}},{"t":"2026-11-03T14:06:00.000Z","type":"arret","data":{}}]`))
	if err != nil {
		t.Fatal(err)
	}
	remplacerMembre(ots, "inputs", entrees)
	r2, err := RejouerTrace(ots, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := actionsDe(r2, "programmer", "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1")
	if len(q) != 1 || chaineOu(q[0], "", "detail", "next_at") != "2026-11-03T20:00:01.000Z" {
		t.Errorf("mise à niveau OpenTimestamps reprogrammée autrement qu'à max(due_at, now)")
	}
}

// EX-5.8 (complément du 2026-11-16) : avec le membre acquisitions de l'entrée
// demarrage, une demande de jeton obtenue sans enregistrement de même
// token_sha256 est rouverte (a_reprendre à l'instant du démarrage, alerte
// file_perdue) et renvoyée au rang attempts_total + 1 ; sans ce membre, la
// règle ne s'applique pas (trace redemarrage-jeton-sans-acquisition).
func TestReouvertureSansAcquisitionEX58(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-jeton-sans-acquisition")
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1"
	e := actionsDe(rejeu, "envoyer_rfc3161", id)
	if len(e) != 1 || entierOu(e[0], 0, "detail", "attempt") != 2 {
		t.Errorf("jeton de clôture non renvoyé au rang 2 : %d envoi(s)", len(e))
	}
	rejouerEtConfronter(t, trace)
	sans := chargerTrace(t, "redemarrage-jeton-sans-acquisition")
	entrees, err := ParseJSON([]byte(`[{"t":"2026-11-03T14:05:00.000Z","type":"demarrage","data":{}},{"t":"2026-11-03T14:06:00.000Z","type":"arret","data":{}}]`))
	if err != nil {
		t.Fatal(err)
	}
	remplacerMembre(sans, "inputs", entrees)
	r2, err := RejouerTrace(sans, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(actionsDe(r2, "ecrire_file", id)); n != 0 {
		t.Errorf("sans membre acquisitions, %d ligne(s) écrite(s) pour le jeton de clôture, aucune attendue", n)
	}
}

// EX-8.12 (complément du 2026-11-16) : avec le membre acquisitions de
// l'entrée stockage_relu, une demande de jeton recréée qui a un enregistrement
// est créée obtenue avec ce résultat, sans tentative ni requête, et ses
// échéances sont satisfaites (traces file-perdue-jeton-point-obtenu et
// file-perdue-jeton-periode-obtenu).
func TestDemandeRecreeeObtenueEX812(t *testing.T) {
	for _, c := range []struct{ nom, id string }{
		{"file-perdue-jeton-point-obtenu", "jeton_point:0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867"},
		{"file-perdue-jeton-periode-obtenu", "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1"},
	} {
		t.Run(c.nom, func(t *testing.T) {
			trace := chargerTrace(t, c.nom)
			rejeu, err := RejouerTrace(trace, nil)
			if err != nil {
				t.Fatal(err)
			}
			ecr := actionsDe(rejeu, "ecrire_file", c.id)
			if len(ecr) == 0 || chaineOu(ecr[0], "", "detail", "state") != "obtenue" {
				t.Errorf("%s : demande recréée autrement qu'obtenue", c.id)
			}
			if c.nom == "file-perdue-jeton-periode-obtenu" && len(actionsDe(rejeu, "envoyer_rfc3161", c.id)) != 0 {
				t.Errorf("%s : requête envoyée pour une demande recréée obtenue", c.id)
			}
			rejouerEtConfronter(t, trace)
		})
	}
}

// Schéma planificateur-ancrage-v0 (complément du 2026-11-16) : le membre
// acquisitions des entrées demarrage et stockage_relu suit
// $defs/acquisition_relue (request_id d'une demande de jeton, result de
// $defs/resultat, aucun autre membre) ; un élément hors de cette forme est
// refusé.
func TestAcquisitionsSchema(t *testing.T) {
	trace := chargerTrace(t, "redemarrage-jeton-sans-acquisition")
	base := trace.Get("inputs").Arr[0]
	acq := base.Get("data").Get("acquisitions").Arr[0]
	for _, c := range []struct {
		nom   string
		modif func(a *Value)
	}{
		{"membre inconnu", func(a *Value) { a.Obj = append(a.Obj, Member{Key: "promoted", Val: vBool(true)}) }},
		{"request_id d'une ancre", func(a *Value) {
			remplacerMembre(a, "request_id", vStr("ancre_registre_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1"))
		}},
		{"result nul", func(a *Value) { remplacerMembre(a, "result", vNull()) }},
	} {
		t.Run(c.nom, func(t *testing.T) {
			tr := copieValeur(t, trace)
			a := copieValeur(t, acq)
			c.modif(a)
			remplacerMembre(tr.Get("inputs").Arr[0].Get("data"), "acquisitions", vArr(a))
			if _, err := RejouerTrace(tr, nil); err == nil {
				t.Errorf("acquisitions (%s) admise à l'entrée demarrage", c.nom)
			}
		})
	}
	// stockage_relu : même forme.
	tr := chargerTrace(t, "file-perdue-jeton-periode-obtenu")
	a := copieValeur(t, tr.Get("inputs").Arr[1].Get("data").Get("acquisitions").Arr[0])
	a.Obj = append(a.Obj, Member{Key: "promoted", Val: vBool(true)})
	remplacerMembre(tr.Get("inputs").Arr[1].Get("data"), "acquisitions", vArr(a))
	if _, err := RejouerTrace(tr, nil); err == nil {
		t.Error("acquisitions (membre inconnu) admise à l'entrée stockage_relu")
	}
}

// comparaisonsConfiguration rend les comparaisons de la famille
// configuration d'un rapport.
func comparaisonsConfiguration(rap *Rapport) []Comparaison {
	var l []Comparaison
	for _, c := range rap.Comparaisons {
		if c.Famille == "configuration" {
			l = append(l, c)
		}
	}
	return l
}

// AN-1 (EX-4.9, règles 4, 4 bis et 9 ; complément du 2026-11-16) : la famille
// configuration publiée est vérifiée cas par cas, verdict et règles violées.
func TestFamilleConfigurationAN1(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "configuration", "configuration.json")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	l := comparaisonsConfiguration(VerifierVecteurs(".."))
	if len(l) < 19 {
		t.Fatalf("%d comparaison(s) de la famille configuration, au moins dix-neuf attendues", len(l))
	}
	for _, c := range l {
		if !c.Concorde {
			t.Errorf("%s · %s : attendu %s, obtenu %s", c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
		}
	}
}

// fixer remplace la valeur au chemin donné (clés d'objet ou indices de liste).
func fixer(t *testing.T, v *Value, chemin string, nouvelle *Value) {
	t.Helper()
	parties := strings.Split(chemin, ".")
	for i, p := range parties {
		dernier := i == len(parties)-1
		switch v.Kind {
		case KindObject:
			trouve := false
			for j := range v.Obj {
				if v.Obj[j].Key == p {
					if dernier {
						v.Obj[j].Val = nouvelle
						return
					}
					v = v.Obj[j].Val
					trouve = true
					break
				}
			}
			if !trouve {
				if !dernier {
					t.Fatalf("chemin %s : %s absent", chemin, p)
				}
				v.Obj = append(v.Obj, Member{Key: p, Val: nouvelle})
				return
			}
		case KindArray:
			var n int
			if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n >= len(v.Arr) {
				t.Fatalf("chemin %s : indice %s", chemin, p)
			}
			if dernier {
				v.Arr[n] = nouvelle
				return
			}
			v = v.Arr[n]
		default:
			t.Fatalf("chemin %s : %s n'est pas un conteneur", chemin, p)
		}
	}
}

// EX-4.9 : chaque règle d'AN-1 sur un document tiré de l'exemple d'EX-4.8,
// dans une famille configuration écrite pour ce test.
func TestReglesConfigurationEX49(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "configuration", "configuration.json"))
	sch, err2 := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "ancrage-v0.schema.json"))
	if err != nil || err2 != nil {
		t.Skip("vecteurs ou schéma publiés absents")
	}
	fam, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	exemple := fam.Get("cases").Arr[0].Get("input").Get("document")
	type cas struct {
		id     string
		profil string
		ck     *Value
		modifs map[string]*Value
		regles []string
	}
	pem := vArr(vStr("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"))
	casListe := []cas{
		{"r1-valeur-differente", "production", vInt(30), nil, []string{"1"}},
		{"r1-valeur-inconnue-production", "production", vNull(), nil, []string{"1"}},
		{"r1-valeur-inconnue-developpement", "developpement", vNull(), nil, nil},
		{"r1-r3-non-diviseur", "developpement", vInt(70), map[string]*Value{"checkpoint_interval_s": vInt(70)}, []string{"1", "3"}},
		{"r2-deux-principaux", "developpement", vInt(60), map[string]*Value{"rfc3161.providers.1.role": vStr("principal")}, []string{"2"}},
		{"r2-id-double", "developpement", vInt(60), map[string]*Value{"rfc3161.providers.2.id": vStr("qtsa-secours")}, []string{"2"}},
		{"r3-multiple", "developpement", vInt(60), map[string]*Value{"rfc3161.checkpoints.interval_s": vInt(90)}, []string{"3"}},
		{"r4-secours-non-qualifie-production", "production", vInt(60), map[string]*Value{"rfc3161.providers.1.qualified": vNull()}, []string{"4"}},
		{"r4-secours-http", "developpement", vInt(60), map[string]*Value{"rfc3161.providers.1.url": vStr("http://horodatage-secours.example/qts")}, []string{"4"}},
		{"r4-interne-http-distant", "developpement", vInt(60), map[string]*Value{"rfc3161.providers.2.url": vStr("http://tsa.example/")}, []string{"4"}},
		{"r4-ots-desactive-production", "production", vInt(60), map[string]*Value{"opentimestamps.enabled": vBool(false)}, []string{"4"}},
		{"r4-registre-aucun-production", "production", vInt(60), map[string]*Value{"registry.checkpoints": vStr("aucun")}, []string{"4"}},
		{"r4-role-aucun-production", "production", vInt(60), map[string]*Value{"rfc3161.checkpoints.provider_role": vStr("aucun")}, []string{"4"}},
		{"r4-role-aucun-test", "test", vInt(60), map[string]*Value{"rfc3161.checkpoints.provider_role": vStr("aucun")}, nil},
		{"r5-un-calendrier", "developpement", vInt(60), map[string]*Value{"opentimestamps.calendars": vArr(vStr("https://a.pool.opentimestamps.org"))}, []string{"5"}},
		{"r5-liste-blanche-vide", "developpement", vInt(60), map[string]*Value{"opentimestamps.upgrade.whitelist": vArr()}, []string{"5"}},
		{"r6-attente-initiale", "developpement", vInt(60), map[string]*Value{"rfc3161.retry.initial_ms": vInt(400000)}, []string{"6"}},
		{"r7-second-rang-absent", "developpement", vInt(60), map[string]*Value{"rfc3161.checkpoints.provider_role": vStr("second_rang")}, []string{"7"}},
		{"r8-pem-illisible", "developpement", vInt(60), map[string]*Value{"rfc3161.providers.0.anchor_certificates": pem}, []string{"8"}},
		{"schema-cle-inconnue", "developpement", vInt(60), map[string]*Value{"inconnue": vInt(1)}, []string{"schema"}},
	}
	var cases []*Value
	for _, c := range casListe {
		doc := copieValeur(t, exemple)
		for chemin, v := range c.modifs {
			fixer(t, doc, chemin, v)
		}
		regles := vArr()
		for _, r := range c.regles {
			regles.Arr = append(regles.Arr, vStr(r))
		}
		cases = append(cases, vObj("id", vStr(c.id), "description", vStr("cas de test"), "input", vObj("document", doc, "profil", vStr(c.profil), "checkpoint_interval_s", c.ck), "expected", vObj("valide", vBool(len(c.regles) == 0), "regles", regles)))
	}
	racine := filepath.Join(t.TempDir(), "vecteurs", "ct-5")
	if err := os.MkdirAll(filepath.Join(racine, "configuration"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(racine, "..", "..", "schemas"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(racine, "..", "..", "schemas", "ancrage-v0.schema.json"), sch, 0o644); err != nil {
		t.Fatal(err)
	}
	doc := vObj("version", vInt(0), "family", vStr("configuration"), "description", vStr("cas de test"), "cases", vArr(cases...))
	if err := os.WriteFile(filepath.Join(racine, "configuration", "configuration.json"), []byte(Rendu(doc)), 0o644); err != nil {
		t.Fatal(err)
	}
	l := comparaisonsConfiguration(VerifierVecteurs(racine))
	if len(l) < len(casListe) {
		t.Fatalf("%d comparaison(s) de la famille configuration, au moins %d attendues", len(l), len(casListe))
	}
	for _, c := range l {
		if !c.Concorde {
			t.Errorf("%s · %s : attendu %s, obtenu %s", c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
		}
	}
}
