// Tests des règles que la révision 0.10 de CT-5 ajoute ou change et que le
// module applique : un test par règle, sur des entrées construites ici ou
// sur les traces publiées qui l'exercent (ignoré quand elles sont absentes).

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reponseStatut construit une TimeStampResp dont le PKIStatus est l'INTEGER
// de contenu donné, suivie du jeton s'il est non nul.
func reponseStatut(contenu []byte, jeton []byte) []byte {
	psi := tlv(0x30, tlv(0x02, contenu))
	return tlv(0x30, append(psi, jeton...))
}

// EX-5.10, étape 2 (révision 0.10) : un status hors de 0 à 5 donne
// statut_<n>, permanente, jeton non lu ; un status hors des entiers
// représentables (au-delà de ±(2^53 − 1)) donne reponse_illisible ; la
// tentative consigne pki_status tel que lu.
func TestStatutHorsTableEX510(t *testing.T) {
	req, err := ConstruireRequete("0x"+strings.Repeat("6a", 32), big.NewInt(0x0180), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	evaluer := func(rep []byte) *Evaluation {
		t.Helper()
		ev, err := EvaluerReponse(req, rep, HTTP{}, "2026-11-03T13:53:00.000Z", "2026-11-03T13:53:03.000Z", nil, Fraicheur{MaxResponseDelayS: 60, ClockToleranceS: 120}, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	code := func(ev *Evaluation) string {
		if ev.ErrorCode == nil {
			return "(nul)"
		}
		return *ev.ErrorCode
	}
	limite := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1))
	audela := new(big.Int).Lsh(big.NewInt(1), 53)
	negatif := new(big.Int).Neg(audela)
	cas := []struct {
		nom     string
		contenu []byte
		code    string
		statut  *int64
	}{
		{"6", []byte{0x06}, "statut_6", ptrI(6)},
		{"256 (deux octets)", []byte{0x01, 0x00}, "statut_256", ptrI(256)},
		{"-1", []byte{0xff}, "statut_-1", ptrI(-1)},
		{"2^53 - 1", entierComplementADeux(limite), "statut_9007199254740991", ptrI(9007199254740991)},
		{"2^53", entierComplementADeux(audela), "reponse_illisible", nil},
		{"-2^53", entierComplementADeux(negatif), "reponse_illisible", nil},
		{"INTEGER vide", []byte{}, "reponse_illisible", nil},
	}
	for _, c := range cas {
		ev := evaluer(reponseStatut(c.contenu, nil))
		if code(ev) != c.code || ev.Outcome != "echec_permanente" || ev.Critical || ev.Token != nil {
			t.Errorf("status %s : %s %s critique %v jeton %v, attendu %s echec_permanente non critique sans jeton", c.nom, ev.Outcome, code(ev), ev.Critical, ev.Token != nil, c.code)
		}
		if (c.statut == nil) != (ev.PKIStatus == nil) || (c.statut != nil && *c.statut != *ev.PKIStatus) {
			t.Errorf("status %s : pki_status consigné %s, attendu %s", c.nom, entierOuNul(ev.PKIStatus), entierOuNul(c.statut))
		}
	}
	// Statut 6 suivi d'un jeton par ailleurs valable (cas statut-6 des vecteurs) :
	// le jeton n'est ni lu ni promu.
	rep, err1 := os.ReadFile(filepath.Join("..", "reponses", "statut-6.tsr"))
	tsq, err2 := os.ReadFile(filepath.Join("..", "requetes", "point-k2-exemple.tsq"))
	if err1 != nil || err2 != nil {
		t.Log("vecteurs publiés absents : cas statut-6 non rejoué")
		return
	}
	ev, err := EvaluerReponse(tsq, rep, HTTP{}, "2026-11-03T13:53:00.000Z", "2026-11-03T13:53:03.000Z", nil, Fraicheur{MaxResponseDelayS: 60, ClockToleranceS: 120}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code(ev) != "statut_6" || ev.Critical || ev.Token != nil || ev.GenTime != nil || ev.NonceInResponse != nil || ev.ImprintMatches != nil {
		t.Errorf("statut-6.tsr : %s %s, jeton lu %v, attendu statut_6 sans lecture du jeton", ev.Outcome, code(ev), ev.Token != nil)
	}
}

func entierOuNul(p *int64) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprint(*p)
}

func chaineOuNul(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}

// entierComplementADeux rend le contenu d'un INTEGER DER minimal (complément à deux).
func entierComplementADeux(v *big.Int) []byte {
	if v.Sign() >= 0 {
		b := v.Bytes()
		if len(b) == 0 || b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b
	}
	n := len(new(big.Int).Neg(v).Bytes()) + 1
	mod := new(big.Int).Lsh(big.NewInt(1), uint(8*n))
	b := new(big.Int).Add(mod, v).Bytes()
	for len(b) > 1 && b[0] == 0xff && b[1]&0x80 != 0 {
		b = b[1:]
	}
	return b
}

// sousIdentifiant encode un sous-identifiant d'OID en base 128.
func sousIdentifiant(v *big.Int) []byte {
	x := new(big.Int).Set(v)
	b := []byte{byte(new(big.Int).And(x, big.NewInt(0x7f)).Int64())}
	x.Rsh(x, 7)
	for x.Sign() > 0 {
		b = append([]byte{byte(new(big.Int).And(x, big.NewInt(0x7f)).Int64()) | 0x80}, b...)
		x.Rsh(x, 7)
	}
	return b
}

// EX-5.1 et EX-4.9 règle 9 (révision 0.10) : chaque arc d'un OID tient sur
// 128 bits, à l'encodage comme au décodage ; au-delà, l'OID est refusé ; un
// arc de plus de 64 bits n'est jamais tronqué.
func TestArcsOID128BitsEX51(t *testing.T) {
	max128 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	audela := new(big.Int).Lsh(big.NewInt(1), 128)
	digest := "0x" + strings.Repeat("6a", 32)
	for _, arc := range []*big.Int{new(big.Int).Lsh(big.NewInt(1), 64), max128} {
		oid := "1.3.6.1.4.1.99999." + arc.String()
		req, err := ConstruireRequete(digest, big.NewInt(0x0180), &oid, true)
		if err != nil {
			t.Errorf("OID %s : refusé (%v), attendu admis", oid, err)
			continue
		}
		lue, err := LireRequete(req)
		if err != nil {
			t.Errorf("OID %s : relecture refusée (%v)", oid, err)
		} else if lue.PolicyOID == nil || *lue.PolicyOID != oid {
			t.Errorf("OID %s : relu %s", oid, chaineOuNul(lue.PolicyOID))
		}
	}
	trop := "1.3.6.1.4.1.99999." + audela.String()
	if _, err := ConstruireRequete(digest, big.NewInt(0x0180), &trop, true); err == nil {
		t.Errorf("OID %s : encodé, attendu refusé (arc au-delà de 128 bits)", trop)
	}
	// Décodage : une reqPolicy dont un arc dépasse 128 bits est refusée.
	contenu := append([]byte{0x2b}, sousIdentifiant(audela)...)
	version, _ := EncoderEntierDER(big.NewInt(1))
	mi := tlv(0x30, append(append([]byte{}, AlgorithmeSHA256DER...), tlv(0x04, h(strings.Repeat("6a", 32)))...))
	nonce, _ := EncoderEntierDER(big.NewInt(0x0180))
	corps := append(append(append(version, mi...), tlv(0x06, contenu)...), nonce...)
	corps = append(corps, tlv(0x01, []byte{0xff})...)
	if lue, err := LireRequete(tlv(0x30, corps)); err == nil {
		t.Errorf("requête dont la politique a un arc de 129 bits relue (%v), attendu refusée", *lue.PolicyOID)
	}
}

// EX-8.5, règle 3 (révision 0.10) : un fragment de fin de fichier qui ne
// finit pas par une fin de ligne est retiré, même s'il se lit ; une ligne mal
// formée hors de la fin du fichier est consignée et ignorée, la ligne valide
// précédente du même id faisant foi.
func TestFragmentEtLignesIllisiblesEX85(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "reprise", "redemarrage-reprise.avant.ndjson"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	lignes := lignesDe(string(b))
	if len(lignes) < 3 {
		t.Fatal("file de départ trop courte")
	}
	// fragment complet sans fin de ligne
	texte := lignes[0] + "\n" + lignes[1] + "\n" + lignes[2]
	f := LireFile(texte)
	if len(f.Demandes) != 2 || !f.Tronquee {
		t.Errorf("fragment sans fin de ligne : %d demande(s), tronquée %v ; attendu 2 demandes, fragment retiré", len(f.Demandes), f.Tronquee)
	}
	// ligne mal formée (membre attempts perdu) au milieu du fichier
	v, err := ParseJSON([]byte(lignes[1]))
	if err != nil {
		t.Fatal(err)
	}
	d, err := DemandeDe(v)
	if err != nil {
		t.Fatal(err)
	}
	abimee := strings.Replace(lignes[1], `"attempts":`, `"tentatives":`, 1)
	if _, err := ParseJSON([]byte(abimee)); err != nil {
		t.Fatal(err)
	}
	f = LireFile(lignes[1] + "\n" + abimee + "\n" + lignes[2] + "\n")
	if len(f.Demandes) != 2 || len(f.Erreurs) != 1 || f.Tronquee {
		t.Fatalf("ligne mal formée : %d demande(s), %d erreur(s), tronquée %v", len(f.Demandes), len(f.Erreurs), f.Tronquee)
	}
	if LigneFile(f.Demandes[0]) != LigneFile(d) {
		t.Errorf("la ligne valide précédente de %s ne fait pas foi", d.ID)
	}
}

// chargerTrace lit une trace publiée de planification/.
func chargerTrace(t *testing.T, nom string) *Value {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "planification", nom+".json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	trace, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return trace
}

// rejouerEtConfronter rejoue une trace et confronte actions, file finale et
// invariants de la section 8.11.
func rejouerEtConfronter(t *testing.T, trace *Value) *Rejeu {
	t.Helper()
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	attendues := trace.Get("expected").Arr
	for i := 0; i < len(attendues) || i < len(rejeu.Actions); i++ {
		a, b := "(absente)", "(absente)"
		if i < len(attendues) {
			a = canon(attendues[i])
		}
		if i < len(rejeu.Actions) {
			b = canon(rejeu.Actions[i])
		}
		if a != b {
			t.Fatalf("action %d\nattendu %s\nobtenu  %s", i, a, b)
		}
	}
	queue := trace.Get("queue_after").Arr
	if len(queue) != len(rejeu.File) {
		t.Fatalf("file finale de %d demandes, %d attendues", len(rejeu.File), len(queue))
	}
	for i := range queue {
		if canon(queue[i]) != LigneFile(rejeu.File[i]) {
			t.Fatalf("demande %d de la file finale différente", i)
		}
	}
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range invariants {
		if len(inv.Ecarts) > 0 {
			t.Errorf("%s : %v", inv.Regle, inv.Ecarts)
		}
	}
	return rejeu
}

// EX-8.12 (révision 0.10) : la minuterie de relève d'EX-8.8 est reposée au
// démarrage à premier envoi + fallback_after_s pour toute demande de jeton non
// finale qui admet la relève et dont le secours n'est ni engagé ni épuisé ;
// échue, elle relève aussitôt (traces redemarrage-releve et file-pleine).
func TestReleveReposeeAuDemarrageEX812(t *testing.T) {
	for _, nom := range []string{"redemarrage-releve", "file-pleine"} {
		t.Run(nom, func(t *testing.T) { rejouerEtConfronter(t, chargerTrace(t, nom)) })
	}
}

// EX-8.12 et EX-4.4 (révision 0.10) : une demande jeton_point non finale relue
// dont toutes les échéances sont inférieures à une échéance satisfaite d'une
// autre demande de la période est close remplacee au démarrage, avec la ligne
// checkpoint_anchor_late (trace redemarrage-echeance-remplacee).
func TestEcheancesRemplaceesAuDemarrageEX812(t *testing.T) {
	rejouerEtConfronter(t, chargerTrace(t, "redemarrage-echeance-remplacee"))
}

// remplacerMembre remplace la valeur d'un membre d'objet.
func remplacerMembre(o *Value, cle string, v *Value) {
	for i := range o.Obj {
		if o.Obj[i].Key == cle {
			o.Obj[i].Val = v
			return
		}
	}
	panic("membre absent : " + cle)
}

// EX-8.9 (révision 0.10) : une tentative close par le redémarrage
// (error_code redemarrage) interrompt la série d'échecs transitoires ; sans
// elle, une demande relue a_reprendre garde ses échecs antérieurs dans k.
func TestSerieDeReprisesRelueEX89(t *testing.T) {
	for _, c := range []struct {
		code2   string
		attendu string // next_at programmé après l'échec de la tentative 3 (14:00:47)
	}{
		{"delai", "2026-11-03T14:01:07.000Z"},       // k = 3 : 5 s × 2² = 20 s
		{"redemarrage", "2026-11-03T14:00:52.000Z"}, // k = 1 : 5 s
	} {
		t.Run(c.code2, func(t *testing.T) {
			trace := chargerTrace(t, "redemarrage-releve")
			qb := trace.Get("queue_before").Arr
			jeton, err := DemandeDe(qb[1])
			if err != nil {
				t.Fatal(err)
			}
			if jeton.Kind != "jeton_periode" || len(jeton.Attempts) != 2 {
				t.Fatalf("file de départ inattendue : %s, %d tentatives", jeton.Kind, len(jeton.Attempts))
			}
			a2 := jeton.Attempts[1]
			a2.Outcome = "echec_transitoire"
			a2.ErrorCode = ptrS(c.code2)
			a2.Detail = "delai de reponse depasse"
			a2.NextAt = ptrS("2026-11-03T14:00:37.000Z")
			if c.code2 == "redemarrage" {
				a2.Detail = "redemarrage : reponse non recue"
			}
			jeton.State = "a_reprendre"
			jeton.DueAt = ptrS("2026-11-03T14:00:37.000Z")
			qb[1] = jeton.Valeur()
			hash := jeton.Subject.Hash
			entree, err := ParseJSON([]byte(fmt.Sprintf(`[{"t":"2026-11-03T14:00:30.000Z","type":"demarrage","data":{}},{"t":"2026-11-03T14:00:47.000Z","type":"reponse_rfc3161","data":{"request_id":"jeton_periode:%s","attempt":3,"transport":"delai","http_status":null,"pki_status":null,"failure_info":null,"retry_after_s":null,"nonce_in_response":null,"imprint_matches":null,"checks_passed":[],"gen_time":null,"accuracy_s":null,"token_sha256":null,"token_size":null}},{"t":"2026-11-03T14:00:50.000Z","type":"arret","data":{}}]`, hash)))
			if err != nil {
				t.Fatal(err)
			}
			remplacerMembre(trace, "inputs", entree)
			rejeu, err := RejouerTrace(trace, nil)
			if err != nil {
				t.Fatal(err)
			}
			var obtenu string
			for _, a := range rejeu.Actions {
				if chaineOu(a, "", "action") == "programmer" && chaineOu(a, "", "t") == "2026-11-03T14:00:47.000Z" {
					obtenu = chaineOu(a, "", "detail", "next_at")
				}
			}
			if obtenu != c.attendu {
				t.Errorf("reprise après la tentative 3 programmée à %q, attendu %s", obtenu, c.attendu)
			}
			// AN-37 recalcule la même attente depuis la file relue.
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
		})
	}
}
