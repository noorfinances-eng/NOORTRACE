package registre_test

// Rejeu des dossiers de spec/vecteurs/ct-6/dossiers sur le seul contrôle 8 :
// l'entrée est construite comme le moteur la construit (moteur.go,
// controlesReserves), à partir de l'analyse de CT-1 du paquet dossier, sans
// dépendre des contrôles 4 et 5. On compare R-1 à R-11, N-4 et K-8 à
// failed_checks et not_executed, le statut du contrôle 8, les
// avertissements AV-R- et AV-K-1, AV-K-3, et le fragment F6 de l'énoncé.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/dossier"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
)

const racineDossiers = racineVecteurs + "/ct-6/dossiers"

// ecartsInterface : dossiers dont l'attendu ne peut pas être atteint avec
// l'interface fixée (R-11 quand la partie points-de-controle.json est
// déclarée présente mais que K-1 échoue : Entree.Point est alors nil ; voir
// LISEZMOI.md, « Lectures »).
var ecartsInterface = map[string]bool{
	"invalide-k1-partie-inexploitable": true,
	"invalide-k1-double-defaut":        true,
}

type attenduDossier struct {
	FailedChecks    []string          `json:"failed_checks"`
	ControlStatuses map[string]string `json:"control_statuses"`
	NotExecuted     []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	} `json:"not_executed"`
	Warnings  []string      `json:"warnings"`
	Anchors   *string       `json:"anchors"`
	Valid     bool          `json:"valid"`
	Statement *texteAttendu `json:"statement"`
}

func partieDossier(p *dossier.Partie) registre.Partie {
	if p == nil {
		return registre.Partie{}
	}
	if !p.Present {
		return registre.Partie{RaisonAbsence: p.Raison}
	}
	return registre.Partie{Presente: true, Etat: p.Lecture.Etat, Octets: p.Lecture.Octets}
}

// entreeDossier reproduit la construction de registre.Entree par le moteur.
func entreeDossier(t *testing.T, rep string, anc *ancres.Ancres) (registre.Entree, bool) {
	dos, d := dossier.Ouvrir(rep)
	if d != nil {
		t.Fatal(d.Message.Fr)
	}
	an, d := dossier.Analyser(dos, dossier.Options{})
	if d != nil {
		t.Fatal(d.Message.Fr)
	}
	e := registre.Entree{
		Registre:    partieDossier(dos.Partie(dossier.PRegistre)),
		Certificat:  partieDossier(dos.Partie(dossier.PCertificat)),
		Validateurs: partieDossier(dos.Partie(dossier.PValidateurs)),
		Ancres:      anc,
	}
	if ev := an.Evenement; ev != nil {
		e.OrgID, e.JournalID = ev.V.Membre("org_id").S(), ev.V.Membre("journal_id").S()
	}
	if an.P1 {
		m := an.Manifeste
		e.Manifeste = registre.Manifeste{Valide: true, PeriodHash: an.PeriodHash, OrgID: m.Membre("org_id").S(), JournalID: m.Membre("journal_id").S(), Root: m.Membre("root").S(), RecorderKeyID: m.Membre("recorder_key_id").S()}
		e.Manifeste.PeriodStart, _ = m.Membre("period_start").Entier()
		e.Manifeste.PeriodEnd, _ = m.Membre("period_end").Entier()
		e.Manifeste.FirstSeq, _ = m.Membre("first_seq").Entier()
		e.Manifeste.LastSeq, _ = m.Membre("last_seq").Entier()
		e.Manifeste.Version, _ = m.Membre("version").Entier()
	}
	e.ClesExploitables = an.ClesExploitables
	for _, k := range an.ClesListe {
		e.Cles = append(e.Cles, ancres.CleDossier{KeyID: k.KeyID, ClePublique: k.Hex})
	}
	avecReference := false
	if pt := an.Point; pt != nil && pt.K1 {
		e.Point = &registre.Point{K2: pt.K2, CheckpointHash: pt.CheckpointHash, KeyID: pt.KeyID}
		if r := pt.AncreRegistre; r != nil {
			ref := &registre.ReferencePoint{Contract: r.Membre("contract").S(), Fingerprint: r.Membre("fingerprint").S(), DocType: r.Membre("doc_type").S(), BlockHash: r.Membre("block_hash").S(), TransactionHash: r.Membre("transaction_hash").S()}
			ref.ChainID, _ = r.Membre("chain_id").Entier()
			ref.BlockNumber, _ = r.Membre("block_number").Entier()
			ref.LogIndex, _ = r.Membre("log_index").Entier()
			e.Point.Reference = ref
			avecReference = pt.K2
		}
	}
	return e, e.PartiesPresentes() || avecReference
}

func famille8(id string) bool {
	return strings.HasPrefix(id, "R-") || id == "N-4" || id == "K-8"
}

// TestDossiersControle8 rejoue les dossiers de CT-6 sur le contrôle 8.
func TestDossiersControle8(t *testing.T) {
	ents, err := filepathGlob(racineDossiers)
	if err != nil {
		t.Fatal(err)
	}
	appeles := 0
	for _, rep := range ents {
		nom := filepath.Base(rep)
		t.Run(nom, func(t *testing.T) {
			var att attenduDossier
			if err := json.Unmarshal(lire(t, filepath.Join(rep, "attendu.json")), &att); err != nil {
				t.Fatal(err)
			}
			var anc *ancres.Ancres
			if att.Anchors != nil {
				a, d := ancres.AnalyserAncres(lire(t, filepath.Join(rep, *att.Anchors)), nil)
				if d != nil {
					t.Fatal(d.Message.Fr)
				}
				anc = a
			}
			e, appel := entreeDossier(t, rep, anc)
			if !appel {
				if att.ControlStatuses["8"] == "reussi" {
					t.Errorf("contrôle 8 attendu réussi sans appel du paquet")
				}
				return
			}
			appeles++
			r := registre.Verifier(e)
			var siennes []commun.Verification
			siennes = append(siennes, r.Verifications...)
			if r.N4 != nil {
				siennes = append(siennes, *r.N4)
			}
			if r.K8 != nil {
				siennes = append(siennes, *r.K8)
			}
			attendus := map[string]string{}
			for _, id := range att.FailedChecks {
				if famille8(id) {
					attendus[id] = "echoue"
				}
			}
			for _, x := range att.NotExecuted {
				if famille8(x.ID) {
					attendus[x.ID] = "non_execute:" + x.Reason
				}
			}
			obtenus := map[string]string{}
			for _, v := range siennes {
				obtenus[v.ID] = etat(v)
				if _, ok := attendus[v.ID]; !ok && v.Statut != commun.Reussi {
					if !(ecartsInterface[nom] && v.ID == "R-11") {
						t.Errorf("%s : %s, attendue réussie (%s)", v.ID, etat(v), v.Detail.Fr)
					}
				}
			}
			for id, st := range attendus {
				if id == "K-8" && strings.HasPrefix(st, "non_execute:") && r.K8 == nil {
					continue // posée par le moteur (prérequis, référence nulle)
				}
				if obtenus[id] != st {
					if ecartsInterface[nom] && id == "R-11" {
						t.Logf("écart connu de l'interface : R-11 %q, attendu %q", obtenus[id], st)
						continue
					}
					t.Errorf("%s : %q, attendu %s", id, obtenus[id], st)
				}
			}
			// Statut du contrôle 8 comme le moteur le pose.
			st := r.Statut
			if !e.PartiesPresentes() {
				st = commun.NonExecute
				if r.K8 != nil && r.K8.Statut == commun.Echoue {
					st = commun.Echoue
				}
			}
			if string(st) != att.ControlStatuses["8"] {
				t.Errorf("contrôle 8 : %s, attendu %s", st, att.ControlStatuses["8"])
			}
			var av, avAtt []string
			for _, a := range r.Avertissements {
				av = append(av, a.ID)
			}
			for _, a := range att.Warnings {
				if strings.HasPrefix(a, "AV-R-") || a == "AV-K-1" || a == "AV-K-3" {
					avAtt = append(avAtt, a)
				}
			}
			if strings.Join(av, ",") != strings.Join(avAtt, ",") {
				t.Errorf("avertissements %v, attendu %v", av, avAtt)
			}
			if att.Valid && st == commun.Reussi && att.Statement != nil {
				if !strings.Contains(att.Statement.Fr, " ; "+r.Proposition.Fr+" ; ") && !strings.Contains(att.Statement.Fr, " ; "+r.Proposition.Fr+".") {
					t.Errorf("F6 fr absent de l'énoncé :\n %s", r.Proposition.Fr)
				}
				if !strings.Contains(att.Statement.En, "; "+r.Proposition.En+"; ") && !strings.Contains(att.Statement.En, "; "+r.Proposition.En+".") {
					t.Errorf("F6 en absent de l'énoncé :\n %s", r.Proposition.En)
				}
			}
			if r.K8 != nil && r.K8.Statut == commun.Reussi && att.Valid {
				if r.FaitsPoint == nil {
					t.Fatalf("K-8 réussie sans faits")
				}
				prouvee := strings.Contains(att.Statement.Fr, "ancré au registre")
				if (r.FaitsPoint.Inclusion == "prouvee") != prouvee {
					t.Errorf("inclusion %s, clause registre de FK : %v", r.FaitsPoint.Inclusion, prouvee)
				}
			}
		})
	}
	if appeles < 50 {
		t.Errorf("%d dossiers appellent le contrôle 8", appeles)
	}
}

// filepathGlob rend les sous-répertoires d'un répertoire, triés.
func filepathGlob(racine string) ([]string, error) {
	ents, err := os.ReadDir(racine)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, filepath.Join(racine, e.Name()))
		}
	}
	return out, nil
}
