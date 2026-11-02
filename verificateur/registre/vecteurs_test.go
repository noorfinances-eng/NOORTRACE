package registre_test

// Rejeu de la famille registre des vecteurs de CT-6 (annexe A.5,
// spec/vecteurs/ct-6/registre/attendu.json) : recalculs par bloc (hachage
// BFT, racine des reçus, journaux décodés), racines synthétiques du trie
// (trie.json), puis les jeux de parties et les variantes : statut de R-1 à
// R-11 et de N-4, statut et raison du contrôle 8, avertissements,
// proposition de l'énoncé (EX-11.22) et faits (EX-11.21).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
)

const (
	racineVecteurs = "../../spec/vecteurs"
	racineRegistre = racineVecteurs + "/ct-6/registre"
	racineAncres   = racineVecteurs + "/ct-6/ancres"
	dossierComplet = racineVecteurs + "/ct-6/dossiers/valide-seq-7-complet"
)

type texteAttendu struct {
	Fr string `json:"fr"`
	En string `json:"en"`
}

type refAttendue struct {
	ChainID         int64  `json:"chain_id"`
	Contract        string `json:"contract"`
	Fingerprint     string `json:"fingerprint"`
	DocType         string `json:"doc_type"`
	BlockNumber     int64  `json:"block_number"`
	BlockHash       string `json:"block_hash"`
	TransactionHash string `json:"transaction_hash"`
	LogIndex        int64  `json:"log_index"`
}

type jeuAttendu struct {
	Nom                string            `json:"nom"`
	Parties            string            `json:"parties"`
	ValidateursPresent bool              `json:"validateurs_present"`
	Manifeste          string            `json:"manifeste"`
	Ancres             *string           `json:"ancres"`
	ControlStatus      string            `json:"control_status"`
	ControlReason      *string           `json:"control_reason"`
	Warnings           []string          `json:"warnings"`
	N4Present          bool              `json:"n4_present"`
	Statuses           map[string]string `json:"statuses"`
	Statement          *texteAttendu     `json:"statement"`
	Facts              json.RawMessage   `json:"facts"`
	Checkpoint         *struct {
		CheckpointHash string      `json:"checkpoint_hash"`
		KeyID          string      `json:"key_id"`
		Reference      refAttendue `json:"reference"`
	} `json:"checkpoint"`
}

type attenduRegistre struct {
	Manifestes map[string]struct {
		Fichier    string `json:"fichier"`
		PeriodHash string `json:"period_hash"`
	} `json:"manifestes"`
	Blocs []struct {
		Height             uint64          `json:"height"`
		Role               string          `json:"role"`
		BftPreimage        string          `json:"bft_preimage"`
		BftBlockHash       string          `json:"bft_block_hash"`
		ReceiptsRoot       string          `json:"receipts_root"`
		ReceiptsRootServed string          `json:"receipts_root_served"`
		ReceiptEncodings   []string        `json:"receipt_encodings"`
		BlockTime          string          `json:"block_time"`
		Emitter            string          `json:"emitter"`
		Event              json.RawMessage `json:"event"`
	} `json:"blocs"`
	JeuxDeParties []jeuAttendu `json:"jeux_de_parties"`
	Variantes     []jeuAttendu `json:"variantes"`
}

func lire(t testing.TB, chemin string) []byte {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lireAttendu(t testing.TB) attenduRegistre {
	t.Helper()
	var a attenduRegistre
	if err := json.Unmarshal(lire(t, filepath.Join(racineRegistre, "attendu.json")), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func partie(t testing.TB, chemin string) registre.Partie {
	return registre.Partie{Presente: true, Etat: entree.Lu, Octets: lire(t, chemin)}
}

func lireAncresFichier(t testing.TB, nom string) *ancres.Ancres {
	t.Helper()
	a, d := ancres.AnalyserAncres(lire(t, filepath.Join(racineAncres, nom)), nil)
	if d != nil {
		t.Fatalf("%s : %s", nom, d.Message.Fr)
	}
	return a
}

// clesDossier : les clés de cles.json du dossier complet (CT-1 §13).
func clesDossier(t testing.TB) []ancres.CleDossier {
	v, err := jsonv.Analyser(lire(t, filepath.Join(dossierComplet, "cles.json")))
	if err != nil {
		t.Fatal(err)
	}
	var out []ancres.CleDossier
	for _, k := range v.Membre("keys").Elements {
		out = append(out, ancres.CleDossier{KeyID: k.Membre("key_id").S(), ClePublique: k.Membre("public_key").S()})
	}
	return out
}

// manifeste lit un manifeste de CT-1 et son periodHash publié.
func manifeste(t testing.TB, chemin, periodHash string) registre.Manifeste {
	v, err := jsonv.Analyser(lire(t, filepath.Join(racineVecteurs, "..", "..", chemin)))
	if err != nil {
		t.Fatal(err)
	}
	m := registre.Manifeste{Valide: true, OrgID: v.Membre("org_id").S(), JournalID: v.Membre("journal_id").S(), Root: v.Membre("root").S(), RecorderKeyID: v.Membre("recorder_key_id").S()}
	m.PeriodStart, _ = v.Membre("period_start").Entier()
	m.PeriodEnd, _ = v.Membre("period_end").Entier()
	m.FirstSeq, _ = v.Membre("first_seq").Entier()
	m.LastSeq, _ = v.Membre("last_seq").Entier()
	m.Version, _ = v.Membre("version").Entier()
	h, ok := cryptographie.LireHex(periodHash, 32)
	if !ok {
		t.Fatalf("periodHash illisible : %s", periodHash)
	}
	copy(m.PeriodHash[:], h)
	return m
}

func entreeJeu(t testing.TB, a attenduRegistre, j jeuAttendu) registre.Entree {
	rep := filepath.Join(racineRegistre, j.Parties)
	e := registre.Entree{
		Registre:   partie(t, filepath.Join(rep, "registre.json")),
		Certificat: partie(t, filepath.Join(rep, "certificat-commit.json")),
	}
	if j.ValidateursPresent {
		e.Validateurs = partie(t, filepath.Join(rep, "validateurs.json"))
	} else {
		e.Validateurs = registre.Partie{RaisonAbsence: "partie non jointe"}
	}
	if j.Ancres != nil {
		e.Ancres = lireAncresFichier(t, *j.Ancres)
	}
	var ph string
	for _, m := range a.Manifestes {
		if strings.HasSuffix(j.Manifeste, filepath.Base(m.Fichier)) {
			ph = m.PeriodHash
		}
	}
	e.Manifeste = manifeste(t, j.Manifeste, ph)
	e.OrgID, e.JournalID = e.Manifeste.OrgID, e.Manifeste.JournalID
	e.ClesExploitables = true
	e.Cles = clesDossier(t)
	if cp := j.Checkpoint; cp != nil {
		h, _ := cryptographie.LireHex(cp.CheckpointHash, 32)
		p := &registre.Point{K2: true, KeyID: cp.KeyID}
		copy(p.CheckpointHash[:], h)
		r := cp.Reference
		p.Reference = &registre.ReferencePoint{ChainID: r.ChainID, Contract: r.Contract, Fingerprint: r.Fingerprint, DocType: r.DocType, BlockNumber: r.BlockNumber, BlockHash: r.BlockHash, TransactionHash: r.TransactionHash, LogIndex: r.LogIndex}
		e.Point = p
	}
	return e
}

func etat(v commun.Verification) string {
	if v.Statut == commun.NonExecute {
		return string(v.Statut) + ":" + string(v.Raison)
	}
	return string(v.Statut)
}

// TestVecteursRegistre rejoue les jeux de parties et les variantes.
func TestVecteursRegistre(t *testing.T) {
	a := lireAttendu(t)
	jeux := append(append([]jeuAttendu{}, a.JeuxDeParties...), a.Variantes...)
	if len(jeux) != 23 {
		t.Errorf("%d jeux, 23 attendus", len(jeux))
	}
	for _, j := range jeux {
		t.Run(j.Nom, func(t *testing.T) {
			e := entreeJeu(t, a, j)
			r := registre.Verifier(e)
			obtenus := map[string]string{}
			for _, v := range r.Verifications {
				obtenus[v.ID] = etat(v)
				if len(v.Controles) != 1 || v.Controles[0] != 8 {
					t.Errorf("%s : contrôles %v", v.ID, v.Controles)
				}
			}
			if r.N4 != nil {
				obtenus["N-4"] = etat(*r.N4)
			}
			if (r.N4 != nil) != j.N4Present || e.N4Figure() != j.N4Present {
				t.Errorf("N-4 figure : %v, attendu %v", r.N4 != nil, j.N4Present)
			}
			for id, st := range j.Statuses {
				if obtenus[id] != st {
					d := ""
					for _, v := range r.Verifications {
						if v.ID == id {
							d = v.Detail.Fr
						}
					}
					t.Errorf("%s : %s, attendu %s (%s)", id, obtenus[id], st, d)
				}
			}
			for id := range obtenus {
				if _, ok := j.Statuses[id]; !ok {
					t.Errorf("%s figure (%s) sans être attendue", id, obtenus[id])
				}
			}
			if string(r.Statut) != j.ControlStatus {
				t.Errorf("contrôle 8 : %s, attendu %s", r.Statut, j.ControlStatus)
			}
			raison := ""
			if j.ControlReason != nil {
				raison = *j.ControlReason
			}
			if string(r.Raison) != raison {
				t.Errorf("raison du contrôle 8 : %q, attendu %q", r.Raison, raison)
			}
			var av []string
			for _, x := range r.Avertissements {
				av = append(av, x.ID)
			}
			if strings.Join(av, ",") != strings.Join(j.Warnings, ",") {
				t.Errorf("avertissements %v, attendu %v", av, j.Warnings)
			}
			if (r.Faits != nil) != (r.Statut == commun.Reussi) || r.Proposition.Vide() == (r.Statut == commun.Reussi) {
				t.Errorf("faits ou proposition hors d'un contrôle réussi")
			}
			if j.Statement != nil {
				if r.Proposition.Fr != j.Statement.Fr {
					t.Errorf("proposition fr :\n obtenue %s\n attendue %s", r.Proposition.Fr, j.Statement.Fr)
				}
				if r.Proposition.En != j.Statement.En {
					t.Errorf("proposition en :\n obtenue %s\n attendue %s", r.Proposition.En, j.Statement.En)
				}
			}
			if len(j.Facts) > 0 && string(j.Facts) != "null" {
				comparerJSON(t, "faits", r.Faits, j.Facts)
			}
		})
	}
}

// comparerJSON compare une valeur Go, sérialisée, à un JSON attendu.
func comparerJSON(t *testing.T, nom string, obtenu any, attendu json.RawMessage) {
	t.Helper()
	b, err := json.Marshal(obtenu)
	if err != nil {
		t.Fatal(err)
	}
	var x, y any
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(attendu, &y); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(x, y) {
		t.Errorf("%s :\n obtenus %s\n attendus %s", nom, b, attendu)
	}
}
