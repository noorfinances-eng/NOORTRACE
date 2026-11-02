package ots

// Rejeu des vecteurs de CT-6 annexe A.4 (spec/vecteurs/ct-6/ots) et des
// vérifications O- et K-9 des dossiers de spec/vecteurs/ct-6/dossiers
// (annexe A.7, EX-A.16), sans le moteur : chaque entrée est construite ici
// depuis les fichiers des vecteurs.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

const (
	repOTS      = "../../spec/vecteurs/ct-6/ots"
	repAncres   = "../../spec/vecteurs/ct-6/ancres"
	repDossiers = "../../spec/vecteurs/ct-6/dossiers"
	// periodHash de la période 1 (EX-A.2), celle de tous les dossiers.
	periodHash1 = "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914"
)

type etatAttendu struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Reason *string `json:"reason"`
}

type attestationAttendue struct {
	Kind   string  `json:"kind"`
	Height *int64  `json:"height"`
	URI    *string `json:"uri"`
	Result *string `json:"result"`
}

type attenduOTS struct {
	BitcoinAnchor struct {
		Network    string `json:"network"`
		Checkpoint struct {
			Height int64  `json:"height"`
			Hash   string `json:"hash"`
		} `json:"checkpoint"`
		MinConfirmations int `json:"min_confirmations"`
	} `json:"bitcoin_anchor"`
	Headers map[string]struct {
		Sha256      string            `json:"sha256"`
		StartHeight int64             `json:"start_height"`
		EndHeight   int64             `json:"end_height"`
		Hashes      map[string]string `json:"hashes"`
	} `json:"headers"`
	Proofs []struct {
		File         string                `json:"file"`
		Sha256       string                `json:"sha256"`
		Size         int                   `json:"size"`
		FileDigest   string                `json:"file_digest"`
		Target       *string               `json:"target"`
		Attestations []attestationAttendue `json:"attestations"`
	} `json:"proofs"`
	Cases []struct {
		Proof             string          `json:"proof"`
		DossierPeriodHash string          `json:"dossier_period_hash"`
		Headers           *string         `json:"headers"`
		Anchors           *string         `json:"anchors"`
		Checks            []etatAttendu   `json:"checks"`
		FailedChecks      []string        `json:"failed_checks"`
		ControlStatus     string          `json:"control_status"`
		ControlReason     *string         `json:"control_reason"`
		Warnings          []string        `json:"warnings"`
		Facts             json.RawMessage `json:"facts"`
		Checkpoint        *struct {
			CheckpointHash string `json:"checkpoint_hash"`
			Check          string `json:"check"`
		} `json:"checkpoint"`
	} `json:"cases"`
}

func lireFichier(t *testing.T, chemin string) []byte {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lireAttenduOTS(t *testing.T) *attenduOTS {
	t.Helper()
	var a attenduOTS
	if err := json.Unmarshal(lireFichier(t, filepath.Join(repOTS, "attendu.json")), &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, ok := cryptographie.LireHex(s, 32)
	if !ok {
		t.Fatalf("hexadécimal invalide %q", s)
	}
	var r [32]byte
	copy(r[:], b)
	return r
}

func lireEntetes(t *testing.T, chemin string) *ancres.Entetes {
	t.Helper()
	e, d := ancres.AnalyserEntetes(lireFichier(t, chemin))
	if d != nil {
		t.Fatalf("%s : %v", chemin, d)
	}
	return e
}

func lireAncreBitcoin(t *testing.T, chemin string) *ancres.Bitcoin {
	t.Helper()
	a, d := ancres.AnalyserAncres(lireFichier(t, chemin), nil)
	if d != nil {
		t.Fatalf("%s : %v", chemin, d)
	}
	return a.Bitcoin
}

// rangVerification : ordre du rapport (EX-5.2) restreint à ce paquet : K-9
// avant O-1 … O-7.
func rangVerification(id string) int {
	if id == "K-9" {
		return 0
	}
	for i, x := range IDs {
		if x == id {
			return i + 1
		}
	}
	return 100
}

// trierAvertissements applique le tri du moteur (EX-6.15) : rang de la
// vérification, puis identifiant, ordre du paquet gardé sinon.
func trierAvertissements(av []commun.Avertissement) []string {
	a := append([]commun.Avertissement{}, av...)
	sort.SliceStable(a, func(i, j int) bool {
		ri, rj := rangVerification(a[i].Verification), rangVerification(a[j].Verification)
		if ri != rj {
			return ri < rj
		}
		return a[i].ID < a[j].ID
	})
	var ids []string
	for _, x := range a {
		ids = append(ids, x.ID)
	}
	return ids
}

func egales(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestVecteursPreuves : lecture (O-1) et résultats des opérations (O-3) de
// chaque fichier de preuves/, contre attendu.json (EX-A.7, EX-A.14).
func TestVecteursPreuves(t *testing.T) {
	a := lireAttenduOTS(t)
	if len(a.Proofs) != 12 {
		t.Fatalf("%d preuves, 12 attendues", len(a.Proofs))
	}
	for _, p := range a.Proofs {
		t.Run(p.File, func(t *testing.T) {
			b := lireFichier(t, filepath.Join(repOTS, p.File))
			if len(b) != p.Size || cryptographie.Hex32(cryptographie.Sha256(b)) != p.Sha256 {
				t.Fatalf("fichier différent de celui de attendu.json")
			}
			pr, d := Analyser(b)
			if p.Target != nil && *p.Target == "O-1" {
				if d == nil {
					t.Fatal("O-1 aurait dû refuser le fichier")
				}
				return
			}
			if d != nil {
				t.Fatalf("O-1 refuse le fichier : %v", d)
			}
			if cryptographie.Hex32(pr.Empreinte) != p.FileDigest {
				t.Errorf("empreinte %s, %s attendue", cryptographie.Hex32(pr.Empreinte), p.FileDigest)
			}
			x := executer(pr)
			if len(x.Attestations) != len(p.Attestations) {
				t.Fatalf("%d attestations, %d attendues", len(x.Attestations), len(p.Attestations))
			}
			for i, at := range p.Attestations {
				g := x.Attestations[i]
				if g.Genre != at.Kind {
					t.Errorf("attestation %d : genre %s, %s attendu", i, g.Genre, at.Kind)
				}
				if at.Height != nil && int64(g.Hauteur) != *at.Height {
					t.Errorf("attestation %d : hauteur %d, %d attendue", i, g.Hauteur, *at.Height)
				}
				if at.URI != nil && g.URI != *at.URI {
					t.Errorf("attestation %d : URI %q, %q attendue", i, g.URI, *at.URI)
				}
				switch {
				case at.Result == nil && g.Calcule:
					t.Errorf("attestation %d : résultat calculé, aucun attendu", i)
				case at.Result != nil && (!g.Calcule || g.Longueur != 32 || cryptographie.Hex32(g.Resultat) != *at.Result):
					t.Errorf("attestation %d : résultat %s, %s attendu", i, cryptographie.Hex32(g.Resultat), *at.Result)
				}
			}
		})
	}
}

// TestVecteursEntetes : hauteurs et hachages (ordre d'affichage) des
// fichiers d'en-têtes (EX-A.6, EX-A.14).
func TestVecteursEntetes(t *testing.T) {
	a := lireAttenduOTS(t)
	for nom, h := range a.Headers {
		t.Run(nom, func(t *testing.T) {
			b := lireFichier(t, filepath.Join(repOTS, nom))
			if cryptographie.Hex32(cryptographie.Sha256(b)) != h.Sha256 {
				t.Fatal("fichier différent de celui de attendu.json")
			}
			c := nouvelleChaine(lireEntetes(t, filepath.Join(repOTS, nom)))
			if int64(c.s) != h.StartHeight || int64(c.t) != h.EndHeight {
				t.Fatalf("hauteurs %d à %d, %d à %d attendues", c.s, c.t, h.StartHeight, h.EndHeight)
			}
			for i := c.s; i <= c.t; i++ {
				if g, w := cryptographie.Hex32(c.hachageAffiche(i)), h.Hashes[commun.Entier(int64(i))]; g != w {
					t.Errorf("hachage %d : %s, %s attendu", i, g, w)
				}
			}
		})
	}
}

// TestVecteursCas : les vingt cas de attendu.json (statuts de O-1 à O-7,
// statut du contrôle 5 ou de K-9, avertissements, faits).
func TestVecteursCas(t *testing.T) {
	a := lireAttenduOTS(t)
	if len(a.Cases) != 20 {
		t.Fatalf("%d cas, 20 attendus", len(a.Cases))
	}
	ancreTest := lireAncreBitcoin(t, filepath.Join(repAncres, "ancres-test.json"))
	if ancreTest.Reseau != a.BitcoinAnchor.Network || int64(ancreTest.Hauteur) != a.BitcoinAnchor.Checkpoint.Height ||
		cryptographie.Hex32(ancreTest.Hachage) != a.BitcoinAnchor.Checkpoint.Hash || ancreTest.MinConfirmations != a.BitcoinAnchor.MinConfirmations {
		t.Fatal("ancre bitcoin de ancres-test.json différente de celle de attendu.json")
	}
	for i, cas := range a.Cases {
		nom := commun.Entier(int64(i)) + " " + cas.Proof
		if cas.Headers != nil {
			nom += " " + *cas.Headers
		}
		t.Run(nom, func(t *testing.T) {
			e := Entree{Usage: Cloture, Etat: entree.Lu, Preuve: lireFichier(t, filepath.Join(repOTS, cas.Proof)), EmpreinteDisponible: true}
			e.EmpreinteAttendue = hex32(t, cas.DossierPeriodHash)
			if cas.Checkpoint != nil {
				e.Usage = Point
				e.EmpreinteAttendue = hex32(t, cas.Checkpoint.CheckpointHash)
			}
			if cas.Headers != nil {
				e.Entetes = lireEntetes(t, filepath.Join(repOTS, *cas.Headers))
			}
			if cas.Anchors != nil {
				e.Ancre = ancreTest
			}
			r := Verifier(e)
			verifierForme(t, e, r)
			var echecs []string
			for k, w := range cas.Checks {
				g := r.Verifications[k]
				wr := ""
				if w.Reason != nil {
					wr = *w.Reason
				}
				if g.ID != w.ID || string(g.Statut) != w.Status || string(g.Raison) != wr {
					t.Errorf("%s : %s %s, %s %s %s attendu (%s)", w.ID, g.Statut, g.Raison, w.ID, w.Status, wr, g.Detail.Fr)
				}
				if g.Statut == commun.Echoue {
					echecs = append(echecs, g.ID)
				}
			}
			if !egales(echecs, cas.FailedChecks) && !(len(echecs) == 0 && len(cas.FailedChecks) == 0) {
				t.Errorf("échecs %v, %v attendus", echecs, cas.FailedChecks)
			}
			wr := ""
			if cas.ControlReason != nil {
				wr = *cas.ControlReason
			}
			if string(r.Statut) != cas.ControlStatus || string(r.Raison) != wr {
				t.Errorf("statut %s %s, %s %s attendu", r.Statut, r.Raison, cas.ControlStatus, wr)
			}
			if g := trierAvertissements(r.Avertissements); !egales(g, cas.Warnings) && !(len(g) == 0 && len(cas.Warnings) == 0) {
				t.Errorf("avertissements %v, %v attendus", g, cas.Warnings)
			}
			if string(cas.Facts) == "null" || len(cas.Facts) == 0 {
				if r.Faits != nil {
					t.Errorf("faits rendus, aucun attendu")
				}
				return
			}
			g, err := json.Marshal(r.Faits)
			if err != nil {
				t.Fatal(err)
			}
			var cg, cw bytes.Buffer
			if err := json.Compact(&cg, g); err != nil {
				t.Fatal(err)
			}
			if err := json.Compact(&cw, cas.Facts); err != nil {
				t.Fatal(err)
			}
			if cg.String() != cw.String() {
				t.Errorf("faits\n%s\nattendus\n%s", cg.String(), cw.String())
			}
		})
	}
}

// verifierForme : invariants du contrat (INTERFACES.md, règles 3, 7, 9).
func verifierForme(t *testing.T, e Entree, r Resultat) {
	t.Helper()
	if len(r.Verifications) != len(IDs) {
		t.Fatalf("%d vérifications, 7 attendues", len(r.Verifications))
	}
	for i, v := range r.Verifications {
		if v.ID != IDs[i] {
			t.Errorf("vérification %d : %s, %s attendue", i, v.ID, IDs[i])
		}
		if len(v.Controles) != 1 || v.Controles[0] != 5 {
			t.Errorf("%s : contrôles %v", v.ID, v.Controles)
		}
		switch v.Statut {
		case commun.Reussi, commun.Echoue:
			if v.Raison != commun.Aucune {
				t.Errorf("%s : raison %s sur un statut %s", v.ID, v.Raison, v.Statut)
			}
		case commun.NonExecute:
			if v.Raison != commun.PrerequisEnEchec && !v.Raison.Admise() || v.Raison == commun.PieceHorsDossier {
				t.Errorf("%s : raison %q hors de la liste fermée", v.ID, v.Raison)
			}
		default:
			t.Errorf("%s : statut %q", v.ID, v.Statut)
		}
		if v.Detail.Fr == "" || v.Detail.En == "" {
			t.Errorf("%s : détail vide %+v", v.ID, v.Detail)
		}
	}
	if r.Statut == commun.NonExecute && (r.Raison == commun.Aucune || r.Raison == commun.AConstruire) ||
		r.Statut != commun.NonExecute && r.Raison != commun.Aucune {
		t.Errorf("statut %s, raison %q", r.Statut, r.Raison)
	}
	if (r.Faits != nil) != (r.Statut == commun.Reussi) {
		t.Errorf("faits %v pour le statut %s", r.Faits != nil, r.Statut)
	}
	if r.Faits != nil && r.Faits.Attestations == nil {
		t.Error("attestations nil")
	}
	if r.Avertissements == nil || r.AncresEmployees == nil {
		t.Error("tranche nil")
	}
	for _, a := range r.Avertissements {
		if a.Detail.Fr == "" || a.Detail.En == "" || !strings.HasPrefix(a.ID, "AV-O-") || rangVerification(a.Verification) == 100 {
			t.Errorf("avertissement %+v", a)
		}
	}
	reussi := r.Statut == commun.Reussi
	if reussi == r.Resume.Vide() {
		t.Errorf("résumé %+v pour le statut %s", r.Resume, r.Statut)
	}
	if (reussi && e.Usage == Cloture) == r.Proposition.Vide() {
		t.Errorf("proposition %+v pour le statut %s", r.Proposition, r.Statut)
	}
}

// partieAttendue : statut attendu d'une vérification d'après attendu.json
// d'un dossier (failed_checks, not_executed ; réussie sinon).
func statutAttendu(echecs []string, nonExec []etatAttendu, id string) (string, string) {
	for _, x := range echecs {
		if x == id {
			return "echoue", ""
		}
	}
	for _, x := range nonExec {
		if x.ID == id {
			r := ""
			if x.Reason != nil {
				r = *x.Reason
			}
			return "non_execute", r
		}
	}
	return "reussi", ""
}

type attenduDossier struct {
	FailedChecks    []string          `json:"failed_checks"`
	ControlStatuses map[string]string `json:"control_statuses"`
	NotExecuted     []etatAttendu     `json:"not_executed"`
	Warnings        []string          `json:"warnings"`
	Anchors         *string           `json:"anchors"`
	BitcoinHeaders  *string           `json:"bitcoin_headers"`
	Statement       *struct {
		Fr string `json:"fr"`
		En string `json:"en"`
	} `json:"statement"`
}

// TestVecteursDossiers : pour chaque dossier de ct-6 qui porte preuve.ots
// ou une preuve de point, les statuts de O-1 à O-7 et de K-9, le statut du
// contrôle 5 (K-9 comprise, EX-10.12), les avertissements AV-O-, et la
// proposition F5 dans l'énoncé attendu.
func TestVecteursDossiers(t *testing.T) {
	ents, err := os.ReadDir(repDossiers)
	if err != nil {
		t.Fatal(err)
	}
	vus, frags := 0, 0
	for _, d := range ents {
		if !d.IsDir() {
			continue
		}
		rep := filepath.Join(repDossiers, d.Name())
		t.Run(d.Name(), func(t *testing.T) {
			var at attenduDossier
			if err := json.Unmarshal(lireFichier(t, filepath.Join(rep, "attendu.json")), &at); err != nil {
				t.Fatal(err)
			}
			var idx struct {
				Parts []struct {
					Name    string `json:"name"`
					Present bool   `json:"present"`
				} `json:"parts"`
			}
			if err := json.Unmarshal(lireFichier(t, filepath.Join(rep, "dossier.json")), &idx); err != nil {
				t.Fatal(err)
			}
			presentes := map[string]bool{}
			for _, p := range idx.Parts {
				presentes[p.Name] = p.Present
			}
			if !presentes["preuve_ots"] {
				t.Skip("preuve.ots absente : contrôle 5 non exécuté par le moteur (EX-4.3)")
			}
			vus++
			base := Entree{}
			if at.BitcoinHeaders != nil {
				base.Entetes = lireEntetes(t, filepath.Join(rep, *at.BitcoinHeaders))
			}
			if at.Anchors != nil {
				base.Ancre = lireAncreBitcoin(t, filepath.Join(rep, *at.Anchors))
			}
			e := base
			e.Usage, e.Etat = Cloture, entree.Lu
			e.Preuve = lireFichier(t, filepath.Join(rep, "preuve.ots"))
			e.EmpreinteAttendue = hex32(t, periodHash1)
			s, _ := statutAttendu(at.FailedChecks, at.NotExecuted, "P-1")
			e.EmpreinteDisponible = s == "reussi"
			r := Verifier(e)
			verifierForme(t, e, r)
			for _, v := range r.Verifications {
				ws, wr := statutAttendu(at.FailedChecks, at.NotExecuted, v.ID)
				if string(v.Statut) != ws || string(v.Raison) != wr {
					t.Errorf("%s : %s %s, %s %s attendu (%s)", v.ID, v.Statut, v.Raison, ws, wr, v.Detail.Fr)
				}
			}
			avert := append([]commun.Avertissement{}, r.Avertissements...)
			statut5, raison5 := r.Statut, r.Raison
			// K-9 (EX-10.16), quand le moteur appellerait le paquet.
			if presentes["points_de_controle"] {
				ks, kr := statutAttendu(at.FailedChecks, at.NotExecuted, "K-9")
				var pt struct {
					CheckpointHash string `json:"checkpoint_hash"`
					Anchors        struct {
						OTS *struct {
							Proof string `json:"proof"`
						} `json:"ots"`
					} `json:"anchors"`
				}
				_ = json.Unmarshal(lireFichier(t, filepath.Join(rep, "points-de-controle.json")), &pt)
				appele := pt.Anchors.OTS != nil && kr != "prerequis_en_echec"
				if appele {
					b, err := cryptographie.Base64Canonique(pt.Anchors.OTS.Proof)
					if err != nil {
						t.Fatal(err)
					}
					ek := base
					ek.Usage, ek.Etat, ek.Preuve = Point, entree.Lu, b
					ek.EmpreinteAttendue, ek.EmpreinteDisponible = hex32(t, pt.CheckpointHash), true
					rk := Verifier(ek)
					verifierForme(t, ek, rk)
					if string(rk.Statut) != ks || string(rk.Raison) != kr {
						t.Errorf("K-9 : %s %s, %s %s attendu", rk.Statut, rk.Raison, ks, kr)
					}
					for _, a := range rk.Avertissements {
						a.Verification = "K-9"
						avert = append(avert, a)
					}
					if rk.Statut == commun.Echoue {
						statut5, raison5 = commun.Echoue, commun.Aucune
					}
				}
			}
			if w := at.ControlStatuses["5"]; string(statut5) != w {
				t.Errorf("contrôle 5 : %s %s, %s attendu", statut5, raison5, w)
			}
			var wav []string
			for _, w := range at.Warnings {
				if strings.HasPrefix(w, "AV-O-") {
					wav = append(wav, w)
				}
			}
			if g := trierAvertissements(avert); !egales(g, wav) && !(len(g) == 0 && len(wav) == 0) {
				t.Errorf("avertissements %v, %v attendus", g, wav)
			}
			if r.Statut == commun.Reussi && at.Statement != nil && !strings.HasPrefix(at.Statement.Fr, "Dossier invalide") {
				frags++
				if !strings.Contains(at.Statement.Fr, " ; "+r.Proposition.Fr+" ; ") && !strings.HasSuffix(at.Statement.Fr, " ; "+r.Proposition.Fr+".") {
					t.Errorf("proposition française absente de l'énoncé attendu :\n%s", r.Proposition.Fr)
				}
				if !strings.Contains(at.Statement.En, "; "+r.Proposition.En+"; ") && !strings.HasSuffix(at.Statement.En, "; "+r.Proposition.En+".") {
					t.Errorf("proposition anglaise absente de l'énoncé attendu :\n%s", r.Proposition.En)
				}
			}
		})
	}
	if vus < 60 || frags < 20 {
		t.Errorf("%d dossiers avec preuve.ots rejoués, %d propositions comparées : trop peu", vus, frags)
	}
}
