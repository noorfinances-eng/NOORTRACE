package dossier

// Essais de la revue de sécurité interne de l'étape 8, sur des copies
// des dossiers publiés de CT-1 et CT-6 modifiées sous un répertoire
// temporaire : EX-4.6 (E-6 et le répertoire --pieces), (A-3 sans
// panique sur un terme absent), EX-15.1 (événements de approbations.json
// bornés, détails bornés) et N-1 (branches de rejet sans essai : C-1,
// A-3, E-10, AT-1).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

const (
	dossierSeq7        = "../../spec/vecteurs/ct-1/dossiers/valide-seq-7"
	dossierAttestation = "../../spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet-attestation"
	// dossierAttestationInscrite : attestation inscrite au journal (membre
	// inscription non nul).
	dossierAttestationInscrite = "../../spec/vecteurs/ct-1/dossiers/valide-seq-12-attestation-inscrite"
)

// copierDossier copie un dossier publié dans un répertoire temporaire.
func copierDossier(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// remplacerPartie réécrit une partie et reporte son SHA-256 dans l'index.
func remplacerPartie(t *testing.T, rep, fichier string, contenu []byte) {
	t.Helper()
	ancien, err := os.ReadFile(filepath.Join(rep, fichier))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rep, fichier), contenu, 0o644); err != nil {
		t.Fatal(err)
	}
	a, n := sha256.Sum256(ancien), sha256.Sum256(contenu)
	idx, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	s := strings.Replace(string(idx), "0x"+hex.EncodeToString(a[:]), "0x"+hex.EncodeToString(n[:]), 1)
	if err := os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// modifierJSON relit une partie comme un objet décodé, la modifie par f et
// la réécrit.
func modifierJSON(t *testing.T, rep, fichier string, f func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rep, fichier))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	f(v)
	n, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	remplacerPartie(t, rep, fichier, n)
}

// analyserRep ouvre et analyse un dossier ; aucun code 2 n'est attendu, et
// une panique (que le moteur rendrait en code 2, erreur_interne) est un
// échec de l'oracle, jamais un arrêt de l'essai.
func analyserRep(t *testing.T, rep string, opt Options) (a *Analyse) {
	t.Helper()
	d, def := Ouvrir(rep)
	if def != nil {
		t.Fatalf("Ouvrir : %s", def.Message.Fr)
	}
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("Analyser : panique (code 2, erreur_interne) : %v", p)
		}
	}()
	a, def = Analyser(d, opt)
	if def != nil {
		t.Fatalf("Analyser : code 2 (%s) : %s", def.Genre, def.Message.Fr)
	}
	return a
}

func statutDe(t *testing.T, a *Analyse, id string) commun.Verification {
	t.Helper()
	v, ok := a.Statut(id)
	if !ok {
		t.Fatalf("%s absente du rapport", id)
	}
	return v
}

// TestA3TermesAbsents : CT-1 A-3. Une approbation sans approver_set, sans
// members, sans approvers ou sans signatures ne fait plus paniquer A-3 : la
// relation n'est pas tenue, A-3 échoue, le dossier est invalide (code 1).
func TestA3TermesAbsents(t *testing.T) {
	cas := []struct {
		nom    string
		muter  func(t *testing.T, rep string)
		detail string
	}{
		{"approbations.json réduit à {}", func(t *testing.T, rep string) { remplacerPartie(t, rep, "approbations.json", []byte(`{}`)) }, "approver_set absent"},
		{"approver_set null", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) { v["approver_set"] = nil })
		}, "approver_set absent"},
		{"approver_set retiré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) { delete(v, "approver_set") })
		}, "approver_set absent"},
		{"approver_set.members retiré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) { delete(v["approver_set"].(map[string]any), "members") })
		}, "approver_set.members absent"},
		{"approval = {} dans evenement.json", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"] = map[string]any{} })
		}, "approval.approvers absent"},
		{"approval.approvers retiré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { delete(v["approval"].(map[string]any), "approvers") })
		}, "approval.approvers absent"},
		{"decision expire et approval.signatures retiré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) {
				ap := v["approval"].(map[string]any)
				ap["decision"] = "expire"
				delete(ap, "signatures")
			})
		}, "approval.signatures absent"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierSeq7)
			c.muter(t, rep)
			a := analyserRep(t, rep, Options{})
			v := statutDe(t, a, "A-3")
			if v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, c.detail) {
				t.Errorf("A-3 %s (%s), attendu echoue avec « %s »", v.Statut, v.Detail.Fr, c.detail)
			}
		})
	}
}

// TestE6PiecesHorsRepertoire : CT-6 EX-4.6. Une référence dont sha256 n'est pas
// un SHA-256 hexadécimal n'ouvre aucun fichier (un nom de 64 caractères fait
// de « .. » et « / » sortait du répertoire --pieces et publiait le SHA-256
// d'un fichier du poste) ; une entrée du répertoire qui porte le bon nom
// sans être un fichier ordinaire n'est pas ouverte et rend l'entrée
// inutilisable (code 2, EX-4.17) ; une pièce ordinaire est lue et comparée.
func TestE6PiecesHorsRepertoire(t *testing.T) {
	base := t.TempDir()
	pieces := filepath.Join(base, "pieces")
	if err := os.Mkdir(pieces, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := []byte("contenu du poste du réviseur\n")
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), secret, 0o644); err != nil {
		t.Fatal(err)
	}
	shaSecret := sha256.Sum256(secret)
	hors := "0x.." + strings.Repeat("/", 52) + "secret.txt" // 64 caractères après 0x
	if len(hors) != 66 {
		t.Fatalf("nom de %d caractères", len(hors))
	}
	t.Run("nom hors motif : rien n'est ouvert", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq7)
		modifierJSON(t, rep, "evenement.json", func(v map[string]any) { sous(v, "execution", "arguments")["sha256"] = hors })
		a := analyserRep(t, rep, Options{RepertoirePieces: pieces})
		v := statutDe(t, a, "E-6")
		if a.PiecesLues() != 0 || strings.Contains(v.Detail.Fr, hex.EncodeToString(shaSecret[:])) || strings.Contains(v.Detail.Fr, "secret") {
			t.Errorf("pièces lues %d, E-6 %s : %s", a.PiecesLues(), v.Statut, v.Detail.Fr)
		}
	})
	piece := []byte("pièce fournie à part")
	shaPiece := sha256.Sum256(piece)
	nomPiece := hex.EncodeToString(shaPiece[:])
	avecReference := func(t *testing.T, length int) string {
		rep := copierDossier(t, dossierSeq7)
		modifierJSON(t, rep, "evenement.json", func(v map[string]any) {
			r := sous(v, "execution", "arguments")
			r["sha256"], r["length"] = "0x"+nomPiece, length
		})
		return rep
	}
	codeDeux := func(t *testing.T, rep, p string) {
		t.Helper()
		d, def := Ouvrir(rep)
		if def != nil {
			t.Fatal(def.Message.Fr)
		}
		a, def := Analyser(d, Options{RepertoirePieces: p})
		if a != nil || def == nil || def.Genre != "entree_illisible" || !strings.Contains(def.Message.Fr, "pas un fichier ordinaire") {
			t.Fatalf("attendu code 2 entree_illisible, obtenu %+v", def)
		}
	}
	t.Run("répertoire nommé par le sha256 : non ouvert, code 2 (EX-4.17)", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pieces")
		if err := os.MkdirAll(filepath.Join(p, nomPiece), 0o755); err != nil {
			t.Fatal(err)
		}
		codeDeux(t, avecReference(t, len(piece)), p)
	})
	t.Run("lien symbolique nommé par le sha256 : non suivi, code 2", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pieces")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		cible := filepath.Join(t.TempDir(), "cible")
		if err := os.WriteFile(cible, piece, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(cible, filepath.Join(p, nomPiece)); err != nil {
			t.Skip("liens symboliques indisponibles :", err)
		}
		codeDeux(t, avecReference(t, len(piece)), p)
	})
	t.Run("pièce ordinaire : lue et comparée", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pieces")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, nomPiece), piece, 0o644); err != nil {
			t.Fatal(err)
		}
		a := analyserRep(t, avecReference(t, len(piece)), Options{RepertoirePieces: p})
		if v := statutDe(t, a, "E-6"); v.Statut != commun.Reussi || a.PiecesLues() != 1 {
			t.Errorf("E-6 %s (%s), pièces lues %d", v.Statut, v.Detail.Fr, a.PiecesLues())
		}
		a = analyserRep(t, avecReference(t, len(piece)+1), Options{RepertoirePieces: p})
		if v := statutDe(t, a, "E-6"); v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, "pièce "+nomPiece) {
			t.Errorf("longueur fausse : E-6 %s (%s)", v.Statut, v.Detail.Fr)
		}
	})
	t.Run("pièce référencée mais non fournie : pas une erreur", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pieces")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		a := analyserRep(t, avecReference(t, len(piece)), Options{RepertoirePieces: p})
		if v := statutDe(t, a, "E-6"); v.Statut != commun.Reussi || a.PiecesLues() != 0 {
			t.Errorf("E-6 %s (%s), pièces lues %d", v.Statut, v.Detail.Fr, a.PiecesLues())
		}
	})
}

// TestEvenementsEnTropBornes : CT-6 EX-15.1. Un approbations.json dont events
// porte 1 500 éléments qui ne sont pas des objets : les 1 024 premiers sont
// jugés, les autres comptés ; A-1 échoue (enveloppe) ; les détails de E-1 et
// des vérifications non exécutées sont bornés à commun.DetailsMax éléments
// écrits un à un.
func TestEvenementsEnTropBornes(t *testing.T) {
	rep := copierDossier(t, dossierSeq7)
	modifierJSON(t, rep, "approbations.json", func(v map[string]any) {
		ev := make([]any, 1500)
		for i := range ev {
			ev[i] = 0
		}
		v["events"] = ev
	})
	a := analyserRep(t, rep, Options{})
	if len(a.decisionsInvalides) != MaxEvenementsApprobations || a.decisionsEnTrop != 476 {
		t.Fatalf("%d non-objets, %d en trop", len(a.decisionsInvalides), a.decisionsEnTrop)
	}
	a1, a2, e1, e3 := statutDe(t, a, "A-1"), statutDe(t, a, "A-2"), statutDe(t, a, "E-1"), statutDe(t, a, "E-3")
	if a1.Statut != commun.Echoue || a2.Statut != commun.Echoue || !strings.Contains(a2.Detail.Fr, "476 élément(s) au-delà des 1024") {
		t.Errorf("A-1 %s ; A-2 %s : %s", a1.Statut, a2.Statut, a2.Detail.Fr)
	}
	for _, v := range []commun.Verification{e1, e3, a2} {
		if n := strings.Count(v.Detail.Fr, " ; ") + 1; n > commun.DetailsMax+1 || !strings.Contains(v.Detail.Fr, "autre(s)") {
			t.Errorf("%s : %d éléments dans le détail (%d caractères)", v.ID, n, len(v.Detail.Fr))
		}
		if n := strings.Count(v.Detail.En, "; ") + 1; n > commun.DetailsMax+1 || !strings.Contains(v.Detail.En, "more") {
			t.Errorf("%s (en) : %d éléments dans le détail", v.ID, n)
		}
	}
	total := 0
	for _, v := range a.Verifs {
		total += len(v.Detail.Fr) + len(v.Detail.En)
	}
	if total > 64*1024 {
		t.Errorf("détails de CT-1 : %d octets en tout", total)
	}
}

// TestPartieValeursBornee : CT-6 EX-15.1. Une partie de CT-1 (16 Mio admis, donc
// 1 048 576 valeurs) faite de plus de valeurs que la borne n'est pas du JSON
// exploitable : la vérification qui la porte échoue (E-8 pour cles.json),
// et l'analyse n'a pas matérialisé ces valeurs.
func TestPartieValeursBornee(t *testing.T) {
	rep := copierDossier(t, dossierSeq7)
	cles := `{"version":0,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164","keys":[` + strings.TrimSuffix(strings.Repeat("0,", 1<<20), ",") + `]}`
	remplacerPartie(t, rep, "cles.json", []byte(cles))
	a := analyserRep(t, rep, Options{})
	p := a.Dossier.Partie(PCles)
	if p.Valeur != nil || !errors.Is(p.ErrJSON, jsonv.ErrValeurs) {
		t.Fatalf("cles.json lu : %v, %v", p.Valeur != nil, p.ErrJSON)
	}
	if v := statutDe(t, a, "E-8"); v.Statut != commun.Echoue {
		t.Errorf("E-8 %s : %s", v.Statut, v.Detail.Fr)
	}
}

// TestC1PreviousNulSeqDifferent : CT-6 N-1. previous nul alors que seq ≠ 1
// met C-1 en échec.
func TestC1PreviousNulSeqDifferent(t *testing.T) {
	rep := copierDossier(t, dossierSeq7)
	modifierJSON(t, rep, "voisins.json", func(v map[string]any) { v["previous"] = nil })
	a := analyserRep(t, rep, Options{})
	if v := statutDe(t, a, "C-1"); v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, "previous nul alors que seq ≠ 1") {
		t.Errorf("C-1 %s : %s", v.Statut, v.Detail.Fr)
	}
}

// TestA3Branches : CT-6 N-1. Approbateur hors du jeu déclaré, seuils
// différents, demande expirée qui porte des signatures.
func TestA3Branches(t *testing.T) {
	cas := []struct {
		nom    string
		muter  func(t *testing.T, rep string)
		detail string
	}{
		{"approbateur hors du jeu déclaré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) {
				m := v["approver_set"].(map[string]any)["members"].([]any)
				m[0] = "0x000000000000000000000000000000000000dead"
			})
		}, "approbateur hors du jeu déclaré"},
		{"threshold différents", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) {
				v["approver_set"].(map[string]any)["threshold"] = map[string]any{"required": 3, "size": 3}
			})
		}, "threshold de l'événement ≠ approver_set.threshold"},
		{"demande expirée qui porte des signatures", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"].(map[string]any)["decision"] = "expire" })
		}, "demande expirée qui porte des signatures"},
		{"required > size", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "approbations.json", func(v map[string]any) {
				v["approver_set"].(map[string]any)["threshold"] = map[string]any{"required": 4, "size": 3}
			})
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) {
				v["approval"].(map[string]any)["threshold"] = map[string]any{"required": 4, "size": 3}
			})
		}, "required > size"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierSeq7)
			c.muter(t, rep)
			a := analyserRep(t, rep, Options{})
			if v := statutDe(t, a, "A-3"); v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, c.detail) {
				t.Errorf("A-3 %s (%s), attendu « %s »", v.Statut, v.Detail.Fr, c.detail)
			}
		})
	}
}

// TestE10Branches : CT-6 N-1. Chaque règle de E-10 (CT-1 §8, §11.4) a son
// cas d'échec, sur l'événement de rotation seq 9 du journal publié et les
// clés de cles.json de valide-seq-7.
func TestE10Branches(t *testing.T) {
	j := evenementsJournal(t)
	an := analyserRep(t, copierDossier(t, dossierSeq7), Options{})
	if !an.ClesExploitables {
		t.Fatal("cles.json de valide-seq-7 inexploitable")
	}
	cas := []struct {
		nom     string
		subs    []string
		analyse *Analyse
		attendu commun.Statut
		detail  string
	}{
		{"témoin : rotation publiée", nil, an, commun.Reussi, "rotation rec-test-01 → rec-test-02"},
		{"old_key_id ≠ recorder_key_id", []string{`"old_key_id":"rec-test-01"`, `"old_key_id":"rec-test-00"`}, an, commun.Echoue, "old_key_id ≠ recorder_key_id"},
		{"valid_from ≠ ts", []string{`"valid_from":"2026-11-05T09:59:58.000Z"`, `"valid_from":"2026-11-05T09:59:59.000Z"`}, an, commun.Echoue, "valid_from ≠ ts"},
		{"new_key_id égal à old_key_id", []string{`"new_key_id":"rec-test-02"`, `"new_key_id":"rec-test-01"`}, an, commun.Echoue, "new_key_id vide ou égal à old_key_id"},
		{"counter_sig altérée", []string{`"counter_sig":"0x`, `"counter_sig":"0xff`}, an, commun.Echoue, "counter_sig invalide"},
		{"cles.json inexploitable", nil, &Analyse{}, commun.NonExecute, "cles.json inexploitable"},
		{"cles.json sans la nouvelle clé", nil, &Analyse{ClesExploitables: true, Cles: map[string]Cle{"rec-test-01": an.Cles["rec-test-01"]}}, commun.Echoue, "clé rec-test-02 absente"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			e := evt(t, j[9], c.subs...)
			r := c.analyse.regleE10(e)
			if r.statut != c.attendu || !strings.Contains(r.detail.Fr, c.detail) {
				t.Errorf("E-10 %s (%s), attendu %s avec « %s »", r.statut, r.detail.Fr, c.attendu, c.detail)
			}
		})
	}
	// Un événement qui n'est pas une rotation passe E-10.
	if r := an.regleE10(evt(t, j[7])); r.statut != commun.Reussi {
		t.Errorf("E-10 sur un appel : %s", r.statut)
	}
}

// TestAT1Branches : CT-6 N-1. Branches de rejet de la forme de l'attestation
// de périmètre (AT-1), sur le dossier publié à attestation.
func TestAT1Branches(t *testing.T) {
	cas := []struct {
		nom    string
		muter  func(v map[string]any)
		detail string
	}{
		{"validity.from postérieur à validity.until", func(v map[string]any) {
			sous(v, "signed", "attestation", "validity")["from"] = "2027-02-01T00:00:00.000Z"
		}, "validity.from postérieur à validity.until"},
		{"validité de plus de 366 jours", func(v map[string]any) {
			sous(v, "signed", "attestation", "validity")["until"] = "2028-01-31T23:59:59.999Z"
		}, "validité de plus de 366 jours"},
		{"date inexistante", func(v map[string]any) {
			sous(v, "signed", "attestation")["issued_at"] = "2026-02-30T16:00:00.000Z"
		}, "date inexistante dans l'attestation"},
		{"journal_id en double", func(v map[string]any) {
			js := sous(v, "signed", "attestation")["journals"].([]any)
			js[0].(map[string]any)["journal_id"] = js[1].(map[string]any)["journal_id"]
		}, "journal_id en double"},
		{"agent dont le journal_id n'est pas dans journals", func(v map[string]any) {
			ag := sous(v, "signed", "attestation")["agents"].([]any)
			ag[0].(map[string]any)["journal_id"] = "0x1111111111111111111111111111111111111111111111111111111111111111"
		}, "agent dont le journal_id n'est pas dans journals"},
		{"agent_id en double", func(v map[string]any) {
			ag := sous(v, "signed", "attestation")["agents"].([]any)
			ag[1].(map[string]any)["agent_id"] = ag[0].(map[string]any)["agent_id"]
		}, "agent_id en double"},
		{"adresse en double dans signatories", func(v map[string]any) {
			s := sous(v, "signed", "attestation")["signatories"].([]any)
			s[1].(map[string]any)["address"] = s[0].(map[string]any)["address"]
		}, "adresse en double dans signatories"},
		{"contraire au schéma (signed retiré)", func(v map[string]any) { delete(v, "signed") }, "contraire au schéma"},
		{"ts de l'inscription inexistant", func(v map[string]any) {
			sous(v, "inscription", "event")["ts"] = "2026-11-31T00:00:00.000Z"
		}, "ts de l'événement d'inscription"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			src := dossierAttestation
			if strings.Contains(c.nom, "inscription") {
				src = dossierAttestationInscrite
			}
			rep := copierDossier(t, src)
			modifierJSON(t, rep, "attestation-perimetre.json", c.muter)
			a := analyserRep(t, rep, Options{})
			if v := statutDe(t, a, "AT-1"); v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, c.detail) {
				t.Errorf("AT-1 %s (%s), attendu « %s »", v.Statut, v.Detail.Fr, c.detail)
			}
		})
	}
	// Témoin : le dossier publié passe AT-1.
	a := analyserRep(t, copierDossier(t, dossierAttestation), Options{})
	if v := statutDe(t, a, "AT-1"); v.Statut != commun.Reussi {
		t.Errorf("témoin : AT-1 %s (%s)", v.Statut, v.Detail.Fr)
	}
}
