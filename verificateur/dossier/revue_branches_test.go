package dossier

// Essais de la revue de sécurité interne de l'étape 8, suite de
// CT-6 N-1 : les branches de rejet que la grille du relecteur
// (« Essais Go ») nommait sans essai Go — C-3, P-5 (dont la continuité avec
// un second manifeste, EX-4.7, et le second manifeste précédent, chemin
// jamais exécuté), K-1 (chaque relation), K-3, K-4, K-6 et AT-4 — ont chacune
// un cas qui échoue quand la règle est retirée. Les dossiers sont des copies
// des vecteurs publiés de CT-1 modifiées sous un répertoire temporaire ; les
// signatures refaites emploient les seules clés de test publiées (graines de
// cles-test.json, comptes Hardhat des approbateurs).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

const (
	dossierPoint          = racineCT1 + "/valide-seq-7-point-de-controle"
	dossierAttestationJeu = racineCT1 + "/valide-seq-7-attestation-sans-inscription"
	clesDeTest            = "../../spec/vecteurs/ct-1/cles/cles-test.json"
	zeroHex32             = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

// attendreEchec : la vérification échoue et son détail porte le motif.
func attendreEchec(t *testing.T, a *Analyse, id, detail string) {
	t.Helper()
	v := statutDe(t, a, id)
	if v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, detail) {
		t.Errorf("%s %s (%s), attendu echoue avec « %s »", id, v.Statut, v.Detail.Fr, detail)
	}
}

// attendrePrerequis : la vérification n'est pas exécutée, prerequis_en_echec,
// et son détail porte le motif.
func attendrePrerequis(t *testing.T, a *Analyse, id, detail string) {
	t.Helper()
	v := statutDe(t, a, id)
	if v.Statut != commun.NonExecute || v.Raison != commun.PrerequisEnEchec || !strings.Contains(v.Detail.Fr, detail) {
		t.Errorf("%s %s/%s (%s), attendu non_execute (prerequis_en_echec) avec « %s »", id, v.Statut, v.Raison, v.Detail.Fr, detail)
	}
}

// lireJSON relit une partie comme un objet décodé.
func lireJSON(t *testing.T, rep, fichier string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rep, fichier))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// valeurDe rend la valeur jsonv d'un objet décodé.
func valeurDe(t *testing.T, v map[string]any) *jsonv.Valeur {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	x, err := jsonv.Analyser(b)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// periodHashDe rend le periodHash (CT-1 §10.2) d'un manifeste décodé.
func periodHashDe(t *testing.T, m map[string]any) string {
	t.Helper()
	cm, err := jcs.Canonique(valeurDe(t, m))
	if err != nil {
		t.Fatal(err)
	}
	return cryptographie.Hex32(cryptographie.Sha256(cryptographie.PrefixeManifeste, cm))
}

// TestC3Branches : CT-6 N-1. C-3 (CT-1 §11.4) : clé de l'événement différente
// de la clé attendue après le voisin précédent ; clé du voisin suivant
// différente de celle attendue après l'événement.
func TestC3Branches(t *testing.T) {
	cas := []struct{ voisin, detail string }{
		{"previous", "clé de l'événement rec-test-01 ≠ rec-autre"},
		{"next", "clé du voisin suivant rec-autre ≠ rec-test-01"},
	}
	for _, c := range cas {
		t.Run(c.voisin, func(t *testing.T) {
			rep := copierDossier(t, dossierSeq7)
			modifierJSON(t, rep, "voisins.json", func(v map[string]any) { sous(v, c.voisin)["recorder_key_id"] = "rec-autre" })
			attendreEchec(t, analyserRep(t, rep, Options{}), "C-3", c.detail)
		})
	}
	// Témoin.
	if v := statutDe(t, analyserRep(t, copierDossier(t, dossierSeq7), Options{}), "C-3"); v.Statut != commun.Reussi {
		t.Errorf("témoin : C-3 %s (%s)", v.Statut, v.Detail.Fr)
	}
}

// TestC1PreviousNonNulSeq1 : CT-6 N-1. C-1 (CT-1 §11.4), seconde branche de
// la règle d'origine : un voisin précédent fourni alors que l'événement
// prouvé a seq = 1 (dossier publié invalide-ts-hors-periode, seul dossier de
// CT-1 à l'origine ; previous y vaut null).
func TestC1PreviousNonNulSeq1(t *testing.T) {
	rep := copierDossier(t, racineCT1+"/invalide-ts-hors-periode")
	modifierJSON(t, rep, "voisins.json", func(v map[string]any) {
		if v["previous"] != nil {
			t.Fatal("le dossier publié a un voisin précédent")
		}
		v["previous"] = v["next"]
	})
	attendreEchec(t, analyserRep(t, rep, Options{}), "C-1", "previous non nul alors que seq = 1")
}

// TestP5Branches : N-1. P-5 (CT-1 §11.4, CT-6 EX-4.7) : recorder_key_id
// différents entre manifeste.json et manifeste.sig, clé absente de
// cles.json, generated_at hors de la validité de la clé, et la continuité
// avec un second manifeste (--second-manifeste) : autre journal, même
// période, continuité rompue, second manifeste suivant vérifié, second
// manifeste précédent vérifié (manifeste resigné avec la clé de test publiée).
func TestP5Branches(t *testing.T) {
	t.Run("recorder_key_id différents", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq7)
		modifierJSON(t, rep, "manifeste.sig", func(v map[string]any) { v["recorder_key_id"] = "rec-test-01" })
		a := analyserRep(t, rep, Options{})
		attendreEchec(t, a, "P-5", "manifeste.recorder_key_id ≠ manifeste.sig.recorder_key_id")
		attendreEchec(t, a, "P-5", "signature du manifeste invalide sous rec-test-01")
	})
	t.Run("clé absente de cles.json", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq7)
		modifierJSON(t, rep, "manifeste.sig", func(v map[string]any) { v["recorder_key_id"] = "rec-inconnu" })
		attendreEchec(t, analyserRep(t, rep, Options{}), "P-5", "clé rec-inconnu absente de cles.json")
	})
	t.Run("generated_at hors de la validité", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq7)
		modifierJSON(t, rep, "manifeste.json", func(v map[string]any) { v["generated_at"] = "2026-10-01T00:00:00.000Z" })
		attendreEchec(t, analyserRep(t, rep, Options{}), "P-5", "generated_at hors de la validité de rec-test-02")
	})
	// Continuité avec un second manifeste (EX-4.7, CT-1 §10.3).
	rep := copierDossier(t, dossierSeq7)
	m := lireJSON(t, rep, "manifeste.json")
	ps, pe := int64(m["period_start"].(float64)), int64(m["period_end"].(float64))
	ls := int64(m["last_seq"].(float64))
	second := func(f func(s map[string]any)) *jsonv.Valeur {
		s := lireJSON(t, rep, "manifeste.json")
		f(s)
		return valeurDe(t, s)
	}
	t.Run("second manifeste d'un autre journal", func(t *testing.T) {
		a := analyserRep(t, rep, Options{SecondManifeste: second(func(s map[string]any) { s["journal_id"] = zeroHex32 })})
		attendreEchec(t, a, "P-5", "second manifeste d'un autre journal")
	})
	t.Run("second manifeste ni précédent ni suivant", func(t *testing.T) {
		a := analyserRep(t, rep, Options{SecondManifeste: second(func(s map[string]any) {})})
		attendreEchec(t, a, "P-5", "second manifeste ni précédent ni suivant")
	})
	t.Run("continuité rompue (first_seq)", func(t *testing.T) {
		a := analyserRep(t, rep, Options{SecondManifeste: second(func(s map[string]any) {
			s["period_start"], s["period_end"], s["first_seq"], s["last_seq"] = pe, pe+3600, ls+2, ls+4
		})})
		attendreEchec(t, a, "P-5", "continuité de CT-1 §10.3 rompue avec le second manifeste")
	})
	t.Run("second manifeste suivant : continuité vérifiée", func(t *testing.T) {
		ph := periodHashDe(t, m)
		a := analyserRep(t, rep, Options{SecondManifeste: second(func(s map[string]any) {
			s["period_start"], s["period_end"], s["first_seq"], s["last_seq"], s["count"], s["prev_period_hash"] = pe, pe+3600, ls+1, ls+3, 3, ph
		})})
		v := statutDe(t, a, "P-5")
		if v.Statut != commun.Reussi || !strings.Contains(v.Detail.Fr, "continuité avec le second manifeste vérifiée") {
			t.Errorf("P-5 %s (%s)", v.Statut, v.Detail.Fr)
		}
	})
	t.Run("second manifeste précédent : continuité vérifiée", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq7)
		prec := lireJSON(t, rep, "manifeste.json")
		prec["period_start"], prec["period_end"], prec["first_seq"], prec["last_seq"], prec["count"] = ps-3600, ps, 0, 0, 1
		// Le manifeste du dossier doit chaîner sur le précédent : il est
		// réécrit (prev_period_hash) et resigné avec la clé de test publiée.
		modifierJSON(t, rep, "manifeste.json", func(v map[string]any) { v["prev_period_hash"] = periodHashDe(t, prec) })
		resignerManifeste(t, rep)
		a := analyserRep(t, rep, Options{SecondManifeste: valeurDe(t, prec)})
		v := statutDe(t, a, "P-5")
		if v.Statut != commun.Reussi || !strings.Contains(v.Detail.Fr, "continuité avec le second manifeste vérifiée") {
			t.Errorf("P-5 %s (%s)", v.Statut, v.Detail.Fr)
		}
		// Le même dossier sans second manifeste : P-5 réussie sans la mention.
		if v := statutDe(t, analyserRep(t, rep, Options{}), "P-5"); v.Statut != commun.Reussi || strings.Contains(v.Detail.Fr, "second manifeste") {
			t.Errorf("sans second manifeste : P-5 %s (%s)", v.Statut, v.Detail.Fr)
		}
	})
}

// resignerManifeste recalcule manifeste.sig (period_hash et signature Ed25519)
// avec la graine publiée de la clé que le manifeste nomme (cles-test.json).
func resignerManifeste(t *testing.T, rep string) {
	t.Helper()
	m := lireJSON(t, rep, "manifeste.json")
	kid := m["recorder_key_id"].(string)
	var cles struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			Seed      string `json:"seed"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	b, err := os.ReadFile(clesDeTest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &cles); err != nil {
		t.Fatal(err)
	}
	var graine, pub []byte
	for _, k := range cles.Keys {
		if k.KeyID == kid {
			graine, _ = hex.DecodeString(strings.TrimPrefix(k.Seed, "0x"))
			pub, _ = hex.DecodeString(strings.TrimPrefix(k.PublicKey, "0x"))
		}
	}
	if len(graine) != ed25519.SeedSize {
		t.Fatalf("graine de %s introuvable dans %s", kid, clesDeTest)
	}
	priv := ed25519.NewKeyFromSeed(graine)
	if !strings.EqualFold(hex.EncodeToString(priv.Public().(ed25519.PublicKey)), hex.EncodeToString(pub)) {
		t.Fatalf("la graine publiée de %s ne donne pas sa clé publique", kid)
	}
	cm, err := jcs.Canonique(valeurDe(t, m))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append(append([]byte{}, cryptographie.PrefixeSignatureManifeste...), cm...))
	modifierJSON(t, rep, "manifeste.sig", func(v map[string]any) {
		v["period_hash"] = cryptographie.Hex32(cryptographie.Sha256(cryptographie.PrefixeManifeste, cm))
		v["sig"] = cryptographie.Hex(sig)
	})
}

// instantISO écrit un instant UNIX en secondes au format de CT-1 §3.
func instantISO(s int64) string { return time.Unix(s, 0).UTC().Format("2006-01-02T15:04:05.000Z") }

// TestK1Branches : CT-6 N-1. K-1 (CT-1 §11.4) : chaque relation du point avec
// le manifeste et l'événement a son cas d'échec ; manifeste.json
// inexploitable rend K-1 non exécutée. La branche « racine du point nulle »
// n'est pas atteignable : le schéma de points-de-controle.json, appliqué
// avant, interdit déjà la racine nulle (« valeur interdite par not »).
func TestK1Branches(t *testing.T) {
	m := lireJSON(t, dossierPoint, "manifeste.json")
	ps := int64(m["period_start"].(float64))
	cas := []struct {
		nom    string
		muter  func(k map[string]any)
		detail string
	}{
		{"checkpoint_ts inexistante", func(k map[string]any) { k["checkpoint_ts"] = "2026-02-30T09:32:00.000Z" }, "checkpoint_ts n'est pas une date existante"},
		{"org_id différent", func(k map[string]any) { k["org_id"] = zeroHex32 }, "org_id ou journal_id du point différent de celui de l'événement"},
		{"journal_id différent", func(k map[string]any) { k["journal_id"] = zeroHex32 }, "org_id ou journal_id du point différent de celui de l'événement"},
		{"period_start différent", func(k map[string]any) { k["period_start"] = ps + 3600 }, "period_start du point ≠ celui du manifeste"},
		{"tree_size au-delà de count", func(k map[string]any) { k["tree_size"] = 10 }, "tree_size 10 hors de [1, count = 9]"},
		{"last_seq incohérent", func(k map[string]any) { k["last_seq"] = 9 }, "last_seq ≠ first_seq + tree_size − 1"},
		{"checkpoint_ts antérieur à period_start", func(k map[string]any) { k["checkpoint_ts"] = instantISO(ps - 1) }, "checkpoint_ts antérieur à period_start"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierPoint)
			modifierJSON(t, rep, "points-de-controle.json", func(v map[string]any) { c.muter(sous(v, "checkpoint")) })
			attendreEchec(t, analyserRep(t, rep, Options{}), "K-1", c.detail)
		})
	}
	t.Run("manifeste.json inexploitable", func(t *testing.T) {
		rep := copierDossier(t, dossierPoint)
		remplacerPartie(t, rep, "manifeste.json", []byte("[]"))
		attendrePrerequis(t, analyserRep(t, rep, Options{}), "K-1", "manifeste.json inexploitable (P-1)")
	})
	// Témoin.
	if v := statutDe(t, analyserRep(t, copierDossier(t, dossierPoint), Options{}), "K-1"); v.Statut != commun.Reussi {
		t.Errorf("témoin : K-1 %s (%s)", v.Statut, v.Detail.Fr)
	}
}

// TestK3K4K6Branches : CT-6 N-1. K-3 (clé du point absente de cles.json,
// checkpoint_ts hors de la validité de la clé, cles.json inexploitable), K-4
// (chemin.json inexploitable, ts de l'événement postérieur à checkpoint_ts)
// et K-6 (last_hash différent). La branche « hachage de l'événement last_seq
// incalculable » de K-6 n'est pas atteignable : un voisin sans forme
// canonique rend voisins.json entier inexploitable (K-6 non exécutée pour
// cette raison), et l'événement prouvé sans forme canonique vaut nil.
func TestK3K4K6Branches(t *testing.T) {
	point := func(f func(k map[string]any)) func(t *testing.T, rep string) {
		return func(t *testing.T, rep string) {
			modifierJSON(t, rep, "points-de-controle.json", func(v map[string]any) { f(sous(v, "checkpoint")) })
		}
	}
	cas := []struct {
		nom       string
		muter     func(t *testing.T, rep string)
		id        string
		prerequis bool
		detail    string
	}{
		{"K-3 : clé du point absente de cles.json", point(func(k map[string]any) { k["key_id"] = "rec-inconnu" }), "K-3", false, "clé rec-inconnu du point absente de cles.json"},
		{"K-3 : checkpoint_ts hors de la validité de la clé", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "cles.json", func(v map[string]any) {
				v["keys"].([]any)[0].(map[string]any)["valid_to"] = "2026-11-05T09:31:00.000Z"
			})
		}, "K-3", false, "checkpoint_ts hors de la validité de rec-test-01"},
		{"K-3 : cles.json inexploitable", func(t *testing.T, rep string) { remplacerPartie(t, rep, "cles.json", []byte("[]")) }, "K-3", true, "cles.json inexploitable (E-8)"},
		{"K-4 : chemin.json inexploitable", func(t *testing.T, rep string) { remplacerPartie(t, rep, "chemin.json", []byte("[]")) }, "K-4", true, "chemin.json inexploitable ou M-3 non réussie"},
		{"K-4 : ts de l'événement postérieur à checkpoint_ts", point(func(k map[string]any) { k["checkpoint_ts"] = "2026-11-05T09:31:00.000Z" }), "K-4", false, "ts de l'événement postérieur à checkpoint_ts"},
		{"K-6 : last_hash différent", point(func(k map[string]any) { k["last_hash"] = zeroHex32 }), "K-6", false, "last_hash " + zeroHex32 + " ≠ hash recalculé de seq 8"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierPoint)
			c.muter(t, rep)
			a := analyserRep(t, rep, Options{})
			if c.prerequis {
				attendrePrerequis(t, a, c.id, c.detail)
			} else {
				attendreEchec(t, a, c.id, c.detail)
			}
		})
	}
	// Témoin : K-1 à K-6 réussies sur le dossier publié.
	a := analyserRep(t, copierDossier(t, dossierPoint), Options{})
	for _, id := range []string{"K-1", "K-2", "K-3", "K-4", "K-5", "K-6"} {
		if v := statutDe(t, a, id); v.Statut != commun.Reussi {
			t.Errorf("témoin : %s %s (%s)", id, v.Statut, v.Detail.Fr)
		}
	}
}

// signerEIP191 signe un condensé en EIP-191 (personal_sign) avec une clé
// secp256k1 : signature r ‖ s ‖ v de 65 octets, v dans {27, 28}, s bas, la
// forme que RecouvrerEIP191 lit (CT-1 §6.3).
func signerEIP191(t *testing.T, cleHex string, d [32]byte) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(cleHex, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	m := cryptographie.MessageEIP191(d)
	compacte := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(b), m[:], false)
	return append(append([]byte{}, compacte[1:]...), compacte[0])
}

// TestAT4Branches : CT-6 N-1. AT-4 (CT-1 §11.4, attestation de périmètre) :
// signataire en double, signataire absent de signatories (signature valide
// d'un approbateur du jeu qui n'est pas signataire déclaré : compte Hardhat
// 3, clé de test publiée), signataire absent du jeu déclaré, required > size.
func TestAT4Branches(t *testing.T) {
	// Compte Hardhat 3 (0x90f7…), membre du jeu d'approbateurs des vecteurs
	// de CT-1 mais absent de signatories de l'attestation.
	const cleHardhat3 = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
	const adresseHardhat3 = "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
	cas := []struct {
		nom    string
		muter  func(t *testing.T, v map[string]any)
		detail string
	}{
		{"signataire en double", func(t *testing.T, v map[string]any) {
			sigs := sous(v, "signed")["signatures"].([]any)
			sous(v, "signed")["signatures"] = append(sigs, sigs[0])
		}, "signataire en double 0x70997970c51812dc3a010c7d01b50e0d17dc79c8"},
		{"signataire absent de signatories", func(t *testing.T, v map[string]any) {
			dh, _ := cryptographie.LireHex(sous(v, "signed")["digest"].(string), 32)
			var d [32]byte
			copy(d[:], dh)
			sig := signerEIP191(t, cleHardhat3, d)
			adr, err := cryptographie.RecouvrerEIP191(d, sig)
			if err != nil || cryptographie.Hex(adr[:]) != adresseHardhat3 {
				t.Fatalf("signature du compte Hardhat 3 : %v, %s", err, cryptographie.Hex(adr[:]))
			}
			sigs := sous(v, "signed")["signatures"].([]any)
			sous(v, "signed")["signatures"] = append(sigs, map[string]any{"address": adresseHardhat3, "signature": cryptographie.Hex(sig)})
		}, adresseHardhat3 + " absent de signatories"},
		{"signataire absent du jeu déclaré", func(t *testing.T, v map[string]any) {
			sous(v, "approver_set")["members"].([]any)[0] = "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
		}, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8 absent du jeu déclaré"},
		{"required > size", func(t *testing.T, v map[string]any) {
			sous(v, "approver_set", "threshold")["required"] = 4
		}, "required > size, ou size ≠ nombre de members"},
		{"seuil non atteint", func(t *testing.T, v map[string]any) {
			sous(v, "approver_set", "threshold")["required"] = 3
		}, "2 signataire(s) pour un seuil de 3"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierAttestationJeu)
			modifierJSON(t, rep, "attestation-perimetre.json", func(v map[string]any) { c.muter(t, v) })
			a := analyserRep(t, rep, Options{})
			if v := statutDe(t, a, "AT-3"); v.Statut != commun.Reussi {
				t.Fatalf("AT-3 %s (%s) : AT-4 non exécutée", v.Statut, v.Detail.Fr)
			}
			attendreEchec(t, a, "AT-4", c.detail)
		})
	}
	// Témoin.
	if v := statutDe(t, analyserRep(t, copierDossier(t, dossierAttestationJeu), Options{}), "AT-4"); v.Statut != commun.Reussi {
		t.Errorf("témoin : AT-4 %s (%s)", v.Statut, v.Detail.Fr)
	}
}
