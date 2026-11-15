package moteur

// Essais de la revue de sécurité interne de l'étape 8, de bout en bout
// sur le moteur : rapport lisible neutralisé (CT-6 EX-8.6), résumé d'un
// contrôle non exécuté, rewrite_window_ms exact (EX-6.17), bornes
// de mémoire et de rapport sur des parties de petites valeurs (EX-15.1),
// fichier d'en-têtes borné (extension).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/rapport"
)

const seq7 = racineCT1 + "/valide-seq-7"

func lireOctets(t *testing.T, chemin string) []byte {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ecrireOctets(t *testing.T, chemin string, b []byte) {
	t.Helper()
	if err := os.WriteFile(chemin, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// raisonHostile : raison d'absence qui efface la ligne précédente d'un
// terminal et y écrit un faux « [réussi] » (essai inj1 de la revue).
const raisonHostile = "x\r\u001b[2K  [réussi]      4  jeton d'horodatage RFC 3161 sur periodHash — selon AC Exemple\nRésultat      : VALIDE\u001b[8m"

// avecRaison remplace la raison d'absence de la partie nommée dans l'index.
func avecRaison(t *testing.T, rep, nom, raison string) {
	t.Helper()
	idx := filepath.Join(rep, "dossier.json")
	b := lireOctets(t, idx)
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	trouve := false
	for _, p := range v["parts"].([]any) {
		pm := p.(map[string]any)
		if pm["name"] == nom {
			pm["reason_if_absent"] = raison
			trouve = true
		}
	}
	if !trouve {
		t.Fatalf("partie %s absente de l'index", nom)
	}
	n, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	ecrireOctets(t, idx, n)
}

// TestRapportLisibleNeutralise : CT-6 EX-8.6. Les chaînes du dossier
// recopiées dans le rapport lisible sont neutralisées : aucun octet de
// commande n'en sort, le seul saut de ligne est celui de fin de ligne, et la
// séquence est écrite visiblement (\u001b) ; le rapport JSON reste exact.
func TestRapportLisibleNeutralise(t *testing.T) {
	rep := copier(t, seq7)
	avecRaison(t, rep, "jeton_rfc3161", raisonHostile)
	res := lancer(t, rep)
	if res.Code != 0 {
		t.Fatalf("code %d : %v", res.Code, res.Erreur)
	}
	txt := rapport.Lisible(res.Rapport, rapport.InfosLisibles{Verificateur: "essai", Repertoire: rep}, false)
	for _, r := range txt {
		if (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("caractère de commande %U dans le rapport lisible", r)
		}
	}
	if !strings.Contains(txt, `\u001b[2K`) || !strings.Contains(txt, `\u000d`) || !strings.Contains(txt, `VALIDE\u001b[8m`) {
		t.Fatalf("séquences non écrites visiblement :\n%s", txt)
	}
	// Le gabarit d'EX-8.6 : une ligne « Résultat » et une seule, la vraie.
	if strings.Count(txt, "\nRésultat") != 1 {
		t.Fatalf("lignes Résultat : %d", strings.Count(txt, "\nRésultat"))
	}
	// Le rapport JSON porte la chaîne telle quelle, échappée par le codage.
	b, err := rapport.EncoderJSON(res.Rapport)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `\r\u001b[2K`) {
		t.Fatalf("rapport JSON : %s", b)
	}
	// Détail d'une vérification et avertissement : même point de passage.
	avecRaison(t, rep, "approbations", raisonHostile)
	res = lancer(t, rep)
	txt = rapport.Lisible(res.Rapport, rapport.InfosLisibles{}, true)
	if strings.ContainsAny(txt, "\r\x1b") {
		t.Fatal("détail non neutralisé")
	}
}

// TestResumeControle8ParFichier : raison de chaque fichier absent. Le résumé d'un contrôle non
// exécuté donne à chaque partie absente sa propre raison quand elles
// diffèrent (la raison du dernier fichier était attribuée à tous) ; quand
// elles sont égales, la forme reste celle de l'exemple de CT-6 §8.5.
func TestResumeControle8ParFichier(t *testing.T) {
	rep := copier(t, seq7)
	res := lancer(t, rep)
	c8 := res.Rapport.Controls[7]
	exemple := "registre.json, certificat-commit.json, validateurs.json absents (hors périmètre CT-1)"
	if c8.Summary == nil || *c8.Summary != exemple {
		t.Fatalf("résumé du contrôle 8 (raisons égales) : %v, attendu %q", c8.Summary, exemple)
	}
	avecRaison(t, rep, "registre", "raison A")
	avecRaison(t, rep, "certificat_commit", "raison B")
	avecRaison(t, rep, "validateurs", "raison C")
	res = lancer(t, rep)
	c8 = res.Rapport.Controls[7]
	attendu := "registre.json (raison A), certificat-commit.json (raison B), validateurs.json (raison C) absents"
	if c8.Summary == nil || *c8.Summary != attendu {
		t.Fatalf("résumé du contrôle 8 (raisons différentes) : %v, attendu %q", c8.Summary, attendu)
	}
	if c4 := res.Rapport.Controls[3]; c4.Summary == nil || *c4.Summary != "jeton-rfc3161.der absent (hors périmètre CT-1)" {
		t.Fatalf("résumé du contrôle 4 : %v", c4.Summary)
	}
}

// TestDifferenceMs : CT-6 EX-6.17. La différence d'instants est exacte en
// millisecondes, là où time.Time.Sub sature à environ 292 ans.
func TestDifferenceMs(t *testing.T) {
	a := time.Date(2026, 11, 5, 10, 0, 6, 500_000_000, time.UTC)
	b := time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	attendu := new(big.Int).Sub(big.NewInt(a.Unix()*1000+500), big.NewInt(b.Unix()*1000))
	if got := differenceMs(a, b); big.NewInt(got).Cmp(attendu) != 0 {
		t.Fatalf("differenceMs = %d, attendu %s", got, attendu)
	}
	if a.Sub(b).Milliseconds() == differenceMs(a, b) {
		t.Fatal("l'essai n'atteint pas la saturation de time.Time.Sub")
	}
	if differenceMs(b, a) != -differenceMs(a, b) {
		t.Fatal("signe")
	}
	c := a.Add(1500 * time.Millisecond)
	if differenceMs(c, a) != 1500 {
		t.Fatalf("1,5 s : %d", differenceMs(c, a))
	}
}

func memoireApres(f func()) uint64 {
	var avant, apres runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&avant)
	f()
	runtime.ReadMemStats(&apres)
	return apres.TotalAlloc - avant.TotalAlloc
}

// TestPartiePetitesValeursBornee : CT-6 EX-15.1. Un cles.json de 2 Mio fait de
// « 0, » (plus d'un million de valeurs, au-delà de la borne d'une partie de
// 16 Mio) est jugé avec un rapport, code 1, E-8 en échec, sous un plafond de
// mémoire écrit (64 Mio alloués) : la lecture s'arrête à la borne.
func TestPartiePetitesValeursBornee(t *testing.T) {
	rep := copier(t, seq7)
	cles := `{"version":0,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164","keys":[` + strings.TrimSuffix(strings.Repeat("0,", 1<<20), ",") + `]}`
	remplacer(t, rep, "cles.json", []byte(cles))
	var res *Resultat
	alloue := memoireApres(func() { res = lancer(t, rep) })
	if res.Code != 1 || verifs(res)["E-8"].Statut != commun.Echoue {
		t.Fatalf("code %d, E-8 %s", res.Code, verifs(res)["E-8"].Statut)
	}
	if alloue > 192<<20 {
		t.Fatalf("%d Mio alloués, seuil 192", alloue>>20)
	}
	b, _ := rapport.EncoderJSON(res.Rapport)
	if len(b) > 1<<20 {
		t.Fatalf("rapport de %d octets", len(b))
	}
}

// TestRapportBorneEvenementsNombreux : CT-6 EX-15.1. Un approbations.json de
// 1 Mio dont events est fait de 524 288 zéros (sous la borne de valeurs)
// rend un rapport de moins de 1 Mio : 1 024 événements jugés, le reste
// compté, détails bornés.
func TestRapportBorneEvenementsNombreux(t *testing.T) {
	rep := copier(t, seq7)
	ap := `{"version":0,"ticket":"apr-2201","request_hash":"0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d","approver_set":{"threshold":{"required":2,"size":3},"members":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8","0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc","0x90f79bf6eb2c4f870365e785982e1f101e93b906"],"source":"x"},"events":[` + strings.TrimSuffix(strings.Repeat("0,", 1<<19), ",") + `]}`
	remplacer(t, rep, "approbations.json", []byte(ap))
	var res *Resultat
	alloue := memoireApres(func() { res = lancer(t, rep) })
	if res.Code != 1 || verifs(res)["A-1"].Statut != commun.Echoue || verifs(res)["E-1"].Statut != commun.Echoue {
		t.Fatalf("code %d, A-1 %s, E-1 %s", res.Code, verifs(res)["A-1"].Statut, verifs(res)["E-1"].Statut)
	}
	b, _ := rapport.EncoderJSON(res.Rapport)
	if len(b) > 1<<20 {
		t.Fatalf("rapport de %d octets", len(b))
	}
	if alloue > 256<<20 {
		t.Fatalf("%d Mio alloués, seuil 256", alloue>>20)
	}
	if d := verifs(res)["A-2"].Detail.Fr; !strings.Contains(d, "élément(s) au-delà des 1024") {
		t.Fatalf("A-2 : %s", d[:min(len(d), 200)])
	}
}

// TestEntetesPetitesValeursBornes : CT-6 EX-15.1 (extension). Un fichier
// d'en-têtes de 16 Mio fait de « 0, » dépasse la borne de valeurs d'une
// entrée de 64 Mio (4 194 304) : code 2, entree_illisible, N-2, et la
// mémoire allouée reste sous 160 octets par valeur admise (640 Mio), là où le
// lecteur relu en demandait 11 Gio pour 64 Mio.
func TestEntetesPetitesValeursBornes(t *testing.T) {
	f := filepath.Join(t.TempDir(), "entetes.json")
	ecrireOctets(t, f, []byte("["+strings.TrimSuffix(strings.Repeat("0,", 8<<20), ",")+"]"))
	var res *Resultat
	alloue := memoireApres(func() {
		res = Verifier(Options{Repertoire: seq7, Entetes: f, Langue: "fr", Version: "0.0.0"})
	})
	if res.Code != 2 || res.Erreur == nil || res.Erreur.Genre != "entree_illisible" || res.Erreur.Verification != "N-2" || !strings.Contains(res.Erreur.Message.Fr, "nombre de valeurs") {
		t.Fatalf("code %d : %+v", res.Code, res.Erreur)
	}
	if alloue > 640<<20 {
		t.Fatalf("%d Mio alloués, seuil 640", alloue>>20)
	}
}

// TestDetailTronque : CT-6 EX-15.1. Une chaîne d'une partie exploitable mais
// contraire à son schéma (recorder_key_id de 100 000 caractères) n'allonge
// pas le rapport à sa mesure : le détail qui la recopie est tronqué à
// 4 096 caractères, dans le rapport JSON comme dans le rapport lisible.
func TestDetailTronque(t *testing.T) {
	rep := copier(t, seq7)
	long := strings.Repeat("k", 100000)
	ev := string(lireOctets(t, filepath.Join(rep, "evenement.json")))
	ev2 := strings.Replace(ev, `"recorder_key_id": "rec-test-01"`, `"recorder_key_id": "`+long+`"`, 1)
	if ev2 == ev {
		ev2 = strings.Replace(ev, `"recorder_key_id":"rec-test-01"`, `"recorder_key_id":"`+long+`"`, 1)
	}
	if ev2 == ev {
		t.Fatal("recorder_key_id non trouvé dans evenement.json")
	}
	remplacer(t, rep, "evenement.json", []byte(ev2))
	res := lancer(t, rep)
	e8 := verifs(res)["E-8"]
	if e8.Statut != commun.Echoue {
		t.Fatalf("E-8 %s", e8.Statut)
	}
	for _, v := range res.Rapport.Checks {
		if v.Detail != nil && len([]rune(*v.Detail)) > commun.LongueurDetailMax+64 {
			t.Fatalf("%s : détail de %d caractères", v.ID, len([]rune(*v.Detail)))
		}
	}
	b, _ := rapport.EncoderJSON(res.Rapport)
	if len(b) > 256<<10 || !strings.Contains(string(b), "texte tronqué à 4096 caractères") {
		t.Fatalf("rapport de %d octets sans troncature écrite", len(b))
	}
	if txt := rapport.Lisible(res.Rapport, rapport.InfosLisibles{}, false); strings.Contains(txt, strings.Repeat("k", 5000)) {
		t.Fatal("rapport lisible non tronqué")
	}
}
