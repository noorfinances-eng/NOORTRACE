// Confrontation des preuves de cohérence RFC 9162 §2.1.4 des vecteurs CT-1
// révision 0.3 (spec/vecteurs/ct-1/merkle/coherence.json,
// spec/vecteurs/ct-1/points-de-controle/attendu.json, parties
// points-de-controle.json des dossiers de CT-1 et de CT-6 révision 0.2) par une
// implémentation de référence de Certificate Transparency, sans le code du
// dépôt : github.com/transparency-dev/merkle v0.0.2 (licence Apache 2.0),
// paquets rfc6962 (hachage des feuilles et des nœuds), testonly (arbre en
// mémoire : racines et preuves de cohérence) et proof (VerifyConsistency).
// CT-5 annexe A.6 ; CT-1 §10.7.
//
// Le programme :
//
//  1. rejoue les vecteurs publics de la bibliothèque (proof/verify_test.go de
//     la version v0.0.2 : huit feuilles de 0 à 16 octets, huit racines, cinq
//     preuves de cohérence) pour établir que l'arbre employé ici est celui de
//     ces vecteurs, et lui soumet des sondes de corruption ;
//
//  2. lit merkle/coherence.json : arbre des douze feuilles de journal-valide,
//     racines des deux tailles de chaque cas, preuve régénérée nœud pour nœud
//     pour les cas acceptés, verdict de proof.VerifyConsistency pour chaque cas ;
//
//  3. lit points-de-controle/attendu.json : pour chaque période, racine du
//     manifeste recalculée et preuve de cohérence de chaque point régénérée ;
//
//  4. lit la partie points-de-controle.json de chaque dossier de CT-1 et de
//     CT-6 qui la porte : preuve régénérée depuis les feuilles de la période
//     dont la racine est second_root, verdict de la bibliothèque comparé aux
//     vérifications en échec attendues (K-5).
//
//     go run . <spec/vecteurs/ct-1> <spec/vecteurs/ct-6>
//
// Code de retour : 0 si aucune discordance, 1 sinon, 2 si une entrée est
// illisible ou l'usage incorrect. Le programme n'accède pas au réseau ; le
// module tiers est résolu par go à la construction (go.sum l'épingle).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// Vecteurs publics : github.com/transparency-dev/merkle, version v0.0.2,
// fichier proof/verify_test.go (Copyright 2017 Google LLC, licence Apache 2.0),
// https://raw.githubusercontent.com/transparency-dev/merkle/v0.0.2/proof/verify_test.go
// (lu le 2026-10-25). Feuilles (octets), racines des arbres de 1 à 8 feuilles,
// racine de l'arbre vide, preuves de cohérence (size1, size2) et le hachage
// « quelconque » des sondes.
var (
	feuillesPubliques = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	racinesPubliques  = []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	racineArbreVide   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hachageQuelconque = "abacaba000000000000000000000000000000000000000000060061e00123456"
	preuvesPubliques  = []struct {
		m, n uint64
		path []string
	}{
		{1, 1, nil},
		{1, 8, []string{"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"}},
		{6, 8, []string{"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
		{2, 5, []string{"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"}},
		{6, 7, []string{"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
	}
)

var hasher merkle.LogHasher = rfc6962.DefaultHasher

// Formes JSON lues (clés anglaises des vecteurs).
type coherence struct {
	Version    int      `json:"version"`
	FirstSize  uint64   `json:"first_size"`
	SecondSize uint64   `json:"second_size"`
	FirstRoot  string   `json:"first_root"`
	SecondRoot string   `json:"second_root"`
	Path       []string `json:"path"`
}

type casCoherence struct {
	coherence
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Valid       bool    `json:"valid"`
	Reason      *string `json:"reason"`
}

type fichierCoherence struct {
	Version     int            `json:"version"`
	Description string         `json:"description"`
	Leaves      []string       `json:"leaves"`
	Cases       []casCoherence `json:"cases"`
}

type pointAttendu struct {
	Index        int        `json:"index"`
	CheckpointTs string     `json:"checkpoint_ts"`
	TreeSize     uint64     `json:"tree_size"`
	Consistency  *coherence `json:"consistency"`
}

type periodeAttendue struct {
	File        string `json:"file"`
	Manifest    string `json:"manifest"`
	PeriodStart int64  `json:"period_start"`
	Count       uint64 `json:"count"`
	Last        struct {
		TreeSize uint64 `json:"tree_size"`
		Root     string `json:"root"`
	} `json:"last"`
	Points []pointAttendu `json:"points"`
}

type attenduPoints struct {
	Periodes []periodeAttendue `json:"periodes"`
}

type manifeste struct {
	PeriodStart int64  `json:"period_start"`
	FirstSeq    int    `json:"first_seq"`
	LastSeq     int    `json:"last_seq"`
	Count       uint64 `json:"count"`
	Root        string `json:"root"`
}

type journalAttendu struct {
	Hashes []struct {
		Seq  int    `json:"seq"`
		Hash string `json:"hash"`
	} `json:"hashes"`
}

type partiePoints struct {
	Checkpoint struct {
		JournalID   string `json:"journal_id"`
		PeriodStart int64  `json:"period_start"`
		TreeSize    uint64 `json:"tree_size"`
		Root        string `json:"root"`
	} `json:"checkpoint"`
	CheckpointHash string     `json:"checkpoint_hash"`
	Consistency    *coherence `json:"consistency"`
}

// Une période connue par son manifeste : ses feuilles et son arbre.
type periode struct {
	nom      string
	manifest manifeste
	feuilles [][]byte
	arbre    *testonly.Tree
}

var (
	sortie       []string
	discordances []string
	limites      []string
)

func dire(format string, a ...any) { sortie = append(sortie, fmt.Sprintf(format, a...)) }

func comparer(libelle string, vecteur, outil any) bool {
	v, o := fmt.Sprint(vecteur), fmt.Sprint(outil)
	ok := v == o
	etat := "concorde"
	if !ok {
		etat = "DISCORDANCE"
		discordances = append(discordances, fmt.Sprintf("%s : vecteur %s, bibliothèque %s", libelle, v, o))
	}
	dire("  %s : vecteur %s ; bibliothèque %s : %s", libelle, v, o, etat)
	return ok
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "coherence : "+format+"\n", a...)
	os.Exit(2)
}

func hexa(b []byte) string { return "0x" + hex.EncodeToString(b) }

func octets(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil {
		fatal("hexadécimal illisible %q : %v", s, err)
	}
	return b
}

func octetsListe(l []string) [][]byte {
	out := make([][]byte, len(l))
	for i, s := range l {
		out[i] = octets(s)
	}
	return out
}

func chemin(p [][]byte) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = hexa(h)
	}
	return out
}

func sha256Fichier(chemin string) string {
	b, err := os.ReadFile(chemin)
	if err != nil {
		fatal("%v", err)
	}
	s := sha256.Sum256(b)
	return hexa(s[:])
}

func lireJSON(chemin string, v any) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		fatal("%v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		fatal("%s : %v", chemin, err)
	}
}

func arbre(feuilles [][]byte) *testonly.Tree {
	t := testonly.New(hasher)
	t.AppendData(feuilles...)
	return t
}

// categorie : « acceptee » ou « refusee », sans le texte de l'erreur.
func categorie(err error) string {
	if err == nil {
		return "acceptee"
	}
	return "refusee"
}

// motif : la catégorie et, pour un refus, la raison donnée par la bibliothèque
// sur une ligne (une RootMismatchError imprime les octets sur plusieurs lignes).
func motif(err error) string {
	if err == nil {
		return "acceptee"
	}
	var rm proof.RootMismatchError
	if errors.As(err, &rm) {
		return "refusee (RootMismatchError : la racine recalculée diffère de la racine attendue)"
	}
	return "refusee (" + strings.Join(strings.Fields(err.Error()), " ") + ")"
}

func verifier(c coherence) error {
	return proof.VerifyConsistency(hasher, c.FirstSize, c.SecondSize, octetsListe(c.Path), octets(c.FirstRoot), octets(c.SecondRoot))
}

// preuveGeneree : PROOF(m, D[n]) par la bibliothèque, ou nil et l'erreur.
func preuveGeneree(t *testonly.Tree, m, n uint64) ([]string, error) {
	if n > t.Size() {
		return nil, fmt.Errorf("taille %d au-delà de l'arbre de %d feuilles", n, t.Size())
	}
	p, err := t.ConsistencyProof(m, n)
	if err != nil {
		return nil, err
	}
	return chemin(p), nil
}

// sondes : altérations d'une preuve acceptée que la bibliothèque doit refuser
// (sur le modèle des sondes de corruption des tests de référence).
func sondes(c coherence) {
	quelconque := "0x" + hachageQuelconque
	alterations := []struct {
		nom string
		c   coherence
	}{
		{"racines échangées", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.SecondRoot, SecondRoot: c.FirstRoot, Path: c.Path}},
		{"tailles échangées (second_size < first_size)", coherence{FirstSize: c.SecondSize, SecondSize: c.FirstSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: c.Path}},
		{"chemin vide", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: nil}},
		{"chemin tronqué du dernier nœud", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: c.Path[:len(c.Path)-1]}},
		{"nœud en trop à la fin", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: append(append([]string{}, c.Path...), quelconque)}},
		{"nœud en trop au début", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: append([]string{quelconque}, c.Path...)}},
		{"première racine quelconque", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: quelconque, SecondRoot: c.SecondRoot, Path: c.Path}},
		{"seconde racine quelconque", coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: quelconque, Path: c.Path}},
	}
	for i := range c.Path {
		p := append([]string{}, c.Path...)
		p[i] = quelconque
		alterations = append(alterations, struct {
			nom string
			c   coherence
		}{fmt.Sprintf("nœud %d remplacé", i), coherence{FirstSize: c.FirstSize, SecondSize: c.SecondSize, FirstRoot: c.FirstRoot, SecondRoot: c.SecondRoot, Path: p}})
	}
	refusees := 0
	for _, a := range alterations {
		if categorie(verifier(a.c)) == "refusee" {
			refusees++
		} else {
			dire("  sonde « %s » : acceptée par la bibliothèque", a.nom)
		}
	}
	comparer(fmt.Sprintf("sondes de corruption refusées (%d sondes)", len(alterations)), len(alterations), refusees)
}

func versionBibliotheque() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			if d.Path == "github.com/transparency-dev/merkle" {
				return d.Version
			}
		}
	}
	return "(version de go.mod)"
}

// echecsAttendus lit controles_en_echec (CT-1) ou failed_checks (CT-6).
func echecsAttendus(chemin string) []string {
	var a map[string]any
	lireJSON(chemin, &a)
	var out []string
	for _, cle := range []string{"controles_en_echec", "failed_checks"} {
		if l, ok := a[cle].([]any); ok {
			for _, x := range l {
				out = append(out, fmt.Sprint(x))
			}
		}
	}
	return out
}

func contient(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage : go run . <spec/vecteurs/ct-1> <spec/vecteurs/ct-6>")
		os.Exit(2)
	}
	ct1, ct6 := os.Args[1], os.Args[2]

	dire("Confrontation des preuves de cohérence RFC 9162 §2.1.4 (CT-1 §10.7 ; CT-5 annexe A.6) par github.com/transparency-dev/merkle %s (rfc6962.DefaultHasher, testonly.Tree, proof.VerifyConsistency), %s", versionBibliotheque(), runtime.Version())
	dire("Entrées : ct-1/merkle/coherence.json, ct-1/points-de-controle/attendu.json, ct-1/manifestes/periode-{1,2,3}.json, ct-1/journal-valide/attendu.json, ct-1/dossiers/*/points-de-controle.json, ct-6/dossiers/*/points-de-controle.json et leurs attendu.json")
	dire("")

	// -----------------------------------------------------------------------
	dire("== 1. Vecteurs publics de transparency-dev/merkle v0.0.2 (proof/verify_test.go) : huit feuilles, racines, preuves de cohérence, sondes")
	tp := arbre(octetsListe(feuillesPubliques))
	comparer("racine de l'arbre vide (EmptyRoot = SHA-256 de la chaîne vide)", "0x"+racineArbreVide, hexa(tp.HashAt(0)))
	for i, r := range racinesPubliques {
		comparer(fmt.Sprintf("racine de l'arbre de %d feuille(s)", i+1), "0x"+r, hexa(tp.HashAt(uint64(i+1))))
	}
	for _, v := range preuvesPubliques {
		dire("-- PROOF(%d, D[%d]) : %d nœud(s) publié(s)", v.m, v.n, len(v.path))
		attendu := make([]string, len(v.path))
		for i, h := range v.path {
			attendu[i] = "0x" + h
		}
		p, err := preuveGeneree(tp, v.m, v.n)
		if err != nil {
			fatal("PROOF(%d, D[%d]) : %v", v.m, v.n, err)
		}
		comparer("preuve générée par la bibliothèque (testonly.Tree.ConsistencyProof), nœud pour nœud", attendu, p)
		c := coherence{FirstSize: v.m, SecondSize: v.n, FirstRoot: hexa(tp.HashAt(v.m)), SecondRoot: hexa(tp.HashAt(v.n)), Path: attendu}
		comparer("proof.VerifyConsistency sur la preuve publiée", "acceptee", motif(verifier(c)))
		if len(c.Path) > 0 {
			sondes(c)
		}
	}
	dire("")

	// -----------------------------------------------------------------------
	dire("== 2. ct-1/merkle/coherence.json (CT-1 §10.7) : arbre des douze feuilles de journal-valide, racines, preuves régénérées, verdicts")
	cheminCoherence := filepath.Join(ct1, "merkle", "coherence.json")
	dire("  SHA-256 de ct-1/merkle/coherence.json : %s", sha256Fichier(cheminCoherence))
	var fc fichierCoherence
	lireJSON(cheminCoherence, &fc)
	feuilles := octetsListe(fc.Leaves)
	for i, f := range feuilles {
		if len(f) != 32 {
			fatal("feuille %d : %d octets", i, len(f))
		}
	}
	tc := arbre(feuilles)
	dire("  %d feuilles (hash des événements, données des feuilles : SHA-256(0x00 ‖ hash)), %d cas", len(feuilles), len(fc.Cases))
	for _, c := range fc.Cases {
		attendu := "acceptee"
		if !c.Valid {
			attendu = "refusee"
		}
		raison := ""
		if c.Reason != nil {
			raison = " (" + *c.Reason + ")"
		}
		dire("-- %s : attendu %s%s", c.Name, attendu, raison)
		if c.Valid {
			if c.FirstSize > 0 {
				comparer(fmt.Sprintf("first_root = racine de l'arbre de %d feuille(s)", c.FirstSize), c.FirstRoot, hexa(tc.HashAt(c.FirstSize)))
			}
			comparer(fmt.Sprintf("second_root = racine de l'arbre de %d feuille(s)", c.SecondSize), c.SecondRoot, hexa(tc.HashAt(c.SecondSize)))
			p, err := preuveGeneree(tc, c.FirstSize, c.SecondSize)
			if err != nil {
				fatal("%s : %v", c.Name, err)
			}
			comparer("path = preuve générée par la bibliothèque, nœud pour nœud", c.Path, p)
		}
		err := verifier(c.coherence)
		obtenu := categorie(err)
		if obtenu != attendu && c.FirstSize == 0 {
			// Limite de la version v0.0.2 : size1 = 0 avec une preuve vide est
			// accepté sans lire first_root (« Any size greater than 0 is
			// consistent with size 0 ») ; la branche main de la bibliothèque le
			// refuse (« consistency proof from empty tree is meaningless ») et
			// CT-1 §10.7 rejette m = 0 avant tout calcul : la période vide de
			// NOORTRACE a une racine nulle, non la racine RFC 6962 de l'arbre vide.
			dire("  proof.VerifyConsistency : vecteur %s ; bibliothèque %s : limite de l'outil (v0.0.2 accepte size1 = 0 avec une preuve vide sans lire first_root ; la branche main le refuse ; CT-1 §10.7 rejette m = 0 avant tout calcul)", attendu, motif(err))
			limites = append(limites, fmt.Sprintf("%s : transparency-dev/merkle v0.0.2 accepte size1 = 0 avec une preuve vide (first_root non lu) là où CT-1 §10.7 rejette m = 0 ; la branche main de la bibliothèque le refuse", c.Name))
			continue
		}
		comparer("proof.VerifyConsistency", attendu, obtenu)
		if err != nil {
			dire("  motif de la bibliothèque : %s", motif(err))
		}
	}
	dire("")

	// -----------------------------------------------------------------------
	dire("== 3. ct-1/points-de-controle/attendu.json : racine des manifestes et preuves de cohérence des séries (CT-1 §10.5 à §10.8)")
	var ja journalAttendu
	lireJSON(filepath.Join(ct1, "journal-valide", "attendu.json"), &ja)
	var ap attenduPoints
	lireJSON(filepath.Join(ct1, "points-de-controle", "attendu.json"), &ap)
	periodes := map[string]*periode{} // racine du manifeste → période (seules les périodes non vides)
	for _, pa := range ap.Periodes {
		var m manifeste
		lireJSON(filepath.Join(ct1, "points-de-controle", pa.Manifest), &m)
		var fs [][]byte
		for _, h := range ja.Hashes {
			if h.Seq >= m.FirstSeq && h.Seq <= m.LastSeq {
				fs = append(fs, octets(h.Hash))
			}
		}
		pr := &periode{nom: pa.File, manifest: m, feuilles: fs, arbre: arbre(fs)}
		dire("-- %s (manifeste %s : period_start %d, count %d, %d point(s))", pa.File, filepath.Base(pa.Manifest), m.PeriodStart, m.Count, len(pa.Points))
		comparer("feuilles de la période (seq de first_seq à last_seq de journal-valide)", m.Count, len(fs))
		if m.Count == 0 {
			dire("  période vide : racine nulle (convention NOORTRACE, CT-1 §9.2), aucune feuille, aucune preuve de cohérence")
			nuls := 0
			for _, pt := range pa.Points {
				if pt.Consistency == nil {
					nuls++
				}
			}
			comparer("points sans preuve (consistency null)", len(pa.Points), nuls)
			continue
		}
		periodes[m.Root] = pr
		comparer(fmt.Sprintf("root du manifeste = racine de l'arbre de %d feuille(s)", m.Count), m.Root, hexa(pr.arbre.HashAt(m.Count)))
		comparer("last.root = racine de l'arbre de last.tree_size feuille(s)", pa.Last.Root, hexa(pr.arbre.HashAt(pa.Last.TreeSize)))
		// Regroupement des points par (first_size, second_size) : même preuve attendue.
		type cle struct{ m, n uint64 }
		groupes := map[cle][]pointAttendu{}
		var ordre []cle
		zeros, nuls := 0, 0
		for _, pt := range pa.Points {
			if pt.TreeSize == 0 {
				zeros++
				if pt.Consistency == nil {
					nuls++
				}
				continue
			}
			if pt.Consistency == nil {
				comparer(fmt.Sprintf("point %d (tree_size %d) : preuve présente", pt.Index, pt.TreeSize), true, false)
				continue
			}
			k := cle{pt.Consistency.FirstSize, pt.Consistency.SecondSize}
			if _, vu := groupes[k]; !vu {
				ordre = append(ordre, k)
			}
			groupes[k] = append(groupes[k], pt)
		}
		comparer("points de tree_size 0 sans preuve (aucune preuve ne part d'une racine nulle)", zeros, nuls)
		sort.Slice(ordre, func(i, j int) bool {
			return ordre[i].m < ordre[j].m || (ordre[i].m == ordre[j].m && ordre[i].n < ordre[j].n)
		})
		for _, k := range ordre {
			pts := groupes[k]
			ref := *pts[0].Consistency
			memes := true
			for _, pt := range pts {
				if pt.TreeSize != k.m || fmt.Sprint(*pt.Consistency) != fmt.Sprint(ref) {
					memes = false
				}
			}
			comparer(fmt.Sprintf("(%d, %d) : %d point(s) de tree_size %d, même preuve vers count %d", k.m, k.n, len(pts), k.m, k.n), true, memes && k.n == m.Count)
			comparer(fmt.Sprintf("(%d, %d) : first_root = racine de l'arbre de %d feuille(s)", k.m, k.n, k.m), ref.FirstRoot, hexa(pr.arbre.HashAt(k.m)))
			comparer(fmt.Sprintf("(%d, %d) : second_root = root du manifeste", k.m, k.n), ref.SecondRoot, m.Root)
			p, err := preuveGeneree(pr.arbre, k.m, k.n)
			if err != nil {
				fatal("%s (%d, %d) : %v", pa.File, k.m, k.n, err)
			}
			comparer(fmt.Sprintf("(%d, %d) : path = preuve générée par la bibliothèque, nœud pour nœud", k.m, k.n), ref.Path, p)
			comparer(fmt.Sprintf("(%d, %d) : proof.VerifyConsistency", k.m, k.n), "acceptee", motif(verifier(ref)))
		}
	}
	dire("")

	// -----------------------------------------------------------------------
	dire("== 4. Dossiers à partie points-de-controle.json (CT-1 §11.2, CT-6 révision 0.2) : preuve de cohérence vérifiée et régénérée")
	for _, racine := range []struct{ etiquette, chemin string }{{"ct-1", ct1}, {"ct-6", ct6}} {
		entrees, err := os.ReadDir(filepath.Join(racine.chemin, "dossiers"))
		if err != nil {
			fatal("%v", err)
		}
		for _, e := range entrees {
			if !e.IsDir() {
				continue
			}
			dossier := filepath.Join(racine.chemin, "dossiers", e.Name())
			cheminPartie := filepath.Join(dossier, "points-de-controle.json")
			if _, err := os.Stat(cheminPartie); err != nil {
				continue
			}
			echecs := echecsAttendus(filepath.Join(dossier, "attendu.json"))
			dire("-- %s/dossiers/%s (vérifications en échec attendues : %s)", racine.etiquette, e.Name(), strings.Join(echecsOuAucune(echecs), ", "))
			dire("  SHA-256 de points-de-controle.json : %s", sha256Fichier(cheminPartie))
			brut, err := os.ReadFile(cheminPartie)
			if err != nil {
				fatal("%v", err)
			}
			if bytes.Equal(bytes.TrimSpace(brut), []byte("null")) {
				dire("  partie « null » : aucune preuve à confronter (sans objet)")
				continue
			}
			var partie partiePoints
			if err := json.Unmarshal(brut, &partie); err != nil {
				dire("  partie illisible pour encoding/json (%s) : sans objet", strings.Join(strings.Fields(err.Error()), " "))
				continue
			}
			if partie.Consistency == nil {
				dire("  aucune preuve de cohérence dans la partie : sans objet")
				continue
			}
			c := *partie.Consistency
			dire("  consistency : (%d, %d), %d nœud(s) ; point : tree_size %d, root %s", c.FirstSize, c.SecondSize, len(c.Path), partie.Checkpoint.TreeSize, partie.Checkpoint.Root)
			verdictLib := verifier(c)
			attendu := "acceptee"
			if contient(echecs, "K-5") {
				attendu = "refusee"
			}
			if pr, ok := periodes[c.SecondRoot]; ok && c.SecondSize == pr.manifest.Count {
				p, err := preuveGeneree(pr.arbre, c.FirstSize, c.SecondSize)
				if err != nil {
					fatal("%s : %v", e.Name(), err)
				}
				dire("  second_root est la racine du manifeste de %s : preuve régénérée depuis ses feuilles : %s", pr.nom, fmt.Sprint(p))
				if contient(echecs, "K-1") {
					// K-1 en échec : la partie peut porter d'autres défauts que le
					// vérificateur n'examine pas (prérequis) ; la comparaison est imprimée
					// pour information et n'est pas comptée.
					dire("  path = preuve régénérée, pour information (K-1 attendue en échec) : %v", fmt.Sprint(c.Path) == fmt.Sprint(p))
				} else if attendu == "acceptee" {
					comparer("path = preuve régénérée, nœud pour nœud", c.Path, p)
				} else {
					comparer("path diffère de la preuve régénérée (K-5 attendue en échec)", true, fmt.Sprint(c.Path) != fmt.Sprint(p))
				}
			} else {
				dire("  second_root n'est la racine d'aucun manifeste de journal-valide : preuve non régénérée")
			}
			if contient(echecs, "K-1") {
				dire("  K-1 attendue en échec : K-5 n'est pas exécutée par le vérificateur (prérequis en échec) ; verdict de la bibliothèque pour information : %s", motif(verdictLib))
				continue
			}
			comparer("proof.VerifyConsistency", attendu, categorie(verdictLib))
			if verdictLib != nil {
				dire("  motif de la bibliothèque : %s", motif(verdictLib))
			}
		}
	}
	dire("")

	dire("Discordances au total : %d", len(discordances))
	for _, d := range discordances {
		dire("  - %s", d)
	}
	dire("Limites de l'outil relevées : %d", len(limites))
	for _, l := range limites {
		dire("  - %s", l)
	}
	fmt.Println(strings.Join(sortie, "\n"))
	if len(discordances) > 0 {
		os.Exit(1)
	}
}

func echecsOuAucune(l []string) []string {
	if len(l) == 0 {
		return []string{"aucune"}
	}
	return l
}
