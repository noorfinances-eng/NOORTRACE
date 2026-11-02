// Vérificateur indépendant CT-9 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct9 [-json] [-v] <répertoire spec/vecteurs/ct-9>
//
// Écrit depuis le seul texte de spec/CT-9-plan-de-tests.md et le schéma
// spec/schemas/plan-de-tests-v0.schema.json, sans lire le code JavaScript
// du dépôt (CT-9 EX-A.17). Il relit les huit spécifications et
// spec/README.md, menaces.json, catalogue.json, test/*.test.js,
// .github/workflows/ci.yml et le texte de CT-9, puis recalcule chaque
// valeur publiée sous spec/vecteurs/ct-9 : identifiants définis par chaque
// spécification (5.2), menaces, titres de tests (EX-4.2), règles de
// couverture (a) à (d), couverture.json membre par membre, index TA- par
// menace, unicité et forme des identifiants du catalogue (EX-3.1), tables
// du texte (EX-4.4), verdicts des cas contre le schéma, rapports de mesure,
// consignations, grilles, extraits et INDEX.md. Chaque valeur recalculée
// est concordante, discordante ou hors périmètre (avec sa raison, -v).
// Code de retour 0 si et seulement si aucune discordance ; 1 sinon ; 2 si
// l'usage est incorrect ou un fichier illisible. La racine du dépôt est le
// troisième parent du répertoire des vecteurs (spec/vecteurs/ct-9).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	enJSON := flag.Bool("json", false, "rapport en JSON sur la sortie standard")
	verbeux := flag.Bool("v", false, "imprime chaque contrôle, raison des hors périmètre comprise")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage : %s [-json] [-v] <répertoire spec/vecteurs/ct-9>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	vecteurs, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if info, err := os.Stat(filepath.Join(vecteurs, "catalogue.json")); err != nil || info.IsDir() {
		fmt.Fprintf(os.Stderr, "catalogue.json introuvable sous %s\n", vecteurs)
		os.Exit(2)
	}
	racine := filepath.Dir(filepath.Dir(filepath.Dir(vecteurs)))
	rap, err := Verifier(racine)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *enJSON {
		if err := rap.EcrireJSON(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		rap.EcrireTexte(os.Stdout, *verbeux)
	}
	if rap.Resume.Discordants > 0 {
		os.Exit(1)
	}
}
