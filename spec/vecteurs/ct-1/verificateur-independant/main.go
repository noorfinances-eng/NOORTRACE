// Vérificateur indépendant CT-1 (Go, bibliothèque standard uniquement).
//
// Usage : verificateur-independant [-strict] [-json] [-v] <racine des vecteurs>
//
// Pour chaque famille de vecteurs (clés, jcs, journaux, arbres, cohérence,
// manifestes, points de contrôle, dossiers), recalcule tout depuis la
// spécification et confronte à chaque valeur attendue. Code de retour 0 si et seulement si tout
// concorde ; 1 en cas de discordance ou d'erreur ; 2 si l'usage est incorrect
// ou la racine introuvable.

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	strict := flag.Bool("strict", false, "exige l'égalité exacte entre contrôles attendus et contrôles en échec (sinon : inclusion, cascades admises)")
	enJSON := flag.Bool("json", false, "rapport en JSON sur la sortie standard")
	verbeux := flag.Bool("v", false, "liste aussi les valeurs concordantes et les détails des contrôles")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage : %s [-strict] [-json] [-v] <répertoire des vecteurs CT-1>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	racine := flag.Arg(0)
	info, err := os.Stat(racine)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "racine des vecteurs introuvable ou non répertoire : %s\n", racine)
		os.Exit(2)
	}
	rap := VerifierVecteurs(racine, *strict)
	if *enJSON {
		if err := rap.EcrireJSON(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		rap.EcrireTexte(os.Stdout, *verbeux)
	}
	if !rap.ToutConcorde() {
		os.Exit(1)
	}
}
