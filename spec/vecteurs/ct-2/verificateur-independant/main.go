// Vérificateur indépendant CT-2 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct2 [-strict] [-json] [-v] <répertoire spec/vecteurs/ct-2>
//
// Recalcule, famille par famille selon l'annexe B de CT-2 (jcs-integral,
// redaction, pieces-mcp, pieces-modele, evenements, INDEX.md), tout ce que
// les vecteurs déclarent, depuis la seule spécification (CT-2, et CT-1 pour
// les événements), et confronte à chaque valeur attendue. Code de retour 0
// si et seulement si tout concorde ; 1 en cas de discordance ou d'erreur ;
// 2 si l'usage est incorrect ou la racine introuvable.

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	strict := flag.Bool("strict", false, "verdicts de chaîne : exige l'égalité exacte entre contrôles attendus et contrôles en échec")
	enJSON := flag.Bool("json", false, "rapport en JSON sur la sortie standard")
	verbeux := flag.Bool("v", false, "liste aussi les valeurs concordantes et les détails des contrôles")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage : %s [-strict] [-json] [-v] <répertoire des vecteurs CT-2>\n", os.Args[0])
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
	rap := VerifierVecteursCT2(racine, *strict)
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
