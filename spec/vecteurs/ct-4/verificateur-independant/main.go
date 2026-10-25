// Vérificateur indépendant CT-4 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct4 [-json] [-v] <répertoire spec/vecteurs/ct-4>
//
// Recalcule, famille par famille selon l'annexe A de CT-4, chaque valeur que
// les vecteurs déclarent, depuis la seule spécification (CT-4, et ce qu'elle
// cite de CT-1 §10 et de CT-6 §11), et confronte. Code de retour 0 si tout
// concorde, 1 si une discordance est trouvée (elle est listée), 2 pour un
// usage incorrect (EX-A.5).

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	enJSON := flag.Bool("json", false, "rapport en JSON sur la sortie standard")
	verbeux := flag.Bool("v", false, "liste aussi les valeurs concordantes et chaque valeur hors périmètre")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage : %s [-json] [-v] <répertoire des vecteurs CT-4>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	racine := flag.Arg(0)
	if info, err := os.Stat(racine); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "racine des vecteurs introuvable ou non répertoire : %s\n", racine)
		os.Exit(2)
	}
	rap := VerifierVecteurs(racine)
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
