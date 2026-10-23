// Vérificateur indépendant CT-3 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct3 [-json] [-v] <répertoire spec/vecteurs/ct-3>
//
// Recalcule, famille par famille selon l'annexe A de CT-3 (constantes,
// schémas, politiques, politiques refusées, évaluation, candidats, épreuve
// d'acceptation, traces de tickets, remises, normalisation des signatures),
// chaque valeur que les vecteurs déclarent, depuis la seule spécification
// (CT-3, et CT-1 pour A, D_A et E-9), et confronte. Code de retour 0 si et
// seulement si tout concorde ; 1 en cas de discordance ou d'erreur ; 2 si
// l'usage est incorrect ou la racine introuvable (EX-A.10).

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
		fmt.Fprintf(os.Stderr, "usage : %s [-json] [-v] <répertoire des vecteurs CT-3>\n", os.Args[0])
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
