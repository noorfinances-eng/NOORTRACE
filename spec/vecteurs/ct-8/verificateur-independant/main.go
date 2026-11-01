// Vérificateur indépendant CT-8 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct8 [-json] [-v] <répertoire spec/vecteurs/ct-8>
//
// Recalcule, depuis le seul texte de CT-8 et les schémas qu'il nomme, chaque
// valeur que les vecteurs de CT-8 déclarent et la confronte (EX-A.21 à
// EX-A.24) : sorties du calculateur de dimensionnement (DM-1 à DM-22,
// EX-9.2, EX-9.3), évaluations du contrôle préalable (EX-6.2, EX-6.3),
// paquets réviseurs (lecture brute et archive/tar, PR-1 à PR-12, SHA-256
// et tailles, état, avertissements, code de retour), fichiers des
// conteneurs (SHA-256, fichiers de référence et description des images
// égaux aux blocs du texte), mesures des coefficients de 9.2. Code de
// retour 0 si et seulement si tout concorde ; 1 en cas de discordance ou
// d'erreur ; 2 si l'usage est incorrect ou la racine introuvable.

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
		fmt.Fprintf(os.Stderr, "usage : %s [-json] [-v] <répertoire des vecteurs CT-8>\n", os.Args[0])
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
