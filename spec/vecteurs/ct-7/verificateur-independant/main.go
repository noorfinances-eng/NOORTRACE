// Vérificateur indépendant CT-7 (Go, bibliothèque standard uniquement).
//
// Usage : noortrace-ct7 [-json] [-v] <répertoire spec/vecteurs/ct-7>
//         noortrace-ct7 condenser <attestation.json>
//         noortrace-ct7 condenser-pv <proces-verbal.json>
//
// condenser et condenser-pv sont le second outil indépendant d'EX-7.8 et
// d'EX-5.8 : ils impriment D_P (attestation P, ou attestation signée dont
// ils prennent le membre attestation) ou D_C (procès-verbal privé de
// signatures), puis le même condensé par groupes de huit chiffres, pour la
// comparaison avec l'outil de référence et l'écran du portefeuille.
//
// Recalcule, depuis le seul texte de CT-7 (et de CT-1 §6.3 pour EIP-191) et
// les schémas qu'il nomme, chaque valeur que les vecteurs de CT-7 déclarent
// et la confronte (EX-A.21 à EX-A.23) : procès-verbaux de cérémonie (D_C,
// CR-1 à CR-12, signataires), attestations de périmètre (JCS(P), D_P, M,
// adresses recouvrées, AT-1 à AT-4, signatures croisées), matrice de
// conformité (MX-1 à MX-3, MX-5, MX-9), modèle de menace (schéma et tables
// du texte), clés de test. Code de retour 0 si et seulement si tout
// concorde ; 1 en cas de discordance ou d'erreur ; 2 si l'usage est
// incorrect ou la racine introuvable.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

func base64Standard(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func main() {
	enJSON := flag.Bool("json", false, "rapport en JSON sur la sortie standard")
	verbeux := flag.Bool("v", false, "liste aussi les valeurs concordantes et chaque valeur hors périmètre")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage : %s [-json] [-v] <répertoire des vecteurs CT-7>\n", os.Args[0])
		flag.PrintDefaults()
	}
	if len(os.Args) == 3 && (os.Args[1] == "condenser" || os.Args[1] == "condenser-pv") {
		os.Exit(condenser(os.Args[1], os.Args[2]))
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

// condenser imprime D_P ou D_C d'un fichier (EX-7.8, EX-5.8). Code 0, ou 2
// si le fichier est illisible, n'est pas du JSON strict ou n'a pas de forme
// canonique.
func condenser(mode, fichier string) int {
	octets, err := os.ReadFile(fichier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s : illisible (%v)\n", fichier, err)
		return 2
	}
	v, err := AnalyserJSONStrict(octets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s : %v\n", fichier, err)
		return 2
	}
	var d []byte
	if mode == "condenser-pv" {
		d, err = CondenseCeremonie(v)
	} else {
		if a := v.Get("attestation"); a != nil && v.Get("signatures") != nil {
			v = a
		}
		d, err = CondenseAttestation(v)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s : forme canonique non calculable (%v)\n", fichier, err)
		return 2
	}
	h := Hex0x(d)
	fmt.Println(h)
	var groupes []string
	for i := 2; i < len(h); i += 8 {
		groupes = append(groupes, h[i:i+8])
	}
	fmt.Println("Groupes de huit :", strings.Join(groupes, " "))
	return 0
}
