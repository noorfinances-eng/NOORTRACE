// Commande noortrace-verifier : vérificateur hors ligne d'un dossier de
// preuve NOORTRACE v0 (CT-6). Interface : CT-6 §8 ; codes de retour : §8.3.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/moteur"
	"github.com/noorfinances-eng/noortrace/verificateur/ots"
	"github.com/noorfinances-eng/noortrace/verificateur/rapport"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// version du binaire, fixée à la construction par
// -ldflags='-X main.version=<version>' (CT-6 EX-14.6).
var version = "0.1.0-dev"

// Ligne : options analysées (CT-6 §8.2).
type Ligne struct {
	Repertoire      string
	Ancres          string
	Entetes         string
	Pieces          string
	SecondManifeste string
	Exiger          []int
	ExigerDonne     bool
	Langue          string
	JSON            bool
	Detail          bool
	Version         bool
	Aide            bool
}

// erreurUsage : usage incorrect (code 2, type usage, EX-8.2).
type erreurUsage struct{ msg commun.Texte }

func (e *erreurUsage) Error() string { return e.msg.Fr }

func usage(fr, en string) *erreurUsage { return &erreurUsage{commun.T(fr, en)} }

// Analyser lit les arguments (sans le nom du programme).
func Analyser(args []string) (Ligne, *erreurUsage) {
	l := Ligne{Langue: "fr"}
	vues := map[string]bool{}
	avecValeur := map[string]bool{"--ancres": true, "--entetes-bitcoin": true, "--pieces": true, "--second-manifeste": true, "--exiger": true, "--langue": true}
	sansValeur := map[string]bool{"--json": true, "--detail": true, "--version": true, "--aide": true, "--help": true}
	var reps []string
	var premiere *erreurUsage
	note := func(e *erreurUsage) {
		if premiere == nil {
			premiere = e
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			reps = append(reps, a)
			continue
		}
		nom, val, aEgal := strings.Cut(a, "=")
		cle := nom
		if cle == "--help" {
			cle = "--aide"
		}
		switch {
		case avecValeur[nom]:
			if !aEgal {
				if i+1 >= len(args) {
					note(usage("option "+nom+" sans sa valeur", "option "+nom+" without its value"))
					continue
				}
				i++
				val = args[i]
			}
		case sansValeur[nom]:
			if aEgal {
				note(usage("l'option "+nom+" ne prend pas de valeur", "option "+nom+" takes no value"))
				continue
			}
		default:
			note(usage("option inconnue : "+a, "unknown option: "+a))
			continue
		}
		if vues[cle] {
			note(usage("option répétée : "+nom, "repeated option: "+nom))
			continue
		}
		vues[cle] = true
		if avecValeur[nom] && val == "" {
			note(usage("option "+nom+" avec une valeur vide", "option "+nom+" with an empty value"))
			continue
		}
		switch nom {
		case "--ancres":
			l.Ancres = val
		case "--entetes-bitcoin":
			l.Entetes = val
		case "--pieces":
			l.Pieces = val
		case "--second-manifeste":
			l.SecondManifeste = val
		case "--exiger":
			l.ExigerDonne = true
			n, err := lireExiger(val)
			if err != nil {
				note(err)
			}
			l.Exiger = n
		case "--langue":
			if val != "fr" && val != "en" {
				note(usage("--langue attend fr ou en", "--langue expects fr or en"))
			} else {
				l.Langue = val
			}
		case "--json":
			l.JSON = true
		case "--detail":
			l.Detail = true
		case "--version":
			l.Version = true
		case "--aide", "--help":
			l.Aide = true
		}
	}
	if premiere != nil {
		return l, premiere
	}
	if l.Version || l.Aide {
		autres := 0
		for k := range vues {
			if k != "--langue" {
				autres++
			}
		}
		if autres != 1 || len(reps) != 0 {
			return l, usage("--version et --aide ne se combinent qu'avec --langue", "--version and --aide combine only with --langue")
		}
		return l, nil
	}
	if len(reps) != 1 {
		return l, usage(fmt.Sprintf("exactement un répertoire de dossier attendu (%d donné(s))", len(reps)), fmt.Sprintf("exactly one dossier directory expected (%d given)", len(reps)))
	}
	l.Repertoire = reps[0]
	return l, nil
}

func lireExiger(v string) ([]int, *erreurUsage) {
	if v == "tous" {
		return []int{1, 2, 3, 4, 5, 6, 7, 8}, nil
	}
	vus := map[int]bool{}
	var out []int
	for _, p := range strings.Split(v, ",") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 8 || p != strconv.Itoa(n) || vus[n] {
			return nil, usage("--exiger attend des numéros de contrôles de 1 à 8, distincts, séparés par « , », ou tous", "--exiger expects distinct control numbers from 1 to 8 separated by “,”, or tous")
		}
		vus[n] = true
		out = append(out, n)
	}
	for i := 1; i < len(out); i++ {
		for k := i; k > 0 && out[k] < out[k-1]; k-- {
			out[k], out[k-1] = out[k-1], out[k]
		}
	}
	return out, nil
}

func aide(langue string) string {
	if langue == "en" {
		return `noortrace-verifier: offline verifier of a NOORTRACE v0 evidence dossier (CT-6).

Usage:
  noortrace-verifier <directory> [--ancres <file>] [--entetes-bitcoin <file>]
                     [--pieces <directory>] [--second-manifeste <file>]
                     [--exiger <controls>] [--langue fr|en] [--json] [--detail]
  noortrace-verifier --version
  noortrace-verifier --aide

Options:
  --ancres <file>             the reviewer's trust anchors file (CT-6 §12)
  --entetes-bitcoin <file>    Bitcoin header chain (CT-6 §10.3)
  --pieces <directory>        pieces named by their sha256 (CT-6 EX-4.6)
  --second-manifeste <file>   previous or next manifest of the same journal
  --exiger <controls>         controls 1 to 8 separated by "," or "tous":
                              a required control not passed gives code 3
  --langue fr|en              language of the output (default: fr)
  --json                      JSON report (rapport-verification-v0)
  --detail                    readable report: every check
  --version, --aide, --help   print the version or this help, then exit

Exit codes: 0 valid, 1 invalid, 2 unusable input (no verdict), 3 incomplete.
The verifier opens no network connection and reads no system certificate store.
`
	}
	return `noortrace-verifier : vérificateur hors ligne d'un dossier de preuve NOORTRACE v0 (CT-6).

Usage :
  noortrace-verifier <répertoire> [--ancres <fichier>] [--entetes-bitcoin <fichier>]
                     [--pieces <répertoire>] [--second-manifeste <fichier>]
                     [--exiger <contrôles>] [--langue fr|en] [--json] [--detail]
  noortrace-verifier --version
  noortrace-verifier --aide

Options :
  --ancres <fichier>            fichier d'ancres de confiance du réviseur (CT-6 §12)
  --entetes-bitcoin <fichier>   chaîne d'en-têtes Bitcoin (CT-6 §10.3)
  --pieces <répertoire>         pièces nommées par leur sha256 (CT-6 EX-4.6)
  --second-manifeste <fichier>  manifeste précédent ou suivant du même journal
  --exiger <contrôles>          contrôles de 1 à 8 séparés par « , », ou « tous » :
                                un contrôle exigé non réussi donne le code 3
  --langue fr|en                langue de la sortie (défaut : fr)
  --json                        rapport JSON (rapport-verification-v0)
  --detail                      rapport lisible : toutes les vérifications
  --version, --aide, --help     imprime la version ou cette aide, puis sort

Codes de retour : 0 valide, 1 invalide, 2 entrée inutilisable (aucun verdict), 3 incomplet.
Le vérificateur n'ouvre aucune connexion réseau et ne lit aucun magasin de certificats du système.
`
}

func texteVersion() (string, error) {
	liste, err := schema.Liste()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s (%s)\n", moteur.Nom, version, runtime.Version())
	for _, s := range liste {
		fmt.Fprintf(&b, "%s %s\n", s.ID, s.Sha256)
	}
	return b.String(), nil
}

// Executer exécute la commande et rend le code de retour.
func Executer(args []string, sortie, erreurs io.Writer) int {
	l, eu := Analyser(args)
	langue := l.Langue
	ecrireErreur := func(genre string, msg commun.Texte, check string, entrees *rapport.Entrees) int {
		if l.JSON {
			ver, _ := moteur.Verificateur(version)
			re := rapport.RapportErreur{Format: rapport.Format, Version: rapport.Version, Verifier: ver, Language: langue,
				Inputs: entrees, ExitCode: 2, Error: rapport.ErreurRapport{Kind: genre, Message: msg.Langue(langue)}}
			if check != "" {
				re.Error.Check = &check
			}
			b, err := rapport.EncoderJSON(re)
			if err == nil {
				sortie.Write(b)
			}
		}
		pref := "Erreur : "
		if langue == "en" {
			pref = "Error: "
		}
		fmt.Fprintln(erreurs, pref+msg.Langue(langue))
		return 2
	}
	if eu != nil {
		return ecrireErreur("usage", eu.msg, "", nil)
	}
	if l.Aide {
		fmt.Fprint(sortie, aide(langue))
		return 0
	}
	if l.Version {
		t, err := texteVersion()
		if err != nil {
			return ecrireErreur("schemas_illisibles", commun.T("schémas embarqués illisibles : "+err.Error(), "embedded schemas unreadable: "+err.Error()), "", nil)
		}
		fmt.Fprint(sortie, t)
		return 0
	}
	if _, err := schema.Liste(); err != nil {
		return ecrireErreur("schemas_illisibles", commun.T("schémas embarqués illisibles : "+err.Error(), "embedded schemas unreadable: "+err.Error()), "", nil)
	}
	res := moteur.Verifier(moteur.Options{Repertoire: l.Repertoire, Ancres: l.Ancres, Entetes: l.Entetes, Pieces: l.Pieces,
		SecondManifeste: l.SecondManifeste, Exiger: l.Exiger, Langue: langue, Version: version})
	if res.Erreur != nil {
		return ecrireErreur(res.Erreur.Genre, res.Erreur.Message, res.Erreur.Verification, res.Entrees)
	}
	r := res.Rapport
	if l.JSON {
		b, err := rapport.EncoderJSON(r)
		if err != nil {
			return ecrireErreur("erreur_interne", commun.T("sérialisation du rapport impossible : "+err.Error(), "cannot serialise the report: "+err.Error()), "", res.Entrees)
		}
		sortie.Write(b)
	} else {
		fmt.Fprint(sortie, rapport.Lisible(r, rapport.InfosLisibles{
			Verificateur: fmt.Sprintf("%s %s (%s)", moteur.Nom, version, runtime.Version()),
			Repertoire:   r.Inputs.Dossier.Path,
		}, l.Detail))
	}
	if a := avertissementProvisoire(langue); a != "" {
		fmt.Fprintln(erreurs, a)
	}
	return res.Code
}

// avertissementProvisoire : tant qu'un des contrôles 4, 5 ou 8 n'est pas
// construit, le binaire le dit sur la sortie d'erreur (EX-8.5) ; rien sinon.
func avertissementProvisoire(langue string) string {
	if horodatage.Construit() && ots.Construit() && registre.Construit() {
		return ""
	}
	if langue == "en" {
		return "warning: provisional binary: controls 4, 5 and 8 are still to be built; N-1 does not yet apply the strict DER profile of CT-6 §9.3 to the anchors file"
	}
	return "avertissement : binaire provisoire : contrôles 4, 5 et 8 à construire ; N-1 n'applique pas encore le profil DER strict de CT-6 §9.3 au fichier d'ancres"
}

func main() {
	os.Exit(Executer(os.Args[1:], os.Stdout, os.Stderr))
}
