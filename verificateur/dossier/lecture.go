// Paquet dossier : lecture du dossier v0 (CT-1 §11) et vérifications de
// CT-1 §11.4 que CT-6 reprend sans changement : D-1, D-2 (index), E-1 à
// E-11 (contrôles 1, 6, 7), C-1 à C-3 (2, 6), M-1 à M-3 et P-1 à P-5
// (3, 2, 6), A-1 à A-4 (7), K-1 à K-6 (partie points-de-controle.json,
// CT-6 §5.4) et AT-1 à AT-7 (partie attestation-perimetre.json, CT-6 §5.5).
//
// K-7, K-8 et K-9 réutilisent les vérifications des contrôles 4, 8 et 5 et
// sont produites par le moteur avec les paquets horodatage, registre et ots.
package dossier

import (
	"fmt"
	"path/filepath"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Noms des parties (CT-1 §11.1), dans l'ordre de l'index.
const (
	PEvenement    = "evenement"
	PVoisins      = "voisins"
	PChemin       = "chemin"
	PManifeste    = "manifeste"
	PManifesteSig = "manifeste_sig"
	PCles         = "cles"
	PApprobations = "approbations"
	PJeton        = "jeton_rfc3161"
	PPreuveOTS    = "preuve_ots"
	PRegistre     = "registre"
	PCertificat   = "certificat_commit"
	PValidateurs  = "validateurs"
	PPoints       = "points_de_controle"
	PAttestation  = "attestation_perimetre"
)

// RaisonHorsPerimetreCT1 : raison d'absence qui donne hors_perimetre_version
// (EX-4.3).
const RaisonHorsPerimetreCT1 = "hors périmètre CT-1"

// Fichiers fixes des parties, et limite de taille de chacune (EX-4.13).
var fichiersParties = map[string]string{
	PEvenement: "evenement.json", PVoisins: "voisins.json", PChemin: "chemin.json",
	PManifeste: "manifeste.json", PManifesteSig: "manifeste.sig", PCles: "cles.json",
	PApprobations: "approbations.json", PJeton: "jeton-rfc3161.der", PPreuveOTS: "preuve.ots",
	PRegistre: "registre.json", PCertificat: "certificat-commit.json", PValidateurs: "validateurs.json",
	PPoints: "points-de-controle.json", PAttestation: "attestation-perimetre.json",
}

var limites = map[string]int64{
	PEvenement: entree.LimitePartieCT1, PVoisins: entree.LimitePartieCT1, PChemin: entree.LimitePartieCT1,
	PManifeste: entree.LimitePartieCT1, PManifesteSig: entree.LimitePartieCT1, PCles: entree.LimitePartieCT1,
	PApprobations: entree.LimitePartieCT1, PJeton: entree.LimiteJeton, PPreuveOTS: entree.LimitePreuveOTS,
	PRegistre: entree.LimiteRegistre, PCertificat: entree.LimiteCertificat, PValidateurs: entree.LimiteValidateurs,
	PPoints: entree.LimitePoints, PAttestation: entree.LimiteAttestation,
}

// Partie : une partie déclarée par l'index.
type Partie struct {
	Nom     string
	Fichier string
	Present bool
	// Raison : reason_if_absent (partie absente).
	Raison string
	// Sha256Declare : sha256 de l'index (partie présente).
	Sha256Declare string
	// Lecture : lecture bornée du fichier (partie présente).
	Lecture entree.Lecture
	// Valeur : document JSON (parties JSON), nil s'il n'est pas du JSON.
	Valeur *jsonv.Valeur
	// ErrJSON : motif quand le fichier n'est pas du JSON.
	ErrJSON error
	// Sha256Flux : SHA-256 calculé en flux au-delà de la limite (attestation,
	// EX-4.15).
	Sha256Flux *[32]byte
}

// Exploitable dit si la partie est présente, lue dans sa limite et un objet
// JSON.
func (p *Partie) Exploitable() bool {
	return p != nil && p.Present && p.Lecture.Etat == entree.Lu && p.Valeur.EstObjet()
}

// Dossier : le répertoire et son index.
type Dossier struct {
	Repertoire  string
	IndexSha256 [32]byte
	Index       *jsonv.Valeur
	// IndexTropGrand : dossier.json dépasse 1 Mio (D-1 en échec).
	IndexTropGrand bool
	// ErrIndex : défaut de schéma de l'index (D-1), nil sinon.
	ErrIndex error
	Parties  []*Partie
	parNom   map[string]*Partie
}

// Partie rend la partie déclarée de ce nom, ou nil.
func (d *Dossier) Partie(nom string) *Partie {
	if d == nil {
		return nil
	}
	return d.parNom[nom]
}

// Defaut : défaut qui rend l'entrée inutilisable (code 2).
type Defaut struct {
	Genre   string
	Message commun.Texte
}

func (d *Defaut) Error() string { return d.Message.Fr }

// Ouvrir lit `dossier.json` (EX-5.2, étape 2). Un répertoire sans
// `dossier.json`, ou dont `dossier.json` n'est pas du JSON, rend le code 2
// (`dossier_illisible`, EX-4.12).
func Ouvrir(rep string) (*Dossier, *Defaut) {
	if !entree.EstRepertoire(rep) {
		return nil, &Defaut{"dossier_illisible", commun.T("le répertoire du dossier n'existe pas ou n'est pas un répertoire : "+rep, "the dossier directory does not exist or is not a directory: "+rep)}
	}
	d := &Dossier{Repertoire: rep, parNom: map[string]*Partie{}}
	l := entree.Lire(filepath.Join(rep, "dossier.json"), entree.LimiteIndex)
	switch l.Etat {
	case entree.Absent:
		return nil, &Defaut{"dossier_illisible", commun.T("dossier.json absent : le répertoire n'est pas un dossier de preuve", "dossier.json missing: the directory is not an evidence dossier")}
	case entree.Illisible:
		return nil, &Defaut{"dossier_illisible", commun.T(fmt.Sprintf("dossier.json illisible (%v)", l.Err), fmt.Sprintf("dossier.json unreadable (%v)", l.Err))}
	case entree.TropGrand:
		// L'index dépasse sa limite : il est inexploitable et met D-1 en
		// échec (EX-4.11) ; son SHA-256 n'est pas calculé au-delà.
		d.IndexTropGrand = true
		return d, nil
	}
	d.IndexSha256 = l.Sha256
	v, err := jsonv.Analyser(l.Octets)
	if err != nil {
		return nil, &Defaut{"dossier_illisible", commun.T("dossier.json n'est pas du JSON ("+err.Error()+")", "dossier.json is not JSON ("+err.Error()+")")}
	}
	d.Index = v
	if err := schema.Valider(schema.Dossier, v); err != nil {
		d.ErrIndex = err
		return d, nil
	}
	if _, ok := commun.LireHorodatage(v.Membre("generated_at").S()); !ok {
		d.ErrIndex = fmt.Errorf("generated_at n'est pas une date existante")
		return d, nil
	}
	for _, pv := range v.Membre("parts").Elements {
		p := &Partie{Nom: pv.Membre("name").S(), Fichier: pv.Membre("file").S(), Present: pv.Membre("present").Bool}
		if r := pv.Membre("reason_if_absent"); r.EstChaine() {
			p.Raison = r.Chaine
		}
		if s := pv.Membre("sha256"); s.EstChaine() {
			p.Sha256Declare = s.Chaine
		}
		d.Parties = append(d.Parties, p)
		d.parNom[p.Nom] = p
	}
	return d, nil
}

// IndexConforme dit si l'index a été lu et suit son schéma.
func (d *Dossier) IndexConforme() bool {
	return d != nil && !d.IndexTropGrand && d.Index != nil && d.ErrIndex == nil
}

// estJSON dit si la partie est un document JSON.
func estJSON(nom string) bool {
	switch nom {
	case PJeton, PPreuveOTS:
		return false
	}
	return true
}

// LireParties lit chaque partie présente, dans sa limite (EX-4.13). Une
// partie attestation-perimetre.json qui dépasse 4 Mio n'est pas analysée,
// mais son SHA-256 est calculé en flux jusqu'à 64 Mio ; au-delà, l'entrée est
// inutilisable (EX-4.15).
func (d *Dossier) LireParties() *Defaut {
	for _, p := range d.Parties {
		if !p.Present {
			continue
		}
		chemin := filepath.Join(d.Repertoire, p.Fichier)
		lim, ok := limites[p.Nom]
		if !ok {
			lim = entree.LimitePartieCT1
		}
		p.Lecture = entree.Lire(chemin, lim)
		if p.Lecture.Etat == entree.TropGrand && p.Nom == PAttestation {
			s, _, err := entree.Empreinte(chemin, entree.PlafondAttestation)
			if err == entree.ErrTaille {
				return &Defaut{"taille_depassee", commun.T("attestation-perimetre.json dépasse 64 Mio (EX-4.15)", "attestation-perimetre.json exceeds 64 MiB (EX-4.15)")}
			}
			if err == nil {
				p.Sha256Flux = &s
			}
		}
		if p.Lecture.Etat == entree.Lu && estJSON(p.Nom) {
			p.Valeur, p.ErrJSON = jsonv.Analyser(p.Lecture.Octets)
		}
	}
	return nil
}

// FichierPartie rend le nom de fichier fixe d'une partie.
func FichierPartie(nom string) string { return fichiersParties[nom] }

// Sha256Calcule rend le SHA-256 des octets de la partie quand il est connu.
func (p *Partie) Sha256Calcule() (string, bool) {
	if p.Lecture.Etat == entree.Lu {
		return cryptographie.Hex32(p.Lecture.Sha256), true
	}
	if p.Sha256Flux != nil {
		return cryptographie.Hex32(*p.Sha256Flux), true
	}
	return "", false
}
