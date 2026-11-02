// Paquet entree : lectures bornées des entrées (CT-6 EX-4.13, EX-15.1).
// Chaque lecture s'arrête à la limite de la table d'EX-4.13 sans lire
// au-delà ; le SHA-256 d'un fichier peut être calculé en flux, sans rien
// conserver, jusqu'à un plafond absolu (EX-4.15).
package entree

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
)

// Limites d'EX-4.13, en octets.
const (
	Kio = 1024
	Mio = 1024 * Kio
	Gio = 1024 * Mio

	LimiteIndex           = 1 * Mio  // dossier.json
	LimitePartieCT1       = 16 * Mio // six autres parties JSON de CT-1
	LimiteJeton           = 64 * Kio // jeton-rfc3161.der (EX-9.3)
	LimitePreuveOTS       = 256 * Kio
	LimiteRegistre        = 64 * Mio // registre.json
	LimiteCertificat      = 64 * Mio // certificat-commit.json
	LimiteValidateurs     = 1 * Mio
	LimitePoints          = 1 * Mio // points-de-controle.json (EX-4.14)
	LimiteAttestation     = 4 * Mio // attestation-perimetre.json (EX-4.15)
	PlafondAttestation    = 64 * Mio
	LimiteEntetes         = 64 * Mio // fichier d'en-têtes Bitcoin
	LimiteSecondManifeste = 1 * Mio
	LimiteAncres          = 16 * Mio
	LimitePiece           = 1 * Gio
	MaxEntetes            = 200000
)

// Etat de la lecture d'un fichier.
type Etat int

const (
	// Lu : le fichier a été lu en entier, dans sa limite.
	Lu Etat = iota
	// Absent : le fichier n'existe pas, ou le chemin ne désigne pas un
	// fichier ordinaire (Err vaut alors ErrNonOrdinaire) : lien symbolique,
	// tube nommé, socket, périphérique ou répertoire, jamais ouverts.
	Absent
	// TropGrand : le fichier dépasse sa limite ; seuls les octets jusqu'à la
	// limite ont été lus, puis la lecture s'est arrêtée.
	TropGrand
	// Illisible : le système de fichiers refuse la lecture (droits, erreur
	// d'entrée-sortie…).
	Illisible
)

// Lecture : résultat d'une lecture bornée.
type Lecture struct {
	Etat   Etat
	Octets []byte
	// Sha256 : SHA-256 des octets lus quand Etat vaut Lu.
	Sha256 [32]byte
	Err    error
}

// ErrTaille : limite de taille dépassée.
var ErrTaille = errors.New("limite de taille dépassée")

// ErrNonOrdinaire : le chemin existe mais ne désigne pas un fichier
// ordinaire (lien symbolique, tube nommé, socket, périphérique,
// répertoire). Le fichier n'est pas ouvert : un tube nommé bloquerait la
// lecture (EX-15.2), un lien désignerait un fichier hors du dossier. La
// lecture rend l'état Absent avec cette erreur : une partie qui n'est pas un
// fichier ordinaire compte comme absente du répertoire (D-2), une entrée à
// part rend l'entrée inutilisable (code 2, EX-4.12).
var ErrNonOrdinaire = errors.New("pas un fichier ordinaire (lien symbolique, tube nommé, socket, périphérique ou répertoire) : non ouvert")

// ouvrir ouvre un fichier ordinaire sans jamais suivre de lien ni bloquer :
// Lstat d'abord (le chemin doit désigner un fichier ordinaire), puis
// ouverture sans suivre de lien et sans attente (ouvrirSansLien), puis
// fstat (le descripteur ouvert est un fichier ordinaire, le même que celui
// que Lstat a vu). Il rend l'état Absent avec ErrNonOrdinaire quand le
// chemin existe sans être un fichier ordinaire.
func ouvrir(chemin string) (*os.File, Etat, error) {
	avant, err := os.Lstat(chemin)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Absent, err
		}
		return nil, Illisible, err
	}
	if !avant.Mode().IsRegular() {
		return nil, Absent, ErrNonOrdinaire
	}
	f, err := ouvrirSansLien(chemin)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, Absent, err
		case lienRefuse(err):
			return nil, Absent, ErrNonOrdinaire
		}
		return nil, Illisible, err
	}
	apres, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, Illisible, err
	}
	if !apres.Mode().IsRegular() || !os.SameFile(avant, apres) {
		f.Close()
		return nil, Absent, ErrNonOrdinaire
	}
	return f, Lu, nil
}

// Lire lit un fichier ordinaire avec une limite. Il ne lit jamais plus de
// limite + 1 octets, ne suit aucun lien symbolique et n'ouvre ni tube, ni
// socket, ni périphérique (voir ouvrir).
func Lire(chemin string, limite int64) Lecture {
	f, etat, err := ouvrir(chemin)
	if err != nil {
		return Lecture{Etat: etat, Err: err}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limite+1))
	if err != nil {
		return Lecture{Etat: Illisible, Err: err}
	}
	if int64(len(b)) > limite {
		return Lecture{Etat: TropGrand, Octets: b[:limite], Err: ErrTaille}
	}
	return Lecture{Etat: Lu, Octets: b, Sha256: sha256.Sum256(b)}
}

// Empreinte calcule en flux le SHA-256 d'un fichier ordinaire sans en
// conserver les octets, jusqu'à un plafond absolu ; au-delà, elle rend
// ErrTaille. Même ouverture que Lire.
func Empreinte(chemin string, plafond int64) ([32]byte, int64, error) {
	var s [32]byte
	f, _, err := ouvrir(chemin)
	if err != nil {
		return s, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, plafond+1))
	if err != nil {
		return s, n, err
	}
	if n > plafond {
		return s, n, ErrTaille
	}
	copy(s[:], h.Sum(nil))
	return s, n, nil
}

// Existe dit si un chemin existe (fichier ou autre), sans le lire.
func Existe(chemin string) bool {
	_, err := os.Lstat(chemin)
	return err == nil
}

// EstRepertoire dit si le chemin désigne un répertoire lisible.
func EstRepertoire(chemin string) bool {
	st, err := os.Stat(chemin)
	return err == nil && st.IsDir()
}
