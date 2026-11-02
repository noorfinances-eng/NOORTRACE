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
	// Absent : le fichier n'existe pas.
	Absent
	// TropGrand : le fichier dépasse sa limite ; seuls les octets jusqu'à la
	// limite ont été lus, puis la lecture s'est arrêtée.
	TropGrand
	// Illisible : le système de fichiers refuse la lecture (droits, pas un
	// fichier régulier…).
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

// Lire lit un fichier régulier avec une limite. Il ne lit jamais plus de
// limite + 1 octets.
func Lire(chemin string, limite int64) Lecture {
	f, err := os.Open(chemin)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Lecture{Etat: Absent, Err: err}
		}
		return Lecture{Etat: Illisible, Err: err}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Lecture{Etat: Illisible, Err: err}
	}
	if !st.Mode().IsRegular() {
		return Lecture{Etat: Illisible, Err: errors.New("pas un fichier régulier")}
	}
	b, err := io.ReadAll(io.LimitReader(f, limite+1))
	if err != nil {
		return Lecture{Etat: Illisible, Err: err}
	}
	if int64(len(b)) > limite {
		return Lecture{Etat: TropGrand, Octets: b[:limite], Err: ErrTaille}
	}
	return Lecture{Etat: Lu, Octets: b, Sha256: sha256.Sum256(b)}
}

// Empreinte calcule en flux le SHA-256 d'un fichier régulier sans en
// conserver les octets, jusqu'à un plafond absolu ; au-delà, elle rend
// ErrTaille.
func Empreinte(chemin string, plafond int64) ([32]byte, int64, error) {
	var s [32]byte
	f, err := os.Open(chemin)
	if err != nil {
		return s, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return s, 0, err
	}
	if !st.Mode().IsRegular() {
		return s, 0, errors.New("pas un fichier régulier")
	}
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
