//go:build unix

package entree

import (
	"errors"
	"os"
	"syscall"
)

// ouvrirSansLien ouvre en lecture sans suivre de lien symbolique
// (O_NOFOLLOW) et sans attendre un écrivain si le chemin a été remplacé par
// un tube nommé entre Lstat et l'ouverture (O_NONBLOCK, sans effet sur la
// lecture d'un fichier ordinaire).
func ouvrirSansLien(chemin string) (*os.File, error) {
	return os.OpenFile(chemin, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// lienRefuse dit si l'ouverture a échoué parce que le chemin est un lien
// symbolique (ELOOP avec O_NOFOLLOW).
func lienRefuse(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}
