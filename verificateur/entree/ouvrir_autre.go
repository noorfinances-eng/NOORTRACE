//go:build !unix

package entree

import "os"

// ouvrirSansLien : hors des systèmes Unix, aucune option d'ouverture ne
// refuse un lien ; le contrôle repose sur Lstat avant l'ouverture et sur
// fstat et os.SameFile après (ouvrir).
func ouvrirSansLien(chemin string) (*os.File, error) {
	return os.Open(chemin)
}

func lienRefuse(error) bool { return false }
