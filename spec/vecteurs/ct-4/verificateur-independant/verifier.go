// Enchaînement des familles.

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// VerifierVecteurs vérifie le répertoire des vecteurs CT-4 et rend le
// rapport.
func VerifierVecteurs(racine string) *Rapport {
	c := NouveauCtx(racine)
	f := c.R.F("texte")
	b, err := os.ReadFile(filepath.Join(c.Spec, "CT-4-registre.md"))
	if err != nil {
		f.Erreur("CT-4-registre.md", "lecture", err, "EX-A.5")
		return c.R
	}
	c.Texte = string(b)
	if err := c.chargerJeuDev(); err != nil {
		f.Erreur("4.8", "jeu de validateurs de l'exemple", err, "RG-18")
	}
	if err := c.chargerCapture(); err != nil {
		c.R.F("capture").Erreur("capture de CT-6", "lecture", err, "EX-A.4")
	}
	c.FamilleConstantes()
	c.FamilleIdentifiants()
	c.FamilleDoctypes()
	c.FamilleEmpreintes()
	c.FamilleCondenses()
	c.FamilleAppels()
	c.FamilleTransactions()
	c.FamilleManifestes()
	c.FamilleDemandes()
	c.FamilleInscription()
	c.FamilleCapture()
	c.FamilleFormat()
	c.FamilleTexte()
	c.FamilleCouverture()
	return c.R
}

// chargerJeuDev prend le jeu du réseau de développement dans l'exemple de
// manifeste d'instance de 4.8 (« copie publique
// test/fixtures/certificat-commit/validators.json »).
func (c *Ctx) chargerJeuDev() error {
	for _, ex := range ExemplesAnnotes(c.Texte) {
		if ex.Schema != "instance-registre" || ex.Err != nil {
			continue
		}
		vs := ex.Valeur.Get("validator_sets")
		if vs == nil || len(vs.Arr) == 0 {
			return fmt.Errorf("validator_sets absent")
		}
		j, err := ChargerJeu(vs.Arr[0].Get("validators"))
		if err != nil {
			return err
		}
		c.JeuDev = &j
		return nil
	}
	return fmt.Errorf("exemple instance-registre introuvable")
}
