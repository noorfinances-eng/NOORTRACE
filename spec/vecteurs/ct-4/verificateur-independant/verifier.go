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
	for _, fam := range []struct {
		nom string
		f   func()
	}{
		{"constantes", c.FamilleConstantes},
		{"identifiants", c.FamilleIdentifiants},
		{"doctypes", c.FamilleDoctypes},
		{"empreintes", c.FamilleEmpreintes},
		{"condenses", c.FamilleCondenses},
		{"appels", c.FamilleAppels},
		{"transactions", c.FamilleTransactions},
		{"manifestes", c.FamilleManifestes},
		{"demandes", c.FamilleDemandes},
		{"inscription", c.FamilleInscription},
		{"capture", c.FamilleCapture},
		{"format", c.FamilleFormat},
		{"texte", c.FamilleTexte},
		{"couverture", c.FamilleCouverture},
	} {
		c.protegerFamille(fam.nom, fam.f)
	}
	return c.R
}

// protegerFamille exécute une famille ; une panne (entrée absente que la
// famille n'aurait pas gardée, par exemple) devient une erreur consignée,
// les autres familles sont confrontées, le rapport est imprimé et le code
// est 1, jamais une trace de pile au code 2 (revue de sécurité de l'étape 8).
func (c *Ctx) protegerFamille(nom string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			c.R.F(nom).Erreur(nom, "famille", fmt.Errorf("panne interne (%v) ; famille non confrontée en entier", r), "")
		}
	}()
	f()
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
