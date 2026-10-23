// Point d'entrée de la vérification : charge les schémas et la
// spécification qui accompagnent les vecteurs, puis rejoue chaque famille.

package main

import (
	"os"
	"path/filepath"
)

// VerifierVecteurs rejoue toutes les familles de l'annexe A.
func VerifierVecteurs(racine string) *Rapport {
	r := NouveauRapport(racine, FamConstantes, FamFormat, FamSchemas, FamPolitiques, FamInvalides, FamEvaluation,
		FamCandidats, FamAcceptation, FamTickets, FamDecisions, FamSignatures)
	dirSchemas := filepath.Join(racine, "..", "..", "schemas")
	sch, err := ChargerSchemas(
		filepath.Join(dirSchemas, "politique-approbation-v0.schema.json"),
		filepath.Join(dirSchemas, "ticket-v0.schema.json"),
		filepath.Join(dirSchemas, "evenement-v0.schema.json"))
	if err != nil {
		r.Erreur("schémas introuvables à côté des vecteurs (%s) : %v", dirSchemas, err)
		return r
	}
	k, err := CalculerConstantes()
	if err != nil {
		r.Erreur("constantes : %v", err)
		return r
	}
	c := &Contexte{Racine: racine, Sch: sch, R: r, Consts: k}
	if src, err := os.ReadFile(filepath.Join(racine, "..", "..", "CT-3-approbations.md")); err == nil {
		c.Spec = string(src)
	} else {
		r.Note("spécification CT-3 introuvable à côté des vecteurs : les comparaisons au texte sont hors périmètre")
	}
	familleConstantes(c)
	familleFormat(c)
	familleSchemas(c)
	famillePolitiques(c)
	famillePolitiquesInvalides(c)
	familleEvaluation(c)
	familleCandidats(c)
	couvertureAP(c)
	familleAcceptation(c)
	connues := familleTickets(c)
	couvertureTK(c)
	connues = append(connues, familleDecisions(c)...)
	couvertureRemisesValides(c)
	familleSignatures(c, connues)
	return r
}
