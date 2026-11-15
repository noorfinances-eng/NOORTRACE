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
		FamCandidats, FamAcceptation, FamTickets, FamReponses, FamDecisions, FamSignatures, FamAnnuaire, FamConsole, FamAcceptationConsole)
	dirSchemas := filepath.Join(racine, "..", "..", "schemas")
	sch, err := ChargerSchemas(
		filepath.Join(dirSchemas, "politique-approbation-v0.schema.json"),
		filepath.Join(dirSchemas, "ticket-v0.schema.json"),
		filepath.Join(dirSchemas, "evenement-v0.schema.json"),
		filepath.Join(dirSchemas, "annuaire-approbateurs-v0.schema.json"),
		filepath.Join(dirSchemas, "console-approbation-v0.schema.json"),
		filepath.Join(dirSchemas, "console-service-v0.schema.json"))
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
	var connues []signatureConnue
	for _, fam := range []struct {
		nom string
		f   func()
	}{
		{FamConstantes, func() { familleConstantes(c) }},
		{FamFormat, func() { familleFormat(c) }},
		{FamSchemas, func() { familleSchemas(c) }},
		{FamPolitiques, func() { famillePolitiques(c) }},
		{FamInvalides, func() { famillePolitiquesInvalides(c) }},
		{FamEvaluation, func() { familleEvaluation(c) }},
		{FamCandidats, func() { familleCandidats(c) }},
		{FamEvaluation, func() { couvertureAP(c) }},
		{FamAcceptation, func() { familleAcceptation(c) }},
		{FamTickets, func() { connues = familleTickets(c) }},
		{FamTickets, func() { couvertureTK(c) }},
		{FamReponses, func() { familleReponses(c) }},
		{FamDecisions, func() { connues = append(connues, familleDecisions(c)...) }},
		{FamDecisions, func() { couvertureRemisesValides(c) }},
		{FamSignatures, func() { familleSignatures(c, connues) }},
		{FamAnnuaire, func() { familleAnnuaire(c) }},
		{FamConsole, func() { familleConsole(c) }},
		{FamAcceptationConsole, func() { familleAcceptationConsole(c) }},
	} {
		protegerFamille(r, fam.nom, fam.f)
	}
	return r
}

// protegerFamille exécute une famille ; une panne (entrée absente que la
// famille n'aurait pas gardée, par exemple) devient une erreur consignée,
// les autres familles sont confrontées, le rapport est imprimé et le code
// est 1, jamais une trace de pile au code 2 (revue de sécurité de l'étape 8).
func protegerFamille(r *Rapport, nom string, f func()) {
	defer func() {
		if x := recover(); x != nil {
			r.Erreur("famille %s : panne interne (%v) ; famille non confrontée en entier", nom, x)
		}
	}()
	f()
}
