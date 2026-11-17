package moteur

// Fragment F3 de l'énoncé (CT-6 EX-6.8, EX-6.11, §7.2 ; décision du porteur
// du 2026-11-16) : une approbation ou un refus est dit sur la demande que les
// approbateurs ont signée, nommée par son request_hash et son ticket, non sur
// l'appel prouvé.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestF3NommeDemandeEtTicket(t *testing.T) {
	cas := []struct {
		nom, ancres, entetes, fr, en string
	}{
		{"valide-seq-7-complet", "../../spec/vecteurs/ct-6/ancres/ancres-test.json", "../../spec/vecteurs/ct-6/ots/entetes/chaine.json",
			" ; l'événement porte l'approbation de la demande %h (ticket %t), signée par ",
			"; the event carries the approval of request %h (ticket %t), signed by "},
		{"valide-decision-refusee", "", "",
			" ; l'événement porte le refus de la demande %h (ticket %t), signé par ",
			"; the event carries the refusal of request %h (ticket %t), signed by "},
	}
	for _, c := range cas {
		rep := filepath.Join(racineCT6, c.nom)
		var ev struct {
			Approval struct {
				Ticket      string `json:"ticket"`
				RequestHash string `json:"request_hash"`
			} `json:"approval"`
		}
		if err := json.Unmarshal(lireOctets(t, filepath.Join(rep, "evenement.json")), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Approval.Ticket == "" || ev.Approval.RequestHash == "" {
			t.Fatalf("%s : approval sans ticket ni request_hash", c.nom)
		}
		res := Verifier(Options{Repertoire: rep, Ancres: c.ancres, Entetes: c.entetes, Langue: "fr", Version: "0.0.0"})
		if res.Erreur != nil || res.Rapport == nil {
			t.Fatalf("%s : erreur %+v", c.nom, res.Erreur)
		}
		r := strings.NewReplacer("%h", ev.Approval.RequestHash, "%t", ev.Approval.Ticket)
		fr, en := r.Replace(c.fr), r.Replace(c.en)
		s := res.Rapport.Statement
		if !strings.Contains(s.Fr, fr) || !strings.Contains(s.En, en) {
			t.Fatalf("%s : F3 ne nomme pas la demande et le ticket :\n%s\n%s", c.nom, s.Fr, s.En)
		}
		for _, ancien := range []string{"a été approuvé par", "porte un refus signé par", "was approved by", "carries a refusal signed by"} {
			if strings.Contains(s.Fr+s.En, ancien) {
				t.Fatalf("%s : ancienne forme « %s »", c.nom, ancien)
			}
		}
	}
}
