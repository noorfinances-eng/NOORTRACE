package registre

// Essais de la revue de sécurité interne de l'étape 8, révision 0.9 de
// CT-6 : sans entrée inscription, R-10 est
// non exécutée avec la raison admise partie_absente, quel que soit l'état de
// P-1 (EX-11.19) ; un certificat de hauteur 0x0 fait échouer R-1
// (EX-11.14).

import (
	"strings"
	"testing"
)

func TestR10SansInscriptionSousP1EnEchecP(t *testing.T) {
	lancer(t, scenario{nom: "R-10 sans inscription, P-1 en échec", prep: func(m *monde) { m.retirer(roleInscription) }, post: func(e *Entree) { e.Manifeste = Manifeste{} },
		modifs: map[string]string{"R-9": PE, "R-10": PA, "N-4": ""}, statut: "non_execute:prerequis_en_echec", avert: []string{"AV-K-3"}})
	// Témoin : sans inscription mais P-1 réussie, R-10 partie_absente et AV-R-1 (clé du manifeste établie, texte inchangé).
	lancer(t, scenario{nom: "R-10 sans inscription, P-1 réussie", prep: func(m *monde) { m.retirer(roleInscription) },
		modifs: map[string]string{"R-10": PA}, avert: []string{"AV-R-1", "AV-K-3"}})
}

func TestR1HauteurZeroP(t *testing.T) {
	lancer(t, scenario{nom: "certificat de hauteur 0", prep: func(m *monde) { m.bloc(roleInscription).numero = 0 },
		modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E,
		verif: func(t *testing.T, r Resultat) {
			if d := detail(r, "R-1"); !strings.Contains(d, "hauteur 0") || !strings.Contains(d, "EX-11.14") {
				t.Errorf("R-1 : %s", d)
			}
		}})
}
