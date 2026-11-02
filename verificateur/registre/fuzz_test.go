package registre

// Cibles de fuzzing du contrôle 8 (EX-15.3) : analyseur de registre.json et
// de certificat-commit.json avec tout le contrôle derrière, et lecture des
// lignes de certificat. Graines : parties des vecteurs (annexe A.5) et
// parties fabriquées. Invariants : aucune panique, raisons de la liste
// fermée, faits seulement pour un contrôle réussi.

import (
	"path/filepath"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

func invariants(t *testing.T, r Resultat) {
	t.Helper()
	vs := append([]commun.Verification{}, r.Verifications...)
	for _, v := range []*commun.Verification{r.N4, r.K8} {
		if v != nil {
			vs = append(vs, *v)
		}
	}
	for _, v := range vs {
		if v.Statut == commun.NonExecute && !(v.Raison.Admise() || v.Raison == commun.PrerequisEnEchec) {
			t.Fatalf("%s : raison %q", v.ID, v.Raison)
		}
		if v.Statut != commun.NonExecute && v.Raison != "" {
			t.Fatalf("%s : raison %q pour %s", v.ID, v.Raison, v.Statut)
		}
	}
	if (r.Faits != nil) != (r.Statut == commun.Reussi) {
		t.Fatalf("faits et statut %s", r.Statut)
	}
	if r.Statut == commun.Reussi && r.Proposition.Vide() {
		t.Fatalf("proposition vide d'un contrôle réussi")
	}
}

func FuzzRegistre(f *testing.F) {
	m := nouveauMonde()
	base := m.entree()
	f.Add(base.Registre.Octets, base.Certificat.Octets)
	for _, rep := range []string{"periode-1", "periode-1-point", "variantes/valide-ligne-non-canonique", "variantes/invalide-r7-recu-falsifie"} {
		f.Add(lireFichier(f, filepath.Join(racineReg, rep, "registre.json")), lireFichier(f, filepath.Join(racineReg, rep, "certificat-commit.json")))
	}
	f.Add([]byte(`{"version":0}`), []byte(`{"version":0,"certificates":[]}`))
	f.Fuzz(func(t *testing.T, reg, cert []byte) {
		e := base
		e.Registre = Partie{Presente: true, Etat: entree.Lu, Octets: reg}
		e.Certificat = Partie{Presente: true, Etat: entree.Lu, Octets: cert}
		invariants(t, Verifier(e))
	})
}

func FuzzLigne(f *testing.F) {
	m := nouveauMonde()
	e := m.entree()
	certs, d := lireCertificats(e.Certificat.Octets)
	if d != nil {
		f.Fatal(d.Fr)
	}
	for _, c := range certs {
		f.Add(c.proposition)
		for _, p := range c.precommits {
			f.Add(p)
		}
	}
	vec, d := lireCertificats(lireFichier(f, filepath.Join(racineReg, "periode-1", "certificat-commit.json")))
	if d != nil {
		f.Fatal(d.Fr)
	}
	f.Add(vec[0].precommits[0])
	f.Add(`{"Domain":"noor/v1/bft","body":{}}`)
	jeu := m.jeu()
	f.Fuzz(func(t *testing.T, ligne string) {
		c := certs[0]
		c.precommits = []string{ligne, c.precommits[1], c.precommits[2]}
		r := verifierCertificat(&c, &jeu)
		if r.valide && len(r.signataires) < quorum(len(jeu.Validateurs)) {
			t.Fatalf("certificat valide sous le quorum")
		}
		_, _, _ = lireLigne(ligne)
	})
}
