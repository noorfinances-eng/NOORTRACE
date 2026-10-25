// Contexte de la vérification : chemins, schémas, constantes de A.2 dont les
// clés sont rederivées, jeux de validateurs, capture de CT-6.

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Ctx est le contexte commun aux familles.
type Ctx struct {
	R          *Rapport
	Racine     string // spec/vecteurs/ct-4
	Spec       string // spec
	Depot      string // racine du dépôt
	CT1, CT6   string
	Schemas    *Schemas
	Constantes *Value
	Cles       map[string][]byte // adresse → clé privée (clés de test publiques)
	ChainID    *big.Int
	JeuDev     *JeuValidateurs // jeu du réseau de développement
	JeuEssai   *JeuValidateurs // jeu d'essai de A.2
	Capture    map[uint64]*BlocCapture
	Texte      string // texte de CT-4

	issues        map[string]*issueCas
	casParFamille map[string][]string
}

// BlocCapture est un bloc de la capture unique de CT-6 (annexe A.5).
type BlocCapture struct {
	EnTete EnTete
	Recus  []Recu
	Cert   Certificat
	Txs    [][]byte
}

// NouveauCtx prépare le contexte depuis le répertoire des vecteurs CT-4.
func NouveauCtx(racine string) *Ctx {
	abs, err := filepath.Abs(racine)
	if err != nil {
		abs = racine
	}
	spec := filepath.Clean(filepath.Join(abs, "..", ".."))
	c := &Ctx{
		R:       NouveauRapport(racine),
		Racine:  abs,
		Spec:    spec,
		Depot:   filepath.Dir(spec),
		CT1:     filepath.Join(abs, "..", "ct-1"),
		CT6:     filepath.Join(abs, "..", "ct-6"),
		Schemas: NouveauxSchemas(filepath.Join(spec, "schemas")),
		Cles:    map[string][]byte{},
		ChainID: big.NewInt(2124),
	}
	return c
}

// LireJSON lit et analyse un fichier.
func LireJSON(chemin string) (*Value, []byte, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, nil, err
	}
	v, err := ParseJSON(b)
	if err != nil {
		return nil, b, fmt.Errorf("%s : %v", filepath.Base(chemin), err)
	}
	return v, b, nil
}

// resultatRPC rend le champ result d'une réponse JSON-RPC brute.
func resultatRPC(v *Value) (*Value, error) {
	if v == nil || v.Kind != KindObject || v.Get("jsonrpc").S() != "2.0" {
		return nil, fmt.Errorf("réponse JSON-RPC 2.0 attendue")
	}
	if v.Get("error") != nil {
		return nil, fmt.Errorf("réponse d'erreur")
	}
	r := v.Get("result")
	if r == nil {
		return nil, fmt.Errorf("result absent")
	}
	return r, nil
}

// chargerCapture lit la capture unique de CT-6 (spec/vecteurs/ct-6/registre/
// capture) : en-têtes, reçus, certificats vérifiés contre le jeu du réseau de
// développement, transactions brutes des propositions (EX-A.4).
func (c *Ctx) chargerCapture() error {
	rep := filepath.Join(c.CT6, "registre", "capture")
	c.Capture = map[uint64]*BlocCapture{}
	ents, err := os.ReadDir(rep)
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "bloc-") || !strings.HasSuffix(n, ".json") {
			continue
		}
		v, _, err := LireJSON(filepath.Join(rep, n))
		if err != nil {
			return err
		}
		r, err := resultatRPC(v)
		if err != nil {
			return fmt.Errorf("%s : %v", n, err)
		}
		et, err := LireEnTete(r)
		if err != nil {
			return fmt.Errorf("%s : %v", n, err)
		}
		bc := &BlocCapture{EnTete: et}
		for _, h := range et.Transactions {
			rv, _, err := LireJSON(filepath.Join(rep, "recu-"+h+".json"))
			if err != nil {
				return err
			}
			rr, err := resultatRPC(rv)
			if err != nil {
				return err
			}
			rc, err := LireRecu(rr)
			if err != nil {
				return err
			}
			bc.Recus = append(bc.Recus, rc)
		}
		cv, _, err := LireJSON(filepath.Join(rep, fmt.Sprintf("certificat-%d.json", et.Number.Uint64())))
		if err != nil {
			return err
		}
		cr, err := resultatRPC(cv)
		if err != nil {
			return err
		}
		if bc.Cert, err = LireCertificat(cr); err != nil {
			return err
		}
		if c.JeuDev == nil {
			return fmt.Errorf("jeu du réseau de développement non chargé")
		}
		if bc.Txs, _, err = VerifierCertificat(bc.Cert, *c.JeuDev); err != nil {
			return fmt.Errorf("certificat %d : %v", et.Number.Uint64(), err)
		}
		c.Capture[et.Number.Uint64()] = bc
	}
	return nil
}

// hauteursCapture rend les hauteurs de la capture, croissantes.
func (c *Ctx) hauteursCapture() []uint64 {
	var hs []uint64
	for h := range c.Capture {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i] < hs[j] })
	return hs
}

// cleDe rend la clé privée d'une référence de vecteur : « hardhat:<i> » ou
// « sha256:<étiquette> » (clés de test publiques de A.2).
func (c *Ctx) cleDe(ref string) ([]byte, error) {
	switch {
	case strings.HasPrefix(ref, "hardhat:"):
		i, err := strconv.Atoi(strings.TrimPrefix(ref, "hardhat:"))
		if err != nil || i < 0 {
			return nil, fmt.Errorf("compte %q inconnu", ref)
		}
		return cleHardhat(i)
	case strings.HasPrefix(ref, "sha256:"):
		return Sha256([]byte(strings.TrimPrefix(ref, "sha256:"))), nil
	}
	return nil, fmt.Errorf("référence de clé %q inconnue", ref)
}
