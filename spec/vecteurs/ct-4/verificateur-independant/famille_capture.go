// Famille « capture » : CP-2 à CP-6 (CP-4 hors ligne) sur les captures de la
// période 1 et leurs variantes ; export des parties (EX-9.8 à EX-9.10)
// confronté à spec/vecteurs/ct-6/registre/periode-1.

package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// jeuDe rend le jeu désigné par input.validators d'un cas de capture.
func (c *Ctx) jeuDe(ref string) (*JeuValidateurs, string) {
	switch ref {
	case "test/fixtures/certificat-commit/validators.json":
		return c.JeuDev, "jeu de l'exemple de 4.8 (copie publique de test/fixtures/certificat-commit/validators.json)"
	case "constantes.json#/test_validators":
		return c.JeuEssai, "jeu d'essai de A.2"
	}
	return nil, ""
}

var ordreCP = []string{"CP-2", "CP-3", "CP-4", "CP-5", "CP-6"}

// FamilleCapture vérifie capture/capture.json.
func (c *Ctx) FamilleCapture() {
	f := c.R.F("capture")
	for _, cs := range c.lireFamille(f, "capture/capture.json", "capture") {
		in := cs.Input
		jeu, _ := c.jeuDe(in.Get("validators").S())
		if jeu == nil {
			f.Erreur(cs.ID, "input.validators", fmt.Errorf("jeu %q inconnu", in.Get("validators").S()), "CP-4")
			continue
		}
		rep := filepath.Join(c.Racine, filepath.FromSlash(in.Get("directory").S()))
		if ix := in.Get("indexes"); ix != nil {
			c.casExport(f, cs, rep, jeu)
			continue
		}
		res := c.VerifierCapture(rep, in.Get("index").S(), jeu, in.Get("bft_chain_id").S())
		c.confronterVerdictsCP(f, cs, res)
	}
}

func (c *Ctx) confronterVerdictsCP(f *Famille, cs Cas, res ResultatCapture) {
	verd := map[string]bool{}
	var premier *Echec
	for _, cp := range ordreCP {
		e := res.Verdicts[cp]
		verd[cp] = e == nil
		if e != nil && premier == nil {
			premier = e
		}
		rec := "reussi"
		if e != nil {
			rec = "echoue (" + e.Raison + ")"
		}
		att := cs.Expected.Get("verdicts").Get(cp).S()
		if att == "echoue" && e != nil {
			rec = "echoue"
		}
		f.Comparer(cs.ID, "verdict "+cp, att, rec, cp)
	}
	chk, code := refusAttendu(cs)
	premierID := ""
	if premier != nil {
		premierID = premier.Check
	}
	c.issueVerdicts(cs, verd, premierID)
	switch {
	case chk == "" && premier == nil:
	case chk == "":
		f.Comparer(cs.ID, "refusal", "null", premier.Check+" "+premier.Code, premier.Check)
	case premier == nil:
		f.Comparer(cs.ID, "refusal.check", chk, "aucune vérification en échec", chk)
	default:
		f.Comparer(cs.ID, "refusal.check", chk, premier.Check, chk)
		f.Comparer(cs.ID, "refusal.code", code, premier.Code, chk)
	}
}

// casExport recalcule les trois parties de la période 1 (EX-9.8 à 9.10).
func (c *Ctx) casExport(f *Famille, cs Cas, rep string, jeu *JeuValidateurs) {
	in := cs.Input
	type cap struct {
		res ResultatCapture
		h   uint64
		ti  int
	}
	var caps []cap
	for _, ix := range in.Get("indexes").Arr {
		idx, _, err := LireJSON(filepath.Join(rep, ix.S()))
		if err != nil {
			f.Erreur(cs.ID, ix.S(), err, "EX-9.8")
			return
		}
		res := c.VerifierCapture(rep, ix.S(), jeu, idx.Get("bft_chain_id").S())
		for _, cp := range ordreCP {
			if e := res.Verdicts[cp]; e != nil {
				f.Erreur(cs.ID, ix.S()+" "+cp, e, "EX-9.11")
				return
			}
		}
		h, _ := strconv.ParseUint(idx.Get("block_number").Num, 10, 64)
		ti, _ := strconv.Atoi(idx.Get("transaction_index").Num)
		caps = append(caps, cap{res, h, ti})
	}
	c.issueVerdicts(cs, map[string]bool{"CP-2": true, "CP-3": true, "CP-4": true, "CP-5": true, "CP-6": true}, "")
	sort.SliceStable(caps, func(i, j int) bool {
		if caps[i].h != caps[j].h {
			return caps[i].h < caps[j].h
		}
		return caps[i].ti < caps[j].ti
	})
	entrees := Tableau()
	certs := Tableau()
	vues := map[uint64]bool{}
	var resume, hauteurs []string
	for _, k := range caps {
		entrees.Arr = append(entrees.Arr, EntreeRegistre(k.res))
		resume = append(resume, fmt.Sprintf("%s/%d/%d", k.res.Index.Get("role").S(), k.h, k.ti))
		if !vues[k.h] {
			vues[k.h] = true
			certs.Arr = append(certs.Arr, Copier(k.res.CertBrut))
			hauteurs = append(hauteurs, strconv.FormatUint(k.h, 10))
		}
	}
	registre := Objet("version", Entier(0), "source", Chaine("export du vérificateur indépendant CT-4"), "entries", entrees)
	certificats := Objet("version", Entier(0), "certificates", certs)
	var vals []*Value
	for _, v := range jeu.Valideurs {
		vals = append(vals, Objet("id", Chaine(v.ID), "pubKeyHex", Chaine(v.CleHex)))
	}
	validateurs := Objet("version", Entier(0), "sets", Tableau(Objet("from_height", Entier(1), "to_height", Nul(), "validators", Tableau(vals...),
		"source", Chaine("publier-jeu (9.7), hachage "+Hex0x(jeu.Hachage())))))

	// Attendus déclarés.
	var attResume []string
	for _, e := range cs.Expected.Get("entries").Arr {
		attResume = append(attResume, fmt.Sprintf("%s/%s/%s", e.Get("role").S(), e.Get("block_number").Num, e.Get("transaction_index").Num))
	}
	f.Comparer(cs.ID, "entries (rôle/bloc/indice, ordre de EX-9.8)", strings.Join(attResume, " "), strings.Join(resume, " "), "EX-9.8")
	var attH []string
	for _, h := range cs.Expected.Get("certificates").Arr {
		attH = append(attH, h.Num)
	}
	f.Comparer(cs.ID, "certificates (hauteurs)", strings.Join(attH, " "), strings.Join(hauteurs, " "), "EX-9.9")
	f.Comparer(cs.ID, "sets", cs.Expected.Get("sets").Num, "1", "EX-9.10")

	// Schémas des parties.
	f.Vrai(cs.ID, "registre.json conforme à registre-v0", len(c.Schemas.Valider("registre-v0.schema.json", registre)) == 0, strings.Join(c.Schemas.Valider("registre-v0.schema.json", registre), " ; "), "EX-9.8")
	f.Vrai(cs.ID, "certificat-commit.json conforme à registre-v0#/$defs/certificat_commit", len(c.Schemas.Valider("registre-v0.schema.json#/$defs/certificat_commit", certificats)) == 0, "", "EX-9.9")
	f.Vrai(cs.ID, "validateurs.json conforme à validateurs-v0", len(c.Schemas.Valider("validateurs-v0.schema.json", validateurs)) == 0, "", "EX-9.10")

	// Confrontation aux parties de CT-6, en valeurs JSON et hors source.
	ref := filepath.Join(c.Depot, filepath.FromSlash(cs.Expected.Get("reference").S()))
	for _, p := range []struct {
		nom   string
		val   *Value
		regle string
	}{{"registre.json", registre, "EX-9.8"}, {"certificat-commit.json", certificats, "EX-9.9"}, {"validateurs.json", validateurs, "EX-9.10"}} {
		r, _, err := LireJSON(filepath.Join(ref, p.nom))
		if err != nil {
			f.Erreur(cs.ID, p.nom, err, p.regle)
			continue
		}
		a, b := SansMembre(r, "source", true), SansMembre(p.val, "source", true)
		f.Vrai(cs.ID, p.nom+" égal à celui de CT-6 (valeurs JSON, hors source)", EgalJSON(a, b), "", p.regle)
	}

	// Sélection des entrées (EX-9.8) : clôture et ancre de la période du
	// manifeste, inscription de la clé du manifeste sous l'émetteur de l'ancre.
	man, _, err := LireJSON(filepath.Join(c.Depot, filepath.FromSlash(in.Get("manifest").S())))
	if err != nil {
		f.Erreur(cs.ID, "manifeste", err, "EX-9.8")
		return
	}
	ph, _ := PeriodHash(man)
	org, _ := DecoderHexN(man.Get("org_id").S(), 32)
	jou, _ := DecoderHexN(man.Get("journal_id").S(), 32)
	_, fp, _ := RG4(org, jou, ph)
	pub := ""
	for _, r := range c.Constantes.Get("recorders").Arr {
		if r.Get("key_id").S() == man.Get("recorder_key_id").S() {
			pub = r.Get("public_key").S()
		}
	}
	var emetteur string
	okCloture, okAncre, okInscr := false, false, false
	for _, k := range caps {
		j := k.res.Recus[k.ti].Journaux[0]
		switch k.res.Index.Get("role").S() {
		case "cloture":
			okCloture = Hex0x(j.Sujets[2]) == Hex0x(ph)
		case "ancre":
			okAncre = Hex0x(j.Sujets[1]) == Hex0x(fp)
			emetteur = Hex0x(j.Sujets[2])
		}
	}
	for _, k := range caps {
		j := k.res.Recus[k.ti].Journaux[0]
		if k.res.Index.Get("role").S() == "inscription" && Hex0x(j.Donnees[:32]) == pub && Hex0x(j.Sujets[2]) == emetteur {
			okInscr = true
		}
	}
	f.Vrai(cs.ID, "clôture retenue : topics[2] = periodHash recalculé du manifeste", okCloture, "", "EX-9.8")
	f.Vrai(cs.ID, "ancre retenue : topics[1] = empreinte recalculée", okAncre, "", "EX-9.8")
	f.Vrai(cs.ID, "inscription de la clé du manifeste sous la clé de chaîne émettrice de l'ancre", okInscr, man.Get("recorder_key_id").S(), "EX-9.8")
}
