package ots

// Contrôle 5 : vérifications O-1 à O-7 (CT-6 §10.4), statut (EX-10.12),
// faits (EX-10.14), proposition (EX-10.15), avertissements AV-O-1 à AV-O-3
// (§10.7), et leur réutilisation par K-9 (EX-10.16).

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// construit : l'implémentation du contrôle 5 est complète (voir Construit).
const construit = true

// Indices des sept vérifications dans IDs.
const (
	o1 = iota
	o2
	o3
	o4
	o5
	o6
	o7
)

// calcul : état d'une vérification de preuve.
type calcul struct {
	e      Entree
	v      [7]commun.Verification
	preuve *Preuve
	x      *execution
	ch     *chaine
	// statutsAtt : statut de chaque attestation (ordre du fichier) pour
	// les faits ; concordantes : hauteurs des attestations Bitcoin
	// concordantes.
	statutsAtt  []commun.Statut
	plusPetiteH uint64
	avO3, avO4  []commun.Avertissement
	avO5, avO7  []commun.Avertissement
	ancreUtile  bool
}

func (c *calcul) poser(i int, s commun.Statut, r commun.Raison, fr, en string) {
	c.v[i] = commun.Nouvelle(IDs[i], s, r, commun.T(fr, en), 5)
}

// raisonPrerequis : raison que porte une vérification dont v est un
// prérequis (EX-5.5) ; vide si v a réussi.
func raisonPrerequis(v commun.Verification) commun.Raison {
	switch v.Statut {
	case commun.Reussi:
		return commun.Aucune
	case commun.Echoue:
		return commun.PrerequisEnEchec
	}
	return v.Raison
}

// textePrerequis décrit les prérequis non réussis.
func textePrerequis(vs ...commun.Verification) (string, string) {
	var fr, en []string
	for _, v := range vs {
		switch v.Statut {
		case commun.Echoue:
			fr = append(fr, v.ID+" en échec")
			en = append(en, v.ID+" failed")
		case commun.NonExecute:
			fr = append(fr, v.ID+" non exécutée ("+string(v.Raison)+")")
			en = append(en, v.ID+" not run ("+string(v.Raison)+")")
		}
	}
	return "prérequis non réussi : " + strings.Join(fr, ", "), "prerequisite not passed: " + strings.Join(en, ", ")
}

func (c *calcul) nomEmpreinte() string {
	if c.e.Usage == Point {
		return "checkpoint_hash"
	}
	return "periodHash"
}

func verifier(e Entree) Resultat {
	c := &calcul{e: e}
	if c.o1() {
		c.o2()
		c.x = executer(c.preuve)
		c.statutsAtt = make([]commun.Statut, len(c.x.Attestations))
		for i := range c.statutsAtt {
			c.statutsAtt[i] = commun.NonExecute
		}
		c.o3()
		c.o7()
		c.o5()
		c.o4()
		c.o6()
	} else {
		fr, en := textePrerequis(c.v[o1])
		for i := o2; i <= o7; i++ {
			c.poser(i, commun.NonExecute, commun.PrerequisEnEchec, fr, en)
		}
	}
	return c.resultat()
}

// o1 : format (EX-10.5). Rend vrai si O-1 réussit.
func (c *calcul) o1() bool {
	switch c.e.Etat {
	case entree.Absent, entree.Illisible:
		c.poser(o1, commun.NonExecute, commun.PrerequisEnEchec, "preuve.ots absente ou illisible (échec de D-2)", "preuve.ots missing or unreadable (D-2 failure)")
		return false
	case entree.TropGrand:
		c.poser(o1, commun.Echoue, "", "fichier de plus de 256 Kio (EX-10.2)", "file larger than 256 KiB (EX-10.2)")
		return false
	}
	p, d := Analyser(c.e.Preuve)
	if d != nil {
		c.poser(o1, commun.Echoue, "", fmt.Sprintf("fichier illisible, octet %d : %s", d.Position, d.Message.Fr),
			fmt.Sprintf("unreadable file, byte %d: %s", d.Position, d.Message.En))
		return false
	}
	c.preuve = p
	c.poser(o1, commun.Reussi, "", "en-tête magique, version 01, opération de fichier 08, arbre conforme, fin de fichier exacte",
		"magic header, version 01, file operation 08, conforming tree, exact end of file")
	return true
}

// o2 : empreinte (EX-10.6, EX-5.4 ; EX-10.16 pour le point).
func (c *calcul) o2() {
	n := c.nomEmpreinte()
	if !c.e.EmpreinteDisponible {
		if c.e.Usage == Point {
			c.poser(o2, commun.NonExecute, commun.PrerequisEnEchec, "checkpoint_hash non recalculé (K-2 non réussie)", "checkpoint_hash not recomputed (K-2 not passed)")
		} else {
			c.poser(o2, commun.NonExecute, commun.PrerequisEnEchec, "periodHash non recalculé (P-1 non réussie)", "periodHash not recomputed (P-1 not passed)")
		}
		return
	}
	lu, attendu := cryptographie.Hex32(c.preuve.Empreinte), cryptographie.Hex32(c.e.EmpreinteAttendue)
	if c.preuve.Empreinte == c.e.EmpreinteAttendue {
		c.poser(o2, commun.Reussi, "", "empreinte du fichier égale au "+n+" recalculé "+attendu, "file digest equals the recomputed "+n+" "+attendu)
		return
	}
	c.poser(o2, commun.Echoue, "", "empreinte du fichier "+lu+" différente du "+n+" recalculé "+attendu,
		"file digest "+lu+" differs from the recomputed "+n+" "+attendu)
}

// designation : description d'une attestation pour les textes.
func designation(a *attestationExecutee) (string, string) {
	switch a.Genre {
	case GenreBitcoin:
		return fmt.Sprintf("Bitcoin de hauteur %d", a.Hauteur), fmt.Sprintf("Bitcoin attestation at height %d", a.Hauteur)
	case GenreAttente:
		if a.URI == "" {
			return "en attente d'URI vide", "pending attestation with an empty URI"
		}
		return "en attente du calendrier " + a.URI, "pending attestation from calendar " + a.URI
	}
	t := "0x" + hex.EncodeToString(a.Etiquette[:])
	return "inconnue d'étiquette " + t, "unknown attestation with tag " + t
}

// o3 : opérations (EX-10.7) ; AV-O-2 pour chaque attestation sous une
// opération hors profil.
func (c *calcul) o3() {
	x := c.x
	for i := range x.Attestations {
		a := &x.Attestations[i]
		if a.OpHorsProfil == 0 {
			continue
		}
		c.statutsAtt[i] = commun.NonExecute
		fr, en := designation(a)
		c.avO3 = append(c.avO3, commun.Avertissement{ID: "AV-O-2", Verification: "O-3", Detail: commun.T(
			"attestation "+fr+" sous l'opération hors profil v0 "+nomOperation(a.OpHorsProfil)+", non exécutée (hors_perimetre_version)",
			en+" under the out-of-profile operation "+nomOperation(a.OpHorsProfil)+", not run (hors_perimetre_version)")})
	}
	if x.Defaut != nil {
		c.poser(o3, commun.Echoue, "", x.Defaut.Fr, x.Defaut.En)
		return
	}
	fr := fmt.Sprintf("opérations rejouées sans défaut, toutes du profil f0, f1, 08 (%d)", x.Operations)
	en := fmt.Sprintf("operations replayed without defect, all in the f0, f1, 08 profile (%d)", x.Operations)
	if x.HorsProfil > 0 {
		fr = fmt.Sprintf("%d opération(s) du profil f0, f1, 08 rejouée(s) sans défaut ; %d opération(s) hors profil non exécutée(s), ni rien sous elle(s)", x.Operations, x.HorsProfil)
		en = fmt.Sprintf("%d operation(s) of the f0, f1, 08 profile replayed without defect; %d out-of-profile operation(s) not run, nor anything under them", x.Operations, x.HorsProfil)
	}
	if c.horsProfilSeul() {
		// EX-10.12 (révision 0.4) : aucune attestation Bitcoin n'est
		// atteinte par les seules opérations du profil ; textes imposés pour
		// que personne ne croie la date établie.
		fr = "attestation sous une opération hors du profil de la version 0 : non vérifiée ; aucune date n'est établie"
		en = "attestation under an operation outside the version 0 profile: not verified; no time is established"
	}
	c.poser(o3, commun.Reussi, "", fr, en)
}

// horsProfilSeul dit si la preuve porte au moins une attestation Bitcoin
// et qu'aucune n'est atteinte par les seules opérations du profil (toutes
// sous une opération hors profil, EX-10.7, EX-10.12).
func (c *calcul) horsProfilSeul() bool {
	hors := false
	for i := range c.x.Attestations {
		a := &c.x.Attestations[i]
		if a.Genre != GenreBitcoin {
			continue
		}
		if a.OpHorsProfil == 0 {
			return false
		}
		hors = true
	}
	return hors
}

// nombre écrit « aucune », « une » ou n devant un nom féminin.
func nombre(n int, un, plusieurs string, fr bool) string {
	switch {
	case n == 0 && fr:
		return "aucune " + un
	case n == 0:
		return "no " + un
	case n == 1 && fr:
		return "une " + un
	case n == 1:
		return "one " + un
	}
	return fmt.Sprintf("%d %s", n, plusieurs)
}

// o7 : attestation Bitcoin présente (EX-10.11) ; AV-O-2 pour chaque
// attestation en attente ou inconnue du profil.
func (c *calcul) o7() {
	nb, na, ni := 0, 0, 0
	for i := range c.x.Attestations {
		a := &c.x.Attestations[i]
		switch a.Genre {
		case GenreBitcoin:
			nb++
			continue
		case GenreAttente:
			na++
		default:
			ni++
		}
		if a.OpHorsProfil != 0 {
			continue
		}
		fr, en := designation(a)
		c.avO7 = append(c.avO7, commun.Avertissement{ID: "AV-O-2", Verification: "O-7", Detail: commun.T(
			"attestation "+fr+", non exploitée : seule une attestation Bitcoin est vérifiée",
			en+", not used: only a Bitcoin attestation is verified")})
	}
	fr := nombre(nb, "attestation Bitcoin", "attestations Bitcoin", true) + ", " + nombre(na, "attestation en attente", "attestations en attente", true)
	en := nombre(nb, "Bitcoin attestation", "Bitcoin attestations", false) + ", " + nombre(na, "pending attestation", "pending attestations", false)
	if ni > 0 {
		fr += ", " + nombre(ni, "attestation inconnue", "attestations inconnues", true)
		en += ", " + nombre(ni, "unknown attestation", "unknown attestations", false)
	}
	if nb > 0 {
		c.poser(o7, commun.Reussi, "", fr, en)
		return
	}
	c.poser(o7, commun.NonExecute, commun.PartieAbsente, fr+" : preuve non complétée (ots upgrade, que le vérificateur ne fait pas)",
		en+": proof not completed (ots upgrade, which the verifier never runs)")
}

// o5 : chaîne d'en-têtes rattachée au point de contrôle (EX-10.9) ; AV-O-3
// quand O-5 est exécutée sur regtest, réseau que fixe l'ancre (R2-F22).
func (c *calcul) o5() {
	raisons := []commun.Raison{raisonPrerequis(c.v[o7])}
	var fr, en []string
	if c.v[o7].Statut != commun.Reussi {
		f, e := textePrerequis(c.v[o7])
		fr, en = append(fr, f), append(en, e)
	}
	if c.e.Entetes == nil {
		raisons = append(raisons, commun.PartieAbsente)
		fr, en = append(fr, "fichier d'en-têtes non fourni (--entetes-bitcoin)"), append(en, "no headers file given (--entetes-bitcoin)")
	}
	if c.e.Ancre == nil {
		raisons = append(raisons, commun.AncreAbsente)
		fr, en = append(fr, "ancre bitcoin absente (aucun fichier d'ancres, ou bitcoin nul)"), append(en, "no bitcoin anchor (no anchors file, or bitcoin null)")
	}
	if r := commun.PremiereRaison(raisons...); r != commun.Aucune {
		c.poser(o5, commun.NonExecute, r, strings.Join(fr, " ; "), strings.Join(en, "; "))
		return
	}
	c.ch = nouvelleChaine(c.e.Entetes)
	var r resultatO5
	if c.ch == nil {
		r = resultatO5{Statut: commun.NonExecute, Raison: commun.AncreAbsente, Detail: commun.T(
			"fichier d'en-têtes vide : la hauteur du point de contrôle n'y figure pas", "empty headers file: the checkpoint height is not in it")}
	} else {
		r = verifierChaine(c.ch, c.e.Ancre)
	}
	c.v[o5] = commun.Nouvelle(IDs[o5], r.Statut, r.Raison, r.Detail, 5)
	if r.Statut == commun.NonExecute {
		return
	}
	c.ancreUtile = true
	if c.e.Ancre.Reseau == ReseauRegtest {
		c.avO5 = append(c.avO5, commun.Avertissement{ID: "AV-O-3", Verification: "O-5", Detail: commun.T(
			"réseau regtest : réseau d'essai, sans valeur probante hors des tests", "regtest network: a test network, no evidential value outside tests")})
	}
}

// o4 : attestations Bitcoin contre les en-têtes (EX-10.8) ; AV-O-1.
func (c *calcul) o4() {
	if r := commun.PremiereRaison(raisonPrerequis(c.v[o3]), raisonPrerequis(c.v[o5])); r != commun.Aucune {
		fr, en := textePrerequis(c.v[o3], c.v[o5])
		c.poser(o4, commun.NonExecute, r, fr, en)
		return
	}
	var fr, en []string
	var raisons []commun.Raison
	concordantes, comparees := 0, 0
	for i := range c.x.Attestations {
		a := &c.x.Attestations[i]
		if a.Genre != GenreBitcoin {
			continue
		}
		h := uint64(a.Hauteur)
		switch {
		case a.OpHorsProfil != 0 || !a.Calcule:
			c.statutsAtt[i] = commun.NonExecute
			raisons = append(raisons, commun.HorsPerimetreVersion)
			fr = append(fr, fmt.Sprintf("attestation Bitcoin de hauteur %d : sous une opération hors profil, non exécutée", h))
			en = append(en, fmt.Sprintf("Bitcoin attestation at height %d: under an out-of-profile operation, not run", h))
		case !c.ch.contient(h):
			c.statutsAtt[i] = commun.NonExecute
			raisons = append(raisons, commun.AncreAbsente)
			fr = append(fr, fmt.Sprintf("attestation Bitcoin de hauteur %d : en-tête absent du fichier (%d à %d)", h, c.ch.s, c.ch.t))
			en = append(en, fmt.Sprintf("Bitcoin attestation at height %d: header not in the file (%d to %d)", h, c.ch.s, c.ch.t))
		case a.Longueur != 32:
			comparees++
			c.statutsAtt[i] = commun.Echoue
			fr = append(fr, fmt.Sprintf("attestation Bitcoin de hauteur %d : résultat de %d octets, 32 attendus", h, a.Longueur))
			en = append(en, fmt.Sprintf("Bitcoin attestation at height %d: result of %d bytes, 32 expected", h, a.Longueur))
		case string(a.Resultat[:]) != string(c.ch.racine(h)):
			comparees++
			c.statutsAtt[i] = commun.Echoue
			fr = append(fr, fmt.Sprintf("attestation Bitcoin de hauteur %d : résultat %s différent des octets 36 à 67 de l'en-tête %d (%s)", h, cryptographie.Hex32(a.Resultat), h, cryptographie.Hex(c.ch.racine(h))))
			en = append(en, fmt.Sprintf("Bitcoin attestation at height %d: result %s differs from bytes 36 to 67 of header %d (%s)", h, cryptographie.Hex32(a.Resultat), h, cryptographie.Hex(c.ch.racine(h))))
		default:
			comparees++
			concordantes++
			c.statutsAtt[i] = commun.Reussi
			if concordantes == 1 || h < c.plusPetiteH {
				c.plusPetiteH = h
			}
			fr = append(fr, fmt.Sprintf("attestation Bitcoin de hauteur %d : résultat égal aux octets 36 à 67 de l'en-tête %d", h, h))
			en = append(en, fmt.Sprintf("Bitcoin attestation at height %d: result equal to bytes 36 to 67 of header %d", h, h))
		}
	}
	tf, te := strings.Join(fr, " ; "), strings.Join(en, "; ")
	switch {
	case concordantes > 0:
		c.poser(o4, commun.Reussi, "", tf, te)
		for i := range c.x.Attestations {
			a := &c.x.Attestations[i]
			if a.Genre == GenreBitcoin && c.statutsAtt[i] == commun.Echoue {
				c.avO4 = append(c.avO4, commun.Avertissement{ID: "AV-O-1", Verification: "O-4", Detail: commun.T(
					fmt.Sprintf("attestation Bitcoin de hauteur %d : résultat différent des octets 36 à 67 de l'en-tête %d, à côté d'une attestation concordante", a.Hauteur, a.Hauteur),
					fmt.Sprintf("Bitcoin attestation at height %d: result differs from bytes 36 to 67 of header %d, next to a matching attestation", a.Hauteur, a.Hauteur))})
			}
		}
	case comparees > 0:
		c.poser(o4, commun.Echoue, "", tf, te)
	default:
		c.poser(o4, commun.NonExecute, commun.PremiereRaison(raisons...), tf, te)
	}
}

// o6 : profondeur (EX-10.10).
func (c *calcul) o6() {
	if r := raisonPrerequis(c.v[o4]); r != commun.Aucune {
		fr, en := textePrerequis(c.v[o4])
		c.poser(o6, commun.NonExecute, r, fr, en)
		return
	}
	h := c.plusPetiteH
	k := c.ch.t - h + 1
	minConf := c.e.Ancre.MinConfirmations
	if k >= uint64(max(minConf, 0)) {
		c.poser(o6, commun.Reussi, "", fmt.Sprintf("profondeur k = %d, au moins min_confirmations = %d", k, minConf),
			fmt.Sprintf("depth k = %d, at least min_confirmations = %d", k, minConf))
		return
	}
	c.poser(o6, commun.NonExecute, commun.AncreAbsente,
		fmt.Sprintf("profondeur k = %d sous l'attestation de hauteur %d (en-têtes jusqu'à %d), inférieure à min_confirmations = %d", k, h, c.ch.t, minConf),
		fmt.Sprintf("depth k = %d under the attestation at height %d (headers up to %d), below min_confirmations = %d", k, h, c.ch.t, minConf))
}

// statut applique EX-10.12 aux sept résultats.
func (c *calcul) statut() (commun.Statut, commun.Raison) {
	for _, i := range []int{o1, o2, o3, o4, o5} {
		if c.v[i].Statut == commun.Echoue {
			return commun.Echoue, commun.Aucune
		}
	}
	if c.v[o2].Statut == commun.Reussi && c.v[o4].Statut == commun.Reussi && c.v[o6].Statut == commun.Reussi && c.v[o7].Statut == commun.Reussi {
		return commun.Reussi, commun.Aucune
	}
	var raisons []commun.Raison
	for _, v := range c.v {
		if v.Statut == commun.NonExecute {
			raisons = append(raisons, v.Raison)
		}
	}
	return commun.NonExecute, commun.PremiereRaison(raisons...)
}

func (c *calcul) resultat() Resultat {
	r := Resultat{
		Verifications:   c.v[:],
		Avertissements:  []commun.Avertissement{},
		AncresEmployees: []string{},
	}
	r.Statut, r.Raison = c.statut()
	for _, l := range [][]commun.Avertissement{c.avO3, c.avO4, c.avO5, c.avO7} {
		r.Avertissements = append(r.Avertissements, l...)
	}
	if c.ancreUtile {
		r.AncresEmployees = append(r.AncresEmployees, "/bitcoin")
	}
	if r.Statut == commun.NonExecute && r.Raison == commun.HorsPerimetreVersion && c.x.Defaut == nil && c.horsProfilSeul() {
		r.Resume = commun.T("preuve hors du profil de la version 0, non vérifiée : aucune date établie", "proof outside the version 0 profile, not verified: no time established")
	}
	if r.Statut != commun.Reussi {
		return r
	}
	r.Faits = c.faits()
	f := r.Faits
	regtest := f.Network == ReseauRegtest
	r.Resume = commun.T(fmt.Sprintf("bloc Bitcoin %d du réseau %s, %d confirmations", f.RetainedHeight, f.Network, f.Confirmations),
		fmt.Sprintf("Bitcoin block %d on network %s, %d confirmations", f.RetainedHeight, f.Network, f.Confirmations))
	if regtest {
		r.Resume.Fr += " (réseau d'essai)"
		r.Resume.En += " (test network)"
	}
	if c.e.Usage == Cloture {
		r.Proposition = proposition(cryptographie.Hex32(c.e.EmpreinteAttendue), f)
	}
	return r
}

// faits : valeurs d'EX-10.14 (contrôle réussi : O-5, O-4 et O-6 réussies).
func (c *calcul) faits() *Faits {
	ch, a := c.ch, c.e.Ancre
	h := c.plusPetiteH
	f := &Faits{
		FileDigest:     cryptographie.Hex32(c.preuve.Empreinte),
		Network:        a.Reseau,
		Checkpoint:     PointBitcoin{Height: int64(a.Hauteur), Hash: cryptographie.Hex32(a.Hachage)},
		Attestations:   []Attestation{},
		RetainedHeight: int64(h),
		BlockHash:      cryptographie.Hex32(ch.hachageAffiche(h)),
		Confirmations:  int64(ch.t - h + 1),
		CumulativeWork: travailCumule(ch, h, uint64(a.Hauteur)).String(),
	}
	f.BlockTimeInstant = time.Unix(int64(ch.nTime(h)), 0).UTC()
	f.BlockTime = commun.FormaterInstant(f.BlockTimeInstant)
	if ch.t >= h+FenetreMediane {
		m := commun.FormaterSecondes(int64(ch.mediane(h + 1)))
		f.MedianBound = &m
	}
	for i := range c.x.Attestations {
		x := &c.x.Attestations[i]
		at := Attestation{Kind: x.Genre, Status: c.statutsAtt[i]}
		switch x.Genre {
		case GenreBitcoin:
			hh := int64(x.Hauteur)
			at.Height = &hh
		case GenreAttente:
			u := x.URI
			at.URI = &u
		default:
			t := "0x" + hex.EncodeToString(x.Etiquette[:])
			at.Tag = &t
		}
		f.Attestations = append(f.Attestations, at)
	}
	return f
}

// proposition : EX-10.15, sans « ; » de tête (fragment F5).
func proposition(empreinte string, f *Faits) commun.Texte {
	fr := fmt.Sprintf("le manifeste d'empreinte %s existait avant la création du bloc Bitcoin %d (%s, réseau %s), sous %d blocs dont le travail se rattache au point de contrôle %d du réviseur ; heure inscrite par le mineur : %s UTC, précision non garantie par le protocole",
		empreinte, f.RetainedHeight, f.BlockHash, f.Network, f.Confirmations, f.Checkpoint.Height, f.BlockTime)
	en := fmt.Sprintf("the manifest with digest %s existed before Bitcoin block %d (%s, %s network) was created, under %d blocks whose work connects to the reviewer's checkpoint %d; time written by the miner: %s UTC, accuracy not guaranteed by the protocol",
		empreinte, f.RetainedHeight, f.BlockHash, f.Network, f.Confirmations, f.Checkpoint.Height, f.BlockTime)
	if f.MedianBound != nil {
		fr += " ; borne sous hypothèse : " + *f.MedianBound + " UTC"
		en += "; bound under assumption: " + *f.MedianBound + " UTC"
	}
	if f.Network == ReseauRegtest {
		fr += " (réseau d'essai, sans valeur probante)"
		en += " (test network, no evidential value)"
	}
	return commun.T(fr, en)
}
