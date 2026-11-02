package dossier

import (
	"fmt"
	"strings"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Point : la partie points-de-controle.json déclarée présente (CT-1 §11.2,
// CT-6 §5.4).
type Point struct {
	// Partie et sa valeur (nil si la partie est inexploitable).
	Partie *Partie
	V      *jsonv.Valeur
	// K1 et K2 : K-1 et K-2 ont réussi.
	K1, K2 bool
	// CheckpointHash : checkpointHash recalculé (K-2).
	CheckpointHash [32]byte
	// Champs du point (valables quand K1).
	TreeSize, LastSeq, LeafIndex  int64
	CheckpointTs                  time.Time
	CheckpointTsTexte             string
	KeyID                         string
	PremiereTaille, SecondeTaille int64
	LongueurChemin                int
	// DernierHashVerifie : K-6 a été exécutée (last_hash_checked).
	DernierHashVerifie bool
	// Ancres embarquées : chaîne base64 du jeton et de la preuve, ou "" si
	// l'ancre vaut null ; référence au registre, ou nil.
	JetonBase64   string
	PreuveBase64  string
	AncreRegistre *jsonv.Valeur
	ck            []byte
}

func (a *Analyse) verificationsK(p *Partie) {
	pt := &Point{Partie: p}
	a.Point = pt
	ev := a.Evenement
	// K-1
	k1 := func() commun.Verification {
		if p.Lecture.Etat == entree.Absent {
			return prerequis("K-1", "points-de-controle.json absent du répertoire (D-2)", "points-de-controle.json missing from the directory (D-2)", 3)
		}
		if p.Lecture.Etat == entree.TropGrand {
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T("points-de-controle.json dépasse 1 Mio", "points-de-controle.json exceeds 1 MiB"), 3)
		}
		if !p.Exploitable() {
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T("points-de-controle.json n'est pas un objet JSON", "points-de-controle.json is not a JSON object"), 3)
		}
		v := p.Valeur
		if jcs.Calculable(v) != nil {
			// Sans forme canonique : E-2 porte l'échec (CT-1 §11.4), et rien
			// n'est lu de la partie.
			return prerequis("K-1", "points-de-controle.json sans forme canonique (E-2)", "points-de-controle.json without canonical form (E-2)", 3)
		}
		if err := schema.Valider(schema.Dossier+"#/$defs/points_de_controle", v); err != nil {
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T("points-de-controle.json contraire à son schéma ("+err.Error()+")", "points-de-controle.json does not follow its schema ("+err.Error()+")"), 3)
		}
		k := v.Membre("checkpoint")
		ts, okTs := commun.LireHorodatage(k.Membre("checkpoint_ts").S())
		if !okTs {
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T("checkpoint_ts n'est pas une date existante", "checkpoint_ts is not an existing date"), 3)
		}
		ck, err := jcs.Canonique(k.SansMembres("sig"))
		if err != nil {
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T("point sans forme canonique", "checkpoint without canonical form"), 3)
		}
		pt.V = v
		pt.ck = ck
		pt.TreeSize, _ = k.Membre("tree_size").Entier()
		pt.LastSeq, _ = k.Membre("last_seq").Entier()
		pt.CheckpointTs = ts
		pt.CheckpointTsTexte = k.Membre("checkpoint_ts").S()
		pt.KeyID = k.Membre("key_id").S()
		c := v.Membre("consistency")
		pt.PremiereTaille, _ = c.Membre("first_size").Entier()
		pt.SecondeTaille, _ = c.Membre("second_size").Entier()
		pt.LongueurChemin = len(c.Membre("path").Elements)
		anc := v.Membre("anchors")
		if j := anc.Membre("rfc3161"); j.EstObjet() {
			pt.JetonBase64 = j.Membre("token").S()
		}
		if o := anc.Membre("ots"); o.EstObjet() {
			pt.PreuveBase64 = o.Membre("proof").S()
		}
		if r := anc.Membre("registry"); r.EstObjet() {
			pt.AncreRegistre = r
		}
		if !a.P1 || ev == nil {
			return prerequis("K-1", "manifeste.json inexploitable (P-1) : comparaisons au manifeste impossibles", "manifeste.json unusable (P-1): comparisons with the manifest impossible", 3)
		}
		m := a.Manifeste
		var ecarts []string
		if k.Membre("org_id").S() != ev.V.Membre("org_id").S() || k.Membre("journal_id").S() != ev.V.Membre("journal_id").S() {
			ecarts = append(ecarts, "org_id ou journal_id du point différent de celui de l'événement")
		}
		mps, _ := m.Membre("period_start").Entier()
		kps, _ := k.Membre("period_start").Entier()
		if kps != mps {
			ecarts = append(ecarts, "period_start du point ≠ celui du manifeste")
		}
		cn, _ := m.Membre("count").Entier()
		fs, _ := m.Membre("first_seq").Entier()
		if pt.TreeSize < 1 || pt.TreeSize > cn {
			ecarts = append(ecarts, fmt.Sprintf("tree_size %d hors de [1, count = %d]", pt.TreeSize, cn))
		}
		if pt.LastSeq != fs+pt.TreeSize-1 {
			ecarts = append(ecarts, "last_seq ≠ first_seq + tree_size − 1")
		}
		if k.Membre("root").S() == zero32 {
			ecarts = append(ecarts, "racine du point nulle")
		}
		if ts.Before(time.Unix(mps, 0)) {
			ecarts = append(ecarts, "checkpoint_ts antérieur à period_start")
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, ", ")
			return commun.Nouvelle("K-1", commun.Echoue, "", commun.T(s, s), 3)
		}
		pt.K1 = true
		return commun.Nouvelle("K-1", commun.Reussi, "", commun.T(fmt.Sprintf("point de taille %d, last_seq %d, cohérent avec le manifeste", pt.TreeSize, pt.LastSeq), fmt.Sprintf("checkpoint of size %d, last_seq %d, consistent with the manifest", pt.TreeSize, pt.LastSeq)), 3)
	}()
	a.ajouter(k1)
	pasK1 := func(id string, controles ...int) commun.Verification {
		return prerequis(id, "K-1 non réussie", "K-1 not passed", controles...)
	}
	// K-2
	if !pt.K1 {
		a.ajouter(pasK1("K-2", 3))
	} else {
		pt.CheckpointHash = cryptographie.Sha256(cryptographie.PrefixePoint, pt.ck)
		h := cryptographie.Hex32(pt.CheckpointHash)
		if h != pt.V.Membre("checkpoint_hash").S() {
			a.ajouter(commun.Nouvelle("K-2", commun.Echoue, "", commun.T("checkpointHash recalculé "+h+" ≠ checkpoint_hash "+pt.V.Membre("checkpoint_hash").S(), "recomputed checkpointHash "+h+" ≠ checkpoint_hash "+pt.V.Membre("checkpoint_hash").S()), 3))
		} else {
			pt.K2 = true
			a.ajouter(commun.Nouvelle("K-2", commun.Reussi, "", commun.T("checkpointHash "+h, "checkpointHash "+h), 3))
		}
	}
	// K-3
	switch {
	case !pt.K1:
		a.ajouter(pasK1("K-3", 6))
	case !a.ClesExploitables:
		a.ajouter(prerequis("K-3", "cles.json inexploitable (E-8)", "cles.json unusable (E-8)", 6))
	default:
		c, trouvee := a.Cles[pt.KeyID]
		k := pt.V.Membre("checkpoint")
		sig, _ := cryptographie.LireHex(k.Membre("sig").S(), 64)
		switch {
		case !trouvee:
			a.ajouter(commun.Nouvelle("K-3", commun.Echoue, "", commun.T("clé "+pt.KeyID+" du point absente de cles.json", "checkpoint key "+pt.KeyID+" missing from cles.json"), 6))
		case !cryptographie.VerifierEd25519(c.Octets, append(append([]byte{}, cryptographie.PrefixeSignaturePoint...), pt.ck...), sig):
			a.ajouter(commun.Nouvelle("K-3", commun.Echoue, "", commun.T("signature du point invalide sous "+pt.KeyID, "invalid checkpoint signature under "+pt.KeyID), 6))
		case pt.CheckpointTs.Before(c.Debut) || (c.Fin != nil && pt.CheckpointTs.After(*c.Fin)):
			a.ajouter(commun.Nouvelle("K-3", commun.Echoue, "", commun.T("checkpoint_ts hors de la validité de "+pt.KeyID, "checkpoint_ts outside the validity of "+pt.KeyID), 6))
		default:
			a.ajouter(commun.Nouvelle("K-3", commun.Reussi, "", commun.T("point signé par "+pt.KeyID, "checkpoint signed by "+pt.KeyID), 6))
		}
	}
	// K-4
	switch {
	case !pt.K1:
		a.ajouter(pasK1("K-4", 3))
	case a.chemin == nil || !a.M3:
		a.ajouter(prerequis("K-4", "chemin.json inexploitable ou M-3 non réussie", "chemin.json unusable or M-3 not passed", 3))
	default:
		li, _ := a.chemin.Membre("leaf_index").Entier()
		pt.LeafIndex = li
		ts, okTs := ev.Ts()
		switch {
		case li >= pt.TreeSize:
			a.ajouter(commun.Nouvelle("K-4", commun.Echoue, "", commun.T(fmt.Sprintf("leaf_index %d ≥ tree_size %d : le point ne couvre pas l'événement", li, pt.TreeSize), fmt.Sprintf("leaf_index %d ≥ tree_size %d: the checkpoint does not cover the event", li, pt.TreeSize)), 3))
		case !okTs || ts.After(pt.CheckpointTs):
			a.ajouter(commun.Nouvelle("K-4", commun.Echoue, "", commun.T("ts de l'événement postérieur à checkpoint_ts", "event ts later than checkpoint_ts"), 3))
		default:
			a.ajouter(commun.Nouvelle("K-4", commun.Reussi, "", commun.T(fmt.Sprintf("leaf_index %d < tree_size %d ; ts ≤ checkpoint_ts", li, pt.TreeSize), fmt.Sprintf("leaf_index %d < tree_size %d; ts ≤ checkpoint_ts", li, pt.TreeSize)), 3))
		}
	}
	// K-5
	if !pt.K1 {
		a.ajouter(pasK1("K-5", 3))
	} else {
		m := a.Manifeste
		c := pt.V.Membre("consistency")
		k := pt.V.Membre("checkpoint")
		cn, _ := m.Membre("count").Entier()
		fr, _ := cryptographie.LireHex(c.Membre("first_root").S(), 32)
		sr, _ := cryptographie.LireHex(c.Membre("second_root").S(), 32)
		var chemin [][]byte
		for _, h := range c.Membre("path").Elements {
			b, _ := cryptographie.LireHex(h.S(), 32)
			chemin = append(chemin, b)
		}
		detail := fmt.Sprintf("first_size %d, second_size %d, first_root %s, second_root %s, chemin de %d nœud(s)", pt.PremiereTaille, pt.SecondeTaille, c.Membre("first_root").S(), c.Membre("second_root").S(), len(chemin))
		detailEn := fmt.Sprintf("first_size %d, second_size %d, first_root %s, second_root %s, path of %d node(s)", pt.PremiereTaille, pt.SecondeTaille, c.Membre("first_root").S(), c.Membre("second_root").S(), len(chemin))
		egalites := pt.PremiereTaille == pt.TreeSize && pt.SecondeTaille == cn && c.Membre("first_root").S() == k.Membre("root").S() && c.Membre("second_root").S() == m.Membre("root").S()
		if egalites && cryptographie.VerifierCoherence(uint64(pt.PremiereTaille), uint64(pt.SecondeTaille), fr, sr, chemin) {
			a.ajouter(commun.Nouvelle("K-5", commun.Reussi, "", commun.T(detail, detailEn), 3))
		} else {
			a.ajouter(commun.Nouvelle("K-5", commun.Echoue, "", commun.T("preuve de cohérence refusée : "+detail, "consistency proof rejected: "+detailEn), 3))
		}
	}
	// K-6
	if !pt.K1 {
		a.ajouter(pasK1("K-6", 2))
	} else {
		e := a.evtSeq(pt.LastSeq)
		lh := pt.V.Chemin("checkpoint", "last_hash").S()
		switch {
		case e == nil:
			a.ajouter(commun.Nouvelle("K-6", commun.NonExecute, commun.PieceHorsDossier, commun.T(fmt.Sprintf("événement last_seq %d absent du dossier : non vérifiable", pt.LastSeq), fmt.Sprintf("event last_seq %d not in the dossier: cannot be checked", pt.LastSeq)), 2))
		case !e.HashOK():
			a.ajouter(prerequis("K-6", "hachage de l'événement last_seq incalculable (E-2)", "hash of the last_seq event not computable (E-2)", 2))
		case e.HashHex() != lh:
			pt.DernierHashVerifie = true
			a.ajouter(commun.Nouvelle("K-6", commun.Echoue, "", commun.T("last_hash "+lh+" ≠ hash recalculé de seq "+fmt.Sprint(pt.LastSeq)+" "+e.HashHex(), "last_hash "+lh+" ≠ recomputed hash of seq "+fmt.Sprint(pt.LastSeq)+" "+e.HashHex()), 2))
		default:
			pt.DernierHashVerifie = true
			a.ajouter(commun.Nouvelle("K-6", commun.Reussi, "", commun.T(fmt.Sprintf("last_hash égal au hash recalculé de seq %d", pt.LastSeq), fmt.Sprintf("last_hash equals the recomputed hash of seq %d", pt.LastSeq)), 2))
		}
	}
}
