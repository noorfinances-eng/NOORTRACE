// Famille cout-agent (annexe B.10, révision 0.5) : coût annuel par agent,
// recalculé depuis la seule formule d'EX-16.4 (CT-2 §16.4) et l'arrondi
// d'EX-16.5. Les prix des vecteurs sont des unités symboliques p.

package main

import (
	"math"
	"path/filepath"
)

// FamilleCoutAgent est le nom de la famille dans le rapport.
const FamilleCoutAgent = "cout-agent"

// GiB = 2^30 (16.4, Notations).
const GiB = 1073741824.0

// EntreesCout sont les entrées de la formule (schéma cout-agent-v0,
// $defs/entrees).
type EntreesCout struct {
	H, e, be, bp, np, A, Nh, oj, bj, S, Canc, Dl, Dlp float64
	Worm                                              bool
	Dw, m, k, g, Dg                                   float64
	PiecesWorm                                        bool
	pl, pw, pput, pget, plh, pout, pin                float64
}

// SortiesCout sont les sorties non arrondies d'EX-16.4.
type SortiesCout struct {
	E, Ve, Vp, Os, Oj, Ow, Bw                     float64
	L, Wst, Wgel, Wput, Wget, Wnet, Ca, C, CJ, Sh float64
}

// CoutAgent applique EX-16.4, ligne par ligne, de gauche à droite, avec les
// parenthèses écrites, en double précision IEEE 754.
func CoutAgent(in EntreesCout) SortiesCout {
	var s SortiesCout
	s.E = in.e * in.H
	s.Ve = s.E * in.be
	s.Vp = s.E * in.bp
	Np := s.E * in.np
	Bh := in.A * in.e * in.be
	if in.e > 0 {
		s.Sh = math.Max(1, math.Ceil(Bh/in.S))
	}
	s.Os = (in.H * s.Sh) / in.A
	s.Oj = (in.Nh * in.oj) / in.A
	Vj := (in.Nh * in.bj) / in.A
	s.L = ((s.Ve+Vj)/GiB)*in.pl*(in.Dl/365) + (s.Vp/GiB)*in.pl*(in.Dlp/365)
	if in.Worm {
		pieces := 0.0
		if in.PiecesWorm {
			pieces = Np
		}
		s.Ow = s.Os + s.Oj + pieces
		bpieces := 0.0
		if in.PiecesWorm {
			bpieces = math.Max(s.Vp, Np*in.m)
		}
		s.Bw = math.Max(s.Ve, s.Os*in.m) + math.Max(Vj, s.Oj*in.m) + bpieces
		Rw := in.Dw / 365
		s.Wst = (s.Bw / GiB) * in.pw * Rw
		s.Wgel = in.g*(s.Bw/GiB)*in.pw*(in.Dg/365) + in.g*s.Ow*2*in.plh
		Tk := s.Ow * Rw
		s.Wput = s.Ow*in.pput + ((in.k*Tk)/1000)*in.pput
		s.Wget = s.Ow*2*in.pget + in.k*Tk*in.pget
		vp := 0.0
		if in.PiecesWorm {
			vp = s.Vp
		}
		Vc := s.Ve + Vj + vp
		s.Wnet = (Vc/GiB)*in.pout + (Vc/GiB)*in.pin
	}
	s.Ca = in.Canc / in.A
	s.C = s.L + s.Wst + s.Wgel + s.Wput + s.Wget + s.Wnet + s.Ca
	s.CJ = s.C * in.A
	return s
}

// Arrondi3 : round(x × 1000) / 1000, demi vers le haut (EX-16.5, comme
// Math.round d'ECMAScript pour des grandeurs positives).
func Arrondi3(x float64) float64 { return math.Floor(x*1000+0.5) / 1000 }

// flottantDe lit un nombre JSON en double.
func flottantDe(v *Value) (float64, bool) {
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	f, err := NombreDouble(v.Num)
	return f, err == nil
}

func lireEntreesCout(in *Value) (EntreesCout, []string) {
	var e EntreesCout
	var manque []string
	lire := func(o *Value, cle string, dst *float64) {
		if f, ok := flottantDe(o.Get(cle)); ok {
			*dst = f
		} else {
			manque = append(manque, cle)
		}
	}
	lire(in, "active_hours_per_year", &e.H)
	lire(in, "events_per_hour", &e.e)
	lire(in, "event_bytes", &e.be)
	lire(in, "piece_bytes_per_event", &e.bp)
	lire(in, "pieces_per_event", &e.np)
	lire(in, "agents_per_journal", &e.A)
	lire(in, "hours_per_year", &e.Nh)
	lire(in, "journal_objects_per_hour", &e.oj)
	lire(in, "journal_bytes_per_hour", &e.bj)
	lire(in, "segment_max_bytes", &e.S)
	lire(in, "anchoring_cost_per_journal", &e.Canc)
	lire(in, "local_retention_days", &e.Dl)
	lire(in, "local_pieces_retention_days", &e.Dlp)
	if w := in.Get("worm"); EstObjet(w) {
		e.Worm = true
		lire(w, "retain_days", &e.Dw)
		lire(w, "min_billable_object_bytes", &e.m)
		lire(w, "lock_audits_per_year", &e.k)
		lire(w, "legal_hold_fraction", &e.g)
		lire(w, "legal_hold_extra_days", &e.Dg)
		if b := w.Get("pieces_in_worm"); b != nil && b.Kind == KindBool {
			e.PiecesWorm = b.Bool
		} else {
			manque = append(manque, "worm.pieces_in_worm")
		}
	} else if w == nil || !w.IsNull() {
		manque = append(manque, "worm")
	}
	p := in.Get("prices")
	lire(p, "local_gib_year", &e.pl)
	lire(p, "worm_gib_year", &e.pw)
	lire(p, "write_request", &e.pput)
	lire(p, "read_request", &e.pget)
	lire(p, "legal_hold_request", &e.plh)
	lire(p, "egress_gib", &e.pout)
	lire(p, "ingress_gib", &e.pin)
	return e, manque
}

func familleCoutAgent(rap *Rapport, ctx *contexteCT2) {
	f := FamilleCoutAgent
	chemin := filepath.Join(ctx.racine, "cout-agent", "cas.json")
	if !fichierExiste(chemin) {
		rap.Erreur("cout-agent/cas.json : absent (annexe B.10)")
		return
	}
	doc := lireFichierJSON(rap, chemin)
	if doc == nil {
		return
	}
	rap.Comparer(f, "cas.json", "version (B.10)", "0", texteOuAbsent(doc.Get("version")))
	rap.Comparer(f, "cas.json", "family (B.10)", "cout-agent", texteOuAbsent(doc.Get("family")))
	cas := doc.Get("cases")
	if !EstTableau(cas) {
		rap.Erreur("cout-agent/cas.json : cases n'est pas un tableau (B.10)")
		return
	}
	vus := map[string]bool{}
	var ancrageReference *Value
	for _, c := range cas.Arr {
		id := chaineDe(c, "id")
		vus[id] = true
		in, manque := lireEntreesCout(c.Get("input"))
		if len(manque) > 0 {
			rap.Erreur("cout-agent/%s : entrées absentes ou non numériques : %v", id, manque)
			continue
		}
		if id == "reference" {
			ancrageReference = c.Get("input").Get("anchoring_cost_per_journal")
		}
		s := CoutAgent(in)
		att := c.Get("expected")
		cmp := func(grandeur string, attendu *Value, x float64) {
			obt := NombreES6(Arrondi3(x))
			a := texteOuAbsent(attendu)
			if fa, ok := flottantDe(attendu); ok {
				a = NombreES6(fa)
			}
			rap.Comparer(f, id, grandeur, a, obt)
		}
		cmp("events_per_year (E)", att.Get("events_per_year"), s.E)
		cmp("event_bytes_per_year (V_e)", att.Get("event_bytes_per_year"), s.Ve)
		cmp("piece_bytes_per_year (V_p)", att.Get("piece_bytes_per_year"), s.Vp)
		cmp("segments_per_year (O_s)", att.Get("segments_per_year"), s.Os)
		cmp("journal_objects_per_year (O_j)", att.Get("journal_objects_per_year"), s.Oj)
		cmp("worm_objects_per_year (O_w)", att.Get("worm_objects_per_year"), s.Ow)
		cmp("worm_billable_bytes_per_year (B_w)", att.Get("worm_billable_bytes_per_year"), s.Bw)
		co := att.Get("cost")
		cmp("cost.local_storage (L)", co.Get("local_storage"), s.L)
		cmp("cost.worm_storage (W_st)", co.Get("worm_storage"), s.Wst)
		cmp("cost.legal_hold (W_gel)", co.Get("legal_hold"), s.Wgel)
		cmp("cost.write_requests (W_put)", co.Get("write_requests"), s.Wput)
		cmp("cost.read_requests (W_get)", co.Get("read_requests"), s.Wget)
		cmp("cost.network (W_net)", co.Get("network"), s.Wnet)
		cmp("cost.anchoring (C_a)", co.Get("anchoring"), s.Ca)
		cmp("cost.total (C)", co.Get("total"), s.C)
		cmp("cost_journal_total (C_J = C × A)", att.Get("cost_journal_total"), s.CJ)
		if imp, ok := CoutImprime164[id]; ok {
			rap.Comparer(f, id, "C imprimé dans la table de 16.4 (valeurs recopiées)", NombreES6(imp), NombreES6(Arrondi3(s.C)))
		}
	}
	for _, o := range []string{"reference", "sans-worm", "pieces-dans-le-worm", "taille-minimale-facturable", "gel-juridique",
		"segments-scindes", "agent-inactif", "un-agent-par-journal", "pieces-purgees"} {
		rap.Comparer(f, "cas.json", "cas obligatoire "+o+" (B.10)", "présent", presentSi(vus[o]))
	}
	// B.10 : C_anc du cas reference = cost_per_journal du cas
	// defaut-second-rang-a1 de spec/vecteurs/ct-5/cout/cout.json.
	ct5 := filepath.Join(ctx.racine, "..", "ct-5", "cout", "cout.json")
	if fichierExiste(ct5) && ancrageReference != nil {
		if d := lireFichierJSON(rap, ct5); d != nil {
			obt := "(cas absent)"
			if cs := d.Get("cases"); EstTableau(cs) {
				for _, c := range cs.Arr {
					if chaineDe(c, "id") == "defaut-second-rang-a1" {
						obt = texteOuAbsent(c.Get("expected").Get("cost_per_journal"))
					}
				}
			}
			rap.Comparer(f, "reference", "anchoring_cost_per_journal = cost_per_journal de ct-5/cout defaut-second-rang-a1 (B.10)", texteOuAbsent(ancrageReference), obt)
		}
	} else {
		rap.Note("cout-agent : spec/vecteurs/ct-5/cout/cout.json introuvable à côté des vecteurs : renvoi de B.10 non confronté")
	}
	rap.Note("cout-agent : %d cas lus ; prix en unités symboliques p (EX-16.5)", len(cas.Arr))
}

// CoutImprime164 recopie la colonne « C (p) » de la table des cas de 16.4.
var CoutImprime164 = map[string]float64{
	"reference":                  2881.27,
	"sans-worm":                  2819.423,
	"pieces-dans-le-worm":        3922.643,
	"taille-minimale-facturable": 2875.799,
	"gel-juridique":              2882.448,
	"segments-scindes":           3605.9,
	"agent-inactif":              2855.931,
	"un-agent-par-journal":       28588.475,
	"pieces-purgees":             2871.237,
}

// presentSi rend « présent » ou « absent ».
func presentSi(b bool) string {
	if b {
		return "présent"
	}
	return "absent"
}
