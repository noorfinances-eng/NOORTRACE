// Calculateur de dimensionnement de CT-8 §9, écrit depuis le seul texte :
// paramètres (9.1), coefficients (9.2, lus dans la table du texte, EX-9.1),
// lignes DM-1 à DM-22 dans l'ordre écrit (EX-9.2), refus (EX-9.3). Calcul en
// float64 IEEE 754, chaque expression de gauche à droite avec les parenthèses
// écrites, sans arrondi intermédiaire ; arrondi unique des sorties :
// math.Ceil pour les octets, les nombres et le gaz, math.Round(x*1000)/1000
// pour les débits et les transactions par heure, math.Round(x*1e6)/1e6 pour
// registry_capacity_share (EX-A.22).

package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Coefficients est la table de 9.2 (EX-9.1).
type Coefficients map[string]float64

// nomsCoefficients sont les membres de $defs/coefficients, dans l'ordre de
// la table de 9.2.
var nomsCoefficients = []string{"b_pt", "b_man", "b_tsq", "b_der", "b_tsr_sup", "b_ots", "b_cap", "gaz_ancre", "gaz_cloture", "tx_par_bloc", "blocs_par_s", "debit_cible"}

// LireCoefficients lit la table de 9.2 : colonne « Valeur », espaces de
// groupement retirés, virgule décimale.
func LireCoefficients(t *Texte) (Coefficients, error) {
	sec, err := t.Section("### 9.2 ")
	if err != nil {
		return nil, err
	}
	tab, err := TableEntete(sec, "Coefficient", "Valeur")
	if err != nil {
		return nil, err
	}
	c := Coefficients{}
	for _, l := range tab.Lignes {
		noms := strings.Split(SansCode(l[0]), ",")
		valeurs := strings.Split(l[1], ";")
		if l[1] == "—" {
			continue // f_pic, b_o, b_acq, b_crl, n_crl, m_0 : à mesurer, entrées
		}
		if len(noms) != len(valeurs) {
			return nil, fmt.Errorf("9.2 : ligne %q : %d noms, %d valeurs", l[0], len(noms), len(valeurs))
		}
		for i, n := range noms {
			n = strings.Fields(strings.TrimSpace(n))[0]
			v := strings.ReplaceAll(strings.TrimSpace(valeurs[i]), " ", "")
			v = strings.ReplaceAll(v, ",", ".")
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("9.2 : valeur %q de %s illisible", valeurs[i], n)
			}
			c[n] = f
		}
	}
	for _, n := range nomsCoefficients {
		if _, ok := c[n]; !ok {
			return nil, fmt.Errorf("9.2 : coefficient %s absent de la table", n)
		}
	}
	return c, nil
}

// ErreurDim est une raison de refus d'EX-9.3.
type ErreurDim struct {
	Journal, Code string
}

// SortieDim est la sortie du calculateur : soit des journaux et des totaux,
// soit des erreurs.
type SortieDim struct {
	Valide   bool
	Erreurs  []ErreurDim
	Journaux [][]Champ
	Totaux   []Champ
}

// Champ est une grandeur de sortie : nom, nombre (ou null) ou booléen.
type Champ struct {
	Nom    string
	Nombre float64
	Null   bool
	Bool   *bool
	Str    *string
}

func nombre(v *Value) float64 {
	if v == nil || v.Kind != KindNumber {
		return math.NaN()
	}
	f, err := NombreDouble(v.Num)
	if err != nil {
		return math.NaN()
	}
	return f
}

func vrai(v *Value) float64 {
	if v != nil && v.Kind == KindBool && v.Bool {
		return 1
	}
	return 0
}

func arr3(x float64) float64 { return math.Round(x*1000) / 1000 }
func arr6(x float64) float64 { return math.Round(x*1e6) / 1e6 }

// Dimensionner applique EX-9.3 puis DM-1 à DM-22 à un document d'entrée
// conforme à dimensionnement-v0.
func Dimensionner(entrees *Value, table Coefficients) SortieDim {
	k := Coefficients{}
	for n, v := range table {
		k[n] = v
	}
	for _, m := range entrees.Get("coefficients").Obj {
		k[m.Cle] = nombre(m.Val)
	}
	Nh := nombre(entrees.Get("hours_per_year"))
	journaux := entrees.Get("journals").Arr

	// EX-9.3 : toutes les raisons, journal par journal, dans l'ordre du texte.
	var errs []ErreurDim
	for _, j := range journaux {
		id := j.Get("id").Str
		an := j.Get("anchoring")
		cK := nombre(an.Get("checkpoint_interval_s"))
		cT := nombre(an.Get("rfc3161_interval_s"))
		if math.Mod(3600, cK) != 0 {
			errs = append(errs, ErreurDim{id, "checkpoint_interval_s_non_diviseur"})
		}
		if math.Mod(cT, cK) != 0 || math.Mod(3600, cT) != 0 {
			errs = append(errs, ErreurDim{id, "rfc3161_interval_s_invalide"})
		}
		if nombre(an.Get("retention_years")) < 10 {
			errs = append(errs, ErreurDim{id, "retention_years_inferieure_a_10"})
		}
		st := j.Get("storage")
		if w := st.Get("worm"); w != nil && !w.EstNull() {
			if nombre(w.Get("retain_days")) < 365*nombre(st.Get("events_years")) {
				errs = append(errs, ErreurDim{id, "retain_days_insuffisant"})
			}
		}
	}
	if len(errs) > 0 {
		return SortieDim{Valide: false, Erreurs: errs}
	}

	var out SortieDim
	out.Valide = true
	var sJ, sSloc, sSw, sAo, sNq, sNs, sNa, sNh, sG, sTj, sW, sF float64
	Cap := k["tx_par_bloc"] * k["blocs_par_s"] * 3600 // DM-21
	for _, j := range journaux {
		id := j.Get("id").Str
		J := nombre(j.Get("count"))
		ac := j.Get("activity")
		A := nombre(ac.Get("agents"))
		e := nombre(ac.Get("events_per_hour"))
		H := nombre(ac.Get("active_hours"))
		fpic := nombre(ac.Get("peak_factor"))
		be := nombre(ac.Get("event_bytes"))
		bp := nombre(ac.Get("piece_bytes_per_event"))
		np := nombre(ac.Get("pieces_per_event"))
		qw := nombre(ac.Get("write_share"))
		bo := nombre(ac.Get("ops_log_bytes_per_event"))
		st := j.Get("storage")
		Dl := nombre(st.Get("local_days"))
		Dlp := nombre(st.Get("pieces_days"))
		minFree := nombre(st.Get("min_free_bytes"))
		pending := nombre(st.Get("pending_max_bytes"))
		rotate := nombre(st.Chemin("ops_log", "rotate_max_bytes"))
		keep := nombre(st.Chemin("ops_log", "keep_files"))
		g := nombre(st.Chemin("fsync", "group_max_events"))
		var Dw, nw, piw, oiw float64
		if w := st.Get("worm"); w != nil && !w.EstNull() {
			Dw = nombre(w.Get("retain_days"))
			nw = nombre(w.Get("copies"))
			piw = vrai(w.Get("pieces_in_worm"))
			oiw = vrai(w.Get("ops_log_in_worm"))
		}
		an := j.Get("anchoring")
		cK := nombre(an.Get("checkpoint_interval_s"))
		cT := nombre(an.Get("rfc3161_interval_s"))
		a := nombre(an.Get("a"))
		r := nombre(an.Get("r"))
		role := an.Get("provider_role").Str
		var dq, ds, dr float64
		if role == "principal" {
			dq = 1
		}
		if role == "second_rang" || role == "interne" {
			ds = 1
		}
		if an.Get("registry_checkpoints").Str != "aucun" {
			dr = 1
		}
		var mi float64
		if an.Get("ots_checkpoint").Str == "mi_periode" {
			mi = 1
		}
		Yanc := nombre(an.Get("retention_years"))
		ncrl := nombre(an.Get("crl_per_token"))
		bcrl := nombre(an.Get("crl_bytes"))
		bacq := nombre(an.Get("acquisition_bytes"))
		me := j.Get("memory")
		C := nombre(me.Get("max_concurrent"))
		req := nombre(me.Get("request_max_bytes"))
		resp := nombre(me.Get("response_max_bytes"))
		base := me.Get("base_bytes")

		E := A * e * H                                                                     // DM-1
		rmoy := (A * e) / 3600                                                             // DM-2
		rpic := rmoy * fpic                                                                // DM-3
		Ve := E * be                                                                       // DM-4
		Vp := E * bp                                                                       // DM-5
		Np := E * np                                                                       // DM-5
		nT := 3600 / cT                                                                    // DM-6
		Nq := Nh * (1 + dq*(nT-1)*a)                                                       // DM-6
		Ns := Nh * ds * (nT - 1) * a                                                       // DM-6
		Na := Nh * (1 + dr*(1+3600/cK))                                                    // DM-7
		Nots := Nh * (1 + mi)                                                              // DM-8
		btok := k["b_tsq"] + k["b_der"] + (k["b_der"] + k["b_tsr_sup"]) + ncrl*bcrl + bacq // DM-9
		Vanc := (Nq+Ns)*(1+r)*btok + Nots*k["b_ots"]                                       // DM-9
		Vpts := Nh * (3600/cK + 1) * k["b_pt"]                                             // DM-10
		Vman := Nh * k["b_man"]                                                            // DM-10
		Vj := Vpts + Vman                                                                  // DM-10
		Vcap := (Na + Nh) * k["b_cap"]                                                     // DM-11
		Vo := E * bo                                                                       // DM-12
		Wpic := rpic * (be + bp + bo)                                                      // DM-13
		Fmax := rpic * (1 + qw)                                                            // DM-14
		Fmin := rpic/g + rpic*qw                                                           // DM-14
		G := Na*k["gaz_ancre"] + Nh*k["gaz_cloture"]                                       // DM-15
		Sloc := (Ve+Vj)*(Dl/365) + Vp*(Dlp/365) + (Vanc+Vcap)*Yanc +
			keep*rotate + pending + 2*minFree // DM-16
		Sw := nw * (Ve + Vj + Vanc + Vcap + piw*Vp + oiw*Vo) * (Dw / 365) // DM-17
		Ao := Vo * (Dl / 365)                                             // DM-18
		Mtamp := C * (req + resp)                                         // DM-19
		Tj := (Na + Nh) / Nh                                              // DM-20
		Jmax := math.Floor(Cap / Tj)                                      // DM-21

		depasse := rpic > k["debit_cible"]
		ch := []Champ{
			{Nom: "id", Str: &id},
			{Nom: "count", Nombre: J},
			{Nom: "events_per_year", Nombre: math.Ceil(E)},
			{Nom: "mean_events_per_s", Nombre: arr3(rmoy)},
			{Nom: "peak_events_per_s", Nombre: arr3(rpic)},
			{Nom: "peak_over_target", Bool: &depasse},
			{Nom: "segment_bytes_per_year", Nombre: math.Ceil(Ve)},
			{Nom: "piece_bytes_per_year", Nombre: math.Ceil(Vp)},
			{Nom: "piece_files_per_year", Nombre: math.Ceil(Np)},
			{Nom: "checkpoint_bytes_per_year", Nombre: math.Ceil(Vpts)},
			{Nom: "manifest_bytes_per_year", Nombre: math.Ceil(Vman)},
			{Nom: "anchor_bytes_per_year", Nombre: math.Ceil(Vanc)},
			{Nom: "capture_bytes_per_year", Nombre: math.Ceil(Vcap)},
			{Nom: "ops_log_bytes_per_year", Nombre: math.Ceil(Vo)},
			{Nom: "tokens_qualified_per_year", Nombre: math.Ceil(Nq)},
			{Nom: "tokens_other_per_year", Nombre: math.Ceil(Ns)},
			{Nom: "registry_anchors_per_year_max", Nombre: math.Ceil(Na)},
			{Nom: "registry_closures_per_year", Nombre: math.Ceil(Nh)},
			{Nom: "ots_submissions_per_year", Nombre: math.Ceil(Nots)},
			{Nom: "registry_tx_per_hour_max", Nombre: arr3(Tj)},
			{Nom: "registry_journals_max", Nombre: Jmax},
			{Nom: "gas_per_year_max", Nombre: math.Ceil(G)},
			{Nom: "local_bytes", Nombre: math.Ceil(Sloc)},
			{Nom: "worm_bytes", Nombre: math.Ceil(Sw)},
			{Nom: "ops_archive_bytes", Nombre: math.Ceil(Ao)},
			{Nom: "peak_write_bytes_per_s", Nombre: math.Ceil(Wpic)},
			{Nom: "peak_fsync_per_s_max", Nombre: arr3(Fmax)},
			{Nom: "peak_fsync_per_s_min", Nombre: arr3(Fmin)},
			{Nom: "memory_buffers_max_bytes", Nombre: math.Ceil(Mtamp)},
		}
		if base == nil || base.EstNull() {
			ch = append(ch, Champ{Nom: "memory_base_bytes", Null: true})
		} else {
			ch = append(ch, Champ{Nom: "memory_base_bytes", Nombre: math.Ceil(nombre(base))})
		}
		out.Journaux = append(out.Journaux, ch)

		// DM-22 : sommes type par type, dans l'ordre des entrées.
		sJ += J
		sSloc += J * Sloc
		sSw += J * Sw
		sAo += J * Ao
		sNq += J * Nq
		sNs += J * Ns
		sNa += J * Na
		sNh += J * Nh
		sG += J * G
		sTj += J * Tj
		sW += J * Wpic
		sF += J * Fmax
	}
	out.Totaux = []Champ{
		{Nom: "journals", Nombre: sJ},
		{Nom: "local_bytes", Nombre: math.Ceil(sSloc)},
		{Nom: "worm_bytes", Nombre: math.Ceil(sSw)},
		{Nom: "ops_archive_bytes", Nombre: math.Ceil(sAo)},
		{Nom: "tokens_qualified_per_year", Nombre: math.Ceil(sNq)},
		{Nom: "tokens_other_per_year", Nombre: math.Ceil(sNs)},
		{Nom: "registry_anchors_per_year_max", Nombre: math.Ceil(sNa)},
		{Nom: "registry_closures_per_year", Nombre: math.Ceil(sNh)},
		{Nom: "gas_per_year_max", Nombre: math.Ceil(sG)},
		{Nom: "registry_tx_per_hour_max", Nombre: arr3(sTj)},
		{Nom: "registry_capacity_tx_per_hour", Nombre: arr3(Cap)},
		{Nom: "registry_capacity_share", Nombre: arr6(sTj / Cap)},
		{Nom: "peak_write_bytes_per_s", Nombre: math.Ceil(sW)},
		{Nom: "peak_fsync_per_s_max", Nombre: arr3(sF)},
	}
	// EX-9.3, depassement_capacite : une grandeur de sortie d'un journal, ou
	// son produit par count, au-delà de 2^53 − 1 ; à défaut un total entier
	// au-delà de 2^53 − 1, attribué au dernier journal.
	const maxSur = 9007199254740991.0
	for i, js := range out.Journaux {
		J := nombre(journaux[i].Get("count"))
		for _, ch := range js {
			if ch.Null || ch.Bool != nil || ch.Str != nil {
				continue
			}
			if ch.Nombre > maxSur || ch.Nombre*J > maxSur {
				errs = append(errs, ErreurDim{journaux[i].Get("id").Str, "depassement_capacite"})
				break
			}
		}
	}
	if len(errs) == 0 && len(journaux) > 0 {
		for _, t := range []float64{sSloc, sSw, sAo, sNq, sNs, sNa, sNh, sG, sW} {
			if math.Ceil(t) > maxSur {
				errs = append(errs, ErreurDim{journaux[len(journaux)-1].Get("id").Str, "depassement_capacite"})
				break
			}
		}
	}
	if len(errs) > 0 {
		return SortieDim{Valide: false, Erreurs: errs}
	}
	return out
}

// TexteChamp rend la valeur d'un champ sous la forme de JSON.stringify.
func TexteChamp(c Champ) string {
	switch {
	case c.Null:
		return "null"
	case c.Bool != nil:
		return strconv.FormatBool(*c.Bool)
	case c.Str != nil:
		return strconv.Quote(*c.Str)
	}
	return NombreES6(c.Nombre)
}

// TexteValeur rend une valeur JSON scalaire sous la forme de JSON.stringify.
func TexteValeur(v *Value) string {
	if v == nil {
		return "(absent)"
	}
	s, err := Stringify2(v)
	if err != nil {
		return "(" + err.Error() + ")"
	}
	return s
}

// ComparerSortieDim confronte une sortie recalculée à `attendu` d'un cas :
// mêmes membres dans le même ordre, chaque nombre à l'égalité exacte.
func ComparerSortieDim(rap *Rapport, famille, cas string, s SortieDim, att *Value) {
	rap.Comparer(famille, cas, "valid", TexteValeur(att.Get("valid")), strconv.FormatBool(s.Valide))
	rap.Comparer(famille, cas, "version", TexteValeur(att.Get("version")), "0")
	if !s.Valide {
		var obtenu, attendu []string
		for _, e := range s.Erreurs {
			obtenu = append(obtenu, e.Journal+":"+e.Code)
		}
		if a := att.Get("errors"); a != nil {
			for _, x := range a.Arr {
				attendu = append(attendu, x.Get("journal").Str+":"+x.Get("code").Str)
			}
		}
		rap.Comparer(famille, cas, "errors (EX-9.3)", Liste(attendu), Liste(obtenu))
		rap.Comparer(famille, cas, "membres de la sortie", "[version, valid, errors]", Liste(att.Cles()))
		return
	}
	rap.Comparer(famille, cas, "membres de la sortie", "[version, valid, journals, totals]", Liste(att.Cles()))
	aj := att.Get("journals")
	n := 0
	if aj != nil {
		n = len(aj.Arr)
	}
	rap.Comparer(famille, cas, "nombre de journaux", strconv.Itoa(n), strconv.Itoa(len(s.Journaux)))
	for i, ch := range s.Journaux {
		if aj == nil || i >= len(aj.Arr) {
			break
		}
		x := aj.Arr[i]
		var noms []string
		for _, c := range ch {
			noms = append(noms, c.Nom)
		}
		rap.Comparer(famille, cas, fmt.Sprintf("journals[%d] : membres et ordre", i), Liste(x.Cles()), Liste(noms))
		for _, c := range ch {
			comparerChamp(rap, famille, cas, fmt.Sprintf("journals[%d].%s", i, c.Nom), c, x.Get(c.Nom))
		}
	}
	at := att.Get("totals")
	var noms []string
	for _, c := range s.Totaux {
		noms = append(noms, c.Nom)
	}
	rap.Comparer(famille, cas, "totals : membres et ordre", Liste(at.Cles()), Liste(noms))
	for _, c := range s.Totaux {
		comparerChamp(rap, famille, cas, "totals."+c.Nom, c, at.Get(c.Nom))
	}
}

func comparerChamp(rap *Rapport, famille, cas, grandeur string, c Champ, v *Value) {
	obtenu := TexteChamp(c)
	attendu := TexteValeur(v)
	if v != nil && v.Kind == KindNumber && !c.Null && c.Bool == nil && c.Str == nil {
		// égalité exacte des doubles ; le texte est celui de Number::toString
		f := nombre(v)
		if f == c.Nombre {
			attendu = obtenu
		}
	}
	rap.Comparer(famille, cas, grandeur, attendu, obtenu)
}
