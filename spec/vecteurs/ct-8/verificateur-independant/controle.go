// Évaluation du contrôle préalable de CT-8 §6, fonction pure des
// observations (EX-6.1) : vérifications IP-1 à IP-13 dans l'ordre de la
// table d'EX-6.2, colonnes « Réussie si », « Rapide », « Production » ;
// verdict et code de sortie d'EX-6.3 ; option --seulement (EX-6.1 : les
// vérifications non demandées sont non_execute, raison non_demandee, non
// bloquantes) ; cache d'écriture (EX-6.4).
//
// Les formes de `measured` et `expected` sont celles de la table d'EX-6.6
// de CT-8 0.1 ; l'ordre de la première faute
// d'IP-10 et les raisons nouvelles (borne_inconnue, adresse_toutes_interfaces,
// adresse_hors_hote, secret_mode_non_conforme, secret_partage_entre_comptes,
// configuration_proprietaire_incorrect, condense_requis) sont ceux d'EX-6.2.

package main

const gio = 1073741824

// VerifIP est le résultat recalculé d'une vérification IP-n.
type VerifIP struct {
	ID       string
	Status   string
	Reason   string // "" pour null
	Measured *Value // nil : forme non fixée par le texte
	NonFixe  string // raison quand Measured est nil
	Expected *Value
	Blocking bool
}

// RapportIP est le rapport recalculé (racine de controle-prealable-v0).
type RapportIP struct {
	Version   int
	Profile   string
	CheckedAt string
	Tool      string
	Verdict   string
	ExitCode  int
	Checks    []VerifIP
}

// ExigencesIP sont les seuils d'un profil (table d'EX-6.2).
type ExigencesIP struct {
	CPUs, Memoire   float64
	EspaceRapide    float64
	Architectures   []string
	FsAdmis         []string
	FsRefuses       []string
	ErreurHorlogeMs float64
	PortsRapide     [][2]any
}

// Exigences rend les seuils de la table d'EX-6.2 pour un profil.
func Exigences(profil string) ExigencesIP {
	e := ExigencesIP{
		Architectures:   []string{"x64"},
		FsAdmis:         []string{"ext4", "xfs", "btrfs"},
		FsRefuses:       []string{"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs"},
		ErreurHorlogeMs: 1000, // clock.warn_skew_ms de l'exemple de CT-2 §15.3
		EspaceRapide:    10 * gio,
		PortsRapide:     [][2]any{{"127.0.0.1", 8300}, {"127.0.0.1", 8400}, {"127.0.0.1", 8500}},
	}
	if profil == "production" {
		e.CPUs, e.Memoire = 4, 8*gio
	} else {
		e.CPUs, e.Memoire = 2, 4*gio
	}
	return e
}

func contient(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// nul dit si une valeur manque ou vaut null.
func nul(v *Value) bool { return v == nil || v.EstNull() }

// adresseEtPort construit {address, port}.
func adresseEtPort(a string, p float64) *Value { return VObj("address", VStr(a), "port", VNum(p)) }

// EvaluerIP évalue des observations pour un profil (EX-6.2, formes
// d'EX-6.6). seuil est storage_free_min_bytes du cas (nil ou null :
// absent) ; only est la liste de --seulement (vide : toutes).
func EvaluerIP(profil string, obs *Value, seuil *Value, only []string) RapportIP {
	ex := Exigences(profil)
	prod := profil == "production"
	var checks []VerifIP

	// Bloquante dans le profil (colonnes Rapide et Production d'EX-6.2).
	bloquante := map[string]bool{
		"IP-1": true, "IP-2": true, "IP-3": true, "IP-4": true, "IP-5": prod,
		"IP-6": true, "IP-7": true, "IP-8": true, "IP-9": prod, "IP-10": true,
		"IP-11": true, "IP-12": true, "IP-13": prod,
	}
	ajout := func(v VerifIP) {
		v.Blocking = bloquante[v.ID]
		checks = append(checks, v)
	}

	// IP-1
	{
		v := VerifIP{ID: "IP-1", Status: "reussi",
			Expected: VObj("platform", VStr("linux"), "architectures", VStrs(ex.Architectures...))}
		p, a := obs.Get("platform"), obs.Get("arch")
		if nul(p) {
			v.Status, v.Reason, v.Measured = "non_execute", "mesure_absente", VNull()
		} else {
			v.Measured = VObj("platform", Copie(p), "arch", Copie(a))
			switch {
			case p.Str != "linux":
				v.Status, v.Reason = "echoue", "systeme_non_pris_en_charge"
			case !contient(ex.Architectures, a.Str):
				v.Status, v.Reason = "echoue", "architecture_non_prise_en_charge"
			}
		}
		ajout(v)
	}
	// IP-2
	{
		cpus, mem := nombre(obs.Get("cpus")), nombre(obs.Get("memory_bytes"))
		v := VerifIP{ID: "IP-2", Status: "reussi",
			Measured: VObj("cpus", Copie(obs.Get("cpus")), "memory_bytes", Copie(obs.Get("memory_bytes"))),
			Expected: VObj("cpus_min", VNum(ex.CPUs), "memory_min_bytes", VNum(ex.Memoire))}
		switch {
		case cpus < ex.CPUs:
			v.Status, v.Reason = "echoue", "processeurs_insuffisants"
		case mem < ex.Memoire:
			v.Status, v.Reason = "echoue", "memoire_insuffisante"
		}
		ajout(v)
	}
	// IP-3 et IP-4
	{
		st := obs.Get("storage")
		var min *Value
		if prod {
			if nul(seuil) {
				min = VNull()
			} else {
				min = seuil
			}
		} else {
			min = VNum(ex.EspaceRapide)
		}
		v3 := VerifIP{ID: "IP-3", Status: "reussi", Expected: VObj("free_min_bytes", min)}
		v4 := VerifIP{ID: "IP-4", Status: "reussi", Expected: VObj("accepted", VStrs(ex.FsAdmis...))}
		if nul(st) {
			v3.Status, v3.Reason, v3.Measured = "non_execute", "mesure_absente", VNull()
			v4.Status, v4.Reason, v4.Measured = "non_execute", "mesure_absente", VNull()
		} else {
			v3.Measured = VObj("free_bytes", Copie(st.Get("free_bytes")))
			switch {
			case min.EstNull():
				v3.Status, v3.Reason = "non_execute", "dimensionnement_absent"
			case nombre(st.Get("free_bytes")) < nombre(min):
				v3.Status, v3.Reason = "echoue", "espace_insuffisant"
			}
			fs := st.Get("fstype").Str
			v4.Measured = VObj("fstype", VStr(fs))
			switch {
			case contient(ex.FsAdmis, fs):
			case contient(ex.FsRefuses, fs):
				v4.Status, v4.Reason = "echoue", "systeme_de_fichiers_refuse"
			default:
				v4.Status, v4.Reason = "avertissement", "systeme_de_fichiers_non_eprouve"
			}
		}
		ajout(v3)
		ajout(v4)
	}
	// IP-5
	{
		cl := obs.Get("clock")
		v := VerifIP{ID: "IP-5", Status: "reussi",
			Expected: VObj("synchronized", VBool(true), "max_error_ms", VNum(ex.ErreurHorlogeMs))}
		switch {
		case nul(cl):
			v.Status, v.Reason, v.Measured = "non_execute", "mesure_absente", VNull()
		case cl.Get("source").Str == "aucune":
			v.Status, v.Reason, v.Measured = "non_execute", "outil_absent", VObj("source", VStr("aucune"))
		default:
			sync := cl.Get("synchronized")
			borne := cl.Get("error_bound_ms")
			v.Measured = VObj("source", Copie(cl.Get("source")), "synchronized", VBool(!nul(sync) && sync.Bool), "error_bound_ms", Copie(borne))
			switch {
			case nul(sync) || !sync.Bool:
				v.Status, v.Reason = "echoue", "horloge_non_synchronisee"
			case nul(borne):
				v.Status, v.Reason = "avertissement", "borne_inconnue"
			case nombre(borne) > ex.ErreurHorlogeMs:
				v.Status, v.Reason = "echoue", "ecart_trop_grand"
			}
		}
		ajout(v)
	}
	// IP-6
	{
		libres := VArr()
		if prod {
			for _, p := range obs.Get("ports").Arr {
				libres.Arr = append(libres.Arr, adresseEtPort(p.Get("address").Str, nombre(p.Get("port"))))
			}
		} else {
			for _, p := range ex.PortsRapide {
				libres.Arr = append(libres.Arr, adresseEtPort(p[0].(string), float64(p[1].(int))))
			}
		}
		occupes := VArr()
		for _, a := range libres.Arr {
			libre := false
			for _, p := range obs.Get("ports").Arr {
				if p.Get("address").Str == a.Get("address").Str && nombre(p.Get("port")) == nombre(a.Get("port")) {
					libre = p.Get("free").Bool
					break
				}
			}
			if !libre {
				occupes.Arr = append(occupes.Arr, a)
			}
		}
		ia := obs.Get("internal_address")
		raison := ""
		if !nul(ia) {
			switch ad := ia.Get("address").Str; {
			case ad == "0.0.0.0" || ad == "::" || ad == "[::]":
				raison = "adresse_toutes_interfaces"
			case !ia.Get("on_host").Bool:
				raison = "adresse_hors_hote"
			}
		}
		if raison == "" && len(occupes.Arr) > 0 {
			raison = "port_occupe"
		}
		v := VerifIP{ID: "IP-6", Status: "reussi", Expected: VObj("free", libres), Measured: VObj("busy", occupes, "internal_address", Copie(ia))}
		if raison != "" {
			v.Status, v.Reason = "echoue", raison
		}
		ajout(v)
	}
	// IP-7
	{
		noms, non := VArr(), VArr()
		for _, d := range obs.Get("dns").Arr {
			noms.Arr = append(noms.Arr, VStr(d.Get("name").Str))
			if len(d.Get("addresses").Arr) == 0 {
				non.Arr = append(non.Arr, VStr(d.Get("name").Str))
			}
		}
		v := VerifIP{ID: "IP-7", Status: "reussi", Expected: VObj("resolved", noms), Measured: VObj("unresolved", non)}
		if len(non.Arr) > 0 {
			v.Status, v.Reason = "echoue", "nom_non_resolu"
		}
		ajout(v)
	}
	// IP-8
	{
		flux, ko := VArr(), VArr()
		premier := ""
		for _, e := range obs.Get("egress").Arr {
			flux.Arr = append(flux.Arr, VStr(e.Get("flow").Str))
			if r := e.Get("result").Str; r != "ouvert" {
				if premier == "" {
					premier = r
				}
				ko.Arr = append(ko.Arr, VObj("flow", Copie(e.Get("flow")), "host", Copie(e.Get("host")), "port", Copie(e.Get("port")), "result", Copie(e.Get("result"))))
			}
		}
		v := VerifIP{ID: "IP-8", Status: "reussi", Expected: VObj("open", flux), Measured: VObj("failed", ko)}
		if premier != "" {
			v.Status, v.Reason = "echoue", premier
		}
		ajout(v)
	}
	// IP-9
	{
		px := obs.Get("proxy")
		v := VerifIP{ID: "IP-9", Status: "reussi",
			Measured: VObj("environment_set", Copie(px.Get("environment_set"))),
			Expected: VObj("declared", Copie(px.Get("declared")))}
		if px.Get("environment_set").Bool != px.Get("declared").Bool {
			v.Status, v.Reason = "avertissement", "mandataire_incoherent"
		}
		ajout(v)
	}
	// IP-10 : première faute dans l'ordre d'EX-6.2.
	{
		dr := obs.Get("rights")
		v := VerifIP{ID: "IP-10", Status: "reussi",
			Measured: VObj("uid_is_root", VBool(nombre(dr.Get("uid")) == 0), "secrets_dir_mode", Copie(dr.Get("secrets_dir_mode")),
				"config_mode", Copie(dr.Get("config_mode")), "config_uid", Copie(dr.Get("config_uid")), "config_expected_uid", Copie(dr.Get("config_expected_uid"))),
			Expected: VObj("secret_modes", VArr(VInt(0o400), VInt(0o600)), "secrets_mode_mask", VInt(0o077), "config_mode_mask", VInt(0o077))}
		fichiers := dr.Get("secret_files").Arr
		existe := func(p func(f *Value) bool) bool {
			for _, f := range fichiers {
				if p(f) {
					return true
				}
			}
			return false
		}
		mode := func(f *Value) int64 { return int64(nombre(f.Get("mode"))) }
		sd, cm := dr.Get("secrets_dir_mode"), dr.Get("config_mode")
		raison := ""
		switch {
		case !nul(sd) && int64(nombre(sd))&0o077 != 0:
			raison = "secrets_lisibles"
		case existe(func(f *Value) bool { return mode(f)&0o077 != 0 }):
			raison = "secrets_lisibles"
		case existe(func(f *Value) bool { m := mode(f) & 0o7777; return m != 0o400 && m != 0o600 }):
			raison = "secret_mode_non_conforme"
		case existe(func(f *Value) bool { return nul(f.Get("expected_uid")) }):
			raison = "secret_partage_entre_comptes"
		case existe(func(f *Value) bool { return nombre(f.Get("uid")) != nombre(f.Get("expected_uid")) }):
			raison = "secret_proprietaire_incorrect"
		case !nul(cm) && int64(nombre(cm))&0o077 != 0:
			raison = "configuration_lisible_par_autrui"
		case !nul(cm) && TexteValeur(Copie(dr.Get("config_uid"))) != TexteValeur(Copie(dr.Get("config_expected_uid"))):
			raison = "configuration_proprietaire_incorrect"
		}
		if raison != "" {
			v.Status, v.Reason = "echoue", raison
		}
		ajout(v)
	}
	// IP-11
	{
		en := obs.Get("engine")
		v := VerifIP{ID: "IP-11", Status: "reussi",
			Measured: VObj("engine_ok", Copie(en.Get("engine_ok")), "compose_ok", Copie(en.Get("compose_ok"))),
			Expected: VObj("engine_ok", VBool(true), "compose_ok", VBool(true))}
		switch {
		case !en.Get("engine_ok").Bool:
			v.Status, v.Reason = "echoue", "moteur_absent"
		case !en.Get("compose_ok").Bool:
			v.Status, v.Reason = "echoue", "compose_absent"
		}
		ajout(v)
	}
	// IP-12
	{
		co := obs.Get("compose")
		v := VerifIP{ID: "IP-12", Status: "reussi",
			Expected: VObj("failed", VArr(), "images_by_digest", VBool(prod))}
		if nul(co) {
			v.Status, v.Reason, v.Measured = "non_execute", "fichier_absent", VNull()
		} else {
			v.Measured = VObj("failed", Copie(co.Get("failed")), "all_images_by_digest", Copie(co.Get("all_images_by_digest")))
			switch {
			case len(co.Get("failed").Arr) > 0:
				v.Status, v.Reason = "echoue", "conteneurs_non_conformes"
			case prod && !co.Get("all_images_by_digest").Bool:
				v.Status, v.Reason = "echoue", "condense_requis"
			}
		}
		ajout(v)
	}
	// IP-13 (EX-6.4)
	{
		d := obs.Chemin("declarations", "write_cache_protected")
		v := VerifIP{ID: "IP-13", Status: "reussi",
			Measured: VObj("declared", VBool(d != nil && d.Bool)),
			Expected: VObj("declared", VBool(true))}
		if d == nil || !d.Bool {
			if prod {
				v.Status, v.Reason = "echoue", "declaration_absente"
			} else {
				v.Status, v.Reason = "non_execute", "declaration_absente"
			}
		}
		ajout(v)
	}

	// --seulement (EX-6.1, EX-6.6).
	if len(only) > 0 {
		for i := range checks {
			if !contient(only, checks[i].ID) {
				checks[i].Status, checks[i].Reason = "non_execute", "non_demandee"
				checks[i].Blocking = false
				checks[i].Measured = VNull()
			}
		}
	}

	// EX-6.3.
	verdict := "pret"
	for _, c := range checks {
		if c.Blocking && (c.Status == "echoue" || c.Status == "non_execute") {
			verdict = "non_pret"
			break
		}
		if c.Status != "reussi" {
			verdict = "pret_avec_avertissements"
		}
	}
	code := 0
	if verdict == "non_pret" {
		code = 1
	}
	return RapportIP{Version: 0, Profile: profil, CheckedAt: obs.Get("checked_at").Str,
		Tool: obs.Get("tool").Str, Verdict: verdict, ExitCode: code, Checks: checks}
}

// ValeurRapportIP rend le rapport sous forme de valeur JSON ; une mesure non
// fixée est écrite null (pour la comparaison à l'exemple de 6.3, qui n'en a
// pas).
func ValeurRapportIP(r RapportIP) *Value {
	ch := VArr()
	for _, c := range r.Checks {
		reason := VNull()
		if c.Reason != "" {
			reason = VStr(c.Reason)
		}
		ch.Arr = append(ch.Arr, VObj("id", VStr(c.ID), "status", VStr(c.Status), "reason", reason,
			"measured", Copie(c.Measured), "expected", c.Expected, "blocking", VBool(c.Blocking)))
	}
	return VObj("version", VInt(int64(r.Version)), "profile", VStr(r.Profile), "checked_at", VStr(r.CheckedAt),
		"tool", VStr(r.Tool), "verdict", VStr(r.Verdict), "exit_code", VInt(int64(r.ExitCode)), "checks", ch)
}
