// Révision 0.4 de CT-1 : quatorzième partie facultative
// attestation-perimetre.json (§11.1, §11.2) et vérifications AT-1 à AT-7
// (§11.4). L'attestation P, son condensé D_P = keccak256(P_P ‖ JCS(P)) et la
// signature EIP-191 de D_P sont ceux que §11.2 reproduit de CT-7 EX-7.6 ;
// la signature se vérifie « comme E-9, section 6.3 ».
//
// Les AT- ne changent ni un autre contrôle ni la validité du dossier (§11.4,
// révision 0.4) : leurs statuts sont tenus à part des Resultats. Elles ne
// s'exécutent que si la partie est déclarée présente ; index à douze ou
// treize parties, ou partie absente avec raison : aucune AT- n'est exécutée
// ni rapportée. Prérequis (§11.4) : AT-2 et AT-3 exigent AT-1 réussie ;
// AT-4 exige AT-3 réussie ; AT-5 exige AT-1 réussie et evenement.json
// exploitable (E-1, E-2) ; AT-6 exige AT-2 réussie, evenement.json et
// cles.json exploitables (première partie de E-8) et n'est pas exécutée,
// partie absente, quand inscription vaut null ; AT-7 exige AT-6 réussie et
// n'est pas exécutée, partie absente, quand AT-6 ne l'est pas pour cette
// raison. Raisons, dans les mots du texte : prerequis_en_echec,
// partie_absente, piece_hors_dossier (§11.4 les nomme pour les K-, qu'AT-7
// reprend « comme A-4 »).

package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PrefixeAttestation est P_P (§11.2, annexe B) : 35 octets.
const PrefixeAttestation = "noortrace/attestation-perimetre/v0\n"

// Limites de la partie (§11.4 : 4 Mio, CT-6 EX-4.15) et du document de
// politique décodé (§11.2 : au plus 2 097 152 octets).
const (
	TailleMaxPartieAttestation = 4 << 20
	TailleMaxDocumentPolitique = 2097152
)

// Statuts et raisons des AT- (vocabulaire des attendus de §11.5).
const (
	ATReussi           = "reussi"
	ATEchoue           = "echoue"
	ATNonExecute       = "non_execute"
	RaisonPrerequis    = "prerequis_en_echec"
	RaisonAbsente      = "partie_absente"
	RaisonAncreAbsente = "ancre_absente"
	RaisonHorsDossier  = "piece_hors_dossier"
)

var idsAT = []string{"AT-1", "AT-2", "AT-3", "AT-4", "AT-5", "AT-6", "AT-7"}

// StatutAT est l'état d'une vérification AT-.
type StatutAT struct {
	ID, Statut, Raison string
	Details            []string
}

// verificationsAT tient les sept statuts dans l'ordre.
type verificationsAT struct{ liste []*StatutAT }

func nouvellesAT() *verificationsAT {
	v := &verificationsAT{}
	for _, id := range idsAT {
		v.liste = append(v.liste, &StatutAT{ID: id, Statut: ATReussi})
	}
	return v
}

func (v *verificationsAT) get(id string) *StatutAT {
	for _, s := range v.liste {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func (v *verificationsAT) echec(id, format string, args ...any) {
	s := v.get(id)
	s.Statut, s.Raison = ATEchoue, ""
	s.Details = append(s.Details, fmt.Sprintf(format, args...))
}

func (v *verificationsAT) nonExecute(id, raison string) {
	s := v.get(id)
	s.Statut, s.Raison = ATNonExecute, raison
}

func (v *verificationsAT) reussie(id string) bool { return v.get(id).Statut == ATReussi }

var (
	reAttSlug      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	reAttAgent     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	reAttAlias     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reAttOutil     = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._:/-]{0,127})$`)
	reAttRoute     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,255}$`)
	reAttEtiquette = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)
	reAttEnv       = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	enumCanaux     = []string{"mandataire_mcp", "passerelle", "icap", "miroir", "sdk", "opentelemetry"}
)

func (m *manquements) motif(v *Value, chemin string, re *regexp.Regexp) {
	if v == nil || v.Kind != KindString || !re.MatchString(v.Str) {
		m.add(chemin, "chaîne conforme à %s attendue", re.String())
	}
}

func (m *manquements) constanteZero(v *Value, chemin string) {
	if v == nil || v.Kind != KindNumber {
		m.add(chemin, "constante 0 attendue")
	} else if n, ok := estEntierJSON(v.Num); !ok || n.Sign() != 0 {
		m.add(chemin, "constante 0 attendue, reçu %s", v.Num)
	}
}

// tableau contrôle un tableau de min à max éléments (max < 0 : sans borne).
func (m *manquements) tableau(v *Value, chemin string, min, max int) []*Value {
	if v == nil || v.Kind != KindArray {
		m.add(chemin, "tableau attendu")
		return nil
	}
	if len(v.Arr) < min || (max >= 0 && len(v.Arr) > max) {
		m.add(chemin, "%d éléments hors de [%d, %d]", len(v.Arr), min, max)
	}
	return v.Arr
}

// uniques signale deux éléments égaux d'un tableau de chaînes (uniqueItems).
func (m *manquements) uniques(xs []*Value, chemin string) {
	vus := map[string]bool{}
	for _, x := range xs {
		if x.Kind != KindString {
			continue
		}
		if vus[x.Str] {
			m.add(chemin, "élément %q en double", x.Str)
		}
		vus[x.Str] = true
	}
}

// validerAttestationP transcrit attestation-perimetre-v0.schema.json (objet
// racine, treize membres) ; les relations d'EX-7.2 sont contrôlées à part.
func validerAttestationP(p *Value, ch string, m *manquements) {
	if !m.clesExactes(p, ch, []string{"version", "org", "journals", "validity", "issued_at", "prepared_by", "agents", "tools_via_proxy_only", "egress", "gateway_credentials", "not_captured", "signatories", "declaration"}) {
		return
	}
	m.constanteZero(p.Get("version"), ch+".version")
	if o := p.Get("org"); m.clesExactes(o, ch+".org", []string{"org_id", "slug", "name"}) {
		m.hex(o.Get("org_id"), ch+".org.org_id", 32, false)
		m.motif(o.Get("slug"), ch+".org.slug", reAttSlug)
		m.chaine(o.Get("name"), ch+".org.name", 1, 256, false)
	}
	for i, j := range m.tableau(p.Get("journals"), ch+".journals", 1, 64) {
		c := fmt.Sprintf("%s.journals[%d]", ch, i)
		if m.clesExactes(j, c, []string{"journal_id", "name"}) {
			m.hex(j.Get("journal_id"), c+".journal_id", 32, false)
			m.chaine(j.Get("name"), c+".name", 1, 128, false)
		}
	}
	if v := p.Get("validity"); m.clesExactes(v, ch+".validity", []string{"from", "until"}) {
		m.horodatage(v.Get("from"), ch+".validity.from")
		m.horodatage(v.Get("until"), ch+".validity.until")
	}
	m.horodatage(p.Get("issued_at"), ch+".issued_at")
	if pb := p.Get("prepared_by"); m.clesExactes(pb, ch+".prepared_by", []string{"identity", "function"}) {
		m.chaine(pb.Get("identity"), ch+".prepared_by.identity", 1, 256, false)
		m.chaine(pb.Get("function"), ch+".prepared_by.function", 1, 256, false)
	}
	for i, a := range m.tableau(p.Get("agents"), ch+".agents", 1, 4096) {
		c := fmt.Sprintf("%s.agents[%d]", ch, i)
		if !m.clesExactes(a, c, []string{"agent_id", "journal_id", "host", "framework", "capture_channels", "notes"}) {
			continue
		}
		m.motif(a.Get("agent_id"), c+".agent_id", reAttAgent)
		m.hex(a.Get("journal_id"), c+".journal_id", 32, false)
		m.chaine(a.Get("host"), c+".host", 1, 256, false)
		m.chaine(a.Get("framework"), c+".framework", 1, 128, false)
		canaux := m.tableau(a.Get("capture_channels"), c+".capture_channels", 1, 6)
		for k, x := range canaux {
			m.enumeration(x, fmt.Sprintf("%s.capture_channels[%d]", c, k), enumCanaux)
		}
		m.uniques(canaux, c+".capture_channels")
		m.chaine(a.Get("notes"), c+".notes", 1, 1024, true)
	}
	for i, t := range m.tableau(p.Get("tools_via_proxy_only"), ch+".tools_via_proxy_only", 0, 1024) {
		c := fmt.Sprintf("%s.tools_via_proxy_only[%d]", ch, i)
		if !m.clesExactes(t, c, []string{"server_alias", "tools", "enforcement"}) {
			continue
		}
		m.motif(t.Get("server_alias"), c+".server_alias", reAttAlias)
		outils := m.tableau(t.Get("tools"), c+".tools", 1, 1024)
		for k, x := range outils {
			m.motif(x, fmt.Sprintf("%s.tools[%d]", c, k), reAttOutil)
		}
		m.uniques(outils, c+".tools")
		m.chaine(t.Get("enforcement"), c+".enforcement", 1, 1024, false)
	}
	if e := p.Get("egress"); m.clesExactes(e, ch+".egress", []string{"default_policy", "rules_sha256", "rules_format", "summary", "allowed_destinations"}) {
		m.enumeration(e.Get("default_policy"), ch+".egress.default_policy", []string{"refus_par_defaut", "autorisation_par_defaut"})
		m.hex(e.Get("rules_sha256"), ch+".egress.rules_sha256", 32, false)
		m.chaine(e.Get("rules_format"), ch+".egress.rules_format", 1, 128, false)
		m.chaine(e.Get("summary"), ch+".egress.summary", 1, 4096, false)
		for i, d := range m.tableau(e.Get("allowed_destinations"), ch+".egress.allowed_destinations", 0, 1024) {
			c := fmt.Sprintf("%s.egress.allowed_destinations[%d]", ch, i)
			if m.clesExactes(d, c, []string{"name", "via", "description"}) {
				m.chaine(d.Get("name"), c+".name", 1, 256, false)
				m.enumeration(d.Get("via"), c+".via", []string{"enregistreur", "mandataire_sortant", "direct"})
				m.chaine(d.Get("description"), c+".description", 1, 1024, false)
			}
		}
	}
	for i, g := range m.tableau(p.Get("gateway_credentials"), ch+".gateway_credentials", 0, 1024) {
		c := fmt.Sprintf("%s.gateway_credentials[%d]", ch, i)
		if !m.clesExactes(g, c, []string{"route", "provider_label", "secret_ref"}) {
			continue
		}
		m.motif(g.Get("route"), c+".route", reAttRoute)
		m.motif(g.Get("provider_label"), c+".provider_label", reAttEtiquette)
		m.referenceSecret(g.Get("secret_ref"), c+".secret_ref")
	}
	for i, n := range m.tableau(p.Get("not_captured"), ch+".not_captured", 0, 1024) {
		c := fmt.Sprintf("%s.not_captured[%d]", ch, i)
		if m.clesExactes(n, c, []string{"channel", "description", "compensating_control"}) {
			m.chaine(n.Get("channel"), c+".channel", 1, 256, false)
			m.chaine(n.Get("description"), c+".description", 1, 4096, false)
			m.chaine(n.Get("compensating_control"), c+".compensating_control", 1, 1024, true)
		}
	}
	for i, s := range m.tableau(p.Get("signatories"), ch+".signatories", 1, 64) {
		c := fmt.Sprintf("%s.signatories[%d]", ch, i)
		if m.clesExactes(s, c, []string{"name", "function", "address"}) {
			m.chaine(s.Get("name"), c+".name", 1, 256, false)
			m.chaine(s.Get("function"), c+".function", 1, 256, false)
			m.hex(s.Get("address"), c+".address", 20, false)
		}
	}
	m.chaine(p.Get("declaration"), ch+".declaration", 1, 4096, false)
}

// referenceSecret transcrit $defs/reference_secret : exactement une des
// formes { env }, { file }, { vault: { path, field } } (CT-2 §15.2).
func (m *manquements) referenceSecret(v *Value, ch string) {
	if v == nil || v.Kind != KindObject || len(v.Obj) != 1 {
		m.add(ch, "objet à un seul membre env, file ou vault attendu")
		return
	}
	switch k := v.Obj[0].Key; k {
	case "env":
		m.motif(v.Get("env"), ch+".env", reAttEnv)
	case "file":
		f := v.Get("file")
		if f == nil || f.Kind != KindString || !strings.HasPrefix(f.Str, "/") || strings.ContainsRune(f.Str, 0) {
			m.add(ch+".file", "chemin absolu sans caractère nul attendu")
		} else if l := longueurChaine(f.Str) - 1; l < 1 || l > 4095 {
			m.add(ch+".file", "chemin de %d caractères après « / », 1 à 4095 attendus", l)
		}
	case "vault":
		if va := v.Get("vault"); m.clesExactes(va, ch+".vault", []string{"path", "field"}) {
			m.chaine(va.Get("path"), ch+".vault.path", 1, 512, false)
			m.chaine(va.Get("field"), ch+".vault.field", 1, 128, false)
		}
	default:
		m.add(ch+"."+k, "forme de référence de secret inconnue")
	}
}

// validerPartieAttestation transcrit #/$defs/attestation_perimetre du
// schéma de dossier et les définitions qu'il emprunte au schéma de
// l'attestation (attestation_signee, jeu_approbateurs) ; l'événement
// d'inscription est validé contre evenement-v0 (E-1).
func validerPartieAttestation(v *Value) []string {
	m := &manquements{}
	if !m.clesExactes(v, "attestation_perimetre", []string{"version", "signed", "approver_set", "inscription"}) {
		return m.liste
	}
	m.constanteZero(v.Get("version"), "attestation_perimetre.version")
	if s := v.Get("signed"); m.clesExactes(s, "signed", []string{"version", "attestation", "digest", "signatures"}) {
		m.constanteZero(s.Get("version"), "signed.version")
		validerAttestationP(s.Get("attestation"), "signed.attestation", m)
		m.hex(s.Get("digest"), "signed.digest", 32, false)
		for i, x := range m.tableau(s.Get("signatures"), "signed.signatures", 1, 64) {
			c := fmt.Sprintf("signed.signatures[%d]", i)
			if m.clesExactes(x, c, []string{"address", "signature"}) {
				m.hex(x.Get("address"), c+".address", 20, false)
				m.hex(x.Get("signature"), c+".signature", 65, false)
			}
		}
	}
	if j := v.Get("approver_set"); m.clesExactes(j, "approver_set", []string{"threshold", "members", "source"}) {
		if t := j.Get("threshold"); m.clesExactes(t, "approver_set.threshold", []string{"required", "size"}) {
			m.entier(t.Get("required"), "approver_set.threshold.required", 1, 65535)
			m.entier(t.Get("size"), "approver_set.threshold.size", 1, 65535)
		}
		membres := m.tableau(j.Get("members"), "approver_set.members", 1, 65535)
		for i, x := range membres {
			m.hex(x, fmt.Sprintf("approver_set.members[%d]", i), 20, false)
		}
		m.uniques(membres, "approver_set.members")
		m.chaine(j.Get("source"), "approver_set.source", 1, 256, false)
	}
	if ins := v.Get("inscription"); ins == nil {
		m.add("inscription", "obligatoire")
	} else if !ins.IsNull() && m.clesExactes(ins, "inscription", []string{"event", "policy_document"}) {
		for _, x := range ValiderSchemaEvenement(ins.Get("event")) {
			m.add("inscription.event", "%s", x)
		}
		if d, ok := m.chaine(ins.Get("policy_document"), "inscription.policy_document", 4, 2796204, false); ok && !estBase64(d) {
			m.add("inscription.policy_document", "base64 standard avec remplissage exact attendu (RFC 4648 §4)")
		}
	}
	return m.liste
}

// relationsAttestation applique les relations d'AT-1 que le schéma
// n'exprime pas (§11.4 ; CT-7 EX-7.2).
func relationsAttestation(p *Value) []string {
	var out []string
	de, okDe := ParseHorodatage(chaineDe(p, "validity", "from"))
	a, okA := ParseHorodatage(chaineDe(p, "validity", "until"))
	if okDe && okA && de.After(a) {
		out = append(out, "validity.from postérieur à validity.until")
	} else if okDe && okA && a.Sub(de) > 366*24*time.Hour {
		out = append(out, "validity : plus de 366 jours entre from et until")
	}
	journaux := map[string]bool{}
	for _, j := range p.Get("journals").Arr {
		id := chaineDe(j, "journal_id")
		if journaux[id] {
			out = append(out, "journal_id "+id+" en double dans journals")
		}
		journaux[id] = true
	}
	agents := map[string]bool{}
	for _, ag := range p.Get("agents").Arr {
		id := chaineDe(ag, "agent_id")
		if agents[id] {
			out = append(out, "agent_id "+id+" en double")
		}
		agents[id] = true
		if !journaux[chaineDe(ag, "journal_id")] {
			out = append(out, "agent "+id+" : journal_id absent de journals")
		}
	}
	adresses := map[string]bool{}
	for _, s := range p.Get("signatories").Arr {
		ad := chaineDe(s, "address")
		if adresses[ad] {
			out = append(out, "adresse "+ad+" en double dans signatories")
		}
		adresses[ad] = true
	}
	return out
}

// MessageEIP191 rend M = keccak256("\x19Ethereum Signed Message:\n32" ‖ d)
// (section 6.3).
func MessageEIP191(d []byte) []byte {
	return Keccak256(append([]byte("\x19Ethereum Signed Message:\n32"), d...))
}

// recouvrerSignatureEIP191 applique la forme de §6.3 (65 octets, s dans la
// moitié basse, v de 27 ou 28) puis recouvre l'adresse sur M.
func recouvrerSignatureEIP191(m []byte, hexsig string) (string, error) {
	b, err := OctetsHex(hexsig, 65)
	if err != nil {
		return "", err
	}
	r, s, v := new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:64]), int(b[64])
	switch {
	case v != 27 && v != 28:
		return "", fmt.Errorf("v = %d hors de {27, 28}", v)
	case s.Cmp(secpDemiN) > 0:
		return "", fmt.Errorf("s dans la moitié haute de l'ordre")
	}
	pub, err := Recouvrer(m, r, s, v-27)
	if err != nil {
		return "", err
	}
	return Hex0x(AdresseDeCle(pub)), nil
}

// controlerAttestation exécute AT-1 à AT-7 (révision 0.4) quand la
// quatorzième partie est déclarée présente.
func (d *Dossier) controlerAttestation() {
	pa := d.Parties["attestation_perimetre"]
	if pa == nil || !pa.Present {
		return
	}
	at := nouvellesAT()
	d.Perimetre = at.liste
	prerequis := func(ids ...string) {
		for _, id := range ids {
			at.nonExecute(id, RaisonPrerequis)
		}
	}

	// AT-1 : forme.
	octets, err := os.ReadFile(filepath.Join(d.Dir, pa.File))
	var v *Value
	switch {
	case err != nil:
		at.echec("AT-1", "%s illisible : %v", pa.File, err)
	case len(octets) > TailleMaxPartieAttestation:
		at.echec("AT-1", "%s : %d octets, au plus 4 Mio", pa.File, len(octets))
	default:
		v, err = ParseJSON(octets)
		if err != nil {
			at.echec("AT-1", "%s : %v", pa.File, err)
		} else if v.Kind != KindObject {
			at.echec("AT-1", "%s : objet JSON attendu, reçu %s", pa.File, v.Kind)
		}
	}
	var p, signee, jeu, ins *Value
	var dp, doc []byte
	if at.reussie("AT-1") {
		for _, x := range validerPartieAttestation(v) {
			at.echec("AT-1", "%s", x)
		}
	}
	if at.reussie("AT-1") {
		signee, jeu, ins = v.Get("signed"), v.Get("approver_set"), v.Get("inscription")
		p = signee.Get("attestation")
		for _, x := range relationsAttestation(p) {
			at.echec("AT-1", "%s", x)
		}
		if c, err := Canonique(p); err != nil {
			at.echec("AT-1", "JCS(signed.attestation) non calculable : %v", err)
		} else {
			dp = Keccak256(append([]byte(PrefixeAttestation), c...))
		}
		if !ins.IsNull() {
			s := chaineDe(ins, "policy_document")
			b, err := base64.StdEncoding.Strict().DecodeString(s)
			switch {
			case err != nil || base64.StdEncoding.EncodeToString(b) != s:
				at.echec("AT-1", "inscription.policy_document : base64 non canonique")
			case len(b) > TailleMaxDocumentPolitique:
				at.echec("AT-1", "inscription.policy_document : %d octets décodés, au plus 2 097 152", len(b))
			default:
				doc = b
			}
		}
	}
	if !at.reussie("AT-1") {
		prerequis("AT-2", "AT-3", "AT-4", "AT-5", "AT-6", "AT-7")
		return
	}

	// AT-2 : condensé déclaré.
	if got := Hex0x(dp); chaineDe(signee, "digest") != got {
		at.echec("AT-2", "signed.digest %s ≠ D_P recalculé %s", chaineDe(signee, "digest"), got)
	}

	// AT-3 : chaque signature, forme et adresse recouvrée sur M.
	m := MessageEIP191(dp)
	for i, s := range signee.Get("signatures").Arr {
		rec, err := recouvrerSignatureEIP191(m, chaineDe(s, "signature"))
		if err != nil {
			at.echec("AT-3", "signatures[%d] : %v", i, err)
		} else if rec != chaineDe(s, "address") {
			at.echec("AT-3", "signatures[%d] : adresse recouvrée %s ≠ %s", i, rec, chaineDe(s, "address"))
		}
	}

	// AT-4 : adresses distinctes, nommées, membres du jeu, au seuil.
	if !at.reussie("AT-3") {
		prerequis("AT-4")
	} else {
		nommes, membres, vus := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, s := range p.Get("signatories").Arr {
			nommes[chaineDe(s, "address")] = true
		}
		for _, x := range jeu.Get("members").Arr {
			membres[x.Str] = true
		}
		for i, s := range signee.Get("signatures").Arr {
			a := chaineDe(s, "address")
			if vus[a] {
				at.echec("AT-4", "signatures[%d] : adresse %s en double", i, a)
			}
			vus[a] = true
			if !nommes[a] {
				at.echec("AT-4", "signatures[%d] : %s absente de signatories", i, a)
			}
			if !membres[a] {
				at.echec("AT-4", "signatures[%d] : %s absente de approver_set.members", i, a)
			}
		}
		requis, _ := entierDe(jeu, "threshold", "required")
		taille, _ := entierDe(jeu, "threshold", "size")
		if int64(len(vus)) < requis {
			at.echec("AT-4", "%d adresse(s) distincte(s) pour un seuil de %d", len(vus), requis)
		}
		if requis > taille {
			at.echec("AT-4", "required %d > size %d", requis, taille)
		}
		if taille != int64(len(jeu.Get("members").Arr)) {
			at.echec("AT-4", "size %d ≠ nombre de membres %d", taille, len(jeu.Get("members").Arr))
		}
	}

	// AT-5 : liaison à l'événement prouvé.
	ev := d.Evenement
	_, errCan := Canonique(ev)
	evExploitable := len(ValiderSchemaEvenement(ev)) == 0 && errCan == nil
	if !evExploitable {
		prerequis("AT-5")
	} else {
		if a, b := chaineDe(p, "org", "org_id"), chaineDe(ev, "org_id"); a != b {
			at.echec("AT-5", "org.org_id %s ≠ org_id de l'événement %s", a, b)
		}
		couvert := false
		for _, j := range p.Get("journals").Arr {
			couvert = couvert || chaineDe(j, "journal_id") == chaineDe(ev, "journal_id")
		}
		if !couvert {
			at.echec("AT-5", "journal_id de l'événement absent de journals")
		}
		de, _ := ParseHorodatage(chaineDe(p, "validity", "from"))
		a, _ := ParseHorodatage(chaineDe(p, "validity", "until"))
		if ts, ok := Ts(ev); ok && (ts.Before(de) || ts.After(a)) {
			at.echec("AT-5", "ts %s hors de validity [%s, %s]", FormaterHorodatage(ts), FormaterHorodatage(de), FormaterHorodatage(a))
		}
	}

	// AT-6 : inscription au journal.
	switch {
	case ins.IsNull():
		at.nonExecute("AT-6", RaisonAbsente)
		at.nonExecute("AT-7", RaisonAbsente)
		return
	case !at.reussie("AT-2") || !evExploitable || d.Cles == nil || !d.clesExploitable:
		prerequis("AT-6", "AT-7")
		return
	}
	insEv := ins.Get("event")
	res := ControlerEvenement(insEv, d.Cles)
	for _, c := range res.Liste() {
		if dansEnum(c.ID, []string{"E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-11"}) && c.Etat != EtatPasse {
			at.echec("AT-6", "événement d'inscription : %s %s (%s)", c.ID, c.Etat, strings.Join(c.Details, " ; "))
		}
	}
	if Outil(insEv) != OutilPolitique {
		at.echec("AT-6", "execution.tool %q, attendu %s", Outil(insEv), OutilPolitique)
	}
	for _, k := range []string{"org_id", "journal_id"} {
		if chaineDe(insEv, k) != chaineDe(ev, k) {
			at.echec("AT-6", "%s de l'inscription ≠ celui de l'événement prouvé", k)
		}
	}
	if got, att := Hex0x(SHA256(doc)), chaineDe(insEv, "execution", "arguments", "value", "policy_sha256"); got != att {
		at.echec("AT-6", "SHA-256 du document %s ≠ policy_sha256 %s", got, att)
	}
	if dv, err := ParseJSON(doc); err != nil || dv.Kind != KindObject {
		at.echec("AT-6", "document de politique : objet JSON UTF-8 sans nom en double attendu (%v)", err)
	} else if per := dv.Get("perimeter"); per == nil || per.Kind != KindObject {
		at.echec("AT-6", "document de politique sans objet perimeter")
	} else if ad := per.Get("attestation_digest"); ad == nil || ad.Kind != KindString || ad.Str != Hex0x(dp) {
		at.echec("AT-6", "perimeter.attestation_digest ≠ D_P recalculé %s", Hex0x(dp))
	}
	if Seq(insEv) > Seq(ev) {
		at.echec("AT-6", "seq de l'inscription %d > seq de l'événement prouvé %d", Seq(insEv), Seq(ev))
	} else if Seq(insEv) == Seq(ev) {
		h1, _, e1 := HashEvenement(insEv)
		h2, _, e2 := HashEvenement(ev)
		if e1 != nil || e2 != nil || Hex0x(h1) != Hex0x(h2) {
			at.echec("AT-6", "même seq que l'événement prouvé mais autre hash recalculé")
		}
	}
	tsI, okI := Ts(insEv)
	tsE, okE := Ts(ev)
	if okI && okE && tsI.After(tsE) {
		at.echec("AT-6", "ts de l'inscription %s postérieur à celui de l'événement prouvé %s", FormaterHorodatage(tsI), FormaterHorodatage(tsE))
	}

	// AT-6 : la clé de l'inscription doit être celle de l'événement prouvé (révision 0.4) ;
	// sinon rien ne la relie au journal : non exécutée, ancre_absente, et AT-7 non exécutée (prérequis).
	if at.reussie("AT-6") && chaineDe(insEv, "recorder_key_id") != chaineDe(ev, "recorder_key_id") {
		at.nonExecute("AT-6", RaisonAncreAbsente)
		prerequis("AT-7")
		return
	}

	// AT-7 : version de politique de l'événement prouvé.
	if !at.reussie("AT-6") {
		prerequis("AT-7")
		return
	}
	if a, b := chaineDe(ev, "code", "policy_version"), chaineDe(insEv, "execution", "arguments", "value", "policy_version"); a != b {
		s := at.get("AT-7")
		s.Statut, s.Raison = ATNonExecute, RaisonHorsDossier
		s.Details = append(s.Details, fmt.Sprintf("version de politique de l'événement (%s) différente de celle de l'inscription (%s) : l'ensemble en vigueur n'est pas dans le dossier", a, b))
	}
}

// PerimetreTexte rend les statuts « AT-n statut raison » dans l'ordre.
func (d *Dossier) PerimetreTexte() []string {
	var out []string
	for _, s := range d.Perimetre {
		r := s.Raison
		if r == "" {
			r = "null"
		}
		out = append(out, s.ID+" "+s.Statut+" "+r)
	}
	return out
}
