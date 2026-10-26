// Famille worm (annexe B.9, révision 0.5) : requêtes exactes (EX-12.39),
// contrôle du verrou d'une version (EX-12.33), périmètre d'un gel
// (EX-12.35) et règle de garde de la levée (EX-12.37, EX-12.38),
// recalculés depuis le seul texte de 12.6 et 12.11.

package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FamilleWorm est le nom de la famille dans le rapport.
const FamilleWorm = "worm"

// Constantes de 12.11 et de B.9.
const (
	EspaceNomsS3       = "http://s3.amazonaws.com/doc/2006-03-01/"
	DeclarationXML     = `<?xml version="1.0" encoding="UTF-8"?>`
	VersionAzure       = "2020-06-12"
	PrefixeWormDemo    = "journal-demo/"
	BucketWormDemo     = "noortrace-demo-worm"
	CopieExempleISO    = "2026-11-10T11:00:05.412Z" // copied_at de l'exemple d'EX-12.29
	JoursRetentionReco = 4018                       // EX-12.30
	DelaiDemandeMs     = 604800000                  // EX-12.38 : sept jours
	ToleranceEcheanceS = 3600                       // EX-12.33 : une heure
)

// ---------------------------------------------------------------- EX-12.39

// EncoderComposant encode octet par octet (EX-12.39) : tout octet UTF-8 hors
// des non réservés de la RFC 3986 devient %XX majuscules ; « / » est gardé si
// garderBarre.
func EncoderComposant(s string, garderBarre bool) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			sb.WriteByte(c)
		case c == '/' && garderBarre:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// RequeteWorm est une requête exacte, sans hôte, date ni signature.
type RequeteWorm struct {
	Methode, Cible string
	EnTetes        [][2]string
	Corps          []byte // nil : aucun corps
}

// ContentMD5 : base64 des 16 octets du MD5 du corps (RFC 1864).
func ContentMD5(b []byte) string {
	s := md5.Sum(b)
	return base64.StdEncoding.EncodeToString(s[:])
}

// CorpsGelS3 : corps XML de PutObjectLegalHold (table d'EX-12.39).
func CorpsGelS3(on bool) []byte {
	st := "OFF"
	if on {
		st = "ON"
	}
	return []byte(DeclarationXML + `<LegalHold xmlns="` + EspaceNomsS3 + `"><Status>` + st + `</Status></LegalHold>`)
}

// CorpsConfigurationVerrou : corps de PutObjectLockConfiguration (EX-12.30,
// EX-12.39), mode COMPLIANCE, Days = retain_days.
func CorpsConfigurationVerrou(jours int64) []byte {
	return []byte(DeclarationXML + `<ObjectLockConfiguration xmlns="` + EspaceNomsS3 + `"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>` +
		strconv.FormatInt(jours, 10) + `</Days><Mode>COMPLIANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>`)
}

func trierEnTetes(h [][2]string) [][2]string {
	sort.SliceStable(h, func(i, j int) bool { return strings.ToLower(h[i][0]) < strings.ToLower(h[j][0]) })
	return h
}

// avecCorpsMD5 : Content-Length et Content-MD5 d'un corps.
func avecCorpsMD5(corps []byte, autres ...[2]string) [][2]string {
	h := [][2]string{{"Content-Length", strconv.Itoa(len(corps))}, {"Content-MD5", ContentMD5(corps)}}
	return trierEnTetes(append(h, autres...))
}

// ConstruireRequeteWorm applique la table d'EX-12.39 à une opération.
func ConstruireRequeteWorm(in *Value) (*RequeteWorm, error) {
	op := chaineDe(in, "operation")
	cle, version, bucket := chaineDe(in, "key"), chaineDe(in, "version_id"), chaineDe(in, "bucket")
	gel := in.Get("hold")
	on := gel != nil && gel.Kind == KindBool && gel.Bool
	cheminS3 := "/" + EncoderComposant(cle, true)
	switch op {
	case "s3_gel":
		corps := CorpsGelS3(on)
		return &RequeteWorm{"PUT", cheminS3 + "?legal-hold&versionId=" + EncoderComposant(version, false), avecCorpsMD5(corps), corps}, nil
	case "s3_lire_gel":
		return &RequeteWorm{"GET", cheminS3 + "?legal-hold&versionId=" + EncoderComposant(version, false), nil, nil}, nil
	case "s3_etat":
		return &RequeteWorm{"HEAD", cheminS3 + "?versionId=" + EncoderComposant(version, false), nil, nil}, nil
	case "s3_liste":
		c := "/?versions"
		if km := chaineDe(in, "key_marker"); km != "" {
			c += "&key-marker=" + EncoderComposant(km, false)
		}
		c += "&max-keys=1000&prefix=" + EncoderComposant(chaineDe(in, "prefix"), false)
		if vm := chaineDe(in, "version_id_marker"); vm != "" {
			c += "&version-id-marker=" + EncoderComposant(vm, false)
		}
		return &RequeteWorm{"GET", c, nil, nil}, nil
	case "s3_configuration_verrou":
		j, ok := EntierDe(in.Get("retain_days"))
		if !ok {
			return nil, fmt.Errorf("retain_days absent")
		}
		corps := CorpsConfigurationVerrou(j)
		return &RequeteWorm{"PUT", "/?object-lock", avecCorpsMD5(corps), corps}, nil
	case "s3_lire_configuration":
		return &RequeteWorm{"GET", "/?object-lock", nil, nil}, nil
	case "s3_copie":
		b := in.Get("body_utf8")
		if !EstChaine(b) {
			return nil, fmt.Errorf("body_utf8 absent")
		}
		corps := []byte(b.Str)
		autres := [][2]string{{"If-None-Match", "*"}}
		if l := in.Get("legal_hold_on_write"); l != nil && l.Kind == KindBool && l.Bool {
			autres = append(autres, [2]string{"x-amz-object-lock-legal-hold", "ON"})
		}
		return &RequeteWorm{"PUT", cheminS3, avecCorpsMD5(corps, autres...), corps}, nil
	case "azure_gel":
		v := "false"
		if on {
			v = "true"
		}
		return &RequeteWorm{"PUT", "/" + EncoderComposant(bucket, false) + "/" + EncoderComposant(cle, true) + "?comp=legalhold&versionid=" + EncoderComposant(version, false),
			trierEnTetes([][2]string{{"Content-Length", "0"}, {"x-ms-legal-hold", v}, {"x-ms-version", VersionAzure}}), nil}, nil
	case "azure_etat":
		return &RequeteWorm{"HEAD", "/" + EncoderComposant(bucket, false) + "/" + EncoderComposant(cle, true) + "?versionid=" + EncoderComposant(version, false),
			[][2]string{{"x-ms-version", VersionAzure}}, nil}, nil
	case "gcs_gel", "gcs_etat":
		cible := "/storage/v1/b/" + EncoderComposant(bucket, false) + "/o/" + EncoderComposant(cle, false) + "?generation=" + EncoderComposant(version, false)
		if op == "gcs_etat" {
			return &RequeteWorm{"GET", cible, nil, nil}, nil
		}
		corps, _ := CanoniqueIntegral(Objet("temporaryHold", Booleen(on)))
		return &RequeteWorm{"PATCH", cible, trierEnTetes([][2]string{{"Content-Length", strconv.Itoa(len(corps))}, {"Content-Type", "application/json"}}), corps}, nil
	}
	return nil, fmt.Errorf("opération inconnue %q", op)
}

// ValeurRequete rend la requête sous la forme $defs/requete de worm-v0.
func (r *RequeteWorm) ValeurRequete() *Value {
	h := TableauVide()
	for _, e := range r.EnTetes {
		h.Arr = append(h.Arr, &Value{Kind: KindArray, Arr: []*Value{Chaine(e[0]), Chaine(e[1])}})
	}
	corps, sha := Nul(), Nul()
	if r.Corps != nil {
		corps = Chaine(string(r.Corps))
		sha = Chaine(Hex0x(SHA256(r.Corps)))
	}
	return Objet("method", Chaine(r.Methode), "target", Chaine(r.Cible), "headers", h, "body_utf8", corps,
		"body_length", Entier(int64(len(r.Corps))), "body_sha256", sha)
}

// ---------------------------------------------------------------- EX-12.33

var (
	reRFC3339 = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$`)
	reIMF     = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$`)
)

// LireEcheance lit une échéance RFC 3339 (avec ou sans fraction, Z ou
// décalage) ou IMF-fixdate et la ramène à la forme de CT-1 §3 (fraction
// au-delà de la milliseconde tronquée) ; faux si illisible.
func LireEcheance(s string) (time.Time, bool) {
	if m := reRFC3339.FindStringSubmatch(s); m != nil {
		frac := strings.TrimPrefix(m[7], ".")
		frac = (frac + "000")[:3]
		base := m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "." + frac + m[8]
		t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", base)
		if err != nil {
			return time.Time{}, false
		}
		// time.Parse admet des valeurs que la date réécrite ne redonne pas (31 février) : contrôle
		if t.Format("2006-01-02T15:04:05.000Z07:00") != base {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	if reIMF.MatchString(s) {
		t, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", s)
		if err != nil || t.Format("Mon, 02 Jan 2006 15:04:05 GMT") != s {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}

// EtatVerrou est le résultat d'EX-12.33.
type EtatVerrou struct {
	Mode          *Value
	Echeance      *Value
	Gel           string
	Raisons, Note []string
}

// ControlerVerrou applique EX-12.33 (mode attendu compliance).
func ControlerVerrou(typ string, h, j *Value, echeanceMin time.Time, gelAttendu bool) (*EtatVerrou, error) {
	e := &EtatVerrou{Mode: Nul(), Echeance: Nul(), Raisons: []string{}, Note: []string{}}
	var mode, echeance, gel *Value
	var attenduMode string
	switch typ {
	case "s3-object-lock":
		mode, echeance, gel = h.Get("x-amz-object-lock-mode"), h.Get("x-amz-object-lock-retain-until-date"), h.Get("x-amz-object-lock-legal-hold")
		attenduMode = "COMPLIANCE"
	case "azure-immutable-blob":
		mode, echeance, gel = h.Get("x-ms-immutability-policy-mode"), h.Get("x-ms-immutability-policy-until-date"), h.Get("x-ms-legal-hold")
		attenduMode = "locked"
	case "gcs-object-retention":
		mode, echeance, gel = j.Get("retention").Get("mode"), j.Get("retention").Get("retainUntilTime"), j.Get("temporaryHold")
		attenduMode = "Locked"
	default:
		return nil, fmt.Errorf("type de support inconnu %q", typ)
	}
	// 1. mode
	switch {
	case mode == nil:
		e.Raisons = append(e.Raisons, "mode_absent")
	default:
		e.Mode = Copier(mode)
		if !EstChaine(mode) || mode.Str != attenduMode {
			e.Raisons = append(e.Raisons, "mode_non_conforme")
		}
	}
	// 2. échéance
	switch {
	case echeance == nil:
		e.Raisons = append(e.Raisons, "echeance_absente")
	default:
		t, ok := time.Time{}, false
		if EstChaine(echeance) {
			t, ok = LireEcheance(echeance.Str)
		}
		if !ok {
			e.Raisons = append(e.Raisons, "date_illisible")
		} else {
			e.Echeance = Chaine(FormaterHorodatage(t))
			if t.Before(echeanceMin) {
				e.Raisons = append(e.Raisons, "echeance_courte")
			}
		}
	}
	// 3. gel
	switch {
	case gel == nil:
		e.Gel = "jamais"
		e.Note = append(e.Note, "jamais_gele")
	case typ == "s3-object-lock" && EstChaine(gel) && gel.Str == "ON",
		typ == "azure-immutable-blob" && EstChaine(gel) && gel.Str == "true",
		typ == "gcs-object-retention" && gel.Kind == KindBool && gel.Bool:
		e.Gel = "on"
	case typ == "s3-object-lock" && EstChaine(gel) && gel.Str == "OFF",
		typ == "azure-immutable-blob" && EstChaine(gel) && gel.Str == "false",
		typ == "gcs-object-retention" && gel.Kind == KindBool && !gel.Bool:
		e.Gel = "off"
	default:
		// valeur hors de la table : jamais lue comme off (EX-12.33)
		e.Gel = "illisible"
	}
	if e.Gel == "illisible" {
		e.Raisons = append(e.Raisons, "gel_illisible")
	} else if gelAttendu && e.Gel != "on" {
		e.Raisons = append(e.Raisons, "gel_absent")
	}
	if !gelAttendu && e.Gel == "on" {
		e.Note = append(e.Note, "gel_inattendu")
	}
	return e, nil
}

func tableauChaines(s []string) *Value {
	t := TableauVide()
	for _, x := range s {
		t.Arr = append(t.Arr, Chaine(x))
	}
	return t
}

// ---------------------------------------------------------------- EX-12.35

// VersionListee est un élément de la liste des versions.
type VersionListee struct {
	Cle, Version       string
	Courante, Marqueur bool
}

// Anomalie de périmètre.
type Anomalie struct{ Cle, Sorte string }

// PerimetreGel applique EX-12.35, pas 2 à 6, à une liste de versions déjà
// lue. manifestes : period_start → (first_seq, last_seq) lus dans la version
// du manifeste ; copiees : les pièces sont copiées ; pieces : empreintes
// référencées ; purgeables : les pièces locales peuvent être purgées. Un
// marqueur de suppression compte comme une version pour les pas 2 et 3.
func PerimetreGel(prefixe string, de, a int64, manifestes map[int64][2]int64, versions []VersionListee, copiees bool, pieces []string, purgeables bool) ([][2]string, []Anomalie) {
	nonMarqueurs := map[string][]string{}
	courantMarqueur := map[string]bool{}
	toutes := map[string]bool{}
	for _, v := range versions {
		toutes[v.Cle] = true
		if v.Marqueur {
			if v.Courante {
				courantMarqueur[v.Cle] = true
			}
			continue
		}
		nonMarqueurs[v.Cle] = append(nonMarqueurs[v.Cle], v.Version)
	}
	aDesVersions := func(k string) bool { return toutes[k] }
	retenues := map[string]bool{}
	var anomalies []Anomalie
	reSeg := regexp.MustCompile("^" + regexp.QuoteMeta(prefixe+"segments/seg-") + `([0-9]{16})-([0-9]{20})\.ndjson$`)
	for p := de; p <= a; p += 3600 {
		ps := fmt.Sprintf("%010d", p)
		cleManifeste := prefixe + "manifestes/periode-" + ps + ".json"
		bornes, lu := manifestes[p]
		manifestePresent := aDesVersions(cleManifeste) && lu
		switch {
		case !aDesVersions(cleManifeste):
			anomalies = append(anomalies, Anomalie{cleManifeste, "manifeste_absent"}, Anomalie{prefixe + "segments/", "segments_indetermines"})
		case !lu:
			// version présente mais non lue : gelée quand même (EX-12.35 pas 2)
			retenues[cleManifeste] = true
			anomalies = append(anomalies, Anomalie{cleManifeste, "manifeste_illisible"}, Anomalie{prefixe + "segments/", "segments_indetermines"})
		default:
			retenues[cleManifeste] = true
		}
		for _, k := range []string{prefixe + "manifestes/periode-" + ps + ".sig", prefixe + "points/periode-" + ps + ".ndjson"} {
			if aDesVersions(k) {
				retenues[k] = true
			} else {
				anomalies = append(anomalies, Anomalie{k, "objet_absent"})
			}
		}
		ancres := prefixe + "ancres/periode-" + ps + "/"
		for k := range toutes {
			if strings.HasPrefix(k, ancres) {
				retenues[k] = true
			}
		}
		if !manifestePresent {
			continue
		}
		first, last := bornes[0], bornes[1]
		premierVu := false
		for k := range toutes {
			m := reSeg.FindStringSubmatch(k)
			if m == nil {
				continue
			}
			f, _ := strconv.ParseInt(m[1], 10, 64)
			if f >= first && f <= last {
				retenues[k] = true
				if f == first {
					premierVu = true
				}
			}
		}
		if last >= first && !premierVu {
			anomalies = append(anomalies, Anomalie{fmt.Sprintf("%ssegments/seg-%016d-%020d.ndjson", prefixe, first, 0), "segment_absent"})
		}
	}
	// 4. pièces : copiées, chaque empreinte sans version est piece_absente ;
	// non copiées et purgeables : pieces_non_copiees
	if copiees {
		for _, h := range pieces {
			hx := strings.TrimPrefix(h, "0x")
			if len(hx) >= 2 {
				k := prefixe + "pieces/" + hx[:2] + "/" + hx
				if aDesVersions(k) {
					retenues[k] = true
				} else {
					anomalies = append(anomalies, Anomalie{k, "piece_absente"})
				}
			}
		}
	} else if purgeables {
		anomalies = append(anomalies, Anomalie{prefixe + "pieces/", "pieces_non_copiees"})
	}
	// 5. versions retenues, 6. liste triée par clé (octets UTF-8), puis ordre de la liste
	cles := make([]string, 0, len(retenues))
	for k := range retenues {
		cles = append(cles, k)
	}
	sort.Strings(cles) // comparaison d'octets
	var objets [][2]string
	for _, k := range cles {
		vs := nonMarqueurs[k]
		if len(vs) > 1 {
			anomalies = append(anomalies, Anomalie{k, "versions_multiples"})
		}
		if courantMarqueur[k] {
			anomalies = append(anomalies, Anomalie{k, "marqueur_de_suppression"})
		}
		for _, v := range vs {
			objets = append(objets, [2]string{k, v})
		}
	}
	return objets, anomalies
}

// OctetsListeObjets : chaque couple en JCS intégral suivi de \n (EX-12.35 pas 6).
func OctetsListeObjets(objets [][2]string) []byte {
	var b []byte
	for _, o := range objets {
		l, _ := CanoniqueIntegral(Objet("key", Chaine(o[0]), "version_id", Chaine(o[1])))
		b = append(b, l...)
		b = append(b, '\n')
	}
	return b
}

// ---------------------------------------------------------------- EX-12.38

// CodesGarde : codes de la table d'EX-12.38, dans l'ordre de la table.
var CodesGarde = []string{"chaine_rompue", "premier_non_pose", "ordre_invalide", "meme_identite", "demande_inconnue",
	"demande_expiree", "levee_en_double", "objets_differents", "periode_differente"}

var successionsAdmises = map[string][]string{
	"pose":           {"pose_resultat"},
	"pose_resultat":  {"pose_resultat", "demande_levee"},
	"demande_levee":  {"demande_levee", "levee"},
	"levee":          {"levee_resultat"},
	"levee_resultat": {"levee_resultat"},
}

// ErreurGarde est une règle violée par l'enregistrement de rang N.
type ErreurGarde struct {
	N    int
	Code string
}

// RegleDeGarde applique EX-12.38 à une suite d'enregistrements ; rend les
// empreintes (SHA-256 du JCS intégral) et les erreurs, une par enregistrement
// et par règle, dans l'ordre des rangs puis de la table.
func RegleDeGarde(recs []*Value) ([]string, []ErreurGarde) {
	emp := make([]string, len(recs))
	for i, r := range recs {
		b, err := CanoniqueIntegral(r)
		if err != nil {
			emp[i] = "! " + err.Error()
			continue
		}
		emp[i] = Hex0x(SHA256(b))
	}
	var errs []ErreurGarde
	if len(recs) == 0 {
		// suite vide : aucune pose (EX-12.38)
		return emp, []ErreurGarde{{N: 1, Code: "premier_non_pose"}}
	}
	premier := recs[0]
	meme := func(a, b *Value) bool { return MemeValeur(a, b) }
	approuvees := map[string]int{}
	for i, r := range recs {
		rang := i + 1
		viol := map[string]bool{}
		// chaine_rompue
		n, okn := EntierDe(r.Get("n"))
		prev := r.Get("prev_sha256")
		switch {
		case !okn || n != int64(rang):
			viol["chaine_rompue"] = true
		case rang == 1 && (prev == nil || !prev.IsNull()):
			viol["chaine_rompue"] = true
		case rang > 1 && (!EstChaine(prev) || prev.Str != emp[i-1]):
			viol["chaine_rompue"] = true
		}
		for _, k := range []string{"gel_id", "org_id", "journal_id", "support"} {
			if !meme(r.Get(k), premier.Get(k)) {
				viol["chaine_rompue"] = true
			}
		}
		kind := chaineDe(r, "kind")
		if rang == 1 && kind != "pose" {
			viol["premier_non_pose"] = true
		}
		if rang > 1 {
			pk := chaineDe(recs[i-1], "kind")
			if !dansEnum(kind, successionsAdmises[pk]) {
				viol["ordre_invalide"] = true
			}
			ta, oka := ParseHorodatage(chaineDe(r, "at"))
			tp, okp := ParseHorodatage(chaineDe(recs[i-1], "at"))
			if !oka || !okp || ta.Before(tp) {
				viol["ordre_invalide"] = true
			}
		}
		if kind == "levee" {
			req := chaineDe(r, "request_sha256")
			// dernière demande_levee qui précède la levée
			derniere := -1
			for j := 0; j < i; j++ {
				if chaineDe(recs[j], "kind") == "demande_levee" {
					derniere = j
				}
			}
			if derniere < 0 || req != emp[derniere] {
				viol["demande_inconnue"] = true
			}
			// demande approuvée : celle dont l'empreinte est request_sha256
			approuvee := -1
			for j := 0; j < i; j++ {
				if chaineDe(recs[j], "kind") == "demande_levee" && emp[j] == req {
					approuvee = j
				}
			}
			if approuvee >= 0 {
				if chaineDe(r, "actor") == chaineDe(recs[approuvee], "actor") {
					viol["meme_identite"] = true
				}
				tl, ok1 := ParseHorodatage(chaineDe(r, "at"))
				td, ok2 := ParseHorodatage(chaineDe(recs[approuvee], "at"))
				if d := tl.Sub(td).Milliseconds(); !ok1 || !ok2 || d < 0 || d > DelaiDemandeMs {
					viol["demande_expiree"] = true
				}
				if approuvees[req] > 0 {
					viol["levee_en_double"] = true
				}
				approuvees[req]++
			}
		}
		if !meme(r.Get("objects"), premier.Get("objects")) {
			viol["objets_differents"] = true
		}
		if !meme(r.Get("periods"), premier.Get("periods")) {
			viol["periode_differente"] = true
		}
		for _, c := range CodesGarde {
			if viol[c] {
				errs = append(errs, ErreurGarde{rang, c})
			}
		}
	}
	return emp, errs
}

// ---------------------------------------------------------------- famille

// EmpreintesImprimees1211 recopie les empreintes des enregistrements de
// l'exemple d'EX-12.37 (0001-pose à 0005-levee_resultat).
var EmpreintesImprimees1211 = []string{
	"0x4b88f9b3b618a27835988b98bb3e146e99177e370eb6cd3af219a7ba4634eb1a",
	"0xb7d1457d111588b55d7d235d313a6d6aabb32ff6c82e75c82c351beed67cc744",
	"0xe9d87eb97309d57d4d2241d12b8d3debe220a9d782fd541b92299eecc30c3af7",
	"0x3543164e9f59156aeff461bcaf1334a5a678a98fa239f1162f6df970bf0e8482",
	"0x1fa25acb0f9f78211f2abdbbd2217233f4b134a69534e2975fc3828dfe892c05",
}

// Valeurs imprimées par EX-12.35 et EX-12.39 (recopiées).
const (
	EmpreinteObjetsExemple    = "0x0a24b97a14bf984ea5e8864e940ef45a5aad5eb8a1be9ec176affbe37a41083c"
	LongueurObjetsExemple     = 673
	LongueurPoseExemple       = 811
	CibleGelExempleS3         = "/journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson?legal-hold&versionId=3%2FL4kqtJl40Nr8X8gdRQBpUMLUo"
	MD5GelPoseExemple         = "PabGSMHFuZL/pMW6ZUAWbQ=="
	MD5GelLeveeExemple        = "dUbasAU9gptvOryKx8wHGQ=="
	MD5ConfigurationExemple   = "MrEn2+g7Ii+EumTicoW97w=="
	CibleGelExempleAzure      = "/noortrace-demo-worm/journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson?comp=legalhold&versionid=2026-11-10T11%3A00%3A05.1234567Z"
	LongueurConfigurationReco = 273
)

func lireFichierWorm(rap *Rapport, ctx *contexteCT2, nom, famille string) *Value {
	chemin := filepath.Join(ctx.racine, "worm", nom)
	if !fichierExiste(chemin) {
		rap.Erreur("worm/%s : absent (annexe B.9)", nom)
		return nil
	}
	d := lireFichierJSON(rap, chemin)
	if d == nil {
		return nil
	}
	rap.Comparer(FamilleWorm, nom, "version (B.9)", "0", texteOuAbsent(d.Get("version")))
	rap.Comparer(FamilleWorm, nom, "family (B.9)", famille, texteOuAbsent(d.Get("family")))
	if !EstTableau(d.Get("cases")) {
		rap.Erreur("worm/%s : cases n'est pas un tableau (B.9)", nom)
		return nil
	}
	return d.Get("cases")
}

func casPresents(rap *Rapport, fichier string, cas *Value, obligatoires []string) {
	vus := map[string]bool{}
	for _, c := range cas.Arr {
		vus[chaineDe(c, "id")] = true
	}
	for _, o := range obligatoires {
		rap.Comparer(FamilleWorm, fichier, "cas "+o+" présent (B.9)", "présent", presentSi(vus[o]))
	}
}

func familleWorm(rap *Rapport, ctx *contexteCT2) {
	f := FamilleWorm
	// requetes.json
	if cas := lireFichierWorm(rap, ctx, "requetes.json", "worm/requetes"); cas != nil {
		for _, c := range cas.Arr {
			id := "requetes/" + chaineDe(c, "id")
			r, err := ConstruireRequeteWorm(c.Get("input"))
			if err != nil {
				rap.Erreur("worm/%s : %v", id, err)
				continue
			}
			att := c.Get("expected")
			obt := r.ValeurRequete()
			for _, k := range []string{"method", "target", "headers", "body_utf8", "body_length", "body_sha256"} {
				comparerValeur(rap, f, id, k+" (EX-12.39)", att.Get(k), obt.Get(k))
			}
		}
		casPresents(rap, "requetes.json", cas, []string{"s3-gel-pose", "s3-gel-levee", "s3-lire-gel", "s3-etat-version", "s3-liste-premiere-page",
			"s3-liste-page-suivante", "s3-configuration-verrou-4018", "s3-lire-configuration", "s3-copie", "s3-copie-gel-a-l-ecriture",
			"s3-cle-a-encoder", "azure-gel-pose", "azure-gel-levee", "azure-etat-version", "gcs-gel-pose", "gcs-gel-levee", "gcs-etat-version"})
		// valeurs imprimées par EX-12.39 (exemple calculé)
		cleEx := "journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson"
		pose, _ := ConstruireRequeteWorm(Objet("operation", Chaine("s3_gel"), "key", Chaine(cleEx), "version_id", Chaine("3/L4kqtJl40Nr8X8gdRQBpUMLUo"), "hold", Booleen(true)))
		rap.Comparer(f, "EX-12.39", "cible du gel de l'exemple (imprimée)", CibleGelExempleS3, pose.Cible)
		rap.Comparer(f, "EX-12.39", "Content-MD5 du gel ON (imprimé), 128 octets", MD5GelPoseExemple+" / 128", ContentMD5(CorpsGelS3(true))+" / "+strconv.Itoa(len(CorpsGelS3(true))))
		rap.Comparer(f, "EX-12.39", "Content-MD5 de la levée OFF (imprimé), 129 octets", MD5GelLeveeExemple+" / 129", ContentMD5(CorpsGelS3(false))+" / "+strconv.Itoa(len(CorpsGelS3(false))))
		rap.Comparer(f, "EX-12.39", "Content-MD5 de la rétention par défaut de 4 018 jours (imprimé), 273 octets", MD5ConfigurationExemple+" / 273",
			ContentMD5(CorpsConfigurationVerrou(JoursRetentionReco))+" / "+strconv.Itoa(len(CorpsConfigurationVerrou(JoursRetentionReco))))
		az, _ := ConstruireRequeteWorm(Objet("operation", Chaine("azure_gel"), "bucket", Chaine(BucketWormDemo), "key", Chaine(cleEx), "version_id", Chaine("2026-11-10T11:00:05.1234567Z"), "hold", Booleen(true)))
		rap.Comparer(f, "EX-12.39", "cible Azure de l'exemple (imprimée)", CibleGelExempleAzure, az.Cible)
	}
	// etats.json
	if cas := lireFichierWorm(rap, ctx, "etats.json", "worm/etats"); cas != nil {
		copie, _ := ParseHorodatage(CopieExempleISO)
		minRecalc := copie.Add(time.Duration(JoursRetentionReco)*24*time.Hour - ToleranceEcheanceS*time.Second)
		for _, c := range cas.Arr {
			id := "etats/" + chaineDe(c, "id")
			in := c.Get("input")
			el := in.Get("expected_lock")
			min := chaineDe(el, "retain_until_min")
			rap.Comparer(f, id, "retain_until_min = copied_at (EX-12.29) + 4 018 j × 86 400 s − 3 600 s (EX-12.33)", min, FormaterHorodatage(minRecalc))
			tmin, ok := ParseHorodatage(min)
			if !ok {
				rap.Erreur("worm/%s : retain_until_min illisible", id)
				continue
			}
			h := el.Get("hold")
			gelAttendu := h != nil && h.Kind == KindBool && h.Bool
			e, err := ControlerVerrou(chaineDe(in, "type"), in.Get("headers"), in.Get("json"), tmin, gelAttendu)
			if err != nil {
				rap.Erreur("worm/%s : %v", id, err)
				continue
			}
			att := c.Get("expected")
			verdict := "conforme"
			if len(e.Raisons) > 0 {
				verdict = "non_conforme"
			}
			comparerValeur(rap, f, id, "mode (EX-12.33 pas 1)", att.Get("mode"), e.Mode)
			comparerValeur(rap, f, id, "retain_until (EX-12.33 pas 2)", att.Get("retain_until"), e.Echeance)
			rap.Comparer(f, id, "legal_hold (EX-12.33 pas 3)", texteOuAbsent(att.Get("legal_hold")), e.Gel)
			rap.Comparer(f, id, "verdict (EX-12.33)", texteOuAbsent(att.Get("verdict")), verdict)
			comparerValeur(rap, f, id, "reasons (EX-12.33)", att.Get("reasons"), tableauChaines(e.Raisons))
			comparerValeur(rap, f, id, "notes (EX-12.33)", att.Get("notes"), tableauChaines(e.Note))
		}
	}
	// perimetres.json
	if cas := lireFichierWorm(rap, ctx, "perimetres.json", "worm/perimetres"); cas != nil {
		for _, c := range cas.Arr {
			id := "perimetres/" + chaineDe(c, "id")
			in := c.Get("input")
			de, ok1 := EntierDe(in.Get("from"))
			a, ok2 := EntierDe(in.Get("to"))
			if !ok1 || !ok2 {
				rap.Erreur("worm/%s : from ou to illisible", id)
				continue
			}
			man := map[int64][2]int64{}
			for _, m := range in.Get("manifests").Arr {
				p, _ := EntierDe(m.Get("period_start"))
				fs, _ := EntierDe(m.Get("first_seq"))
				ls, _ := EntierDe(m.Get("last_seq"))
				man[p] = [2]int64{fs, ls}
			}
			var vs []VersionListee
			for _, v := range in.Get("versions").Arr {
				vs = append(vs, VersionListee{chaineDe(v, "key"), chaineDe(v, "version_id"), v.Get("is_latest") != nil && v.Get("is_latest").Bool, v.Get("delete_marker") != nil && v.Get("delete_marker").Bool})
			}
			var pieces []string
			copiees := false
			if p := in.Get("pieces"); EstTableau(p) {
				copiees = true
				for _, x := range p.Arr {
					pieces = append(pieces, x.Str)
				}
			}
			purgeables := in.Get("pieces_purgeable") != nil && in.Get("pieces_purgeable").Kind == KindBool && in.Get("pieces_purgeable").Bool
			objets, anomalies := PerimetreGel(chaineDe(in, "prefix"), de, a, man, vs, copiees, pieces, purgeables)
			lo := TableauVide()
			for _, o := range objets {
				lo.Arr = append(lo.Arr, Objet("key", Chaine(o[0]), "version_id", Chaine(o[1])))
			}
			la := TableauVide()
			for _, x := range anomalies {
				la.Arr = append(la.Arr, Objet("key", Chaine(x.Cle), "kind", Chaine(x.Sorte)))
			}
			octets := OctetsListeObjets(objets)
			att := c.Get("expected")
			comparerValeur(rap, f, id, "objects (EX-12.35 pas 3 à 6)", att.Get("objects"), lo)
			rap.Comparer(f, id, "objects_sha256 = SHA-256 des lignes JCS intégral + \\n (EX-12.35 pas 6)", chaineDe(att, "objects_sha256"), Hex0x(SHA256(octets)))
			rap.Comparer(f, id, "count", texteOuAbsent(att.Get("count")), strconv.Itoa(len(objets)))
			comparerValeur(rap, f, id, "anomalies (EX-12.35)", att.Get("anomalies"), la)
			if chaineDe(c, "id") == "exemple-ex-12-35" {
				rap.Comparer(f, id, "empreinte et longueur imprimées par EX-12.35", fmt.Sprintf("%s / %d octets", EmpreinteObjetsExemple, LongueurObjetsExemple),
					fmt.Sprintf("%s / %d octets", Hex0x(SHA256(octets)), len(octets)))
			}
		}
		casPresents(rap, "perimetres.json", cas, []string{"exemple-ex-12-35"})
		rap.Note("worm/perimetres : B.9 ne nomme que l'exemple d'EX-12.35 ; les autres cas obligatoires sont confrontés par leur contenu, pas par leur nom")
	}
	// gardes.json
	if cas := lireFichierWorm(rap, ctx, "gardes.json", "worm/gardes"); cas != nil {
		codesVus := map[string]bool{}
		for _, c := range cas.Arr {
			id := "gardes/" + chaineDe(c, "id")
			recs := c.Get("input").Get("records")
			if !EstTableau(recs) {
				rap.Erreur("worm/%s : records n'est pas un tableau", id)
				continue
			}
			emp, errs := RegleDeGarde(recs.Arr)
			att := c.Get("expected")
			comparerValeur(rap, f, id, "record_sha256 (SHA-256 du JCS intégral, EX-12.37)", att.Get("record_sha256"), tableauChaines(emp))
			le := TableauVide()
			for _, e := range errs {
				le.Arr = append(le.Arr, Objet("n", Entier(int64(e.N)), "code", Chaine(e.Code)))
				codesVus[e.Code] = true
			}
			rap.Comparer(f, id, "valid (EX-12.38)", texteOuAbsent(att.Get("valid")), strconv.FormatBool(len(errs) == 0))
			comparerValeur(rap, f, id, "errors (EX-12.38, rang puis ordre de la table)", att.Get("errors"), le)
			if chaineDe(c, "id") == "suite-valide" {
				rap.Comparer(f, id, "empreintes imprimées en 12.11 (EX-12.37)", strings.Join(EmpreintesImprimees1211, " "), strings.Join(emp, " "))
				if b, err := CanoniqueIntegral(recs.Arr[0]); err == nil {
					rap.Comparer(f, id, "longueur de 0001-pose en JCS intégral (imprimée : 811 octets)", strconv.Itoa(LongueurPoseExemple), strconv.Itoa(len(b)))
				}
			}
		}
		for _, code := range CodesGarde {
			rap.Comparer(f, "gardes.json", "une suite par code d'erreur : "+code+" (B.9)", "présent", presentSi(codesVus[code]))
		}
	}
	// levees.json (EX-12.40) : versions couvertes par un autre gel actif
	if cas := lireFichierWorm(rap, ctx, "levees.json", "worm/levees"); cas != nil {
		for _, c := range cas.Arr {
			id := "levees/" + chaineDe(c, "id")
			in := c.Get("input")
			couvreur := map[string]string{}
			for _, g := range in.Get("other_holds").Arr {
				for _, o := range g.Get("objects").Arr {
					k := chaineDe(o, "key") + "\x00" + chaineDe(o, "version_id")
					if _, deja := couvreur[k]; !deja {
						couvreur[k] = chaineDe(g, "gel_id")
					}
				}
			}
			lever, garder := TableauVide(), TableauVide()
			for _, o := range in.Get("objects").Arr {
				if g, ok := couvreur[chaineDe(o, "key")+"\x00"+chaineDe(o, "version_id")]; ok {
					garder.Arr = append(garder.Arr, Objet("key", Chaine(chaineDe(o, "key")), "version_id", Chaine(chaineDe(o, "version_id")), "gel_id", Chaine(g)))
				} else {
					lever.Arr = append(lever.Arr, Objet("key", Chaine(chaineDe(o, "key")), "version_id", Chaine(chaineDe(o, "version_id"))))
				}
			}
			att := c.Get("expected")
			comparerValeur(rap, f, id, "lift (EX-12.40)", att.Get("lift"), lever)
			comparerValeur(rap, f, id, "keep (EX-12.40, premier gel couvrant)", att.Get("keep"), garder)
		}
	}
}
