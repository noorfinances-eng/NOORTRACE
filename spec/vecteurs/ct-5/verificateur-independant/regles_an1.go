// AN-1 : validation d'une configuration ancrage-v0 (CT-5 EX-4.9, famille
// configuration de l'annexe A.4, complément du 2026-11-16). « Au démarrage
// et à chaque rechargement, le composant d'ancrage valide le document contre
// son schéma, puis applique les règles que le schéma n'exprime pas ; une
// règle violée refuse la configuration [...], avec un rapport nominatif. »
// Le verdict est la liste triée des règles violées : « schema (le document ne
// suit pas ancrage-v0 ; les règles suivantes ne sont pas évaluées), puis les
// règles d'EX-4.9 (4 bis compte pour 4) » ($defs/cas_configuration).

package main

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// VerdictConfiguration est le verdict d'AN-1 : valide, ou la liste triée des
// règles violées et, par règle, les raisons.
type VerdictConfiguration struct {
	Valide  bool
	Regles  []string
	Raisons map[string][]string
}

// VerifierConfiguration applique AN-1 à un document, pour un profil de CT-2
// §15 (developpement, test, production) et la valeur checkpoint_interval_s
// de l'enregistreur (nil : inconnue).
func VerifierConfiguration(sch *Schema, doc *Value, profil string, ckEnregistreur *int64) *VerdictConfiguration {
	v := &VerdictConfiguration{Raisons: map[string][]string{}}
	violer := func(regle, format string, args ...any) {
		v.Raisons[regle] = append(v.Raisons[regle], fmt.Sprintf(format, args...))
	}
	if ecarts := sch.Valider(doc); len(ecarts) > 0 {
		v.Raisons["schema"] = ecarts
	} else {
		appliquerRegles(doc, profil, ckEnregistreur, violer)
	}
	for r := range v.Raisons {
		v.Regles = append(v.Regles, r)
	}
	// « schema » d'abord, puis 1 à 9
	sort.Slice(v.Regles, func(i, j int) bool {
		a, b := v.Regles[i], v.Regles[j]
		if (a == "schema") != (b == "schema") {
			return a == "schema"
		}
		return a < b
	})
	if v.Regles == nil {
		v.Regles = []string{}
	}
	v.Valide = len(v.Regles) == 0
	return v
}

// adresseLocale dit si l'hôte d'une url http:// est une adresse locale au
// sens de la règle 4 (« 127.0.0.1, ::1, localhost »).
func adresseLocale(url string) bool {
	reste := url[strings.Index(url, "://")+3:]
	if i := strings.IndexByte(reste, '/'); i >= 0 {
		reste = reste[:i]
	}
	hote := reste
	if strings.HasPrefix(hote, "[") {
		if i := strings.IndexByte(hote, ']'); i >= 0 {
			hote = hote[1:i]
		}
	} else if i := strings.LastIndexByte(hote, ':'); i >= 0 {
		hote = hote[:i]
	}
	return hote == "127.0.0.1" || hote == "::1" || hote == "localhost"
}

// autoriteSansIdentifiant dit si la partie d'autorité d'une url ne porte ni
// identifiant ni mot de passe (EX-4.8, AN-54 : « sa partie d'autorité ne
// contient pas @ »).
func autoriteSansIdentifiant(url string) bool {
	i := strings.Index(url, "://")
	if i < 0 {
		return false
	}
	reste := url[i+3:]
	if j := strings.IndexByte(reste, '/'); j >= 0 {
		reste = reste[:j]
	}
	return !strings.Contains(reste, "@")
}

// certificatLisible lit un PEM d'anchor_certificates : un seul bloc
// CERTIFICATE en base64, dont le DER suit le profil de lecture borné de CT-6
// EX-9.4 tel que ParseDER l'applique (longueurs minimales, étiquettes
// inférieures à 31, profondeur au plus 32, aucun octet après la structure) et
// a la forme d'un Certificate X.509 : SEQUENCE { tbsCertificate SEQUENCE {
// [0] version facultative, serialNumber INTEGER, signature SEQUENCE, issuer
// SEQUENCE, validity SEQUENCE, subject SEQUENCE, subjectPublicKeyInfo
// SEQUENCE, … }, signatureAlgorithm SEQUENCE, signatureValue BIT STRING }.
func certificatLisible(pem string) error {
	const debut, fin = "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----"
	if !strings.HasPrefix(pem, debut) || !strings.Contains(pem, fin) {
		return fmt.Errorf("bloc PEM CERTIFICATE attendu")
	}
	corps := pem[len(debut):strings.Index(pem, fin)]
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(corps, "\n", ""))
	if err != nil {
		return fmt.Errorf("base64 illisible")
	}
	n, err := ParseDER(der)
	if err != nil {
		return err
	}
	if n.Etiquette != 0x30 || len(n.Enfants) != 3 || n.Enfants[0].Etiquette != 0x30 || n.Enfants[1].Etiquette != 0x30 || n.Enfants[2].Etiquette != 0x03 || len(n.Enfants[2].Val) == 0 {
		return fmt.Errorf("Certificate X.509 attendu (SEQUENCE de tbsCertificate, signatureAlgorithm, signatureValue)")
	}
	tbs := n.Enfants[0].Enfants
	if len(tbs) > 0 && tbs[0].Etiquette == 0xa0 {
		tbs = tbs[1:]
	}
	if len(tbs) < 6 || tbs[0].Etiquette != 0x02 || len(tbs[0].Val) == 0 {
		return fmt.Errorf("tbsCertificate incomplet")
	}
	for _, e := range tbs[1:6] {
		if e.Etiquette != 0x30 {
			return fmt.Errorf("tbsCertificate : SEQUENCE attendue")
		}
	}
	return nil
}

// appliquerRegles applique les règles 1 à 9 d'EX-4.9 à un document conforme
// au schéma.
func appliquerRegles(doc *Value, profil string, ckEnregistreur *int64, violer func(regle, format string, args ...any)) {
	production := profil == "production"
	ck, _ := entierDe(doc, "checkpoint_interval_s")
	r := doc.Get("rfc3161")
	providers := r.Get("providers").Arr
	role := chaineOu(r, "", "checkpoints", "provider_role")

	// 1. « checkpoint_interval_s égal à la valeur de l'enregistreur et diviseur
	// de 3600 ; en profil de production, la valeur de l'enregistreur DOIT être
	// connue [...] : une valeur absente refuse la configuration »
	if ckEnregistreur != nil && *ckEnregistreur != ck {
		violer("1", "checkpoint_interval_s %d différent de la valeur de l'enregistreur %d", ck, *ckEnregistreur)
	}
	if ck <= 0 || 3600%ck != 0 {
		violer("1", "checkpoint_interval_s %d ne divise pas 3600", ck)
	}
	if production && ckEnregistreur == nil {
		violer("1", "valeur checkpoint_interval_s de l'enregistreur inconnue en production")
	}

	// 2. « exactement un prestataire de rôle principal ; au plus un de rôle
	// secours ; des id distincts »
	nRoles := map[string]int{}
	ids := map[string]bool{}
	var principal, secours *Value
	for _, p := range providers {
		ro := chaineOu(p, "", "role")
		nRoles[ro]++
		if ro == "principal" {
			principal = p
		}
		if ro == "secours" {
			secours = p
		}
		id := chaineOu(p, "", "id")
		if ids[id] {
			violer("2", "id %s en double", id)
		}
		ids[id] = true
	}
	if nRoles["principal"] != 1 {
		violer("2", "%d prestataire(s) de rôle principal, un attendu", nRoles["principal"])
	}
	if nRoles["secours"] > 1 {
		violer("2", "%d prestataires de rôle secours, au plus un attendu", nRoles["secours"])
	}

	// 3. « rfc3161.checkpoints.interval_s multiple de checkpoint_interval_s et
	// diviseur de 3600 »
	cT, _ := entierDe(r, "checkpoints", "interval_s")
	if ck <= 0 || cT%ck != 0 || 3600%cT != 0 {
		violer("3", "interval_s %d : multiple de checkpoint_interval_s %d et diviseur de 3600 attendu", cT, ck)
	}

	// 4. Production, adresses, authentification, qualification ; 4 bis.
	if production {
		if role == "aucun" {
			violer("4", "provider_role aucun en production")
		}
		if chaineOu(doc, "", "registry", "checkpoints") == "aucun" {
			violer("4", "registry.checkpoints aucun en production")
		}
		if !booleenOu(doc, false, "opentimestamps", "enabled") {
			violer("4", "opentimestamps.enabled faux en production")
		}
		if principal != nil && estNul(principal, "qualified") {
			violer("4", "principal %s sans qualified en production", chaineOu(principal, "", "id"))
		}
		if secours != nil && estNul(secours, "qualified") {
			violer("4", "secours %s sans qualified en production", chaineOu(secours, "", "id"))
		}
		// « en production, opentimestamps.headers_source est non nul (EX-6.6,
		// EX-6.9) »
		if estNul(doc, "opentimestamps", "headers_source") {
			violer("4", "opentimestamps.headers_source nul en production")
		}
	}
	for _, p := range providers {
		id, ro, url := chaineOu(p, "", "id"), chaineOu(p, "", "role"), chaineOu(p, "", "url")
		methode := chaineOu(p, "", "auth", "method")
		secretNul := estNul(p, "auth", "secret")
		qualifie := !estNul(p, "qualified")
		http := strings.HasPrefix(url, "http://")
		// « tout url de rôle autre qu'interne commence par https:// » (production)
		if production && ro != "interne" && !strings.HasPrefix(url, "https://") {
			violer("4", "%s : url de rôle %s hors https:// en production", id, ro)
		}
		// « dans tout profil, un prestataire de rôle interne a qualified = null
		// (EX-5.6, EX-7.2) et tout url est sans identifiant ni mot de passe »
		if ro == "interne" && qualifie {
			violer("4", "%s : prestataire interne qualifié", id)
		}
		if !autoriteSansIdentifiant(url) {
			violer("4", "%s : url portant un identifiant", id)
		}
		// « dans tout profil, auth.method = aucune va avec auth.secret = null,
		// basic et certificat_client avec un secret non nul »
		if methode == "aucune" && !secretNul {
			violer("4", "%s : auth.method aucune avec un secret", id)
		}
		if (methode == "basic" || methode == "certificat_client") && secretNul {
			violer("4", "%s : auth.method %s sans secret", id, methode)
		}
		// Règles d'adresse et d'authentification du rôle interne, que suit
		// aussi, hors production, un principal non qualifié (révision 0.9) :
		// « url en http:// vers une adresse locale avec auth.method = aucune, ou
		// url en https:// avec basic ou certificat_client » ; « un url de rôle
		// interne en http:// n'est admis que vers une adresse locale ».
		commeInterne := ro == "interne" || (ro == "principal" && !qualifie && !production)
		switch {
		case commeInterne && http:
			if !adresseLocale(url) {
				violer("4", "%s : url http:// hors d'une adresse locale", id)
			}
			if methode != "aucune" {
				violer("4", "%s : url http:// locale avec authentification %s", id, methode)
			}
		case commeInterne:
			if methode == "aucune" {
				violer("4", "%s : url https:// sans authentification", id)
			}
		default:
			// « un principal qualifié, un secours ou un second_rang restent en
			// https:// avec authentification dans tout profil » ; en production,
			// un principal en http:// ou sans authentification : « le serveur
			// RFC 3161 interne n'est admis comme principal que hors production ».
			if http {
				violer("4", "%s : url http:// de rôle %s", id, ro)
			}
			if methode == "aucune" {
				violer("4", "%s : rôle %s sans authentification", id, ro)
			}
		}
		// 4 bis : crl_hosts (forme : schéma) ; le contrôle des adresses de CRL a
		// lieu à la capture (EX-5.10, étape 10) et ne se lit pas dans le
		// document (A.3).
	}

	// 5. « opentimestamps.enabled = true ⇒ au moins deux calendars distincts,
	// min_responses ≤ longueur de calendars, au moins une entrée dans
	// upgrade.whitelist »
	if booleenOu(doc, false, "opentimestamps", "enabled") {
		cals := chainesDe(doc, "opentimestamps", "calendars")
		distincts := map[string]bool{}
		for _, c := range cals {
			distincts[c] = true
		}
		if len(distincts) < 2 {
			violer("5", "%d calendrier(s) distinct(s), deux attendus", len(distincts))
		}
		if m, _ := entierDe(doc, "opentimestamps", "min_responses"); m > int64(len(cals)) {
			violer("5", "min_responses %d au-delà de %d calendriers", m, len(cals))
		}
		if len(chainesDe(doc, "opentimestamps", "upgrade", "whitelist")) < 1 {
			violer("5", "upgrade.whitelist vide")
		}
	}

	// 6. « rfc3161.retention_years ≥ 10 ; retry.initial_ms ≤ retry.max_ms ;
	// upgrade.interval_s ≥ 60 »
	if n, _ := entierDe(r, "retention_years"); n < 10 {
		violer("6", "retention_years %d inférieur à 10", n)
	}
	if a, b := nombreOu(r, 0, "retry", "initial_ms"), nombreOu(r, 0, "retry", "max_ms"); a > b {
		violer("6", "retry.initial_ms %v au-delà de retry.max_ms %v", a, b)
	}
	if n, _ := entierDe(doc, "opentimestamps", "upgrade", "interval_s"); n < 60 {
		violer("6", "upgrade.interval_s %d inférieur à 60", n)
	}

	// 7. « provider_role = second_rang ⇒ un prestataire de ce rôle existe ;
	// provider_role = interne ⇒ un prestataire de ce rôle existe »
	if (role == "second_rang" || role == "interne") && nRoles[role] == 0 {
		violer("7", "provider_role %s sans prestataire de ce rôle", role)
	}

	// 8. « chaque PEM d'anchor_certificates se lit comme un certificat par le
	// lecteur de CT-6 §9.3 »
	for _, p := range providers {
		for i, pem := range chainesDe(p, "anchor_certificates") {
			if err := certificatLisible(pem); err != nil {
				violer("8", "%s : anchor_certificates[%d] : %s", chaineOu(p, "", "id"), i, err.Error())
			}
		}
	}

	// 9. « chaque policy_oid et chaque OID d'accepted_policies s'encode dans la
	// requête d'EX-5.1 : premier arc 0, 1 ou 2, second arc inférieur à 40 sous
	// un premier arc 0 ou 1, chaque arc tenant sur 128 bits, DER de l'OID d'au
	// plus 127 octets »
	for _, p := range providers {
		oids := chainesDe(p, "accepted_policies")
		if o, ok := chaineDe(p, "policy_oid"); ok {
			oids = append([]string{o}, oids...)
		}
		for _, o := range oids {
			der, err := EncoderOIDDER(o)
			if err != nil {
				violer("9", "%s : %s", chaineOu(p, "", "id"), err.Error())
			} else if len(der) > 127 {
				violer("9", "%s : DER de l'OID de %d octets, au plus 127", chaineOu(p, "", "id"), len(der))
			}
		}
	}
}
