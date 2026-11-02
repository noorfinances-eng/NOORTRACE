// Paquet ancres : le fichier d'ancres de confiance du réviseur (CT-6 §12,
// schéma ancres-confiance-v0) et sa vérification N-1, le fichier d'en-têtes
// Bitcoin (CT-6 §10.3, schéma entetes-bitcoin-v0) et sa vérification N-2,
// et la vérification N-3 des clés d'enregistreur (EX-12.4, EX-12.6).
//
// N-1 et N-2 ne figurent pas dans `checks` : en défaut, elles rendent
// l'entrée inutilisable (code 2). N-4 (clé de chaîne) relève du contrôle 8 et
// du paquet registre.
package ancres

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
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

// Ancres : le fichier d'ancres lu et contrôlé par N-1. Tout ce qu'il
// contient est « de confiance » (CT-6 §3.1), sauf les intermédiaires et les
// CRL, qui sont vérifiés par T-7 et T-10 (§12.1).
type Ancres struct {
	// Chemin et Sha256 : désignation du fichier (inputs.anchors).
	Chemin string
	Sha256 [32]byte
	// Autorites : tsa_authorities, dans l'ordre du fichier.
	Autorites []Autorite
	// CRLs : revocation.crls, DER, dans l'ordre du fichier.
	CRLs []CRL
	// Declarations : revocation.statements, dans l'ordre du fichier.
	Declarations []Declaration
	// Bitcoin : ancre bitcoin, ou nil.
	Bitcoin *Bitcoin
	// Registre : ancre registry, ou nil.
	Registre *Registre
	// Enregistreurs : recorders, dans l'ordre du fichier.
	Enregistreurs []Enregistreur
}

// Autorite d'horodatage de confiance (§12.2).
type Autorite struct {
	// Pointeur : pointeur JSON de l'autorité (« /tsa_authorities/0 »).
	Pointeur string
	Nom      string
	// Certificat : DER du certificat de l'autorité (clé et nom de confiance).
	Certificat []byte
	// Intermediaires : DER des intermédiaires (non crus, vérifiés par T-7).
	Intermediaires [][]byte
	// PolitiquesAdmises : OID admis, ou nil pour toute politique.
	PolitiquesAdmises []string
	// Qualification : statut qualifié déclaré, ou nil.
	Qualification *Qualification
	Source        string
}

// Qualification déclarée par le réviseur (T-11).
type Qualification struct {
	// Cadre : « eidas » ou « zertes ».
	Cadre string
	Debut time.Time
	// Fin : nil pour « pas de borne haute ».
	Fin    *time.Time
	Source string
}

// CRL du fichier d'ancres.
type CRL struct {
	Pointeur string // « /revocation/crls/0 »
	DER      []byte
}

// Declaration de non-révocation du réviseur (T-10, règle 2).
type Declaration struct {
	Pointeur         string // « /revocation/statements/0 »
	CertificatSha256 [32]byte
	NonRevoqueA      time.Time
	Methode          string
	Source           string
}

// Bitcoin : ancre du contrôle 5 (§12.2).
type Bitcoin struct {
	// Reseau : « mainnet » ou « regtest ».
	Reseau string
	// Hauteur et Hachage du point de contrôle Bitcoin ; Hachage est dans
	// l'ordre d'affichage de Bitcoin Core, tel qu'écrit dans le fichier.
	Hauteur          uint32
	Hachage          [32]byte
	MinConfirmations int
	Source           string
}

// Registre : ancre du contrôle 8 (§12.2).
type Registre struct {
	ChainID             string
	PeriodRegistry      [20]byte
	AttestationRegistry [20]byte
	RecorderRegistry    [20]byte
	Jeux                []JeuValidateurs
	Source              string
}

// JeuValidateurs déclaré par le réviseur, avec ses hauteurs de validité.
type JeuValidateurs struct {
	Pointeur string // « /registry/validator_sets/0 »
	De       uint64
	// A : nil pour « sans borne haute ».
	A           *uint64
	Validateurs []Validateur
	Source      string
}

// Validateur : identifiant et clé publique telle que déclarée.
type Validateur struct {
	ID string
	// CleHex : la chaîne pubKeyHex telle qu'écrite (le hachage du jeu porte
	// sur les octets tels que déclarés, EX-11.8).
	CleHex string
	Cle    []byte
}

// Enregistreur : clé d'enregistreur de confiance (N-3, N-4).
type Enregistreur struct {
	Pointeur    string // « /recorders/0 »
	OrgID       string
	JournalID   string
	KeyID       string
	ClePublique string
	// CleChaine : adresse en hexadécimal « 0x… », ou "" pour null.
	CleChaine string
	Source    string
}

// ControleurDER applique aux certificats et aux CRL du fichier d'ancres le
// profil de lecture de CT-6 §9.3 et EX-9.21 (N-1). Il est fourni par le
// paquet horodatage, qui porte ce profil.
type ControleurDER interface {
	Certificat(der []byte) error
	CRL(der []byte) error
}

// Defaut : défaut qui rend une entrée inutilisable (code 2).
type Defaut struct {
	// Genre : « ancres_inutilisables », « taille_depassee » ou
	// « entree_illisible » (CT-6 §8.6, champ error.kind).
	Genre string
	// Verification : « N-1 » ou « N-2 ».
	Verification string
	Message      commun.Texte
}

func (d *Defaut) Error() string { return d.Message.Fr }

func defautN1(fr, en string) *Defaut {
	return &Defaut{Genre: "ancres_inutilisables", Verification: "N-1", Message: commun.T("fichier d'ancres inutilisable : "+fr, "anchors file unusable: "+en)}
}

// Lire lit et contrôle le fichier d'ancres (N-1, EX-12.2). Tout défaut rend
// l'entrée inutilisable, type ancres_inutilisables (EX-4.10).
func Lire(chemin string, der ControleurDER) (*Ancres, *Defaut) {
	l := entree.Lire(chemin, entree.LimiteAncres)
	switch l.Etat {
	case entree.Absent, entree.Illisible:
		return nil, defautN1(fmt.Sprintf("lecture impossible (%v)", l.Err), fmt.Sprintf("cannot read (%v)", l.Err))
	case entree.TropGrand:
		return nil, defautN1("plus de 16 Mio", "more than 16 MiB")
	}
	a, d := AnalyserAncres(l.Octets, der)
	if a != nil {
		a.Chemin, a.Sha256 = chemin, l.Sha256
	}
	return a, d
}

// AnalyserAncres applique N-1 aux octets d'un fichier d'ancres déjà lu
// dans sa limite (cible de fuzzing, EX-15.3).
func AnalyserAncres(octets []byte, der ControleurDER) (*Ancres, *Defaut) {
	v, err := jsonv.Analyser(octets)
	if err != nil {
		return nil, defautN1("ce n'est pas du JSON ("+err.Error()+")", "not JSON ("+err.Error()+")")
	}
	if !v.EstObjet() {
		return nil, defautN1("ce n'est pas un objet JSON", "not a JSON object")
	}
	if m, ok := sansFormeCanonique(v); ok {
		return nil, defautN1("sans forme canonique ("+m+")", "without canonical form ("+m+")")
	}
	if ver := v.Membre("version"); ver != nil {
		if n, ok := ver.Entier(); ok && n != 0 {
			return nil, defautN1(fmt.Sprintf("version %d, seule la version 0 est lue (EX-14.11)", n), fmt.Sprintf("version %d, only version 0 is read (EX-14.11)", n))
		}
	}
	if err := schema.Valider(schema.AncresConfiance, v); err != nil {
		return nil, defautN1("contraire au schéma ancres-confiance-v0 ("+err.Error()+")", "does not follow the ancres-confiance-v0 schema ("+err.Error()+")")
	}
	a := &Ancres{}
	if _, ok := commun.LireHorodatage(v.Membre("prepared_at").S()); !ok {
		return nil, defautN1("prepared_at n'est pas une date existante", "prepared_at is not an existing date")
	}
	noms := map[string]bool{}
	for i, au := range v.Membre("tsa_authorities").Elements {
		ptr := fmt.Sprintf("/tsa_authorities/%d", i)
		nom := au.Membre("name").S()
		if noms[nom] {
			return nil, defautN1("deux autorités portent le nom « "+nom+" »", "two authorities are named “"+nom+"”")
		}
		noms[nom] = true
		cert, d := certificat(au.Membre("certificate").S(), ptr+"/certificate", der)
		if d != nil {
			return nil, d
		}
		aut := Autorite{Pointeur: ptr, Nom: nom, Certificat: cert, Source: au.Membre("source").S()}
		for k, inter := range au.Membre("intermediates").Elements {
			c, d := certificat(inter.S(), fmt.Sprintf("%s/intermediates/%d", ptr, k), der)
			if d != nil {
				return nil, d
			}
			aut.Intermediaires = append(aut.Intermediaires, c)
		}
		if pol := au.Membre("accepted_policies"); pol.EstTableau() {
			aut.PolitiquesAdmises = []string{}
			for _, p := range pol.Elements {
				aut.PolitiquesAdmises = append(aut.PolitiquesAdmises, p.S())
			}
		}
		if q := au.Membre("qualified"); q.EstObjet() {
			deb, ok := commun.LireHorodatage(q.Membre("valid_from").S())
			if !ok {
				return nil, defautN1(ptr+"/qualified/valid_from n'est pas une date existante", ptr+"/qualified/valid_from is not an existing date")
			}
			qu := &Qualification{Cadre: q.Membre("framework").S(), Debut: deb, Source: q.Membre("source").S()}
			if f := q.Membre("valid_to"); f.EstChaine() {
				fin, ok := commun.LireHorodatage(f.Chaine)
				if !ok {
					return nil, defautN1(ptr+"/qualified/valid_to n'est pas une date existante", ptr+"/qualified/valid_to is not an existing date")
				}
				if deb.After(fin) {
					return nil, defautN1(ptr+"/qualified : valid_from suit valid_to", ptr+"/qualified: valid_from is after valid_to")
				}
				qu.Fin = &fin
			}
			aut.Qualification = qu
		}
		a.Autorites = append(a.Autorites, aut)
	}
	rev := v.Membre("revocation")
	for i, c := range rev.Membre("crls").Elements {
		ptr := fmt.Sprintf("/revocation/crls/%d", i)
		b, d := blocPEM(c.S(), "X509 CRL", ptr)
		if d != nil {
			return nil, d
		}
		if _, err := x509.ParseRevocationList(b); err != nil {
			return nil, defautN1(ptr+" : CRL illisible ("+err.Error()+")", ptr+": unreadable CRL ("+err.Error()+")")
		}
		if der != nil {
			if err := der.CRL(b); err != nil {
				return nil, defautN1(ptr+" : "+err.Error(), ptr+": "+err.Error())
			}
		}
		a.CRLs = append(a.CRLs, CRL{Pointeur: ptr, DER: b})
	}
	for i, s := range rev.Membre("statements").Elements {
		ptr := fmt.Sprintf("/revocation/statements/%d", i)
		t, ok := commun.LireHorodatage(s.Membre("not_revoked_at").S())
		if !ok {
			return nil, defautN1(ptr+"/not_revoked_at n'est pas une date existante", ptr+"/not_revoked_at is not an existing date")
		}
		h, _ := cryptographie.LireHex(s.Membre("certificate_sha256").S(), 32)
		dcl := Declaration{Pointeur: ptr, NonRevoqueA: t, Methode: s.Membre("method").S(), Source: s.Membre("source").S()}
		copy(dcl.CertificatSha256[:], h)
		a.Declarations = append(a.Declarations, dcl)
	}
	if b := v.Membre("bitcoin"); b.EstObjet() {
		h, _ := b.Chemin("checkpoint", "height").Entier()
		mc, _ := b.Membre("min_confirmations").Entier()
		bt := &Bitcoin{Reseau: b.Membre("network").S(), Hauteur: uint32(h), MinConfirmations: int(mc), Source: b.Membre("source").S()}
		hh, _ := cryptographie.LireHex(b.Chemin("checkpoint", "hash").S(), 32)
		copy(bt.Hachage[:], hh)
		a.Bitcoin = bt
	}
	if r := v.Membre("registry"); r.EstObjet() {
		reg, d := registre(r)
		if d != nil {
			return nil, d
		}
		a.Registre = reg
	}
	triplets := map[string]bool{}
	for i, e := range v.Membre("recorders").Elements {
		en := Enregistreur{
			Pointeur:    fmt.Sprintf("/recorders/%d", i),
			OrgID:       e.Membre("org_id").S(),
			JournalID:   e.Membre("journal_id").S(),
			KeyID:       e.Membre("key_id").S(),
			ClePublique: e.Membre("public_key").S(),
			Source:      e.Membre("source").S(),
		}
		if ck := e.Membre("chain_key"); ck.EstChaine() {
			en.CleChaine = ck.Chaine
		}
		t := en.OrgID + "|" + en.JournalID + "|" + en.KeyID
		if triplets[t] {
			return nil, defautN1("deux entrées de recorders pour le triplet ("+en.OrgID+", "+en.JournalID+", "+en.KeyID+")", "two recorders entries for the triple ("+en.OrgID+", "+en.JournalID+", "+en.KeyID+")")
		}
		triplets[t] = true
		a.Enregistreurs = append(a.Enregistreurs, en)
	}
	return a, nil
}

// sansFormeCanonique dit si un document n'a pas de forme canonique JCS v0
// (clé en double, nombre non entier ou hors de l'intervalle sûr, substitut
// isolé, CT-1 §4) et rend le motif. Un tel fichier d'ancres ou d'en-têtes
// est refusé (N-1, N-2) au lieu d'être lu en dernière occurrence ou par
// arrondi (« Lectures », point 21 du LISEZMOI du module).
func sansFormeCanonique(v *jsonv.Valeur) (string, bool) {
	err := jcs.Calculable(v)
	if err == nil {
		return "", false
	}
	if e, ok := err.(*jcs.Erreur); ok {
		return e.Motif, true
	}
	return err.Error(), true
}

func blocPEM(s, genre, ptr string) ([]byte, *Defaut) {
	bloc, reste := pem.Decode([]byte(s))
	if bloc == nil || bloc.Type != genre || len(bytes.TrimSpace(reste)) != 0 || len(bloc.Headers) != 0 {
		return nil, defautN1(ptr+" : PEM qui ne se décode pas en un seul objet "+genre, ptr+": PEM that does not decode to a single "+genre)
	}
	return bloc.Bytes, nil
}

func certificat(s, ptr string, der ControleurDER) ([]byte, *Defaut) {
	b, d := blocPEM(s, "CERTIFICATE", ptr)
	if d != nil {
		return nil, d
	}
	c, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, defautN1(ptr+" : certificat illisible ("+err.Error()+")", ptr+": unreadable certificate ("+err.Error()+")")
	}
	if c.Version != 3 {
		return nil, defautN1(ptr+" : certificat qui n'est pas X.509 v3", ptr+": not an X.509 v3 certificate")
	}
	if der != nil {
		if err := der.Certificat(b); err != nil {
			return nil, defautN1(ptr+" : "+err.Error(), ptr+": "+err.Error())
		}
	}
	return b, nil
}

func registre(r *jsonv.Valeur) (*Registre, *Defaut) {
	reg := &Registre{ChainID: r.Membre("chain_id").S(), Source: r.Membre("source").S()}
	adr := func(nom string) [20]byte {
		var a [20]byte
		b, _ := cryptographie.LireHex(r.Chemin("contracts", nom).S(), 20)
		copy(a[:], b)
		return a
	}
	reg.PeriodRegistry = adr("period_registry")
	reg.AttestationRegistry = adr("attestation_registry")
	reg.RecorderRegistry = adr("recorder_registry")
	for i, j := range r.Membre("validator_sets").Elements {
		ptr := fmt.Sprintf("/registry/validator_sets/%d", i)
		jeu, d := LireJeu(j, ptr)
		if d != nil {
			return nil, defautN1(d.Fr, d.En)
		}
		reg.Jeux = append(reg.Jeux, jeu)
	}
	if fr, en, ok := Recouvrements(reg.Jeux); !ok {
		return nil, defautN1(fr, en)
	}
	return reg, nil
}

// LireJeu lit un jeu de validateurs conforme au schéma (ancre ou
// validateurs.json) et le charge « comme le nœud le charge » : identifiants
// non vides et distincts, clés secp256k1 exploitables et toutes distinctes,
// from_height ≤ to_height (EX-12.2).
func LireJeu(j *jsonv.Valeur, ptr string) (JeuValidateurs, *commun.Texte) {
	de, _ := j.Membre("from_height").Entier()
	jeu := JeuValidateurs{Pointeur: ptr, De: uint64(de), Source: j.Membre("source").S()}
	if a := j.Membre("to_height"); !a.EstNul() {
		v, _ := a.Entier()
		u := uint64(v)
		jeu.A = &u
		if u < jeu.De {
			t := commun.T(ptr+" : from_height supérieur à to_height", ptr+": from_height greater than to_height")
			return jeu, &t
		}
	}
	ids := map[string]bool{}
	cles := map[string]bool{}
	for _, val := range j.Membre("validators").Elements {
		// Identifiant chargé comme le nœud le charge (EX-12.2) : espaces de
		// tête et de queue retirés (strings.TrimSpace), puis non vide et
		// distinct (« Lectures », point 22 du LISEZMOI du module).
		id := strings.TrimSpace(val.Membre("id").S())
		h := val.Membre("pubKeyHex").S()
		if id == "" || ids[id] {
			t := commun.T(ptr+" : identifiant de validateur vide ou en double ("+id+")", ptr+": empty or duplicate validator id ("+id+")")
			return jeu, &t
		}
		ids[id] = true
		b, ok := cryptographie.LireHex(h, -1)
		if !ok {
			t := commun.T(ptr+" : clé du validateur "+id+" illisible", ptr+": unreadable key of validator "+id)
			return jeu, &t
		}
		cle, err := lireCleValidateur(b)
		if err != nil {
			t := commun.T(ptr+" : clé du validateur "+id+" inexploitable ("+err.Error()+")", ptr+": unusable key of validator "+id+" ("+err.Error()+")")
			return jeu, &t
		}
		norm := string(cle)
		if cles[norm] {
			t := commun.T(ptr+" : deux validateurs portent la même clé", ptr+": two validators share the same key")
			return jeu, &t
		}
		cles[norm] = true
		jeu.Validateurs = append(jeu.Validateurs, Validateur{ID: id, CleHex: h, Cle: b})
	}
	return jeu, nil
}

// lireCleValidateur lit une clé de validateur (33 ou 65 octets, ou 64
// octets non compressés sans préfixe) et rend sa forme non compressée.
func lireCleValidateur(b []byte) ([]byte, error) {
	if len(b) == 64 {
		b = append([]byte{0x04}, b...)
	}
	c, err := cryptographie.LireCleSecp256k1(b)
	if err != nil {
		return nil, err
	}
	return c.SerializeUncompressed(), nil
}

// Recouvrements vérifie que les intervalles de hauteurs des jeux ne se
// recouvrent pas (EX-12.2).
func Recouvrements(jeux []JeuValidateurs) (string, string, bool) {
	for i := range jeux {
		for k := i + 1; k < len(jeux); k++ {
			a, b := jeux[i], jeux[k]
			finA, finB := uint64(1<<63), uint64(1<<63)
			if a.A != nil {
				finA = *a.A
			}
			if b.A != nil {
				finB = *b.A
			}
			if a.De <= finB && b.De <= finA {
				return fmt.Sprintf("les jeux %s et %s se recouvrent", a.Pointeur, b.Pointeur), fmt.Sprintf("sets %s and %s overlap", a.Pointeur, b.Pointeur), false
			}
		}
	}
	return "", "", true
}

// JeuPourHauteur rend le jeu de l'ancre dont l'intervalle contient h, ou nil.
func (r *Registre) JeuPourHauteur(h uint64) *JeuValidateurs {
	if r == nil {
		return nil
	}
	for i := range r.Jeux {
		j := &r.Jeux[i]
		if h >= j.De && (j.A == nil || h <= *j.A) {
			return j
		}
	}
	return nil
}

// Entetes : le fichier d'en-têtes Bitcoin lu et contrôlé par N-2 (EX-12.3).
type Entetes struct {
	Chemin string
	Sha256 [32]byte
	Reseau string
	// Debut : start_height ; l'en-tête i est à la hauteur Debut + i.
	Debut   uint32
	Entetes [][80]byte
	Source  string
}

func defautN2(genre, fr, en string) *Defaut {
	return &Defaut{Genre: genre, Verification: "N-2", Message: commun.T("fichier d'en-têtes inutilisable : "+fr, "headers file unusable: "+en)}
}

// LireEntetes lit et contrôle le fichier d'en-têtes (N-2, EX-12.3 ; EX-4.12
// pour le type d'erreur).
func LireEntetes(chemin string) (*Entetes, *Defaut) {
	l := entree.Lire(chemin, entree.LimiteEntetes)
	switch l.Etat {
	case entree.Absent, entree.Illisible:
		return nil, defautN2("entree_illisible", fmt.Sprintf("lecture impossible (%v)", l.Err), fmt.Sprintf("cannot read (%v)", l.Err))
	case entree.TropGrand:
		return nil, defautN2("taille_depassee", "plus de 64 Mio", "more than 64 MiB")
	}
	e, d := AnalyserEntetes(l.Octets)
	if e != nil {
		e.Chemin, e.Sha256 = chemin, l.Sha256
	}
	return e, d
}

// AnalyserEntetes applique N-2 aux octets d'un fichier d'en-têtes déjà lu
// dans sa limite (cible de fuzzing, EX-15.3).
func AnalyserEntetes(octets []byte) (*Entetes, *Defaut) {
	v, err := jsonv.Analyser(octets)
	if err != nil {
		return nil, defautN2("entree_illisible", "ce n'est pas du JSON ("+err.Error()+")", "not JSON ("+err.Error()+")")
	}
	if m, ok := sansFormeCanonique(v); ok {
		return nil, defautN2("entree_illisible", "sans forme canonique ("+m+")", "without canonical form ("+m+")")
	}
	if h := v.Membre("headers"); h.EstTableau() && len(h.Elements) > entree.MaxEntetes {
		return nil, defautN2("taille_depassee", "plus de 200 000 en-têtes", "more than 200,000 headers")
	}
	if err := schema.Valider(schema.EntetesBitcoin, v); err != nil {
		return nil, defautN2("entree_illisible", "contraire au schéma entetes-bitcoin-v0 ("+err.Error()+")", "does not follow the entetes-bitcoin-v0 schema ("+err.Error()+")")
	}
	debut, _ := v.Membre("start_height").Entier()
	n := int64(len(v.Membre("headers").Elements))
	if debut+n-1 >= 1<<32 {
		return nil, defautN2("entree_illisible", "start_height + n − 1 atteint 2^32", "start_height + n − 1 reaches 2^32")
	}
	e := &Entetes{Reseau: v.Membre("network").S(), Debut: uint32(debut), Source: v.Membre("source").S()}
	for _, h := range v.Membre("headers").Elements {
		b, _ := cryptographie.LireHex(h.S(), 80)
		var x [80]byte
		copy(x[:], b)
		e.Entetes = append(e.Entetes, x)
	}
	return e, nil
}

// CleDossier : une clé de cles.json, telle que N-3 la compare.
type CleDossier struct {
	KeyID       string
	ClePublique string
}

// ResultatN3 : la vérification N-3 et les clés qu'elle a comparées avec
// succès (provenance « ancres », EX-6.8).
type ResultatN3 struct {
	// Figure : N-3 figure au rapport (EX-5.6).
	Figure       bool
	Verification commun.Verification
	// Confirmees : key_id comparés et égaux à l'ancre.
	Confirmees map[string]bool
	// Pointeurs : pointeurs des enregistreurs comparés (anchors_used).
	Pointeurs []string
}

// EntreeN3 : ce que N-3 compare.
type EntreeN3 struct {
	OrgID, JournalID string
	// ClesExploitables : cles.json remplit la première partie de E-8.
	ClesExploitables bool
	Cles             []CleDossier
	// Signataires : key_id qui signent un événement du dossier, le
	// manifeste, ou le point de contrôle du journal quand K-1 a réussi.
	Signataires []string
}

// VerifierN3 applique EX-12.4 et EX-12.6.
func (a *Ancres) VerifierN3(e EntreeN3) ResultatN3 {
	r := ResultatN3{Confirmees: map[string]bool{}}
	if a == nil {
		return r
	}
	var duJournal []Enregistreur
	for _, en := range a.Enregistreurs {
		if en.OrgID == e.OrgID && en.JournalID == e.JournalID {
			duJournal = append(duJournal, en)
		}
	}
	if len(duJournal) == 0 {
		return r
	}
	r.Figure = true
	if !e.ClesExploitables {
		r.Verification = commun.Nouvelle("N-3", commun.NonExecute, commun.PrerequisEnEchec,
			commun.T("cles.json inexploitable (E-8) : clés non comparées", "cles.json unusable (E-8): keys not compared"), 6)
		return r
	}
	cles := map[string]string{}
	for _, c := range e.Cles {
		cles[c.KeyID] = c.ClePublique
	}
	vus := map[string]bool{}
	var egales, differentes []string
	var pointeursEgaux, pointeursEcartes []string
	for _, kid := range e.Signataires {
		if vus[kid] {
			continue
		}
		vus[kid] = true
		pub, ok := cles[kid]
		if !ok {
			continue
		}
		for _, en := range duJournal {
			if en.KeyID != kid {
				continue
			}
			if en.ClePublique == pub {
				egales = append(egales, kid)
				pointeursEgaux = append(pointeursEgaux, en.Pointeur)
			} else {
				differentes = append(differentes, kid)
				pointeursEcartes = append(pointeursEcartes, en.Pointeur)
			}
		}
	}
	switch {
	case len(differentes) > 0:
		r.Verification = commun.Nouvelle("N-3", commun.Echoue, commun.Aucune,
			commun.T(commun.JoindreListe(differentes, ", ", " et ")+" de cles.json différente(s) de l'ancre ("+strings.Join(pointeursEcartes, ", ")+")",
				commun.JoindreListe(differentes, ", ", " and ")+" in cles.json differ(s) from the anchor ("+strings.Join(pointeursEcartes, ", ")+")"), 6)
	case len(egales) > 0:
		for _, k := range egales {
			r.Confirmees[k] = true
		}
		r.Pointeurs = pointeursEgaux
		r.Verification = commun.Nouvelle("N-3", commun.Reussi, commun.Aucune,
			commun.T(commun.JoindreListe(egales, ", ", " et ")+" de cles.json "+commun.Pluriel(len(egales), "égale à la clé", "égales aux clés")+" de l'ancre ("+strings.Join(pointeursEgaux, ", ")+")",
				commun.JoindreListe(egales, ", ", " and ")+" in cles.json "+commun.Pluriel(len(egales), "equals the key", "equal the keys")+" of the anchor ("+strings.Join(pointeursEgaux, ", ")+")"), 6)
	default:
		r.Verification = commun.Nouvelle("N-3", commun.NonExecute, commun.AncreAbsente,
			commun.T("le fichier d'ancres ne donne aucune clé sous le key_id d'une clé qui signe dans le dossier", "the anchors file gives no key under the key_id of a key that signs in the dossier"), 6)
	}
	return r
}

// CleChainePour rend l'enregistreur de l'ancre de même triplet, ou nil.
func (a *Ancres) CleChainePour(org, journal, kid string) *Enregistreur {
	if a == nil {
		return nil
	}
	for i := range a.Enregistreurs {
		e := &a.Enregistreurs[i]
		if e.OrgID == org && e.JournalID == journal && e.KeyID == kid {
			return e
		}
	}
	return nil
}
