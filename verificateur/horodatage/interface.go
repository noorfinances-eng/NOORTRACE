// Paquet horodatage : contrôle 4 de CT-6, jeton d'horodatage RFC 3161 sur
// periodHash (section 9, vérifications T-1 à T-11), et sa réutilisation par
// K-7 sur le checkpoint_hash d'un point de contrôle du journal (section 9.9).
//
// Ce fichier fixe l'interface que le moteur appelle. Elle est stable : le
// développeur du contrôle 4 remplace l'implémentation provisoire
// (provisoire.go) sans changer ces types ni ces signatures. Le contrat
// complet est dans INTERFACES.md, section « Contrôle 4 ».
package horodatage

import (
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// Usage : sur quoi porte le jeton.
type Usage int

const (
	// Cloture : jeton de la partie jeton-rfc3161.der, sur periodHash
	// (contrôle 4).
	Cloture Usage = iota
	// Point : jeton embarqué dans points-de-controle.json, sur
	// checkpoint_hash (K-7, EX-9.22).
	Point
)

// Entree : tout ce que la vérification d'un jeton peut lire. Le paquet ne lit
// aucun fichier, aucune variable d'environnement, ni l'horloge du système
// (EX-3.2, EX-3.3).
type Entree struct {
	// Usage : Cloture (contrôle 4) ou Point (K-7).
	Usage Usage
	// Jeton : octets DER du TimeStampToken, tels que lus (jamais réencodés,
	// EX-9.6). Pour Cloture, ce sont les octets de jeton-rfc3161.der lus
	// dans la limite de 64 Kio ; pour Point, les octets décodés du base64
	// canonique (le moteur a déjà refusé un base64 non canonique ou de plus
	// de 64 Kio décodés : K-7 échoue alors sans appel, EX-9.22).
	Jeton []byte
	// Etat : état de la lecture de la partie (Cloture seulement) :
	// entree.Lu ; entree.TropGrand (plus de 64 Kio : T-1 échoue, EX-9.3) ;
	// entree.Absent ou entree.Illisible (fichier déclaré présent mais absent
	// ou illisible : l'échec est porté par D-2, T-1 est non_execute,
	// prerequis_en_echec). Toujours entree.Lu pour Point.
	Etat entree.Etat
	// EmpreinteAttendue : periodHash recalculé depuis manifeste.json
	// (Cloture, EX-5.4, EX-9.1) ou checkpoint_hash recalculé par K-2
	// (Point, EX-9.22). Jamais une valeur lue dans le jeton ou l'index.
	EmpreinteAttendue [32]byte
	// EmpreinteDisponible : faux quand P-1 (Cloture) ou K-2 (Point) n'a pas
	// réussi ; T-2 est alors non_execute, prerequis_en_echec, et les autres
	// T- s'exécutent (EX-5.4).
	EmpreinteDisponible bool
	// Ancres : le fichier d'ancres du réviseur, contrôlé par N-1, ou nil
	// sans --ancres. Seuls Autorites, CRLs et Declarations servent ici
	// (section 12). Les certificats et CRL sont en DER.
	Ancres *ancres.Ancres
	// TsEvenement : ts de l'événement prouvé (AV-T-4, et AV-T-4 du jeton du
	// point, EX-9.22) ; TsDisponible faux si evenement.json est
	// inexploitable.
	TsEvenement  time.Time
	TsDisponible bool
	// CheckpointTs : checkpoint_ts du point (Point seulement), pour AV-K-2
	// et AV-K-4 (section 9.9).
	CheckpointTs time.Time
}

// Resultat : ce que la vérification d'un jeton rend au moteur.
type Resultat struct {
	// Verifications : T-1 à T-11, toutes les onze, dans l'ordre, chacune
	// avec Controles = []int{4}, statut, raison de la liste fermée (6.2) et
	// détail. Le moteur les place telles quelles dans `checks` (Cloture)
	// ou les résume dans le détail de K-7 (Point).
	Verifications []commun.Verification
	// Statut, Raison : statut d'EX-9.18 calculé sur ces onze résultats
	// (echoue si l'une de T-1 à T-10 échoue ; sinon non_execute avec la
	// raison qu'EX-6.5 choisit parmi celles de T-1 à T-10 ; sinon reussi ;
	// T-11 n'y entre pas). Pour Cloture, c'est le statut du contrôle 4 avant
	// que le moteur n'y ajoute K-7 ; pour Point, c'est le statut de K-7.
	Statut commun.Statut
	Raison commun.Raison
	// Faits : valeurs d'EX-9.19, non nil si et seulement si Statut vaut
	// reussi (facts.timestamp, ou facts.checkpoint.timestamp pour Point).
	Faits *Faits
	// Avertissements : AV-T-1 à AV-T-4, dans l'ordre d'EX-6.15, avec
	// Verification = l'identifiant T- qui le lève ; pour Point, s'y
	// ajoutent AV-K-2 et AV-K-4 (Verification = « K-7 »). Le moteur
	// remplace Verification par « K-7 » pour tous les avertissements d'un
	// jeton de point (EX-9.22).
	Avertissements []commun.Avertissement
	// AncresEmployees : pointeurs JSON (RFC 6901) de l'autorité retenue par
	// T-7 et des CRL retenues par T-10 (« /tsa_authorities/0 »,
	// « /revocation/crls/0 »), dans l'ordre du fichier ; anchors_used du
	// contrôle 4 (EX-9.22 : ceux du jeton du point s'y ajoutent).
	AncresEmployees []string
	// Resume : summary du contrôle 4 dans les deux langues, par exemple
	// « selon AC de test CT-6 (unité TSA de test CT-6), au plus tard
	// 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré ». Vide si le
	// paquet n'a rien à dire (le moteur écrit alors la liste des
	// vérifications en échec ou non exécutées).
	Resume commun.Texte
	// Proposition : la proposition d'EX-9.20, sans « ; » de tête, quand
	// Statut vaut reussi ; le moteur l'insère comme fragment F4. Vide pour
	// Point (la clause jeton de FK est construite par le moteur depuis
	// Faits, EX-6.16).
	Proposition commun.Texte
}

// Precision : accuracy de TSTInfo (EX-9.19). Un pointeur nil est écrit null.
type Precision struct {
	Seconds *int64 `json:"seconds"`
	Millis  *int64 `json:"millis"`
	Micros  *int64 `json:"micros"`
}

// Qualifie : statut qualifié déclaré par l'ancre et retenu par T-11.
type Qualifie struct {
	// Framework : « eidas » ou « zertes ».
	Framework string `json:"framework"`
	Source    string `json:"source"`
}

// Revocation : preuve de non-révocation retenue par T-10 pour un
// certificat du chemin.
type Revocation struct {
	CertificateSha256 string `json:"certificate_sha256"`
	// Evidence : « crl » ou « declaration ».
	Evidence string `json:"evidence"`
	// IssuedAt : thisUpdate de la CRL ou not_revoked_at de la déclaration,
	// au format d'EX-6.11.
	IssuedAt string `json:"issued_at"`
}

// Faits : valeurs rapportées du contrôle 4 (EX-9.19), dans l'ordre du schéma
// rapport-verification-v0 (#/$defs/faits_horodatage). Les instants sont au
// format d'EX-6.11 (commun.FormaterInstant), les hachages en « 0x »
// minuscule.
type Faits struct {
	Authority            string       `json:"authority"`
	TsuCertificateSha256 string       `json:"tsu_certificate_sha256"`
	TsuSubjectCN         *string      `json:"tsu_subject_cn"`
	GenTime              string       `json:"gen_time"`
	Accuracy             *Precision   `json:"accuracy"`
	UpperBound           *string      `json:"upper_bound"`
	Policy               string       `json:"policy"`
	SerialNumber         string       `json:"serial_number"`
	DigestAlgorithm      string       `json:"digest_algorithm"`
	SignatureAlgorithm   string       `json:"signature_algorithm"`
	KeyBits              int          `json:"key_bits"`
	QualifiedClaim       bool         `json:"qualified_claim"`
	Qualified            *Qualifie    `json:"qualified"`
	Revocation           []Revocation `json:"revocation"`
	// GenTimeInstant et UpperBoundInstant : les mêmes instants, décodés,
	// pour les calculs du moteur (rewrite_window_ms, AV-K-2). Non
	// sérialisés.
	GenTimeInstant    time.Time  `json:"-"`
	UpperBoundInstant *time.Time `json:"-"`
}

// IDs : les onze vérifications du contrôle 4, dans l'ordre du rapport.
var IDs = []string{"T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11"}

// Verifier vérifie un jeton (contrôle 4 ou K-7). Elle ne panique pas : une
// panique est néanmoins rattrapée par le moteur et rendue comme erreur
// interne (code 2, EX-15.2).
func Verifier(e Entree) Resultat { return verifier(e) }

// ControleurAncres applique le profil de lecture DER de §9.3 et EX-9.21
// (valeurs DEFAULT encodées, noms UTF8String et BMPString d'EX-9.4) aux
// certificats et aux CRL du fichier d'ancres, pour N-1 (EX-12.2). Une
// erreur rend le fichier d'ancres inutilisable (code 2,
// ancres_inutilisables, error.check = « N-1 ») ; son texte nomme le défaut.
// Le paquet ancres a déjà décodé le PEM, lu l'objet avec crypto/x509 et
// exigé un certificat X.509 v3.
type ControleurAncres struct{}

// Certificat contrôle un certificat du fichier d'ancres (DER).
func (ControleurAncres) Certificat(der []byte) error { return controlerCertificat(der) }

// CRL contrôle une CRL du fichier d'ancres (DER).
func (ControleurAncres) CRL(der []byte) error { return controlerCRL(der) }

// Construit dit si l'implémentation de ce contrôle est construite. Le
// fichier provisoire.go fixe la constante construit à faux ; l'implémentation
// réelle la fixe à vrai. Les tests de rejeu des vecteurs s'en servent : un
// dossier dont l'attendu dépend de ce contrôle reste « en attente » tant
// qu'elle vaut faux, et il est rejoué en entier dès qu'elle vaut vrai.
func Construit() bool { return construit }
