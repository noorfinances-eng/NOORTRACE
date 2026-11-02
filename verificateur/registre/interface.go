// Paquet registre : contrôle 8 de CT-6, inclusion des transactions du
// registre dans des blocs certifiés par un quorum (section 11,
// vérifications R-1 à R-11), vérification N-4 de la clé de chaîne
// (EX-12.5) et K-8, référence au registre d'un point de contrôle du journal
// (EX-11.25).
//
// Ce fichier fixe l'interface que le moteur appelle. Elle est stable : le
// développeur du contrôle 8 remplace l'implémentation provisoire
// (provisoire.go) sans changer ces types ni ces signatures. Le contrat
// complet est dans INTERFACES.md, section « Contrôle 8 ».
package registre

import (
	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// Partie : une partie du dossier telle que l'index la déclare et que le
// moteur l'a lue (limites d'EX-4.13 : 64 Mio pour registre.json et
// certificat-commit.json, 1 Mio pour validateurs.json).
type Partie struct {
	// Presente : l'index déclare la partie présente.
	Presente bool
	// RaisonAbsence : reason_if_absent de l'index quand Presente est faux
	// (« hors périmètre CT-1 » donne hors_perimetre_version, toute autre
	// raison partie_absente, EX-4.3 ; utile à R-3, EX-11.12).
	RaisonAbsence string
	// Etat : état de la lecture quand Presente : entree.Lu, entree.TropGrand
	// (partie inexploitable : R-1 ou R-3 échoue, EX-4.11), entree.Absent ou
	// entree.Illisible (D-2 porte l'échec ; R-1 ou R-3 non_execute
	// prerequis_en_echec).
	Etat entree.Etat
	// Octets : octets lus (Etat == entree.Lu).
	Octets []byte
}

// Manifeste : valeurs du manifeste dont R-9, R-10 et N-4 ont besoin ; Valide
// faux quand P-1 n'a pas réussi (R-9, R-10 non_execute prerequis_en_echec ;
// N-4 ne figure pas, EX-5.4, EX-12.5).
type Manifeste struct {
	Valide bool
	// PeriodHash : periodHash recalculé (jamais manifeste.sig.period_hash).
	PeriodHash [32]byte
	// Champs de manifeste.json (hexadécimal « 0x » minuscule, entiers).
	OrgID, JournalID, Root     string
	PeriodStart, PeriodEnd     int64
	FirstSeq, LastSeq, Version int64
	// RecorderKeyID : recorder_key_id du manifeste (clé dont R-10 cherche
	// l'inscription et dont N-4 compare la clé de chaîne).
	RecorderKeyID string
}

// ReferencePoint : anchors.registry de points-de-controle.json (CT-1 §11.2),
// entiers de la section 3 de CT-1.
type ReferencePoint struct {
	ChainID         int64
	Contract        string
	Fingerprint     string
	DocType         string
	BlockNumber     int64
	BlockHash       string
	TransactionHash string
	LogIndex        int64
}

// Point : la partie points-de-controle.json quand elle est déclarée présente
// et que K-1 a réussi ; nil sinon (le moteur rend alors K-8 non_execute,
// prerequis_en_echec, sans appeler ce paquet pour K-8).
type Point struct {
	// K2 : K-2 a réussi ; CheckpointHash est alors le checkpoint_hash
	// recalculé. Sans K-2, K-8 et la règle 2 de R-11 sont non_execute,
	// prerequis_en_echec (EX-11.24, EX-11.25).
	K2             bool
	CheckpointHash [32]byte
	// KeyID : key_id du point (règle 3 de R-11).
	KeyID string
	// Reference : anchors.registry, ou nil quand il vaut null (K-8 est alors
	// non_execute, partie_absente, posé par le moteur).
	Reference *ReferencePoint
}

// Entree : tout ce que le contrôle 8 peut lire.
type Entree struct {
	// Registre, Certificat, Validateurs : les trois parties du contrôle 8.
	// Le moteur n'appelle Verifier avec Registre ou Certificat absents que
	// pour K-8 (référence au registre d'un point) : aucune R- ni N-4 ne
	// figure alors (EX-5.6), et K-8 rend inclusion « declarative ».
	Registre, Certificat, Validateurs Partie
	// Ancres : le fichier d'ancres (registry, recorders), ou nil.
	Ancres *ancres.Ancres
	// Manifeste : voir le type.
	Manifeste Manifeste
	// ClesExploitables : cles.json remplit la première partie de E-8
	// (EX-11.19 : sinon R-10 non_execute prerequis_en_echec) ; Cles : ses
	// clés.
	ClesExploitables bool
	Cles             []ancres.CleDossier
	// OrgID, JournalID : ceux de l'événement prouvé (empreinte du point,
	// EX-11.24 règle 2, EX-11.25).
	OrgID, JournalID string
	// Point : voir le type.
	Point *Point
	// PointDeclare : l'index déclare la partie points-de-controle.json
	// présente, que K-1 ait réussi ou non. Point est nil quand K-1 a échoué :
	// R-11 figure alors quand même (EX-6.18), non exécutée, avec la raison
	// prerequis_en_echec si registre.json porte une entrée
	// ancre_point_de_controle, partie_absente sinon (vecteurs
	// invalide-k1-double-defaut et invalide-k1-partie-inexploitable).
	PointDeclare bool
}

// Inscription : une inscription de clé d'enregistreur prouvée par R-10
// réussie, dans un contrôle 8 qui réussit (provenance « registre »,
// EX-6.8 ; clause FP).
type Inscription struct {
	// ClePublique : clé Ed25519 inscrite, « 0x » + 64 hexadécimaux.
	ClePublique string
	// CleChaine : adresse de la clé de chaîne inscrite.
	CleChaine string
	// Bloc : hauteur du bloc de l'inscription.
	Bloc int64
}

// Resultat : ce que le contrôle 8 rend au moteur.
type Resultat struct {
	// Verifications : R-1 à R-11, toutes les onze, dans l'ordre, chacune
	// avec Controles = []int{8}, quand registre.json et
	// certificat-commit.json sont déclarés présents ; vide sinon (EX-5.6).
	Verifications []commun.Verification
	// N4 : la vérification N-4 (Controles = []int{8}) quand elle figure
	// (EX-12.5 : P-1 réussie, chain_key non nulle dans l'ancre pour la clé
	// du manifeste, parties du contrôle 8 présentes), nil sinon ; voir
	// N4Figure.
	N4 *commun.Verification
	// K8 : la vérification K-8 (Controles = []int{8}) quand Entree.Point
	// porte une Reference et que K-2 a réussi ; nil sinon.
	K8 *commun.Verification
	// Statut, Raison : statut du contrôle 8 selon EX-11.20 (K-8 et N-4 en
	// échec le font échouer ; R-3, R-10, R-11, K-8 et N-4 non exécutées
	// n'empêchent pas la réussite), quand les parties sont présentes. Quand
	// elles ne le sont pas, le moteur pose la raison d'EX-4.3 et ignore ces
	// champs, sauf un échec de K-8.
	Statut commun.Statut
	Raison commun.Raison
	// Faits : valeurs d'EX-11.21 (facts.registry), non nil si et seulement
	// si Statut vaut reussi.
	Faits *Faits
	// FaitsPoint : valeurs d'EX-11.25 (facts.checkpoint.registry), non nil
	// si et seulement si K8 a réussi ; Inclusion vaut « prouvee » si R-11 a
	// réussi en rattachant la référence dans un contrôle 8 réussi,
	// « declarative » sinon (et AV-K-1 est levé).
	FaitsPoint *FaitsAncrePoint
	// Inscriptions : les inscriptions que R-10 réussie prouve, quand le
	// contrôle 8 réussit ; vide sinon.
	Inscriptions []Inscription
	// Avertissements : AV-R-1 à AV-R-3, AV-K-1, AV-K-3, dans l'ordre
	// d'EX-6.15, avec Verification = l'identifiant qui le lève (R-n, K-8).
	Avertissements []commun.Avertissement
	// AncresEmployees : « /registry », pointeurs des jeux retenus par R-2
	// (« /registry/validator_sets/0 ») et de l'enregistreur comparé par N-4
	// (« /recorders/1 »).
	AncresEmployees []string
	// Resume : summary du contrôle 8, par exemple « noortrace-2124-dev :
	// inscriptions blocs 16648 et 16652, ancre bloc 16660, clôture bloc
	// 16668, 3 validateurs sur 4 à chaque bloc ».
	Resume commun.Texte
	// Proposition : proposition d'EX-11.22 (avec les mentions de R-10 et de
	// N-4 et la proposition de signature), sans « ; » de tête, quand Statut
	// vaut reussi ; fragment F6.
	Proposition commun.Texte
}

// Entree de facts.registry.entries (EX-11.21).
type EntreeFaits struct {
	// Role : « cloture », « ancre », « inscription » ou
	// « ancre_point_de_controle ».
	Role                    string `json:"role"`
	BlockNumber             int64  `json:"block_number"`
	BlockHash               string `json:"block_hash"`
	BlockTime               string `json:"block_time"`
	TransactionIndex        int64  `json:"transaction_index"`
	TransactionHashDeclared string `json:"transaction_hash_declared"`
	Emitter                 string `json:"emitter"`
	// Event : valeurs décodées d'EX-11.9 ; une valeur des types
	// EvenementCloture, EvenementAncre ou EvenementInscription.
	Event any `json:"event"`
}

// EvenementCloture : journal PeriodSubmitted décodé.
type EvenementCloture struct {
	Name        string `json:"name"` // « PeriodSubmitted »
	ID          int64  `json:"id"`
	PeriodHash  string `json:"periodHash"`
	OrgID       string `json:"orgId"`
	JournalID   string `json:"journalId"`
	Root        string `json:"root"`
	PeriodStart int64  `json:"periodStart"`
	PeriodEnd   int64  `json:"periodEnd"`
	FirstSeq    int64  `json:"firstSeq"`
	LastSeq     int64  `json:"lastSeq"`
	Version     int64  `json:"version"`
	Publisher   string `json:"publisher"`
	URI         string `json:"uri"`
	PublishedAt int64  `json:"publishedAt"`
}

// EvenementAncre : journal Anchored décodé (rôles ancre et
// ancre_point_de_controle).
type EvenementAncre struct {
	Name        string `json:"name"` // « Anchored »
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	DocType     string `json:"docType"`
}

// EvenementInscription : journal RecorderRegistered décodé.
type EvenementInscription struct {
	Name          string `json:"name"` // « RecorderRegistered »
	OrgID         string `json:"orgId"`
	ChainKey      string `json:"chainKey"`
	JournalID     string `json:"journalId"`
	Ed25519PubKey string `json:"ed25519PubKey"`
	Publisher     string `json:"publisher"`
}

// CertificatFaits : facts.registry.certificates (EX-11.21).
type CertificatFaits struct {
	Height     int64    `json:"height"`
	ValsetHash string   `json:"valset_hash"`
	SetSource  string   `json:"set_source"`
	SetSize    int      `json:"set_size"`
	Quorum     int      `json:"quorum"`
	Signers    []string `json:"signers"`
}

// Faits : facts.registry (EX-11.21), ordre du schéma.
type Faits struct {
	ChainID      string            `json:"chain_id"`
	Entries      []EntreeFaits     `json:"entries"`
	Certificates []CertificatFaits `json:"certificates"`
}

// FaitsAncrePoint : facts.checkpoint.registry (EX-11.25), ordre du schéma
// (#/$defs/faits_ancre_registre_point).
type FaitsAncrePoint struct {
	ChainIDDeclared         int64  `json:"chain_id_declared"`
	Contract                string `json:"contract"`
	Fingerprint             string `json:"fingerprint"`
	DocType                 string `json:"doc_type"`
	BlockNumber             int64  `json:"block_number"`
	BlockHash               string `json:"block_hash"`
	TransactionHashDeclared string `json:"transaction_hash_declared"`
	LogIndex                int64  `json:"log_index"`
	// Inclusion : « prouvee » ou « declarative ».
	Inclusion string `json:"inclusion"`
	// BlockTime, Issuer : nil sauf inclusion prouvée.
	BlockTime *string `json:"block_time"`
	Issuer    *string `json:"issuer"`
}

// IDs : les vérifications R-, dans l'ordre du rapport.
var IDs = []string{"R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "R-11"}

// DocTypePoint : docType d'un point de contrôle du journal (CT-1 §10.6).
const DocTypePoint = "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178"

// PartiesPresentes dit si les deux parties requises du contrôle 8 sont
// déclarées présentes (EX-11.20).
func (e Entree) PartiesPresentes() bool { return e.Registre.Presente && e.Certificat.Presente }

// N4Figure dit si N-4 figure au rapport (EX-12.5, EX-5.6) : P-1 réussie,
// une chain_key non nulle dans l'ancre pour la clé du manifeste (mêmes
// org_id, journal_id, key_id), parties du contrôle 8 présentes.
func (e Entree) N4Figure() bool {
	if !e.Manifeste.Valide || !e.PartiesPresentes() {
		return false
	}
	en := e.Ancres.CleChainePour(e.Manifeste.OrgID, e.Manifeste.JournalID, e.Manifeste.RecorderKeyID)
	return en != nil && en.CleChaine != ""
}

// Verifier exécute le contrôle 8 (et K-8).
func Verifier(e Entree) Resultat { return verifier(e) }

// Construit dit si l'implémentation de ce contrôle est construite. Le
// fichier provisoire.go fixe la constante construit à faux ; l'implémentation
// réelle la fixe à vrai. Les tests de rejeu des vecteurs s'en servent : un
// dossier dont l'attendu dépend de ce contrôle reste « en attente » tant
// qu'elle vaut faux, et il est rejoué en entier dès qu'elle vaut vrai.
func Construit() bool { return construit }
