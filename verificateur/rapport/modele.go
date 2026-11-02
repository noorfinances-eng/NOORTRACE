// Paquet rapport : le rapport de vérification `rapport-verification-v0`
// (CT-6 §8.6), sa forme lisible (§8.5), l'énoncé (§6.5) et la borne (§6.6).
//
// Les types de ce fichier suivent, champ par champ et dans l'ordre, le
// schéma rapport-verification-v0 : encoding/json écrit les champs dans
// l'ordre de déclaration, ce qui donne la mise en forme d'EX-8.7.
package rapport

import (
	"bytes"
	"encoding/json"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/ots"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
)

// Format et version du rapport.
const (
	Format  = "noortrace/rapport-verification"
	Version = 0
)

// Schema : identifiant et SHA-256 d'un schéma embarqué.
type Schema struct {
	ID     string `json:"id"`
	Sha256 string `json:"sha256"`
}

// Verificateur : verifier (EX-8.7, EX-14.3).
type Verificateur struct {
	Name           string   `json:"name"`
	Implementation string   `json:"implementation"`
	Version        string   `json:"version"`
	Runtime        string   `json:"runtime"`
	Schemas        []Schema `json:"schemas"`
}

// EntreeDossier : inputs.dossier.
type EntreeDossier struct {
	Path        string  `json:"path"`
	IndexSha256 *string `json:"index_sha256"`
}

// FichierLu : inputs.anchors, bitcoin_headers, second_manifest.
type FichierLu struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

// EntreePieces : inputs.pieces.
type EntreePieces struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
}

// Entrees : inputs.
type Entrees struct {
	Dossier          EntreeDossier `json:"dossier"`
	Anchors          *FichierLu    `json:"anchors"`
	BitcoinHeaders   *FichierLu    `json:"bitcoin_headers"`
	SecondManifest   *FichierLu    `json:"second_manifest"`
	Pieces           *EntreePieces `json:"pieces"`
	RequiredControls []int         `json:"required_controls"`
}

// Evenement : event.
type Evenement struct {
	Seq  int64   `json:"seq"`
	Hash string  `json:"hash"`
	Ts   string  `json:"ts"`
	Tool *string `json:"tool"`
}

// Periode : period.
type Periode struct {
	PeriodStart int64  `json:"period_start"`
	PeriodEnd   int64  `json:"period_end"`
	PeriodHash  string `json:"period_hash"`
}

// Controle : une entrée de controls.
type Controle struct {
	Number      int            `json:"number"`
	Status      commun.Statut  `json:"status"`
	Reason      *commun.Raison `json:"reason"`
	Checks      []string       `json:"checks"`
	AnchorsUsed []string       `json:"anchors_used"`
	Summary     *string        `json:"summary"`
	// ResumeBilingue : summary dans les deux langues (rapport lisible).
	ResumeBilingue commun.Texte `json:"-"`
}

// Verification : une entrée de checks.
type Verification struct {
	ID       string         `json:"id"`
	Controls []int          `json:"controls"`
	Status   commun.Statut  `json:"status"`
	Reason   *commun.Raison `json:"reason"`
	Admitted *bool          `json:"admitted"`
	Detail   *string        `json:"detail"`
	// DetailBilingue : détail dans les deux langues (rapport lisible).
	DetailBilingue commun.Texte `json:"-"`
}

// PartieAbsente : une entrée de absent_parts.
type PartieAbsente struct {
	Name   string  `json:"name"`
	File   string  `json:"file"`
	Reason *string `json:"reason"`
}

// Avertissement : une entrée de warnings.
type Avertissement struct {
	ID     string  `json:"id"`
	Check  *string `json:"check"`
	Detail string  `json:"detail"`
	// DetailBilingue : détail dans les deux langues.
	DetailBilingue commun.Texte `json:"-"`
}

// FaitsCles : facts.recorder_keys.
type FaitsCles struct {
	EventKeyID        string `json:"event_key_id"`
	ManifestKeyID     string `json:"manifest_key_id"`
	Source            string `json:"source"`
	EventKeySource    string `json:"event_key_source"`
	ManifestKeySource string `json:"manifest_key_source"`
}

// FaitsApprobation : facts.approval.
type FaitsApprobation struct {
	Decision  string   `json:"decision"`
	Ticket    string   `json:"ticket"`
	Approvers []string `json:"approvers"`
	Required  int64    `json:"required"`
	Size      int64    `json:"size"`
	SetSource string   `json:"set_source"`
}

// Coherence : facts.checkpoint.consistency.
type Coherence struct {
	FirstSize  int64 `json:"first_size"`
	SecondSize int64 `json:"second_size"`
	PathLength int   `json:"path_length"`
}

// FaitsPoint : facts.checkpoint (EX-6.17).
type FaitsPoint struct {
	TreeSize         int64                     `json:"tree_size"`
	LastSeq          int64                     `json:"last_seq"`
	LeafIndex        int64                     `json:"leaf_index"`
	CheckpointTs     string                    `json:"checkpoint_ts"`
	CheckpointHash   string                    `json:"checkpoint_hash"`
	KeyID            string                    `json:"key_id"`
	KeySource        string                    `json:"key_source"`
	Consistency      Coherence                 `json:"consistency"`
	LastHashChecked  bool                      `json:"last_hash_checked"`
	Timestamp        *horodatage.Faits         `json:"timestamp"`
	Bitcoin          *ots.Faits                `json:"bitcoin"`
	Registry         *registre.FaitsAncrePoint `json:"registry"`
	RewriteWindowEnd *string                   `json:"rewrite_window_end"`
	RewriteWindowMs  *int64                    `json:"rewrite_window_ms"`
}

// InscriptionPerimetre : facts.perimeter.inscription.
type InscriptionPerimetre struct {
	Seq               int64  `json:"seq"`
	Hash              string `json:"hash"`
	Ts                string `json:"ts"`
	KeyID             string `json:"key_id"`
	PolicyVersion     string `json:"policy_version"`
	PolicySha256      string `json:"policy_sha256"`
	SamePolicyVersion bool   `json:"same_policy_version"`
}

// FaitsPerimetre : facts.perimeter (EX-6.20).
type FaitsPerimetre struct {
	Provenance          string                `json:"provenance"`
	Digest              string                `json:"digest"`
	OrgID               string                `json:"org_id"`
	JournalIDs          []string              `json:"journal_ids"`
	ValidFrom           string                `json:"valid_from"`
	ValidUntil          string                `json:"valid_until"`
	IssuedAt            string                `json:"issued_at"`
	Signers             []string              `json:"signers"`
	Required            int64                 `json:"required"`
	Size                int64                 `json:"size"`
	SetSource           string                `json:"set_source"`
	Agents              int                   `json:"agents"`
	CaptureChannels     []string              `json:"capture_channels"`
	Exceptions          int                   `json:"exceptions"`
	EgressDefaultPolicy string                `json:"egress_default_policy"`
	EgressRulesSha256   string                `json:"egress_rules_sha256"`
	Inscription         *InscriptionPerimetre `json:"inscription"`
}

// Faits : facts (EX-6.13).
type Faits struct {
	RecorderKeys *FaitsCles        `json:"recorder_keys"`
	Approval     *FaitsApprobation `json:"approval"`
	Timestamp    *horodatage.Faits `json:"timestamp"`
	Bitcoin      *ots.Faits        `json:"bitcoin"`
	Registry     *registre.Faits   `json:"registry"`
	Checkpoint   *FaitsPoint       `json:"checkpoint"`
	Perimeter    *FaitsPerimetre   `json:"perimeter"`
}

// Enonce : statement.
type Enonce struct {
	Fr string `json:"fr"`
	En string `json:"en"`
}

// Rapport : rapport de vérification (codes 0, 1 et 3).
type Rapport struct {
	Format             string          `json:"format"`
	Version            int             `json:"version"`
	Verifier           Verificateur    `json:"verifier"`
	Language           string          `json:"language"`
	Inputs             Entrees         `json:"inputs"`
	Event              *Evenement      `json:"event"`
	OrgID              *string         `json:"org_id"`
	JournalID          *string         `json:"journal_id"`
	Period             *Periode        `json:"period"`
	Controls           []Controle      `json:"controls"`
	Checks             []Verification  `json:"checks"`
	FailedChecks       []string        `json:"failed_checks"`
	BlockingUnexecuted []string        `json:"blocking_unexecuted"`
	AbsentParts        []PartieAbsente `json:"absent_parts"`
	Warnings           []Avertissement `json:"warnings"`
	Facts              Faits           `json:"facts"`
	Verdict            string          `json:"verdict"`
	ExitCode           int             `json:"exit_code"`
	Statement          Enonce          `json:"statement"`
	Bound              *string         `json:"bound"`

	// Données du rapport lisible, absentes du JSON.
	Lisible DonneesLisibles `json:"-"`
}

// DonneesLisibles : lignes du rapport lisible qui ne figurent pas telles
// quelles dans le JSON (EX-8.6, EX-8.8, EX-8.10).
type DonneesLisibles struct {
	BorneBilingue *commun.Texte
	// LignePoint : ligne « Pt de contrôle », ou nil.
	LignePoint *commun.Texte
	// LignePerimetre : ligne « Périmètre », ou nil.
	LignePerimetre *commun.Texte
	// ResultatExige : contrôles exigés non réussis (INCOMPLET).
	ExigesNonReussis []int
}

// ErreurRapport : error d'un rapport d'erreur.
type ErreurRapport struct {
	Kind    string  `json:"kind"`
	Message string  `json:"message"`
	Check   *string `json:"check"`
}

// RapportErreur : rapport d'erreur (code 2).
type RapportErreur struct {
	Format   string        `json:"format"`
	Version  int           `json:"version"`
	Verifier Verificateur  `json:"verifier"`
	Language string        `json:"language"`
	Inputs   *Entrees      `json:"inputs"`
	Verdict  *string       `json:"verdict"`
	ExitCode int           `json:"exit_code"`
	Error    ErreurRapport `json:"error"`
}

// EncoderJSON sérialise un rapport, indenté de deux espaces, sans
// échappement HTML, suivi d'un saut de ligne.
func EncoderJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
