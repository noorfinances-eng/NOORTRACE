// Projection de la configuration ancrage-v0 (CT-5 EX-8.2) et source d'aléa
// des vecteurs (annexe A.2 : nonces dérivés d'étiquettes, gigues injectées).

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Prestataire est un prestataire projeté (EX-8.2).
type Prestataire struct {
	ID               string
	Role             string
	PolicyOID        *string
	Qualified        bool
	MinIntervalMs    int64
	RequestTimeoutMs int64
}

// Config est la projection d'EX-8.2 : les seules clés que le planificateur emploie.
type Config struct {
	CheckpointIntervalS       int64
	Providers                 []*Prestataire
	ManifestFallbackAfterS    int64
	CheckpointsIntervalS      int64
	ProviderRole              string
	CheckpointsFallbackAfterS int64
	CountersignIdle           bool
	Fraicheur                 Fraicheur
	Retry                     Reprise
	RegistryCheckpoints       string
	SquatWaitS                int64
	InclusionAlertS           int64
	OtsEnabled                bool
	Calendars                 []string
	MinResponses              int64
	OtsTimeoutMs              int64
	OtsCheckpoint             string
	UpgradeFirstAfterS        int64
	UpgradeIntervalS          int64
	UpgradeGiveUpAfterS       int64
	MaxPending                int64
	AnchorPendingAlertS       int64
}

// ProjeterConfiguration applique les valeurs par défaut d'EX-8.2 à un
// document ancrage-v0 ou à une projection.
func ProjeterConfiguration(doc *Value) *Config {
	r := doc.Get("rfc3161")
	o := doc.Get("opentimestamps")
	c := &Config{
		CheckpointIntervalS:       entierOu(doc, 60, "checkpoint_interval_s"),
		ManifestFallbackAfterS:    entierOu(r, 300, "manifest", "fallback_after_s"),
		CheckpointsIntervalS:      entierOu(r, 300, "checkpoints", "interval_s"),
		ProviderRole:              chaineOu(r, "principal", "checkpoints", "provider_role"),
		CheckpointsFallbackAfterS: entierOu(r, 120, "checkpoints", "fallback_after_s"),
		CountersignIdle:           booleenOu(r, false, "checkpoints", "countersign_idle"),
		Fraicheur:                 Fraicheur{MaxResponseDelayS: entierOu(r, 60, "freshness", "max_response_delay_s"), ClockToleranceS: entierOu(r, 120, "freshness", "clock_tolerance_s")},
		Retry:                     Reprise{InitialMs: nombreOu(r, 5000, "retry", "initial_ms"), Factor: nombreOu(r, 2, "retry", "factor"), MaxMs: nombreOu(r, 300000, "retry", "max_ms"), JitterMs: entierOu(r, 250, "retry", "jitter_ms")},
		RegistryCheckpoints:       chaineOu(doc, "nouveaux_evenements", "registry", "checkpoints"),
		SquatWaitS:                entierOu(doc, 5, "registry", "squat_wait_s"),
		InclusionAlertS:           entierOu(doc, 60, "registry", "inclusion_alert_s"),
		OtsEnabled:                booleenOu(o, true, "enabled"),
		Calendars:                 chainesDe(o, "calendars"),
		MinResponses:              entierOu(o, 2, "min_responses"),
		OtsTimeoutMs:              entierOu(o, 5000, "timeout_ms"),
		OtsCheckpoint:             chaineOu(o, "aucun", "checkpoint"),
		UpgradeFirstAfterS:        entierOu(o, 21600, "upgrade", "first_after_s"),
		UpgradeIntervalS:          entierOu(o, 1800, "upgrade", "interval_s"),
		UpgradeGiveUpAfterS:       entierOu(o, 1209600, "upgrade", "give_up_after_s"),
		MaxPending:                entierOu(doc, 100000, "queue", "max_pending"),
		AnchorPendingAlertS:       entierOu(doc, 7200, "queue", "anchor_pending_alert_s"),
	}
	if c.Calendars == nil {
		c.Calendars = []string{}
	}
	if ps := champ(r, "providers"); ps != nil && ps.Kind == KindArray {
		for _, p := range ps.Arr {
			q := p.Get("qualified")
			pr := &Prestataire{ID: chaineOu(p, "", "id"), Role: chaineOu(p, "", "role"), PolicyOID: ptrChaine(p, "policy_oid"), Qualified: q != nil && q.Kind != KindNull && !(q.Kind == KindBool && !q.Bool), MinIntervalMs: entierOu(p, 0, "min_interval_ms"), RequestTimeoutMs: entierOu(p, 10000, "request_timeout_ms")}
			c.Providers = append(c.Providers, pr)
		}
	}
	return c
}

// Aleatoire fournit les nonces et les gigues (EX-8.13).
type Aleatoire interface {
	NonceTsa(sujet *Sujet, n int64) *big.Int
	NonceOts(sujet *Sujet) []byte
	Gigue() int64
}

// JournalIDOf rend keccak256(UTF-8(nom)) en 0x (CT-1 §13).
func JournalIDOf(nom string) string { return "0x" + hex.EncodeToString(Keccak256([]byte(nom))) }

// JournauxVecteurs nomme les journaux des vecteurs par journal_id.
var JournauxVecteurs = map[string]string{JournalIDOf("journal-principal"): "journal-principal", JournalIDOf("journal-sinistres"): "journal-sinistres"}

// NomJournalVecteurs rend le nom d'un journal des vecteurs.
func NomJournalVecteurs(journalID string) string {
	nom, ok := JournauxVecteurs[journalID]
	if !ok {
		panic(refus("", "journal_id %s inconnu des vecteurs (journal-principal ou journal-sinistres attendus)", journalID))
	}
	return nom
}

// Étiquettes de dérivation des vecteurs (annexe A.2).
func EtiquetteNonceTsa(journal, sorte, hash string, n int64) string {
	return fmt.Sprintf("noortrace/vecteurs/v0/ct-5/nonce-tsa/%s/%s/%s/%d", journal, sorte, hash[2:], n)
}
func EtiquetteNonceOts(journal, sorte, hash string) string {
	return fmt.Sprintf("noortrace/vecteurs/v0/ct-5/ots/nonce/%s/%s/%s", journal, sorte, hash[2:])
}
func EtiquetteCalendrier(calendrier, journal, sorte, hash string) string {
	return fmt.Sprintf("noortrace/vecteurs/v0/ct-5/ots/calendrier/%s/%s/%s/%s", calendrier, journal, sorte, hash[2:])
}

// NonceDepuisEtiquette rend les 64 premiers bits de SHA-256(UTF-8(étiquette)).
func NonceDepuisEtiquette(etiquette string) *big.Int {
	s := sha256.Sum256([]byte(etiquette))
	return new(big.Int).SetBytes(s[:8])
}

// OctetsDepuisEtiquette rend les n premiers octets de SHA-256(UTF-8(étiquette)).
func OctetsDepuisEtiquette(etiquette string, n int) []byte {
	s := sha256.Sum256([]byte(etiquette))
	return append([]byte{}, s[:n]...)
}

// AleatoireVecteurs dérive les nonces des étiquettes d'A.2 et sert les
// gigues de la trace dans l'ordre (jitter_ms, EX-8.9).
type AleatoireVecteurs struct {
	Gigues []int64
	i      int
}

func (a *AleatoireVecteurs) NonceTsa(s *Sujet, n int64) *big.Int {
	return NonceDepuisEtiquette(EtiquetteNonceTsa(NomJournalVecteurs(s.JournalID), s.Kind, s.Hash, n))
}
func (a *AleatoireVecteurs) NonceOts(s *Sujet) []byte {
	return OctetsDepuisEtiquette(EtiquetteNonceOts(NomJournalVecteurs(s.JournalID), s.Kind, s.Hash), 16)
}
func (a *AleatoireVecteurs) Gigue() int64 {
	if a.i >= len(a.Gigues) {
		panic(refus("", "gigue injectée épuisée (jitter_ms porte %d valeur(s))", len(a.Gigues)))
	}
	g := a.Gigues[a.i]
	a.i++
	return g
}

// IdentifiantCorrelation rend l'attempt_id d'EX-5.13 : <kind>:<16 premiers hex>:<n>.
func IdentifiantCorrelation(kind, hash string, n int64) string {
	return fmt.Sprintf("%s:%s:%d", kind, hash[2:18], n)
}

// DocTypes des ancres (CT-4 §6.4) : keccak256 des étiquettes.
var (
	DocTypePeriode         = "0x" + hex.EncodeToString(Keccak256([]byte("noortrace/periode/v0")))
	DocTypePointDeControle = "0x" + hex.EncodeToString(Keccak256([]byte("noortrace/point-de-controle/v0")))
)

// EmpreinteAncre calcule keccak256(org_id ‖ journal_id ‖ hash) en 0x (CT-5 §9.1).
func EmpreinteAncre(orgID, journalID, hash string) string {
	o, _ := hex.DecodeString(orgID[2:])
	j, _ := hex.DecodeString(journalID[2:])
	h, _ := hex.DecodeString(hash[2:])
	return "0x" + hex.EncodeToString(AnchorFingerprint(o, j, h))
}
