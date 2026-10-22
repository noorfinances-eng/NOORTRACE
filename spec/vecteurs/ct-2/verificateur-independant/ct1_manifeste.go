// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/manifeste.go).

// Manifeste de période v0 (CT-1 §10) : schéma manifeste-v0.schema.json
// transcrit en Go, periodHash = SHA-256(P_M || JCS(manifeste)), signature
// portée à côté (manifeste.sig), période vide à racine nulle, continuité.

package main

import (
	"bytes"
	"fmt"
	"time"
)

var clesManifeste = []string{"version", "org_id", "journal_id", "period_start", "period_end", "first_seq", "last_seq",
	"count", "root", "prev_period_hash", "recorder_key_id", "nonce", "generated_at"}

// Manifeste donne un accès typé aux champs d'un manifeste bien formé.
type Manifeste struct {
	V           *Value
	OrgID       string
	JournalID   string
	PeriodStart int64
	PeriodEnd   int64
	FirstSeq    int64
	LastSeq     int64
	Count       int64
	Root        string
	PrevHash    string
	KeyID       string
	GeneratedAt time.Time
}

// LireManifeste extrait les champs sans valider (valeurs par défaut si absents).
func LireManifeste(v *Value) *Manifeste {
	m := &Manifeste{V: v}
	m.OrgID = chaineDe(v, "org_id")
	m.JournalID = chaineDe(v, "journal_id")
	m.PeriodStart, _ = entierDe(v, "period_start")
	m.PeriodEnd, _ = entierDe(v, "period_end")
	m.FirstSeq, _ = entierDe(v, "first_seq")
	m.LastSeq, _ = entierDe(v, "last_seq")
	m.Count, _ = entierDe(v, "count")
	m.Root = chaineDe(v, "root")
	m.PrevHash = chaineDe(v, "prev_period_hash")
	m.KeyID = chaineDe(v, "recorder_key_id")
	m.GeneratedAt, _ = ParseHorodatage(chaineDe(v, "generated_at"))
	return m
}

// Contient dit si l'instant t est dans [period_start, period_end).
func (m *Manifeste) Contient(t time.Time) bool {
	ms := t.UnixMilli()
	return ms >= m.PeriodStart*1000 && ms < m.PeriodEnd*1000
}

// ValiderSchemaManifeste transcrit le schéma, y compris son allOf (racine
// nulle si et seulement si count = 0), et les relations arithmétiques de
// §10.1 (P-1 : period_end = period_start + 3600, count = last_seq -
// first_seq + 1).
func ValiderSchemaManifeste(v *Value) []string {
	m := &manquements{}
	if !m.clesExactes(v, "$", clesManifeste) {
		return m.liste
	}
	if ver := v.Get("version"); ver.Kind != KindNumber {
		m.add("$.version", "constante 0 attendue")
	} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
		m.add("$.version", "constante 0 attendue, reçu %s", ver.Num)
	}
	m.hex(v.Get("org_id"), "$.org_id", 32, false)
	m.hex(v.Get("journal_id"), "$.journal_id", 32, false)
	ps, okPs := m.entier(v.Get("period_start"), "$.period_start", 0, EntierSurMax)
	pe, okPe := m.entier(v.Get("period_end"), "$.period_end", 3600, EntierSurMax)
	if okPs && ps%3600 != 0 {
		m.add("$.period_start", "heure UTC pleine attendue (multiple de 3600)")
	}
	if okPe && pe%3600 != 0 {
		m.add("$.period_end", "heure UTC pleine attendue (multiple de 3600)")
	}
	if okPs && okPe && pe != ps+3600 {
		m.add("$.period_end", "period_start + 3600 attendu (%d), reçu %d", ps+3600, pe)
	}
	fs, okFs := m.entier(v.Get("first_seq"), "$.first_seq", 1, EntierSurMax)
	ls, okLs := m.entier(v.Get("last_seq"), "$.last_seq", 0, EntierSurMax)
	ct, okCt := m.entier(v.Get("count"), "$.count", 0, EntierSurMax)
	if okFs && okLs && okCt && ct != ls-fs+1 {
		m.add("$.count", "last_seq - first_seq + 1 attendu (%d), reçu %d", ls-fs+1, ct)
	}
	if okFs && okLs && ls < fs-1 {
		m.add("$.last_seq", "inférieur à first_seq - 1")
	}
	if root, ok := m.hex(v.Get("root"), "$.root", 32, false); ok && okCt && (ct == 0) != (root == Zero32) {
		m.add("$.root", "racine nulle si et seulement si count = 0 (allOf du schéma) ; count = %d, root = %s", ct, root)
	}
	m.hex(v.Get("prev_period_hash"), "$.prev_period_hash", 32, false)
	if k := v.Get("recorder_key_id"); k.Kind != KindString || !EstIdentifiantCle(k.Str) {
		m.add("$.recorder_key_id", "identifiant de clé attendu")
	}
	m.hex(v.Get("nonce"), "$.nonce", 32, false)
	m.horodatage(v.Get("generated_at"), "$.generated_at")
	return m.liste
}

// PeriodHash recalcule periodHash et rend aussi C_M.
func PeriodHash(v *Value) (hash []byte, canonique []byte, err error) {
	c, err := Canonique(v)
	if err != nil {
		return nil, nil, err
	}
	return SHA256Prefixe(PrefixeManifeste, c), c, nil
}

// ValiderSchemaManifesteSig transcrit #/$defs/manifeste_sig.
func ValiderSchemaManifesteSig(v *Value) []string {
	m := &manquements{}
	if !m.clesExactes(v, "$", []string{"version", "period_hash", "recorder_key_id", "sig"}) {
		return m.liste
	}
	if ver := v.Get("version"); ver.Kind != KindNumber {
		m.add("$.version", "constante 0 attendue")
	} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
		m.add("$.version", "constante 0 attendue, reçu %s", ver.Num)
	}
	m.hex(v.Get("period_hash"), "$.period_hash", 32, false)
	if k := v.Get("recorder_key_id"); k.Kind != KindString || !EstIdentifiantCle(k.Str) {
		m.add("$.recorder_key_id", "identifiant de clé attendu")
	}
	m.hex(v.Get("sig"), "$.sig", 64, false)
	return m.liste
}

// ControlerManifeste exécute P-1 (schéma et arithmétique), P-4 (racine nulle
// ⇔ période vide) et P-5 (periodHash, signature, clé, generated_at) sur un
// manifeste et sa signature. sig et cles peuvent être nil.
func ControlerManifeste(v, sig *Value, cles *JeuCles) *Resultats {
	r := NouveauxResultats()
	if v == nil || v.Kind != KindObject {
		r.Echec("P-1", "le manifeste n'est pas un objet JSON")
		return r
	}
	for _, mq := range ValiderSchemaManifeste(v) {
		r.Echec("P-1", "%s", mq)
	}
	r.Passe("P-1")
	m := LireManifeste(v)
	nulle := m.Root == Zero32
	if (m.Count == 0) != nulle {
		r.Echec("P-4", "root %s pour count = %d (racine nulle si et seulement si la période est vide)", m.Root, m.Count)
	}
	if m.Root == Hex0x(RacineVideRFC6962) {
		r.Echec("P-4", "root = SHA-256(\"\"), hachage de l'arbre vide RFC 6962 : la convention NOORTRACE est 32 octets nuls")
	}
	r.Passe("P-4")
	if _, err := Canonique(v); err != nil {
		r.Echec("P-5", "manifeste non canonisable : %v", err)
		return r
	}
	if sig == nil {
		r.NonExecute("P-5", "manifeste.sig absent")
		return r
	}
	for _, mq := range ValiderSchemaManifesteSig(sig) {
		r.Echec("P-5", "manifeste.sig : %s", mq)
	}
	ph, c, err := PeriodHash(v)
	if err != nil {
		r.Echec("P-5", "%v", err)
		return r
	}
	if got, att := Hex0x(ph), chaineDe(sig, "period_hash"); got != att {
		r.Echec("P-5", "periodHash recalculé %s ≠ manifeste.sig.period_hash %s", got, att)
	}
	keyID := chaineDe(sig, "recorder_key_id")
	if keyID != m.KeyID {
		r.Echec("P-5", "manifeste.recorder_key_id %q ≠ manifeste.sig.recorder_key_id %q", m.KeyID, keyID)
	}
	sigOctets, err := OctetsHex(chaineDe(sig, "sig"), 64)
	if err != nil {
		r.Echec("P-5", "sig : %v", err)
		return r
	}
	if cles == nil {
		r.NonExecute("P-5", "signature non vérifiée : aucun jeu de clés fourni")
		return r
	}
	cle := cles.Trouver(keyID)
	if cle == nil {
		r.Echec("P-5", "clé %q absente de cles.json", keyID)
		return r
	}
	msg := append(append([]byte{}, PrefixeSignatureManifeste...), c...)
	if err := VerifierEd25519(cle.PublicKey, msg, sigOctets); err != nil {
		r.Echec("P-5", "signature du manifeste sous %s : %v", keyID, err)
	}
	if !m.GeneratedAt.IsZero() && !cle.Couvre(m.GeneratedAt) {
		r.Echec("P-5", "generated_at %s hors de la validité annoncée %s de la clé %s", FormaterHorodatage(m.GeneratedAt), cle.Intervalle(), keyID)
	}
	r.Passe("P-5")
	return r
}

// ControlerContinuite exécute la continuité de §10.3 entre deux manifestes
// consécutifs p puis q du même journal (P-5).
func ControlerContinuite(r *Resultats, p, q *Value) {
	mp, mq := LireManifeste(p), LireManifeste(q)
	if mp.OrgID != mq.OrgID || mp.JournalID != mq.JournalID {
		r.Echec("P-5", "continuité : org_id ou journal_id différents")
	}
	if mq.PeriodStart != mp.PeriodEnd {
		r.Echec("P-5", "continuité : period_start %d ≠ period_end précédent %d (discontinuité temporelle)", mq.PeriodStart, mp.PeriodEnd)
	}
	if mq.FirstSeq != mp.LastSeq+1 {
		r.Echec("P-5", "continuité : first_seq %d ≠ last_seq précédent + 1 (%d) (discontinuité de séquence)", mq.FirstSeq, mp.LastSeq+1)
	}
	if ph, _, err := PeriodHash(p); err == nil {
		if got := Hex0x(ph); got != mq.PrevHash {
			r.Echec("P-5", "continuité : prev_period_hash %s ≠ periodHash précédent recalculé %s", mq.PrevHash, got)
		}
	}
	r.Passe("P-5")
}

// ControlerManifesteContreJournal recalcule, depuis les événements fournis,
// ce que le manifeste déclare : les événements de la période sont ceux dont
// period_start ≤ ts < period_end ; first_seq, last_seq, count et root
// doivent correspondre. Rend la racine recalculée.
func ControlerManifesteContreJournal(r *Resultats, v *Value, journal []*Value) []byte {
	m := LireManifeste(v)
	var D [][]byte
	var seqs []int64
	for _, ev := range journal {
		ts, ok := Ts(ev)
		if !ok || !m.Contient(ts) {
			continue
		}
		hash, _, err := HashEvenement(ev)
		if err != nil {
			r.NonExecute("P-2", fmt.Sprintf("hash de seq %d non calculable", Seq(ev)))
			return nil
		}
		D = append(D, hash)
		seqs = append(seqs, Seq(ev))
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			r.Echec("P-2", "événements de la période non contigus en seq (%d puis %d)", seqs[i-1], seqs[i])
		}
	}
	if len(D) == 0 {
		if m.Count != 0 {
			r.Echec("P-2", "aucun événement du journal dans la période, count = %d", m.Count)
		}
	} else {
		if seqs[0] != m.FirstSeq {
			r.Echec("P-2", "first_seq %d ≠ premier seq de la période %d", m.FirstSeq, seqs[0])
		}
		if seqs[len(seqs)-1] != m.LastSeq {
			r.Echec("P-2", "last_seq %d ≠ dernier seq de la période %d", m.LastSeq, seqs[len(seqs)-1])
		}
		if int64(len(D)) != m.Count {
			r.Echec("P-2", "count %d ≠ nombre d'événements de la période %d", m.Count, len(D))
		}
	}
	racine := Racine(D)
	if got := Hex0x(racine); got != m.Root {
		r.Echec("P-4", "root %s ≠ racine recalculée %s", m.Root, got)
	}
	r.Passe("P-2")
	r.Passe("P-4")
	return racine
}

// AnchorFingerprintManifeste calcule keccak256(org_id || journal_id || periodHash).
func AnchorFingerprintManifeste(v *Value) ([]byte, error) {
	m := LireManifeste(v)
	org, err := OctetsHex(m.OrgID, 32)
	if err != nil {
		return nil, err
	}
	jr, err := OctetsHex(m.JournalID, 32)
	if err != nil {
		return nil, err
	}
	ph, _, err := PeriodHash(v)
	if err != nil {
		return nil, err
	}
	return AnchorFingerprint(org, jr, ph), nil
}

// memeCanonique dit si deux valeurs ont la même forme canonique.
func memeCanonique(a, b *Value) bool {
	ca, err1 := Canonique(a)
	cb, err2 := Canonique(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}
