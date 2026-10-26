// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/point.go).

// Point de contrôle (CT-1 révision 0.3, §10.5 à §10.7) : schéma
// point-de-controle-v0.schema.json transcrit en Go, checkpointHash =
// SHA-256(P_K || JCS(K')), signature Ed25519 sur P_SK || JCS(K'), clé en
// vigueur (§10.5, règle 5) et règles de série (§10.5, règles 2 à 5).

package main

import (
	"fmt"
	"time"
)

// clesPoint sont les douze clés d'un point signé, dans l'ordre du schéma.
var clesPoint = []string{"version", "org_id", "journal_id", "period_start", "tree_size", "root", "last_seq", "last_hash", "checkpoint_ts", "prev_checkpoint_hash", "key_id", "sig"}

// Point donne un accès typé aux champs d'un point bien formé.
type Point struct {
	V            *Value
	OrgID        string
	JournalID    string
	PeriodStart  int64
	TreeSize     int64
	Root         string
	LastSeq      int64
	LastHash     string
	CheckpointTs time.Time
	TsOK         bool
	PrevHash     string
	KeyID        string
	Sig          string
}

// LirePoint extrait les champs sans valider (valeurs par défaut si absents).
func LirePoint(v *Value) *Point {
	p := &Point{V: v}
	p.OrgID = chaineDe(v, "org_id")
	p.JournalID = chaineDe(v, "journal_id")
	p.PeriodStart, _ = entierDe(v, "period_start")
	p.TreeSize, _ = entierDe(v, "tree_size")
	p.Root = chaineDe(v, "root")
	p.LastSeq, _ = entierDe(v, "last_seq")
	p.LastHash = chaineDe(v, "last_hash")
	p.CheckpointTs, p.TsOK = ParseHorodatage(chaineDe(v, "checkpoint_ts"))
	p.PrevHash = chaineDe(v, "prev_checkpoint_hash")
	p.KeyID = chaineDe(v, "key_id")
	p.Sig = chaineDe(v, "sig")
	return p
}

// ValiderSchemaPoint transcrit point-de-controle-v0.schema.json et la règle
// « racine nulle si et seulement si tree_size = 0 » (§10.5, règle 2).
func ValiderSchemaPoint(v *Value) []string {
	m := &manquements{}
	if v == nil || v.Kind != KindObject {
		return []string{"point : objet JSON attendu"}
	}
	if !m.clesExactes(v, "point", clesPoint) {
		return m.liste
	}
	if ver := v.Get("version"); ver.Kind != KindNumber {
		m.add("point.version", "constante 0 attendue")
	} else if n, ok := estEntierJSON(ver.Num); !ok || n.Sign() != 0 {
		m.add("point.version", "constante 0 attendue, reçu %s", ver.Num)
	}
	m.hex(v.Get("org_id"), "point.org_id", 32, false)
	m.hex(v.Get("journal_id"), "point.journal_id", 32, false)
	if ps, ok := m.entier(v.Get("period_start"), "point.period_start", 0, EntierSurMax); ok && ps%3600 != 0 {
		m.add("point.period_start", "heure UTC pleine attendue (multiple de 3600)")
	}
	ts, okTs := m.entier(v.Get("tree_size"), "point.tree_size", 0, EntierSurMax)
	root, okRoot := m.hex(v.Get("root"), "point.root", 32, false)
	m.entier(v.Get("last_seq"), "point.last_seq", 0, EntierSurMax)
	m.hex(v.Get("last_hash"), "point.last_hash", 32, false)
	m.horodatage(v.Get("checkpoint_ts"), "point.checkpoint_ts")
	m.hex(v.Get("prev_checkpoint_hash"), "point.prev_checkpoint_hash", 32, false)
	if k := v.Get("key_id"); k.Kind != KindString || !EstIdentifiantCle(k.Str) {
		m.add("point.key_id", "identifiant de clé attendu")
	}
	m.hex(v.Get("sig"), "point.sig", 64, false)
	if okTs && okRoot && (ts == 0) != (root == Zero32) {
		if ts == 0 {
			m.add("point.root", "racine non nulle pour tree_size = 0")
		} else {
			m.add("point.root", "racine nulle pour tree_size > 0")
		}
	}
	return m.liste
}

// SansSig rend K', le point privé de sa clé sig (§10.6).
func SansSig(v *Value) *Value {
	out := &Value{Kind: KindObject}
	for _, mb := range v.Obj {
		if mb.Key == "sig" {
			continue
		}
		out.Obj = append(out.Obj, mb)
	}
	return out
}

// CheckpointHash calcule checkpointHash = SHA-256(P_K || JCS(K')) et rend C_K.
func CheckpointHash(v *Value) (hash []byte, canonique []byte, err error) {
	c, err := Canonique(SansSig(v))
	if err != nil {
		return nil, nil, err
	}
	return SHA256Prefixe(PrefixePoint, c), c, nil
}

// VerifierSignaturePoint vérifie sig sous la clé donnée, sur P_SK || C_K.
func VerifierSignaturePoint(v *Value, cle *Cle) error {
	_, c, err := CheckpointHash(v)
	if err != nil {
		return err
	}
	sig, err := OctetsHex(chaineDe(v, "sig"), 64)
	if err != nil {
		return fmt.Errorf("sig : %v", err)
	}
	msg := append(append([]byte{}, PrefixeSignaturePoint...), c...)
	return VerifierEd25519(cle.PublicKey, msg, sig)
}

// CleEnVigueur rend la clé en vigueur pour un point (§10.5, règle 5) : la clé
// du dernier événement de seq ≤ lastSeq, ou new_key_id si cet événement est
// une rotation ; "" si aucun événement ne précède.
func CleEnVigueur(journal []*Value, lastSeq int64) string {
	var dernier *Value
	for _, ev := range journal {
		s := Seq(ev)
		if s < 0 || s > lastSeq {
			continue
		}
		if dernier == nil || s > Seq(dernier) {
			dernier = ev
		}
	}
	if dernier == nil {
		return ""
	}
	if EstRotation(dernier) {
		if n := NouvelleCleRotation(dernier); n != "" {
			return n
		}
	}
	return chaineDe(dernier, "recorder_key_id")
}

// hashesPeriode rend les hash recalculés des événements du journal de seq
// first_seq à last_seq du manifeste, dans l'ordre des seq (tableau vide, non
// nil, pour une période vide), et le hash de l'événement first_seq − 1 (ou
// 32 octets nuls si le journal est vide, §10.5 règle 2) ; nil si le journal ne
// couvre pas la période entière.
func hashesPeriode(journal []*Value, m *Manifeste) (hashes [][]byte, precedent []byte) {
	parSeq := map[int64][]byte{}
	for _, ev := range journal {
		h, _, err := HashEvenement(ev)
		if err != nil {
			continue
		}
		parSeq[Seq(ev)] = h
	}
	hashes = [][]byte{}
	for s := m.FirstSeq; s <= m.LastSeq; s++ {
		h, ok := parSeq[s]
		if !ok {
			return nil, nil
		}
		hashes = append(hashes, h)
	}
	if int64(len(hashes)) != m.Count {
		return nil, nil
	}
	precedent = append([]byte{}, RacineVide...)
	if h, ok := parSeq[m.FirstSeq-1]; ok {
		precedent = h
	}
	return hashes, precedent
}

// ControlerSerie applique les règles de série de §10.5 (règles 2 à 5) à une
// liste de points d'une période, contre son manifeste, le journal (racine,
// last_hash, clé en vigueur ; nil : non contrôlés) et le jeu de clés
// (signatures et validité ; nil : non contrôlés). Rend les règles violées,
// dans l'ordre de première violation, et les messages.
func ControlerSerie(points []*Value, m *Manifeste, journal []*Value, cles *JeuCles) (regles []string, erreurs []string) {
	vues := map[string]bool{}
	regle := func(nom, format string, args ...any) {
		if !vues[nom] {
			vues[nom] = true
			regles = append(regles, nom)
		}
		erreurs = append(erreurs, fmt.Sprintf(format, args...))
	}
	if len(points) == 0 {
		regle("serie_vide", "série vide")
		return
	}
	var hashes [][]byte
	var precedentHash []byte
	if journal != nil {
		hashes, precedentHash = hashesPeriode(journal, m)
	}
	var precedent *Point
	for i, v := range points {
		ou := fmt.Sprintf("point[%d]", i)
		if mq := ValiderSchemaPoint(v); len(mq) > 0 {
			for _, x := range mq {
				regle("format", "%s : %s", ou, x)
			}
			precedent = LirePoint(v)
			continue
		}
		p := LirePoint(v)
		if p.OrgID != m.OrgID || p.JournalID != m.JournalID {
			regle("journal", "%s : org_id ou journal_id différents du manifeste", ou)
		}
		if p.PeriodStart != m.PeriodStart {
			regle("period_start", "%s : period_start %d différent de celui du manifeste %d", ou, p.PeriodStart, m.PeriodStart)
		}
		if p.TreeSize > m.Count {
			regle("tree_size", "%s : tree_size %d supérieur à count %d", ou, p.TreeSize, m.Count)
		}
		if p.LastSeq != m.FirstSeq+p.TreeSize-1 {
			regle("last_seq", "%s : last_seq %d différent de first_seq + tree_size - 1 (%d)", ou, p.LastSeq, m.FirstSeq+p.TreeSize-1)
		}
		if p.TsOK && p.CheckpointTs.UnixMilli() < m.PeriodStart*1000 {
			regle("period_start", "%s : checkpoint_ts %s antérieur à period_start", ou, FormaterHorodatage(p.CheckpointTs))
		}
		attenduPrev := Zero32
		if precedent != nil {
			if h, _, err := CheckpointHash(precedent.V); err == nil {
				attenduPrev = Hex0x(h)
			}
		}
		if p.PrevHash != attenduPrev {
			regle("chainage", "%s : prev_checkpoint_hash %s différent de %s", ou, p.PrevHash, attenduPrev)
		}
		if precedent != nil {
			if p.TreeSize < precedent.TreeSize {
				regle("tree_size_decroissant", "%s : tree_size %d décroît (précédent %d)", ou, p.TreeSize, precedent.TreeSize)
			}
			if p.TsOK && precedent.TsOK && p.CheckpointTs.Before(precedent.CheckpointTs) {
				regle("checkpoint_ts_decroissant", "%s : checkpoint_ts %s antérieur au précédent %s", ou, FormaterHorodatage(p.CheckpointTs), FormaterHorodatage(precedent.CheckpointTs))
			}
		}
		if hashes != nil && p.TreeSize >= 0 && p.TreeSize <= int64(len(hashes)) {
			if root := Hex0x(Racine(hashes[:p.TreeSize])); p.Root != root {
				regle("root", "%s : root %s différent de la racine recalculée %s", ou, p.Root, root)
			}
			attenduLast := Hex0x(precedentHash)
			if p.TreeSize > 0 {
				attenduLast = Hex0x(hashes[p.TreeSize-1])
			}
			if p.LastHash != attenduLast {
				regle("last_hash", "%s : last_hash %s différent du hash de l'événement %d (%s)", ou, p.LastHash, p.LastSeq, attenduLast)
			}
		}
		if journal != nil {
			if attendue := CleEnVigueur(journal, p.LastSeq); attendue != "" && attendue != p.KeyID {
				regle("cle_en_vigueur", "%s : key_id %s, clé en vigueur attendue %s", ou, p.KeyID, attendue)
			}
		}
		if cles != nil {
			cle := cles.Trouver(p.KeyID)
			if cle == nil {
				regle("cle_absente", "%s : clé %s absente du jeu de clés", ou, p.KeyID)
			} else {
				if err := VerifierSignaturePoint(v, cle); err != nil {
					regle("signature", "%s : signature invalide sous %s : %v", ou, p.KeyID, err)
				}
				if p.TsOK && !cle.Couvre(p.CheckpointTs) {
					regle("validite_cle", "%s : checkpoint_ts %s hors de la validité de la clé %s", ou, FormaterHorodatage(p.CheckpointTs), p.KeyID)
				}
			}
		}
		precedent = p
	}
	dernier := LirePoint(points[len(points)-1])
	if dernier.TreeSize != m.Count {
		regle("dernier_point", "dernier point : tree_size %d différent de count %d", dernier.TreeSize, m.Count)
	}
	if dernier.Root != m.Root {
		regle("dernier_point", "dernier point : root %s différent de celui du manifeste", dernier.Root)
	}
	if dernier.LastSeq != m.LastSeq {
		regle("dernier_point", "dernier point : last_seq %d différent de celui du manifeste %d", dernier.LastSeq, m.LastSeq)
	}
	return
}
