// Point de contrôle (CT-1 révision 0.3, §10.5 à §10.7) : schéma
// point-de-controle-v0.schema.json transcrit en Go, checkpointHash =
// SHA-256(P_K || JCS(K')), signature Ed25519 sur P_SK || JCS(K'), clé en
// vigueur (§10.5, règle 5) et règles de série (§10.5, règles 2 à 5).

package main

import (
	"fmt"
	"sort"
	"strings"
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

// CleEnVigueurPoint applique la règle exacte de la clé en vigueur d'un point
// (§10.5, règle 5, révision 0.5) : quand l'événement de seq = lastSeq est
// fourni, son new_key_id s'il est une rotation, sinon son recorder_key_id ;
// sinon (lastSeq = 0, journal encore vide, ou événement non fourni), la clé de
// cles.json de plus grand valid_from inférieur ou égal à checkpointTs, la
// dernière dans l'ordre de keys en cas d'égalité. Un événement de seq
// inférieur à lastSeq ne remplace jamais l'événement lastSeq manquant. Rend
// false quand aucune clé ne remplit la condition (la règle est alors violée)
// ou que la clé ne peut être lue.
func CleEnVigueurPoint(journal []*Value, cles *JeuCles, lastSeq int64, checkpointTs time.Time, tsOK bool) (string, bool) {
	if lastSeq >= 1 {
		if ev := evenementDeSeq(journal, lastSeq); ev != nil {
			return cleAttendueApres(ev)
		}
	}
	if cles == nil || !tsOK {
		return "", false
	}
	var retenue *Cle
	for _, c := range cles.Cles {
		if c.ValidFrom.After(checkpointTs) {
			continue
		}
		if retenue == nil || !c.ValidFrom.Before(retenue.ValidFrom) {
			retenue = c
		}
	}
	if retenue == nil {
		return "", false
	}
	return retenue.KeyID, true
}

// evenementDeSeq rend le premier événement fourni dont le seq est l'entier s.
func evenementDeSeq(journal []*Value, s int64) *Value {
	for _, ev := range journal {
		if x, ok := SeqTypee(ev); ok && x == s {
			return ev
		}
	}
	return nil
}

// RegleNonEvaluee est une règle de série qui ne se décide pas pour un point,
// faute d'une donnée (§10.5, révision 0.5) : raison piece_hors_dossier
// (événement non fourni) ou prerequis_en_echec (événement fourni dont le hash
// ne se recalcule pas, E-2).
type RegleNonEvaluee struct {
	Regle, Raison string
}

// ordreRegles est la liste fermée des noms de règle de série, dans l'ordre
// du texte (§10.5, révision 0.5) : rules_failed et rules_not_evaluated la
// suivent.
var ordreRegles = []string{"chainage", "tree_size_decroissant", "checkpoint_ts_decroissant", "period_start", "root", "last_seq", "last_hash", "dernier_point", "cle_en_vigueur", "signature", "validite_cle"}

func rangRegle(nom string) int {
	for i, r := range ordreRegles {
		if r == nom {
			return i
		}
	}
	return len(ordreRegles)
}

// rangRaison : prerequis_en_echec avant piece_hors_dossier (CT-6 EX-6.5).
func rangRaison(r string) int {
	if r == RaisonNEPrerequis {
		return 0
	}
	return 1
}

// ControlerSerie applique les règles de série de §10.5 (règles 2 à 5) à une
// liste de points d'une période, contre son manifeste, les événements fournis
// (racine, last_hash, clé en vigueur ; nil : aucun) et cles.json (signatures,
// validité, clé en vigueur quand l'événement last_seq n'est pas fourni).
// Chaque règle est évaluée point par point (révision 0.5) : une règle qui
// manque d'une donnée n'est pas évaluée, jamais violée, et aucune valeur par
// défaut (32 octets nuls) ne remplace un événement manquant. Raisons :
// piece_hors_dossier (événement non fourni, ou cles.json absent : cles nil),
// prerequis_en_echec (événement fourni dont le hash ne se recalcule pas ; un
// événement manque et un autre ne se hache pas ; cles.json défectueux :
// clesDefectueux). Les noms de règle sont ceux de la liste fermée
// (ordreRegles) ; rules_failed porte chaque règle une fois,
// rules_not_evaluated une entrée par couple (règle, raison), toutes deux dans
// l'ordre de la liste, prerequis_en_echec avant piece_hors_dossier. La série
// n'est valide que si les deux listes sont vides.
func ControlerSerie(points []*Value, m *Manifeste, journal []*Value, cles *JeuCles, clesDefectueux bool) (regles []string, erreurs []string, nonEvaluees []RegleNonEvaluee) {
	defer func() {
		sort.SliceStable(regles, func(i, j int) bool { return rangRegle(regles[i]) < rangRegle(regles[j]) })
		sort.SliceStable(nonEvaluees, func(i, j int) bool {
			a, b := nonEvaluees[i], nonEvaluees[j]
			if rangRegle(a.Regle) != rangRegle(b.Regle) {
				return rangRegle(a.Regle) < rangRegle(b.Regle)
			}
			return rangRaison(a.Raison) < rangRaison(b.Raison)
		})
	}()
	raisonCles := RaisonNEHorsDossier
	if clesDefectueux {
		raisonCles = RaisonNEPrerequis
		cles = nil
	}
	vues := map[string]bool{}
	regle := func(nom, format string, args ...any) {
		if !vues[nom] {
			vues[nom] = true
			regles = append(regles, nom)
		}
		erreurs = append(erreurs, fmt.Sprintf(format, args...))
	}
	nonVues := map[RegleNonEvaluee]bool{}
	nonEvaluee := func(nom, raison string) {
		x := RegleNonEvaluee{nom, raison}
		if !nonVues[x] {
			nonVues[x] = true
			nonEvaluees = append(nonEvaluees, x)
		}
	}
	if len(points) == 0 {
		regle("dernier_point", "série vide : aucun dernier point")
		return
	}
	// hashFourni rend le hash recalculé de l'événement seq s, et la raison de
	// non-évaluation quand il manque ("" sinon).
	hashFourni := func(s int64) ([]byte, string) {
		ev := evenementDeSeq(journal, s)
		if ev == nil {
			return nil, RaisonNEHorsDossier
		}
		h, ok := HashCalculable(ev)
		if !ok {
			return nil, RaisonNEPrerequis
		}
		return h, ""
	}
	var precedent *Point
	for i, v := range points {
		ou := fmt.Sprintf("point[%d]", i)
		if mq := ValiderSchemaPoint(v); len(mq) > 0 {
			// Point contraire à son schéma ou à sa forme : « en-tête du point »
			// (period_start) ; racine nulle ou non nulle à tort : root.
			for _, x := range mq {
				if strings.HasPrefix(x, "point.root : racine ") {
					regle("root", "%s : %s", ou, x)
				} else {
					regle("period_start", "%s : %s", ou, x)
				}
			}
			precedent = LirePoint(v)
			continue
		}
		p := LirePoint(v)
		if p.OrgID != m.OrgID || p.JournalID != m.JournalID {
			regle("period_start", "%s : org_id ou journal_id différents du manifeste (en-tête du point)", ou)
		}
		if p.PeriodStart != m.PeriodStart {
			regle("period_start", "%s : period_start %d différent de celui du manifeste %d", ou, p.PeriodStart, m.PeriodStart)
		}
		if p.TreeSize > m.Count {
			regle("last_seq", "%s : tree_size %d supérieur à count %d (last_seq au-delà de celui du manifeste)", ou, p.TreeSize, m.Count)
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
		// root : n = 0 exige 32 octets nuls ; n ≥ 1 se décide si les événements
		// first_seq à first_seq + n − 1 sont tous fournis et que leur hash se
		// recalcule.
		{ // root et last_hash, sur les événements fournis (journal nil : aucun)
			if p.TreeSize == 0 {
				if p.Root != Zero32 {
					regle("root", "%s : root %s pour tree_size = 0 (32 octets nuls attendus)", ou, p.Root)
				}
			} else {
				// Un événement manque et un autre est fourni sans forme
				// canonique : prerequis_en_echec (révision 0.5).
				var feuilles [][]byte
				raison := ""
				for s := m.FirstSeq; s < m.FirstSeq+p.TreeSize; s++ {
					h, r := hashFourni(s)
					switch {
					case r == RaisonNEPrerequis:
						raison = r
					case r == RaisonNEHorsDossier && raison == "":
						raison = r
					case r == "":
						feuilles = append(feuilles, h)
					}
				}
				if raison != "" {
					nonEvaluee("root", raison)
				} else if root := Hex0x(Racine(feuilles)); p.Root != root {
					regle("root", "%s : root %s différent de la racine recalculée %s", ou, p.Root, root)
				}
			}
			// last_hash : last_seq = 0 exige 32 octets nuls ; sinon l'événement
			// last_seq doit être fourni (pour n = 0, il appartient à la période
			// précédente), et 32 octets nuls ne le remplacent jamais.
			if p.LastSeq == 0 {
				if p.LastHash != Zero32 {
					regle("last_hash", "%s : last_hash %s pour last_seq = 0 (32 octets nuls attendus)", ou, p.LastHash)
				}
			} else if h, raison := hashFourni(p.LastSeq); raison != "" {
				nonEvaluee("last_hash", raison)
			} else if attendu := Hex0x(h); p.LastHash != attendu {
				regle("last_hash", "%s : last_hash %s différent du hash de l'événement %d (%s)", ou, p.LastHash, p.LastSeq, attendu)
			}
		}
		// cle_en_vigueur : règle 5 (révision 0.5) ; sans l'événement last_seq,
		// elle lit cles.json.
		if attendue, ok := CleEnVigueurPoint(journal, cles, p.LastSeq, p.CheckpointTs, p.TsOK); ok {
			if attendue != p.KeyID {
				regle("cle_en_vigueur", "%s : key_id %s, clé en vigueur attendue %s", ou, p.KeyID, attendue)
			}
		} else if p.LastSeq >= 1 && evenementDeSeq(journal, p.LastSeq) != nil {
			regle("cle_en_vigueur", "%s : key_id de l'événement last_seq illisible", ou)
		} else if cles == nil {
			nonEvaluee("cle_en_vigueur", raisonCles)
		} else {
			regle("cle_en_vigueur", "%s : key_id %s n'est la clé en vigueur d'aucun point (aucune clé de valid_from ≤ checkpoint_ts)", ou, p.KeyID)
		}
		if cles == nil {
			nonEvaluee("signature", raisonCles)
			nonEvaluee("validite_cle", raisonCles)
		} else {
			cle := cles.Trouver(p.KeyID)
			if cle == nil {
				regle("signature", "%s : clé %s absente de cles.json : la signature ne se vérifie sous aucune clé désignée", ou, p.KeyID)
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

// hashesPeriode rend les hash recalculés des événements fournis de seq
// first_seq à last_seq du manifeste, dans l'ordre des seq (tableau vide, non
// nil, pour une période vide) ; nil si l'un manque ou ne se recalcule pas.
// Sert à régénérer les preuves de cohérence des vecteurs.
func hashesPeriode(journal []*Value, m *Manifeste) [][]byte {
	hashes := [][]byte{}
	for s := m.FirstSeq; s <= m.LastSeq; s++ {
		h, ok := HashCalculable(evenementDeSeq(journal, s))
		if !ok {
			return nil
		}
		hashes = append(hashes, h)
	}
	if int64(len(hashes)) != m.Count {
		return nil
	}
	return hashes
}
