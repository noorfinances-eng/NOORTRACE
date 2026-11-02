package registre

// Chaque vérification du contrôle 8 en réussite et en échec, sur des
// parties fabriquées (fabrique_test.go) : R-1 à R-11, N-4, K-8, statut du
// contrôle (EX-11.20), avertissements AV-R-1 à AV-R-3, AV-K-1, AV-K-3,
// faits et proposition.

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

const (
	R  = "reussi"
	E  = "echoue"
	PE = "non_execute:prerequis_en_echec"
	AA = "non_execute:ancre_absente"
	PA = "non_execute:partie_absente"
	HP = "non_execute:hors_perimetre_version"
)

// tousReussis : l'état attendu du monde de base.
func tousReussis() map[string]string {
	m := map[string]string{"N-4": R, "K-8": R}
	for _, id := range IDs {
		m[id] = R
	}
	return m
}

func etats(r Resultat) map[string]string {
	out := map[string]string{}
	vs := append([]commun.Verification{}, r.Verifications...)
	if r.N4 != nil {
		vs = append(vs, *r.N4)
	}
	if r.K8 != nil {
		vs = append(vs, *r.K8)
	}
	for _, v := range vs {
		s := string(v.Statut)
		if v.Statut == commun.NonExecute {
			s += ":" + string(v.Raison)
		}
		out[v.ID] = s
	}
	return out
}

func detail(r Resultat, id string) string {
	for _, v := range r.Verifications {
		if v.ID == id {
			return v.Detail.Fr
		}
	}
	for _, v := range []*commun.Verification{r.N4, r.K8} {
		if v != nil && v.ID == id {
			return v.Detail.Fr
		}
	}
	return ""
}

type scenario struct {
	nom    string
	prep   func(m *monde)
	post   func(e *Entree)
	modifs map[string]string // écarts à tousReussis ; "" : ne figure pas
	statut string            // statut[:raison] du contrôle 8
	avert  []string
	verif  func(t *testing.T, r Resultat)
}

func lancer(t *testing.T, s scenario) {
	t.Helper()
	m := nouveauMonde()
	if s.prep != nil {
		s.prep(m)
	}
	e := m.entree()
	if s.post != nil {
		s.post(&e)
	}
	r := Verifier(e)
	att := tousReussis()
	for k, v := range s.modifs {
		if v == "" {
			delete(att, k)
		} else {
			att[k] = v
		}
	}
	ob := etats(r)
	for k, v := range att {
		if ob[k] != v {
			t.Errorf("%s : %q, attendu %q (%s)", k, ob[k], v, detail(r, k))
		}
	}
	for k, v := range ob {
		if _, ok := att[k]; !ok {
			t.Errorf("%s figure (%s) sans être attendue", k, v)
		}
	}
	st := string(r.Statut)
	if r.Statut == commun.NonExecute {
		st += ":" + string(r.Raison)
	}
	if s.statut == "" {
		s.statut = R
	}
	if st != s.statut {
		t.Errorf("contrôle 8 : %s, attendu %s", st, s.statut)
	}
	var av []string
	for _, a := range r.Avertissements {
		av = append(av, a.ID)
		if a.Detail.Fr == "" || a.Detail.En == "" {
			t.Errorf("%s sans détail", a.ID)
		}
	}
	if strings.Join(av, ",") != strings.Join(s.avert, ",") {
		t.Errorf("avertissements %v, attendu %v", av, s.avert)
	}
	// Invariants de l'interface.
	if (r.Faits != nil) != (r.Statut == commun.Reussi) {
		t.Errorf("faits présents : %v, statut %s", r.Faits != nil, r.Statut)
	}
	if (r.FaitsPoint != nil) != (r.K8 != nil && r.K8.Statut == commun.Reussi) {
		t.Errorf("faits du point : %v", r.FaitsPoint != nil)
	}
	if r.Verifications == nil || r.Avertissements == nil || r.AncresEmployees == nil || r.Inscriptions == nil {
		t.Errorf("tranche nulle dans le résultat")
	}
	for i, v := range r.Verifications {
		if i > 0 && rangR(v.ID) <= rangR(r.Verifications[i-1].ID) {
			t.Errorf("ordre des vérifications : %s après %s", v.ID, r.Verifications[i-1].ID)
		}
		if v.Detail.Fr == "" || v.Detail.En == "" {
			t.Errorf("%s sans détail bilingue", v.ID)
		}
		if v.Statut == commun.NonExecute && !(v.Raison.Admise() || v.Raison == commun.PrerequisEnEchec) {
			t.Errorf("%s : raison %q hors de la liste fermée", v.ID, v.Raison)
		}
	}
	if r.Statut == commun.Reussi {
		if r.Proposition.Vide() || r.Resume.Vide() {
			t.Errorf("proposition ou résumé vides")
		}
		b, err := json.Marshal(r.Faits)
		if err != nil || !strings.Contains(string(b), `"signers":["`) {
			t.Errorf("faits : %s", b)
		}
	}
	if s.verif != nil {
		s.verif(t, r)
	}
}

func rangR(id string) int {
	for i, x := range IDs {
		if x == id {
			return i
		}
	}
	return -1
}

func avecLigne(h uint64, i int, f func(e *enveloppe)) func(m *monde) {
	return func(m *monde) {
		m.apres = func(hh uint64, ii int, e *enveloppe) {
			if hh == h && ii == i {
				f(e)
			}
		}
	}
}

func avantSignature(h uint64, i int, f func(e *enveloppe)) func(m *monde) {
	return func(m *monde) {
		m.avant = func(hh uint64, ii int, e *enveloppe) {
			if hh == h && ii == i {
				f(e)
			}
		}
	}
}

func corps(e *enveloppe, v any) {
	b, _ := json.Marshal(v)
	e.Body = b
	h := cryptographie.Sha256(b)
	e.BodyHash = h[:]
}

func TestScenarios(t *testing.T) {
	sansAncreR := map[string]string{"R-2": AA, "R-4": AA, "R-5": AA, "R-8": AA, "N-4": AA, "K-8": AA}
	scenarios := []scenario{
		{nom: "base", verif: func(t *testing.T, r Resultat) {
			if r.FaitsPoint.Inclusion != "prouvee" || r.FaitsPoint.BlockTime == nil || *r.FaitsPoint.Issuer != hexA(adr("chaine-B")) {
				t.Errorf("faits du point %+v", r.FaitsPoint)
			}
			if len(r.Inscriptions) != 2 {
				t.Errorf("inscriptions %v", r.Inscriptions)
			}
			if !strings.Contains(r.Proposition.Fr, ", clé de chaîne inscrite au bloc 100 pour la clé d'enregistreur rec-a, que le réviseur tient pour la clé de chaîne de rec-a ; chacun de ces blocs est signé par 3 des 4 validateurs du jeu ") {
				t.Errorf("proposition %s", r.Proposition.Fr)
			}
			if strings.Join(r.AncresEmployees, ",") != "/registry,/registry/validator_sets/0,/recorders/0" {
				t.Errorf("ancres employées %v", r.AncresEmployees)
			}
			if r.Resume.Fr != "noortrace-essai : inscriptions blocs 100 et 104, ancre bloc 108, ancre de point de contrôle bloc 116, clôture bloc 112, 3 validateurs sur 4 à chaque bloc" {
				t.Errorf("résumé %s", r.Resume.Fr)
			}
			if r.Faits.Certificates[0].Quorum != 3 || strings.Join(r.Faits.Certificates[0].Signers, ",") != "v1,v3,v4" {
				t.Errorf("certificat %+v", r.Faits.Certificates[0])
			}
		}},
		// R-1.
		{nom: "R-1 registre trop grand", post: func(e *Entree) { e.Registre.Etat = entree.TropGrand },
			modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E},
		{nom: "R-1 certificat absent du répertoire", post: func(e *Entree) { e.Certificat.Etat = entree.Absent; e.Certificat.Octets = nil },
			modifs: map[string]string{"R-1": PE, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: "non_execute:prerequis_en_echec", avert: nil},
		{nom: "R-1 JSON tronqué", post: func(e *Entree) { e.Registre.Octets = e.Registre.Octets[:len(e.Registre.Octets)/2] },
			modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E},
		{nom: "R-1 sans entrée ancre (schéma)", prep: func(m *monde) {
			m.retirer(roleAncre)
			m.blocs = append(m.blocs, &blocFab{role: roleInscription, numero: 108, recus: m.bloc(roleInscription).recus})
		},
			modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E},
		{nom: "R-1 certificat sans entrée", prep: func(m *monde) {
			m.certAltere = func(c map[string]any) {
				if c["height"] == "0x70" {
					c["height"] = "0x71"
				}
			}
		}, modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E},
		{nom: "R-1 log_index hors du reçu", prep: func(m *monde) { m.bloc(roleCloture).lg = 3 },
			modifs: map[string]string{"R-1": E, "R-2": PE, "R-3": PE, "R-4": PE, "R-5": PE, "R-6": PE, "R-7": PE, "R-8": PE, "R-9": PE, "R-10": PE, "R-11": PE, "N-4": PE}, statut: E},
		{nom: "R-1 deux entrées dans un bloc", prep: func(m *monde) {
			b := m.bloc(roleInscription)
			j := m.jInscription(m.pubB, m.ckB)
			b.recus = append(b.recus, recuDe(j))
			m.blocs[1] = &blocFab{role: roleInscription, numero: 100, recus: b.recus, tx: 1, txHash: m.blocs[1].txHash}
		}, verif: func(t *testing.T, r Resultat) {
			if len(r.Faits.Entries) != 5 || len(r.Faits.Certificates) != 4 {
				t.Errorf("faits : %d entrées, %d certificats", len(r.Faits.Entries), len(r.Faits.Certificates))
			}
		}},
		// R-2.
		{nom: "R-2 jeu substitué", prep: func(m *monde) {
			j := m.jeu()
			c := secp256k1.PrivKeyFromBytes([]byte("autre-cle-autre-cle-autre-cle-32")).PubKey().SerializeUncompressed()
			j.Validateurs[3].Cle, j.Validateurs[3].CleHex = c, cryptographie.Hex(c)
			m.jeuAncre = &j
		}, modifs: map[string]string{"R-2": E, "R-5": PE, "N-4": PE}, statut: E},
		{nom: "R-2 aucun jeu pour la hauteur", prep: func(m *monde) {
			j := m.jeu()
			j.De = 1000
			m.jeuAncre = &j
		}, modifs: map[string]string{"R-2": AA, "R-5": AA, "N-4": AA}, statut: "non_execute:ancre_absente",
			verif: func(t *testing.T, r Resultat) {
				if strings.Join(r.AncresEmployees, ",") != "/registry" {
					t.Errorf("ancres employées %v", r.AncresEmployees)
				}
			}},
		// R-3.
		{nom: "R-3 jeu déclaré différent", prep: func(m *monde) {
			m.validateurs = []byte(`{"version":0,"sets":[{"from_height":1,"to_height":null,"validators":[{"id":"v1","pubKeyHex":"0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}],"source":"autre"}]}`)
		}, modifs: map[string]string{"R-3": E}, statut: E},
		{nom: "R-3 validateurs.json hors périmètre", prep: func(m *monde) { m.sansValidRais = "hors périmètre CT-1" }, modifs: map[string]string{"R-3": HP}},
		{nom: "R-3 validateurs.json absent", prep: func(m *monde) { m.sansValidRais = "non fournie" }, modifs: map[string]string{"R-3": PA}},
		{nom: "R-3 validateurs.json trop grand", post: func(e *Entree) { e.Validateurs.Etat = entree.TropGrand }, modifs: map[string]string{"R-3": E}, statut: E},
		{nom: "R-3 validateurs.json illisible", post: func(e *Entree) { e.Validateurs.Etat = entree.Illisible }, modifs: map[string]string{"R-3": PE}},
		{nom: "R-3 identifiants en double", prep: func(m *monde) {
			m.validateurs = []byte(`{"version":0,"sets":[{"from_height":1,"to_height":null,"validators":[{"id":"v1","pubKeyHex":"0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},{"id":"v1","pubKeyHex":"0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"}],"source":"x"}]}`)
		}, modifs: map[string]string{"R-3": E}, statut: E},
		// R-4.
		{nom: "R-4 autre chaîne", post: func(e *Entree) { e.Ancres.Registre.ChainID = "autre-chaine" }, modifs: map[string]string{"R-4": E}, statut: E},
		// R-5.
		{nom: "R-5 sous le quorum", prep: func(m *monde) { m.signataires[112] = []string{"v1", "v2"} }, modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 signataire en double", prep: func(m *monde) { m.signataires[112] = []string{"v1", "v1", "v2", "v3"} }, modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 validateur hors du jeu", prep: func(m *monde) { m.signataires[112] = []string{"v1", "v2", "v3", "v9"} }, modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 signature altérée", prep: avecLigne(112, 2, func(e *enveloppe) { e.Sig[5] ^= 1 }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 signature de la proposition altérée", prep: avecLigne(112, 0, func(e *enveloppe) { e.Sig[40] ^= 1 }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 S haut", prep: avecLigne(112, 1, func(e *enveloppe) {
			s := new(big.Int).SetBytes(e.Sig[32:64])
			s.Sub(secp256k1.S256().N, s)
			s.FillBytes(e.Sig[32:64])
			e.Sig[64] ^= 1
		}), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 type de ligne", prep: avantSignature(112, 1, func(e *enveloppe) { e.Type = typeProposition }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 domaine", prep: avantSignature(112, 1, func(e *enveloppe) { e.Domain = "noor/v2/bft" }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 chainId de la ligne", prep: avantSignature(112, 1, func(e *enveloppe) { e.ChainID = "autre" }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 hauteur de la ligne", prep: avantSignature(112, 2, func(e *enveloppe) { e.Height++ }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 bodyHash", prep: avantSignature(112, 1, func(e *enveloppe) { e.BodyHash[0] ^= 1 }), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 votant du corps", prep: avantSignature(112, 1, func(e *enveloppe) {
			corps(e, corpsVote{Height: e.Height, Voter: "v2", Type: 2, BlockHash: cryptographie.Hex(e.BlockHash)})
		}), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 vote de type 1", prep: avantSignature(112, 1, func(e *enveloppe) {
			corps(e, corpsVote{Height: e.Height, Voter: e.ValidatorID, Type: 1, BlockHash: cryptographie.Hex(e.BlockHash)})
		}), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 bloc du corps", prep: avantSignature(112, 0, func(e *enveloppe) {
			corps(e, corpsProposition{Height: e.Height, Proposer: "v1", BlockHash: cryptographie.Hex32(octets32("x"))})
		}), modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 votant non renseigné", prep: avantSignature(112, 1, func(e *enveloppe) {
			corps(e, corpsVote{Height: e.Height, Type: 2, BlockHash: cryptographie.Hex(e.BlockHash)})
		})},
		{nom: "R-5 ligne illisible", prep: func(m *monde) {
			m.certAltere = func(c map[string]any) {
				if c["height"] == "0x70" {
					c["precommits"].([]map[string]any)[0]["line"] = `{"domain":`
				}
			}
		}, modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "R-5 ligne profonde", prep: func(m *monde) {
			m.certAltere = func(c map[string]any) {
				if c["height"] == "0x70" {
					c["precommits"].([]map[string]any)[0]["line"] = `{"body":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`
				}
			}
		}, modifs: map[string]string{"R-5": E}, statut: E},
		{nom: "AV-R-2 ligne non canonique", prep: func(m *monde) {
			m.certAltere = func(c map[string]any) {
				if c["height"] == "0x70" {
					p := c["precommits"].([]map[string]any)[1]
					p["line"] = strings.Replace(p["line"].(string), `{"domain"`, `{"DOMAIN"`, 1)
				}
			}
		}, avert: []string{"AV-R-2"}},
		// R-6, R-7.
		{nom: "R-6 en-tête modifié", prep: func(m *monde) { m.bloc(roleCloture).apresHachage = func(e *entete) { e.horodatage++ } },
			modifs: map[string]string{"R-6": E, "R-8": PE, "R-9": PE}, statut: E},
		{nom: "R-6 en-tête modifié de l'ancre", prep: func(m *monde) { m.bloc(roleAncre).apresHachage = func(e *entete) { e.gazUtilise++ } },
			modifs: map[string]string{"R-6": E, "R-8": PE, "R-9": PE, "N-4": PE}, statut: E},
		{nom: "R-7 reçu falsifié", prep: func(m *monde) {
			m.bloc(roleCloture).alterRecus = func(r []recu) []recu {
				j := r[1].journaux[0]
				j.sujets = append([][32]byte{}, j.sujets...)
				j.sujets[2] = octets32("autre")
				r[1] = recu{genre: 2, statut: 1, cumul: r[1].cumul, journaux: []journal{j}}
				return r
			}
		}, modifs: map[string]string{"R-7": E, "R-8": PE, "R-9": PE}, statut: E},
		// R-8.
		{nom: "R-8 autre contrat", post: func(e *Entree) { e.Ancres.Registre.PeriodRegistry = adr("autre") }, modifs: map[string]string{"R-8": E}, statut: E},
		// R-9.
		{nom: "R-9 autre période", post: func(e *Entree) { e.Manifeste.PeriodHash = octets32("autre") }, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 autre période de début", post: func(e *Entree) { e.Manifeste.PeriodStart++ }, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 docType de l'ancre", prep: func(m *monde) {
			m.bloc(roleAncre).recus = []recu{recuDe(m.jAncre(cryptographie.Keccak256(m.org[:], m.jr[:], m.ph[:]), m.ckA, docTypePoint))}
		}, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 remplissage de uri", prep: func(m *monde) {
			j := m.jCloture(112, "e2e://essai")
			j.donnees[len(j.donnees)-1] = 1
			m.bloc(roleCloture).recus[1] = recuDe(j)
		}, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 position de uri", prep: func(m *monde) {
			j := m.jCloture(112, "")
			j.donnees[8*32+31] = 0x60
			m.bloc(roleCloture).recus[1] = recuDe(j)
		}, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 cloture à trois sujets", prep: func(m *monde) {
			j := m.jCloture(112, "")
			j.sujets = j.sujets[:3]
			m.bloc(roleCloture).recus[1] = recuDe(j)
		}, modifs: map[string]string{"R-9": E}, statut: E},
		{nom: "R-9 et R-10 sans P-1", post: func(e *Entree) { e.Manifeste = Manifeste{} },
			modifs: map[string]string{"R-9": PE, "R-10": PE, "R-11": PE, "N-4": ""}, statut: "non_execute:prerequis_en_echec"},
		// R-10.
		{nom: "R-10 clé inconnue", prep: func(m *monde) {
			m.blocs = append(m.blocs, &blocFab{role: roleInscription, numero: 120, recus: []recu{recuDe(m.jInscription(octets32("inconnue"), adr("x")))}, txHash: m.blocs[0].txHash})
		}, modifs: map[string]string{"R-10": E, "R-11": PE}, statut: E},
		{nom: "R-10 autre organisation", prep: func(m *monde) {
			j := m.jInscription(m.pubB, m.ckB)
			j.sujets[1] = octets32("autre-org")
			m.blocs[1].recus = []recu{recuDe(j)}
		}, modifs: map[string]string{"R-10": E, "R-11": PE}, statut: E},
		{nom: "R-10 cles.json inexploitable", post: func(e *Entree) { e.ClesExploitables = false },
			modifs: map[string]string{"R-10": PE, "R-11": PE}},
		{nom: "R-10 aucune inscription", prep: func(m *monde) { m.retirer(roleInscription) },
			modifs: map[string]string{"R-10": PA}, avert: []string{"AV-R-1", "AV-K-3"},
			verif: func(t *testing.T, r Resultat) {
				if strings.Contains(r.Proposition.Fr, "inscrite au bloc") || !strings.Contains(r.Proposition.Fr, "que le réviseur tient pour la clé de chaîne de rec-a") {
					t.Errorf("proposition %s", r.Proposition.Fr)
				}
				if len(r.Inscriptions) != 0 {
					t.Errorf("inscriptions %v", r.Inscriptions)
				}
			}},
		{nom: "R-10 clé du manifeste sous une autre clé de chaîne seulement", prep: func(m *monde) {
			m.blocs[0].recus = []recu{recuDe(m.jInscription(m.pubA, adr("ancienne")))}
		}, modifs: map[string]string{"R-10": E, "R-11": PE}, statut: E},
		{nom: "AV-R-3 inscription ancienne à côté", prep: func(m *monde) {
			m.blocs = append(m.blocs, &blocFab{role: roleInscription, numero: 96, recus: []recu{recuDe(m.jInscription(m.pubA, adr("ancienne")))}, txHash: m.blocs[0].txHash})
		}, avert: []string{"AV-R-3"}},
		{nom: "AV-R-1 clé du manifeste non inscrite", prep: func(m *monde) { m.blocs = append(m.blocs[:0], m.blocs[1:]...) },
			avert: []string{"AV-R-1"}},
		// R-11.
		{nom: "R-11 ancre de période relabellisée", prep: func(m *monde) {
			m.bloc(rolePoint).recus = []recu{recuDe(m.jAncre(cryptographie.Keccak256(m.org[:], m.jr[:], m.ckPoint[:]), m.ckB, docTypePeriode))}
		}, modifs: map[string]string{"R-11": E}, statut: E, verif: func(t *testing.T, r Resultat) {
			if r.FaitsPoint.Inclusion != "declarative" {
				t.Errorf("inclusion %s", r.FaitsPoint.Inclusion)
			}
		}},
		{nom: "R-11 autre bloc que la référence", post: func(e *Entree) { e.Point.Reference.BlockNumber = 117 }, modifs: map[string]string{"R-11": E}, statut: E},
		{nom: "R-11 autre transaction que la référence", post: func(e *Entree) { e.Point.Reference.TransactionHash = cryptographie.Hex32(octets32("t")) }, modifs: map[string]string{"R-11": E}, statut: E},
		{nom: "R-11 émetteur sans inscription de la clé du point", prep: func(m *monde) {
			m.bloc(rolePoint).recus = []recu{recuDe(m.jAncre(cryptographie.Keccak256(m.org[:], m.jr[:], m.ckPoint[:]), m.ckA, docTypePoint))}
		}, modifs: map[string]string{"R-11": E}, statut: E},
		{nom: "AV-K-3 clé du point non inscrite", prep: func(m *monde) { m.blocs = append(m.blocs[:1], m.blocs[2:]...) }, avert: []string{"AV-K-3"}},
		{nom: "R-11 sans partie points-de-controle.json", prep: func(m *monde) { m.point = nil }, modifs: map[string]string{"R-11": PA, "K-8": ""}},
		{nom: "R-11 référence nulle", post: func(e *Entree) { e.Point.Reference = nil }, modifs: map[string]string{"R-11": PA, "K-8": ""}},
		{nom: "R-11 K-2 non réussie", post: func(e *Entree) { e.Point.K2 = false }, modifs: map[string]string{"R-11": PE, "K-8": ""}},
		{nom: "R-11 et K-8 sans entrée", prep: func(m *monde) { m.retirer(rolePoint) }, modifs: map[string]string{"R-11": PA}, avert: []string{"AV-K-1"},
			verif: func(t *testing.T, r Resultat) {
				if r.FaitsPoint.Inclusion != "declarative" || r.FaitsPoint.BlockTime != nil || r.FaitsPoint.Issuer != nil {
					t.Errorf("faits du point %+v", r.FaitsPoint)
				}
			}},
		{nom: "R-11 absente sans partie ni entrée", prep: func(m *monde) { m.point = nil; m.retirer(rolePoint) }, modifs: map[string]string{"R-11": "", "K-8": ""}},
		// N-4.
		{nom: "N-4 autre clé de chaîne", prep: func(m *monde) { m.recorders[0].CleChaine = hexA(m.ckB) }, modifs: map[string]string{"N-4": E}, statut: E,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits != nil || !r.Proposition.Vide() {
					t.Errorf("faits ou proposition d'un contrôle en échec")
				}
			}},
		{nom: "N-4 sans clé de chaîne", prep: func(m *monde) { m.recorders[0].CleChaine = "" }, modifs: map[string]string{"N-4": ""},
			verif: func(t *testing.T, r Resultat) {
				if strings.Contains(r.Proposition.Fr, "que le réviseur tient") {
					t.Errorf("proposition %s", r.Proposition.Fr)
				}
			}},
		{nom: "N-4 R-5 en échec sur le bloc de l'ancre", prep: func(m *monde) { m.signataires[108] = []string{"v1"} }, modifs: map[string]string{"R-5": E, "N-4": PE}, statut: E},
		// K-8.
		{nom: "K-8 empreinte", post: func(e *Entree) { e.Point.Reference.Fingerprint = cryptographie.Hex32(octets32("x")) }, modifs: map[string]string{"K-8": E}, statut: E},
		{nom: "K-8 docType", post: func(e *Entree) { e.Point.Reference.DocType = hexDocTypePeriode }, modifs: map[string]string{"K-8": E}, statut: E},
		{nom: "K-8 contrat", post: func(e *Entree) { e.Point.Reference.Contract = hexA(adr("PeriodRegistry")) }, modifs: map[string]string{"K-8": E}, statut: E},
		{nom: "K-8 événement illisible", post: func(e *Entree) { e.OrgID = "x" }, modifs: map[string]string{"K-8": PE, "R-11": E}, statut: E},
		{nom: "sans ancre registry", prep: func(m *monde) { m.sansRegistre = true }, modifs: sansAncreR, statut: "non_execute:ancre_absente"},
		{nom: "sans fichier d'ancres", post: func(e *Entree) { e.Ancres = nil }, modifs: map[string]string{"R-2": AA, "R-4": AA, "R-5": AA, "R-8": AA, "N-4": "", "K-8": AA}, statut: "non_execute:ancre_absente",
			verif: func(t *testing.T, r Resultat) {
				if len(r.AncresEmployees) != 0 {
					t.Errorf("ancres employées %v", r.AncresEmployees)
				}
			}},
		{nom: "K-8 seule, parties absentes", post: func(e *Entree) { e.Registre, e.Certificat = Partie{RaisonAbsence: "x"}, Partie{RaisonAbsence: "x"} },
			modifs: func() map[string]string {
				m := map[string]string{"N-4": ""}
				for _, id := range IDs {
					m[id] = ""
				}
				return m
			}(), statut: "non_execute:partie_absente", avert: []string{"AV-K-1"}},
		{nom: "K-8 en échec, parties absentes", post: func(e *Entree) {
			e.Registre, e.Certificat = Partie{RaisonAbsence: "x"}, Partie{RaisonAbsence: "x"}
			e.Point.Reference.DocType = hexDocTypePeriode
		}, modifs: func() map[string]string {
			m := map[string]string{"N-4": "", "K-8": E}
			for _, id := range IDs {
				m[id] = ""
			}
			return m
		}(), statut: E, avert: []string{"AV-K-1"}},
		// Proposition à deux groupes.
		{nom: "deux jeux de validateurs", post: func(e *Entree) {
			j1 := e.Ancres.Registre.Jeux[0]
			j2 := j1
			a := uint64(104)
			j1.A = &a
			j2.De, j2.Pointeur, j2.Source = 105, "/registry/validator_sets/1", "second jeu"
			e.Ancres.Registre.Jeux = []ancres.JeuValidateurs{j1, j2}
		}, verif: func(t *testing.T, r Resultat) {
			if !strings.Contains(r.Proposition.Fr, " ; les blocs 100 et 104 sont signés par 3 des 4 validateurs du jeu ") ||
				!strings.Contains(r.Proposition.Fr, "(jeu d'essai) et les blocs 108, 112 et 116 par 3 des 4 validateurs du jeu ") ||
				!strings.HasSuffix(r.Proposition.En, "declared by the reviewer (second jeu)") ||
				!strings.Contains(r.Proposition.En, "; blocks 100 and 104 are signed by 3 of the 4") {
				t.Errorf("proposition\n %s\n %s", r.Proposition.Fr, r.Proposition.En)
			}
			if strings.Join(r.AncresEmployees, ",") != "/registry,/registry/validator_sets/0,/registry/validator_sets/1,/recorders/0" {
				t.Errorf("ancres employées %v", r.AncresEmployees)
			}
		}},
		{nom: "groupe d'un seul bloc", post: func(e *Entree) {
			j1 := e.Ancres.Registre.Jeux[0]
			j2 := j1
			a := uint64(100)
			j1.A = &a
			j2.De, j2.Pointeur = 101, "/registry/validator_sets/1"
			e.Ancres.Registre.Jeux = []ancres.JeuValidateurs{j1, j2}
		}, verif: func(t *testing.T, r Resultat) {
			if !strings.Contains(r.Proposition.Fr, " ; le bloc 100 est signé par 3 des 4") || !strings.Contains(r.Proposition.En, "; block 100 is signed by 3 of the 4") {
				t.Errorf("proposition\n %s\n %s", r.Proposition.Fr, r.Proposition.En)
			}
		}},
	}
	noms := map[string]bool{}
	for _, s := range scenarios {
		if noms[s.nom] {
			t.Fatalf("scénario en double : %s", s.nom)
		}
		noms[s.nom] = true
		t.Run(s.nom, func(t *testing.T) { lancer(t, s) })
	}
}
