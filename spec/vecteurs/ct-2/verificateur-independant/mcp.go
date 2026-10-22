// Frontal MCP (CT-2 §4) : transcriptions JSON-RPC des vecteurs pieces-mcp
// (annexe B.4), noms annoncés (4.3), pièces d'un appel relayé (4.4, 8.2),
// codes d'erreur fixes (table de 4.4), agrégation de tools/list.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// IdentiteEnregistreur est {"name":"noortrace-enregistreur","version":<code.recorder>} (EX-4.4).
const NomEnregistreur = "noortrace-enregistreur"

// VersionEnregistreurVecteurs est code.recorder des vecteurs (annexe B).
const VersionEnregistreurVecteurs = "0.1.0"

// MessagesErreurs est la table des codes de l'enregistreur (4.4, EX-4.24).
var MessagesErreurs = map[int64]string{
	-32010: "noortrace: appel bloque, enregistreur en mode degrade",
	-32011: "noortrace: delai du serveur d'outils depasse",
	-32012: "noortrace: appel annule par l'hote",
	-32013: "noortrace: taille maximale depassee",
	-32014: "noortrace: serveur d'outils injoignable",
	-32015: "noortrace: approbation requise",
	-32016: "noortrace: resultat ou requete non relayable par la configuration",
	-32017: "noortrace: appel execute, evenement non durable",
}

// CleServerInfo et CleClientInfo sont les clés _meta de 2026-07-28 (EX-4.4, EX-4.7).
const (
	CleServerInfo = "io.modelcontextprotocol/serverInfo"
	CleClientInfo = "io.modelcontextprotocol/clientInfo"
)

var (
	reAlias      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reIDAmont    = regexp.MustCompile(`^e-[0-9]{12}$`)
	reNomOutilV0 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

// ObjetReprise est la pièce « résultat » d'un événement de reprise (12.5).
func ObjetReprise(intentionSHA256 string) *Value {
	return Objet("intention_sha256", Chaine(intentionSHA256),
		"noortrace_reprise", Chaine("resultat inconnu : enregistreur arrete pendant le relais"))
}

// sansIdentiteServeur retire _meta["io.modelcontextprotocol/serverInfo"] d'un
// résultat (et _meta s'il devient vide) : la seule clé que le frontal réécrit
// dans le résultat rendu (4.4 pas 14).
func sansIdentiteServeur(r *Value) *Value {
	c := Copier(r)
	if m := c.Get("_meta"); EstObjet(m) {
		Retirer(m, CleServerInfo)
		if len(m.Obj) == 0 {
			Retirer(c, "_meta")
		}
	}
	return c
}

// LigneTranscription est une ligne d'enveloppe de hote.jsonl ou amont.jsonl :
// {"dir":"in"|"out","t":"<horodatage>","line":"<ligne telle quelle>"}, ou
// {"dir":"in","t":"<horodatage>","eof":true} pour la fin de fichier sur la
// sortie standard d'un serveur stdio (annexe B.4).
type LigneTranscription struct {
	Num    int
	Dir    string
	T      time.Time
	TTexte string
	Ligne  []byte // octets de la ligne JSON-RPC (ou du corps HTTP), tels quels
	Val    *Value // ligne analysée (nil si invalide)
	Err    error
	EOF    bool
}

// LireTranscription lit un fichier .jsonl d'enveloppes.
func LireTranscription(chemin string) ([]*LigneTranscription, error) {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	var out []*LigneTranscription
	sc := bufio.NewScanner(bytes.NewReader(octets))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	n := 0
	for sc.Scan() {
		n++
		l := sc.Bytes()
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		env, err := ParseJSON(l)
		if err != nil {
			return nil, fmt.Errorf("ligne %d : enveloppe invalide : %v", n, err)
		}
		lt := &LigneTranscription{Num: n, Dir: chaineDe(env, "dir"), TTexte: chaineDe(env, "t")}
		if lt.Dir != "in" && lt.Dir != "out" {
			return nil, fmt.Errorf("ligne %d : dir %q (attendu in ou out)", n, lt.Dir)
		}
		if t, ok := lireInstant(lt.TTexte); ok {
			lt.T = t
		}
		if e := env.Get("eof"); e != nil && e.Kind == KindBool && e.Bool && env.Get("line") == nil {
			lt.EOF = true
			out = append(out, lt)
			continue
		}
		ligne := env.Get("line")
		if !EstChaine(ligne) {
			return nil, fmt.Errorf("ligne %d : line n'est pas une chaîne", n)
		}
		lt.Ligne = []byte(ligne.Str)
		lt.Val, lt.Err = ParseJSON(lt.Ligne)
		out = append(out, lt)
	}
	return out, sc.Err()
}

func lireInstant(s string) (time.Time, bool) {
	if t, ok := ParseHorodatage(s); ok {
		return t, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func (l *LigneTranscription) methode() string {
	if l.Val == nil {
		return ""
	}
	return chaineDe(l.Val, "method")
}
func (l *LigneTranscription) id() string {
	if l.Val == nil || l.Val.Get("id") == nil {
		return ""
	}
	return doitIntegral(l.Val.Get("id"))
}
func (l *LigneTranscription) estReponse() bool {
	return l.Val != nil && l.Val.Kind == KindObject && l.Val.Get("method") == nil && (l.Val.Has("result") || l.Val.Has("error"))
}

// trouverRequete rend la première ligne de direction dir et de méthode m.
func trouverRequete(ls []*LigneTranscription, dir, m string) *LigneTranscription {
	for _, l := range ls {
		if l.Dir == dir && l.methode() == m {
			return l
		}
	}
	return nil
}

// trouverReponse rend la première réponse de direction dir à l'id donné.
func trouverReponse(ls []*LigneTranscription, dir, id string) *LigneTranscription {
	for _, l := range ls {
		if l.Dir == dir && l.estReponse() && l.id() == id {
			return l
		}
	}
	return nil
}

// definitionsListees rend les outils des réponses tools/list d'une
// transcription (direction dir), par nom.
func definitionsListees(ls []*LigneTranscription, dir string) map[string]*Value {
	out := map[string]*Value{}
	ids := map[string]bool{}
	for _, l := range ls {
		if l.methode() == "tools/list" {
			ids[l.id()] = true
		}
	}
	for _, l := range ls {
		if l.Dir != dir || !l.estReponse() || !ids[l.id()] {
			continue
		}
		if tools := l.Val.Get("result").Get("tools"); EstTableau(tools) {
			for _, t := range tools.Arr {
				if n := chaineDe(t, "name"); n != "" {
					out[n] = t
				}
			}
		}
	}
	return out
}

// DecouperNomAnnonce découpe un nom annoncé au premier « __ » (EX-4.10).
func DecouperNomAnnonce(nom string) (alias, origine string, prefixe bool) {
	if i := strings.Index(nom, "__"); i > 0 {
		return nom[:i], nom[i+2:], true
	}
	return "", nom, false
}

// ClasseOutil applique EX-4.17 sans configuration : readOnlyHint: true →
// lecture, sinon ecriture.
func ClasseOutil(def *Value) string {
	if h := def.Get("annotations").Get("readOnlyHint"); h != nil && h.Kind == KindBool && h.Bool {
		return "lecture"
	}
	return "ecriture"
}

// ---------------------------------------------------------------- agrégation

// Normalisation est le gabarit et la normalisation des noms d'une connexion
// d'hôte (tool_name_template, tool_name_sanitize, EX-5.22).
type Normalisation struct {
	Gabarit    string
	Normaliser bool
}

func pointeurs(ns []Normalisation) []*Normalisation {
	var out []*Normalisation
	for i := range ns {
		out = append(out, &ns[i])
	}
	return out
}

var reHorsNomModele = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// NomVuParModele applique le gabarit ({tool_announced}, {alias}, {tool}) puis,
// si demandé, remplace par « _ » chaque caractère hors A-Z a-z 0-9 _ - (EX-5.22).
func NomVuParModele(annonce, gabarit string, normaliser bool) string {
	if gabarit == "" {
		gabarit = "{tool_announced}"
	}
	alias, origine, _ := DecouperNomAnnonce(annonce)
	n := strings.NewReplacer("{tool_announced}", annonce, "{alias}", alias, "{tool}", origine).Replace(gabarit)
	if normaliser {
		n = reHorsNomModele.ReplaceAllString(n, "_")
	}
	return n
}

// OutilAnnonce est une entrée de la liste agrégée ; Definition est l'objet
// Tool annoncé (celui du serveur, nom remplacé par le nom annoncé, EX-4.16).
type OutilAnnonce struct {
	Alias, Origine, Annonce, Classe string
	Definition                      *Value
}

// OutilRejete est un rejet d'EX-4.11.
type OutilRejete struct {
	Alias, Origine, Raison string
}

// Agregation est le résultat de l'agrégation de tools/list (4.3).
type Agregation struct {
	Annonces     []OutilAnnonce
	Rejets       []OutilRejete
	Pages        [][]string
	RefusConfig  bool
	RaisonsRefus []string
}

// Agreger construit la liste agrégée : nom annoncé <alias>__<origine> (ou
// l'origine sans préfixe), rejets d'EX-4.11, ordre par alias puis par nom
// d'origine (unités UTF-16), pages de taille page. Collision : tous les
// outils qui portent le même nom annoncé sont rejetés. Sans préfixe, plus
// d'un serveur est un refus de configuration (EX-4.10).
func Agreger(serveurs *Value, prefixe bool, page int, normalisations ...Normalisation) *Agregation {
	ag := &Agregation{}
	if page <= 0 {
		page = 100
	}
	type cand struct {
		alias, origine string
		def            *Value
	}
	var cs []cand
	alias := map[string]bool{}
	for _, s := range serveurs.Arr {
		a := chaineDe(s, "alias")
		if !reAlias.MatchString(a) || a == "noortrace" {
			ag.RefusConfig = true
			ag.RaisonsRefus = append(ag.RaisonsRefus, fmt.Sprintf("alias %q invalide ou réservé (EX-4.9)", a))
		}
		if alias[a] {
			ag.RefusConfig = true
			ag.RaisonsRefus = append(ag.RaisonsRefus, fmt.Sprintf("alias %q en double (EX-4.9)", a))
		}
		alias[a] = true
		if tools := s.Get("tools"); EstTableau(tools) {
			for _, t := range tools.Arr {
				cs = append(cs, cand{a, chaineDe(t, "name"), t})
			}
		}
	}
	if !prefixe && len(serveurs.Arr) > 1 {
		ag.RefusConfig = true
		ag.RaisonsRefus = append(ag.RaisonsRefus, "préfixe désactivé avec plus d'un serveur d'outils (EX-4.10)")
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if c := ComparerUTF16(cs[i].alias, cs[j].alias); c != 0 {
			return c < 0
		}
		return ComparerUTF16(cs[i].origine, cs[j].origine) < 0
	})
	// noms annoncés et décompte, pour les collisions (EX-4.11) : tous les
	// outils dont le nom annoncé est porté par un autre outil sont rejetés
	// (lecture littérale ; aucun n'est préféré à l'autre).
	annonceDe := func(c cand) string {
		if prefixe {
			return c.alias + "__" + c.origine
		}
		return c.origine
	}
	// règle 3 : collision du nom annoncé, ou du nom vu par le modèle sous le
	// gabarit et la normalisation d'une connexion d'hôte
	valide := func(c cand) bool {
		a := annonceDe(c)
		return !strings.HasPrefix(c.origine, "noortrace.") && len([]rune(a)) <= 128 && reNomOutilV0.MatchString(a)
	}
	enCollision := map[int]bool{}
	for _, n := range append([]*Normalisation{nil}, pointeurs(normalisations)...) {
		parNom := map[string][]int{}
		for i, c := range cs {
			if !valide(c) {
				continue
			}
			k := annonceDe(c)
			if n != nil {
				k = NomVuParModele(k, n.Gabarit, n.Normaliser)
			}
			parNom[k] = append(parNom[k], i)
		}
		for _, is := range parNom {
			if len(is) > 1 {
				for _, i := range is {
					enCollision[i] = true
				}
			}
		}
	}
	for i, c := range cs {
		annonce := annonceDe(c)
		switch {
		case strings.HasPrefix(c.origine, "noortrace."):
			ag.Rejets = append(ag.Rejets, OutilRejete{c.alias, c.origine, "nom_reserve"})
		case len([]rune(annonce)) > 128 || !reNomOutilV0.MatchString(annonce):
			ag.Rejets = append(ag.Rejets, OutilRejete{c.alias, c.origine, "nom_invalide"})
		case enCollision[i]:
			ag.Rejets = append(ag.Rejets, OutilRejete{c.alias, c.origine, "collision"})
		default:
			def := Copier(c.def)
			Definir(def, "name", Chaine(annonce))
			ag.Annonces = append(ag.Annonces, OutilAnnonce{c.alias, c.origine, annonce, ClasseOutil(c.def), def})
		}
	}
	for i := 0; i < len(ag.Annonces); i += page {
		j := i + page
		if j > len(ag.Annonces) {
			j = len(ag.Annonces)
		}
		var p []string
		for _, a := range ag.Annonces[i:j] {
			p = append(p, a.Annonce)
		}
		ag.Pages = append(ag.Pages, p)
	}
	return ag
}
