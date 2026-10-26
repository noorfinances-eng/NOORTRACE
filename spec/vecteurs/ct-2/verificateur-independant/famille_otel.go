// Famille otel (annexe B.8, révision 0.5) : une requête OTLP par cas ;
// statut et corps de la réponse, forme normalisée, classification,
// doublons, recouvrements, pièces (réapplication de pii-v1), événements
// (hash, sig, chaîne) et lag_ms recalculés depuis le seul texte de 6.8.

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// FamilleOTel est le nom de la famille dans le rapport.
const FamilleOTel = "otel"

// Constantes des vecteurs otel (B.8, 7.2).
const (
	CleTestOTel       = "rec-test-01"
	VersionRecorder   = "0.1.0"
	JetonPromptOTel   = "[REDIGE:prompt-systeme]"
	MarqueAbsentOTel  = "noortrace_otel_absent"
	NomInvalideOTel   = "nom-invalide"
	MaxDureeMsOTel    = 9007199254740991
	ProvenanceExemple = "noortrace/exemple/ct-2/6.8/evenement-precedent"
)

var (
	reNomOutilOTel    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	reFournisseurOTel = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	reRunIDOTel       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// sortieOTel est ce qu'un cas produit.
type sortieOTel struct {
	statut     int
	protobuf   bool
	rejetes    int
	spans      []*spanOTel
	compte     map[string]int
	retryApres *Value
}

type spanOTel struct {
	chemin     [3]int
	traceID    string
	spanID     string
	issue      string
	raison     *Value
	overlapSeq *Value
	normalise  *Value
	pieces     map[string]*Piece // source, envelope, request|arguments, response|result, system_prompt, intent
	inference  bool
	evenement  *Value
	lag        *Value
}

// recordedOTel : entrée du registre de recouvrement (B.8).
type recordedOTel struct {
	sorte, groupe, nom string
	t                  time.Time
	seq                int64
	apparie            bool
}

func familleOTel(rap *Rapport, ctx *contexteCT2) {
	dir := filepath.Join(ctx.racine, "otel")
	cas := sousRepertoires(dir)
	if len(cas) == 0 {
		rap.Erreur("otel/ : absent ou vide (annexe B.8)")
		return
	}
	resultats := map[string]*sortieOTel{}
	for _, c := range cas {
		if s := verifierCasOTel(rap, ctx, filepath.Join(dir, c), c); s != nil {
			resultats[c] = s
		}
	}
	// paires JSON / protobuf (EX-6.30) et gzip (B.8)
	for _, p := range [][2]string{{"json-exemple-6-8-16", "pb-exemple-6-8-16"}, {"json-identifiants-invalides", "pb-identifiants-invalides"}} {
		a, b := resultats[p[0]], resultats[p[1]]
		if a == nil || b == nil {
			continue
		}
		rap.Comparer(FamilleOTel, p[1], "même forme normalisée, mêmes pièces et événements que "+p[0]+" (EX-6.30)", empreinteSortie(a), empreinteSortie(b))
	}
	obligatoires := []string{"json-exemple-6-8-16", "pb-exemple-6-8-16", "json-inference-sans-contenu", "json-inference-gemini", "json-inference-fournisseur",
		"json-inference-erreur", "json-inference-prompt-inline", "json-outil-sans-contenu", "json-outil-erreur", "json-outil-mcp-tools-call",
		"json-outil-nom-invalide", "json-outil-gabarit-effets", "json-spans-ignores", "json-sorte-desactivee", "json-identifiants-invalides",
		"pb-identifiants-invalides", "json-doublon-meme-requete", "json-doublon-deja-vu", "json-recouvrement-mcp", "json-recouvrement-passerelle",
		"json-recouvrement-conserve", "json-entiers-64-bits", "json-valeurs-diverses", "json-cle-double", "json-contenu-chaine-non-json",
		"json-champ-inconnu", "json-run-id-refuse", "json-retard", "json-lot-vide", "pb-champ-inconnu", "json-enum-en-chaine",
		"json-identifiant-non-hexadecimal", "json-non-analysable", "pb-champ-double", "pb-tronque", "gzip-json", "deflate-refuse",
		"type-de-contenu-inconnu", "trop-grand", "trop-grand-apres-decompression", "non-authentifie",
		"non-authentifie-type-texte", "deflate-trop-grand", "non-chemin-normalisable", "json-entier-fractionnaire", "json-fin-nulle",
		"json-contenu-hors-span", "json-operation-renommee"}
	present := map[string]bool{}
	for _, c := range cas {
		present[c] = true
	}
	for _, o := range obligatoires {
		rap.Comparer(FamilleOTel, "otel/", "cas "+o+" présent (B.8)", "présent", presentSi(present[o]))
	}
	rap.Note("otel : %d cas lus", len(cas))
}

// empreinteSortie résume formes normalisées, pièces et événements d'un cas.
func empreinteSortie(s *sortieOTel) string {
	var b strings.Builder
	for _, sp := range s.spans {
		b.WriteString(sp.issue)
		if sp.normalise != nil {
			b.WriteString(doitIntegral(sp.normalise))
		}
		for _, k := range []string{"source", "envelope", "request", "arguments", "response", "result", "system_prompt", "intent"} {
			if p := sp.pieces[k]; p != nil {
				b.WriteString(k + p.SHA256Hex())
			}
		}
		if sp.evenement != nil {
			b.WriteString(doitIntegral(sp.evenement))
		}
	}
	return Hex0x(SHA256([]byte(b.String())))
}

func lireCorpsOTel(dir string) ([]byte, string, error) {
	for _, n := range []string{"requete.json", "requete.pb", "requete.brut"} {
		if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			return b, n, nil
		}
	}
	return nil, "", fmt.Errorf("ni requete.json, ni requete.pb, ni requete.brut (B.8)")
}

func verifierCasOTel(rap *Rapport, ctx *contexteCT2, dir, nom string) *sortieOTel {
	f := FamilleOTel
	src := lireFichierJSON(rap, filepath.Join(dir, "source.json"))
	ent := lireFichierJSON(rap, filepath.Join(dir, "requete-entetes.json"))
	att := lireFichierJSON(rap, filepath.Join(dir, "attendu.json"))
	if src == nil || ent == nil || att == nil {
		return nil
	}
	corps, _, err := lireCorpsOTel(dir)
	if err != nil {
		rap.Erreur("otel/%s : %v", nom, err)
		return nil
	}
	pol := ctx.politiqueNommee(chaineDe(src, "redaction"))
	if pol == nil {
		rap.Erreur("otel/%s : politique de rédaction %q introuvable", nom, chaineDe(src, "redaction"))
		return nil
	}
	s := traiterRequeteOTel(rap, nom, src, ent, corps, pol)
	if s == nil {
		return nil
	}
	// réponse
	rap.Comparer(f, nom, "status (EX-6.27)", texteOuAbsent(att.Get("status")), strconv.Itoa(s.statut))
	rep := att.Get("response")
	ct := "application/json"
	if s.protobuf {
		ct = MediaProtobuf
	}
	rap.Comparer(f, nom, "response.content_type (EX-6.27)", chaineDe(rep, "content_type"), ct)
	comparerValeur(rap, f, nom, "response.retry_after (EX-6.27)", rep.Get("retry_after"), s.retryApres)
	j, pb := ReponseOTel(s.statut, s.rejetes, s.protobuf)
	if s.protobuf {
		rap.Comparer(f, nom, "response.body_hex (corps protobuf, EX-6.27)", texteOuAbsent(rep.Get("body_hex")), hex.EncodeToString(pb))
	} else {
		comparerValeur(rap, f, nom, "response.body_json (EX-6.27)", rep.Get("body_json"), j)
	}
	rap.Comparer(f, nom, "rejected_spans (EX-6.32)", texteOuAbsent(att.Get("rejected_spans")), strconv.Itoa(s.rejetes))
	comptes := Objet("scelle", Entier(int64(s.compte["scelle"])), "ignore", Entier(int64(s.compte["ignore"])), "doublon", Entier(int64(s.compte["doublon"])),
		"recouvrement", Entier(int64(s.compte["recouvrement"])), "rejete", Entier(int64(s.compte["rejete"])))
	comparerValeur(rap, f, nom, "counts (EX-6.41)", att.Get("counts"), comptes)
	// spans
	attSpans := att.Get("spans")
	nAtt := 0
	if EstTableau(attSpans) {
		nAtt = len(attSpans.Arr)
	}
	rap.Comparer(f, nom, "nombre de spans décrits", strconv.Itoa(nAtt), strconv.Itoa(len(s.spans)))
	cles := jeuClesTestOTel()
	var precedent *Value
	for i, sp := range s.spans {
		if i >= nAtt {
			break
		}
		a := attSpans.Arr[i]
		etiq := fmt.Sprintf("%s · span %d", nom, i)
		chemin := TableauVide()
		for _, x := range sp.chemin {
			chemin.Arr = append(chemin.Arr, Entier(int64(x)))
		}
		comparerValeur(rap, f, etiq, "path", a.Get("path"), chemin)
		rap.Comparer(f, etiq, "trace_id", chaineDe(a, "trace_id"), sp.traceID)
		rap.Comparer(f, etiq, "span_id", chaineDe(a, "span_id"), sp.spanID)
		rap.Comparer(f, etiq, "issue (EX-6.32 à EX-6.34)", chaineDe(a, "issue"), sp.issue)
		comparerValeur(rap, f, etiq, "reason (EX-6.32)", a.Get("reason"), sp.raison)
		comparerValeur(rap, f, etiq, "overlap_seq (EX-6.34)", a.Get("overlap_seq"), sp.overlapSeq)
		norm := sp.normalise
		if norm == nil {
			norm = Nul()
		}
		comparerValeur(rap, f, etiq, "normalized (EX-6.31)", a.Get("normalized"), norm)
		ap := a.Get("pieces")
		if sp.pieces == nil {
			comparerValeur(rap, f, etiq, "pieces (aucune pièce)", ap, Nul())
		} else {
			for _, k := range []string{"source", "envelope", "request", "arguments", "response", "result", "system_prompt", "intent"} {
				av := ap.Get(k)
				p := sp.pieces[k]
				if av == nil && p == nil {
					continue
				}
				comparerPiece(rap, f, etiq, k+" (EX-6.35)", av, p, nil)
			}
		}
		ev := sp.evenement
		if ev == nil {
			ev = Nul()
		}
		comparerValeur(rap, f, etiq, "event (EX-6.36)", a.Get("event"), ev)
		comparerValeur(rap, f, etiq, "lag_ms (EX-6.41)", a.Get("lag_ms"), sp.lag)
		// l'événement attendu : evenement-v0 et E-1 à E-7 (B.8), chaîne
		if ae := a.Get("event"); EstObjet(ae) {
			r := ControlerEvenement(ae, cles)
			echecs := r.Echecs()
			rap.Comparer(f, etiq, "événement attendu : schéma evenement-v0 et contrôles E-1 à E-8 (CT-1)", "aucun échec", nonVideOu(strings.Join(echecs, " ; "), "aucun échec"))
			if precedent != nil {
				rp := NouveauxResultats()
				ControlerPaire(rp, precedent, ae, etiq)
				rap.Comparer(f, etiq, "chaîne avec l'événement précédent du cas (C-1 à C-3)", "aucun échec", nonVideOu(strings.Join(rp.Echecs(), " ; "), "aucun échec"))
			} else {
				rap.Comparer(f, etiq, "prev_hash du premier événement = chain.prev_hash", chaineDe(src, "chain", "prev_hash"), chaineDe(ae, "prev_hash"))
			}
			precedent = ae
		}
	}
	if nom == "json-exemple-6-8-16" || nom == "pb-exemple-6-8-16" {
		comparerExemple6816(rap, nom, src, s)
	} else {
		// convention de B.8 et d'INDEX.md : seq_start 2 (aucun fragment ne
		// commence à seq 1, que CT-1 C-2 réserve au prev_hash nul) et
		// prev_hash = SHA-256(UTF-8 "noortrace/vecteurs/v0/otel/<cas>/precedent") ;
		// pb-identifiants-invalides reprend la chaîne de son jumeau JSON
		// (mêmes événements), comme le disent B.8 et INDEX.md
		etiquette := nom
		if nom == "pb-identifiants-invalides" {
			etiquette = "json-identifiants-invalides"
		}
		rap.Comparer(f, nom, "chain.seq_start et chain.prev_hash (convention de B.8, jumeau JSON pour une paire)",
			"2 "+Hex0x(SHA256([]byte("noortrace/vecteurs/v0/otel/"+etiquette+"/precedent"))),
			texteOuAbsent(src.Get("chain").Get("seq_start"))+" "+chaineDe(src, "chain", "prev_hash"))
	}
	return s
}

func nonVideOu(s, defaut string) string {
	if s == "" {
		return defaut
	}
	return s
}

func jeuClesTestOTel() *JeuCles {
	debut, _ := ParseHorodatage("2026-01-01T00:00:00.000Z")
	return &JeuCles{Cles: []*Cle{{KeyID: CleTestOTel, PublicKey: ClePubliqueDepuisGraine(GraineCleTest(CleTestOTel)), ValidFrom: debut}}}
}

// traiterRequeteOTel applique 6.8 à une requête.
func traiterRequeteOTel(rap *Rapport, nom string, src, ent *Value, corps []byte, pol *Politique) *sortieOTel {
	s := &sortieOTel{compte: map[string]int{}, retryApres: Nul()}
	opts := src.Get("options")
	media := TypeDeMedia(chaineDe(ent, "content-type"))
	encodages := map[string]bool{}
	if e := opts.Get("encodings"); EstTableau(e) {
		for _, x := range e.Arr {
			encodages[x.Str] = true
		}
	}
	switch {
	case media == MediaProtobuf && encodages["protobuf"]:
		s.protobuf = true
	case media == "application/json" && encodages["json"]:
	default:
		media = ""
	}
	chemin, okChemin := NormaliserChemin(strings.SplitN(chaineDe(ent, "path"), "?", 2)[0])
	maxCorps, _ := EntierDe(opts.Get("max_body_bytes"))
	profMax, _ := EntierDe(opts.Get("json_max_depth"))
	membresMax, _ := EntierDe(opts.Get("json_max_members"))
	refus := func(st int) *sortieOTel {
		s.statut = st
		if st == 429 || st == 503 {
			n, _ := EntierDe(opts.Get("retry_after_s"))
			s.retryApres = Entier(n)
		}
		return s
	}
	switch {
	case !okChemin:
		// une normalisation refusée (EX-5.2) ne peut pas égaler otel.path : 404 (EX-6.27)
		return refus(404)
	case chemin != CheminOTel:
		return refus(404)
	case chaineDe(ent, "method") != "POST":
		return refus(405)
	case ent.Get("token_id") == nil || ent.Get("token_id").IsNull():
		return refus(401)
	case media == "":
		return refus(415)
	}
	switch strings.ToLower(strings.TrimSpace(chaineDe(ent, "content-encoding"))) {
	case "", "identity":
		if int64(len(corps)) > maxCorps {
			return refus(413)
		}
	case "gzip":
		if int64(len(corps)) > maxCorps {
			return refus(413)
		}
		zr, err := gzip.NewReader(bytes.NewReader(corps))
		if err != nil {
			return refus(400)
		}
		lu, err := io.ReadAll(io.LimitReader(zr, maxCorps+1))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			if int64(len(lu)) > maxCorps {
				return refus(413)
			}
			return refus(400)
		}
		if int64(len(lu)) > maxCorps {
			return refus(413)
		}
		if err != nil {
			return refus(400)
		}
		corps = lu
	default:
		return refus(415)
	}
	var rss []otResourceSpans
	var err error
	if s.protobuf {
		rss, err = DecoderOTLPProtobuf(corps, int(profMax), int(membresMax))
	} else {
		rss, err = DecoderOTLPJSON(corps, int(profMax), int(membresMax))
	}
	if err != nil {
		rap.Detail("otel/%s : corps non décodable : %v", nom, err)
		return refus(400)
	}
	s.statut = 200
	traiterSpansOTel(rap, nom, src, opts, NormaliserSpans(rss), pol, s)
	return s
}

func traiterSpansOTel(rap *Rapport, nom string, src, opts *Value, spans []SpanNormalise, pol *Politique, s *sortieOTel) {
	alias := chaineDe(src, "alias")
	host := src.Get("host")
	psrc := src.Get("policy_source")
	ingest := map[string]bool{}
	if e := psrc.Get("ingest"); EstTableau(e) {
		for _, x := range e.Arr {
			ingest[x.Str] = true
		}
	}
	tRecep, _ := ParseHorodatage(chaineDe(src, "t_reception"))
	dedupMs, _ := EntierDe(opts.Get("dedup_window_ms"))
	overlapMs, _ := EntierDe(opts.Get("overlap_window_ms"))
	vus := map[string]bool{}
	if sv := src.Get("seen"); EstTableau(sv) {
		for _, x := range sv.Arr {
			at, ok := ParseHorodatage(chaineDe(x, "at"))
			if ok && !at.Before(tRecep.Add(-time.Duration(dedupMs)*time.Millisecond)) && !at.After(tRecep) {
				vus[chaineDe(x, "trace_id")+"/"+chaineDe(x, "span_id")] = true
			}
		}
	}
	var registre []*recordedOTel
	if rv := src.Get("recorded"); EstTableau(rv) {
		for _, x := range rv.Arr {
			t, _ := ParseHorodatage(chaineDe(x, "t"))
			seq, _ := EntierDe(x.Get("seq"))
			n := chaineDe(x, "seen_name")
			if chaineDe(x, "kind") == "echange_modele" {
				n = chaineDe(x, "model")
			}
			registre = append(registre, &recordedOTel{sorte: chaineDe(x, "kind"), groupe: chaineDe(x, "host_group"), nom: n, t: t, seq: seq})
		}
	}
	chaine := src.Get("chain")
	seq, _ := EntierDe(chaine.Get("seq_start"))
	prev := chaineDe(chaine, "prev_hash")
	tsListe := chaine.Get("ts")
	k := 0
	for _, sn := range spans {
		sp := &spanOTel{chemin: sn.Chemin, traceID: chaineDe(sn.N, "trace_id"), spanID: chaineDe(sn.N, "span_id"), raison: Nul(), overlapSeq: Nul(), lag: Nul()}
		s.spans = append(s.spans, sp)
		attrs := sn.N.Get("attributes")
		op := ""
		if o := attrs.Get("gen_ai.operation.name"); EstChaine(o) {
			op = o.Str
		} else if m := attrs.Get("mcp.method.name"); EstChaine(m) && m.Str == "tools/call" {
			op = "execute_tool"
		}
		sorte := ""
		switch op {
		case "chat", "generate_content", "text_completion":
			sorte = "inference"
		case "execute_tool":
			sorte = "outil"
		}
		ignorer := func(r string) {
			sp.issue, sp.raison = "ignore", Chaine(r)
			s.compte["ignore"]++
		}
		switch {
		case op == "":
			ignorer("hors_genai")
			continue
		case sorte == "":
			ignorer("operation_non_retenue")
			continue
		case !ingest[sorte]:
			ignorer("sorte_desactivee")
			continue
		}
		sp.normalise = sn.N
		if !idValide(sp.traceID, 32) || !idValide(sp.spanID, 16) || (sn.N.Get("parent_span_id") != nil && EstChaine(sn.N.Get("parent_span_id")) && !idValide(chaineDe(sn.N, "parent_span_id"), 16)) {
			sp.issue, sp.raison = "rejete", Chaine("identifiants_invalides")
			s.compte["rejete"]++
			s.rejetes++
			continue
		}
		cle := sp.traceID + "/" + sp.spanID
		if vus[cle] {
			sp.issue = "doublon"
			s.compte["doublon"]++
			continue
		}
		vus[cle] = true
		// pièces et événement (calculés avant le recouvrement, qui emploie M ou N)
		c := construireOTel(alias, host, psrc, sn.N, sorte, pol, opts)
		if chaineDe(psrc, "overlap") != "conserver" {
			groupe := chaineDe(host, "host_group")
			var trouve *recordedOTel
			for _, r := range registre {
				if r.apparie || r.groupe != groupe || r.t.After(tRecep) || r.t.Before(tRecep.Add(-time.Duration(overlapMs)*time.Millisecond)) {
					continue
				}
				if (sorte == "outil" && r.sorte == "appel_outil" && r.nom == c.nomDeclare) ||
					(sorte == "inference" && r.sorte == "echange_modele" && c.modele != "" && r.nom == c.modele) {
					if trouve == nil || r.t.Before(trouve.t) {
						trouve = r
					}
				}
			}
			if trouve != nil {
				trouve.apparie = true
				sp.issue, sp.overlapSeq = "recouvrement", Entier(trouve.seq)
				s.compte["recouvrement"]++
				continue
			}
		}
		// scellement
		if !EstTableau(tsListe) || k >= len(tsListe.Arr) {
			rap.Erreur("otel/%s : chain.ts ne porte pas d'horodatage pour l'événement %d", nom, k+1)
			return
		}
		ts := tsListe.Arr[k].Str
		k++
		ev := c.evenement(seq, ts, prev, src)
		seq++
		prev = chaineDe(ev, "hash")
		sp.issue, sp.pieces, sp.evenement, sp.inference = "scelle", c.pieces, ev, sorte == "inference"
		s.compte["scelle"]++
		// lag_ms = ts − fin déclarée du span, en ms, 0 si négatif ; null quand la fin déclarée vaut 0 (EX-6.41)
		if fin, _ := new(big.Int).SetString(chaineDe(sn.N, "end_time_unix_nano"), 10); fin == nil || fin.Sign() == 0 {
			sp.lag = Nul()
		} else if t, ok := ParseHorodatage(ts); ok {
			tsNs := new(big.Int).Mul(big.NewInt(t.UnixMilli()), big.NewInt(1000000))
			d := new(big.Int).Sub(tsNs, fin)
			if d.Sign() < 0 {
				d.SetInt64(0)
			}
			d.Quo(d, big.NewInt(1000000))
			sp.lag = Entier(d.Int64())
		}
	}
}

func idValide(h string, n int) bool {
	if len(h) != n {
		return false
	}
	return strings.Trim(h, "0") != ""
}

// constructionOTel porte les pièces et les champs d'un span retenu.
type constructionOTel struct {
	pieces     map[string]*Piece
	nomDeclare string // N (outil)
	nomOutil   string
	modele     string // M (inférence)
	champs     *Value // événement sans enveloppe de chaîne
}

func pieceRef(p *Piece, contexte bool) *Value {
	r := Objet("sha256", Chaine(p.SHA256Hex()), "length", Entier(int64(len(p.Octets))), "redacted", Booleen(p.Redigee))
	if p.MediaType != "" {
		Definir(r, "media_type", Chaine(p.MediaType))
	}
	if contexte {
		Definir(r, "kind", Chaine("autre"))
	}
	return r
}

// sansAttributs rend une copie de N(S) dont attributes ne garde que les
// attributs pour lesquels garder rend vrai.
func sansAttributs(n *Value, garder func(string) bool) *Value {
	c := Copier(n)
	a := c.Get("attributes")
	var obj []Member
	for _, m := range a.Obj {
		if garder(m.Key) {
			obj = append(obj, m)
		}
	}
	if obj == nil {
		obj = []Member{}
	}
	a.Obj = obj
	return c
}

// pieceEnveloppeOTel construit la pièce d'enveloppe (EX-6.35) : les règles de
// portée contexte ne s'appliquent qu'aux membres textuels de N(S) (name,
// trace_state, attributes, events[].name, events[].attributes,
// status.message, resource, scope, schema_url), lus dans une projection de
// mêmes pointeurs ; les membres structurels (identifiants, flags, kind,
// horodatages, events[].time_unix_nano, compteurs) restent tels quels.
func pieceEnveloppeOTel(pol *Politique, outil string, env *Value) *Piece {
	textuels := map[string]bool{"name": true, "trace_state": true, "attributes": true, "resource": true, "scope": true, "schema_url": true}
	proj := ObjetVide()
	for _, m := range env.Obj {
		switch {
		case textuels[m.Key]:
			Definir(proj, m.Key, Copier(m.Val))
		case m.Key == "events":
			evs := TableauVide()
			for _, e := range m.Val.Arr {
				o := ObjetVide()
				Definir(o, "name", Copier(e.Get("name")))
				Definir(o, "attributes", Copier(e.Get("attributes")))
				evs.Arr = append(evs.Arr, o)
			}
			Definir(proj, "events", evs)
		case m.Key == "status":
			Definir(proj, "status", Objet("message", Copier(m.Val.Get("message"))))
		}
	}
	red := Copier(proj)
	if pol != nil {
		red = pol.Appliquer("contexte", outil, proj).Valeur
	}
	sortie := ObjetVide()
	for _, m := range env.Obj {
		switch {
		case textuels[m.Key]:
			if v := red.Get(m.Key); v != nil && EstObjet(red) {
				Definir(sortie, m.Key, v)
			}
		case m.Key == "events":
			evs := TableauVide()
			rev := red.Get("events")
			for i, e := range m.Val.Arr {
				o := ObjetVide()
				var p *Value
				if rev != nil && EstTableau(rev) && i < len(rev.Arr) && EstObjet(rev.Arr[i]) {
					p = rev.Arr[i]
				}
				if p != nil && p.Get("name") != nil {
					Definir(o, "name", p.Get("name"))
				}
				Definir(o, "time_unix_nano", e.Get("time_unix_nano"))
				if p != nil && p.Get("attributes") != nil {
					Definir(o, "attributes", p.Get("attributes"))
				}
				Definir(o, "dropped_attributes_count", e.Get("dropped_attributes_count"))
				evs.Arr = append(evs.Arr, o)
			}
			Definir(sortie, "events", evs)
		case m.Key == "status":
			st := Objet("code", m.Val.Get("code"))
			if rs := red.Get("status"); rs != nil && EstObjet(rs) && rs.Get("message") != nil {
				Definir(st, "message", rs.Get("message"))
			}
			Definir(sortie, "status", st)
		default:
			Definir(sortie, m.Key, m.Val)
		}
	}
	avant, _ := CanoniqueIntegral(env)
	apres, _ := CanoniqueIntegral(sortie)
	return &Piece{Octets: apres, Redigee: string(apres) != string(avant), MediaType: MediaJSONExplicite}
}

func estOUT(cle string) bool {
	return cle == "gen_ai.output.messages" || cle == "gen_ai.completion" || strings.HasPrefix(cle, "gen_ai.response.") || strings.HasPrefix(cle, "gen_ai.usage.")
}

func construireOTel(alias string, host, psrc, n *Value, sorte string, pol *Politique, opts *Value) *constructionOTel {
	c := &constructionOTel{pieces: map[string]*Piece{}}
	attrs := n.Get("attributes")
	enLigne := chaineDe(opts, "prompt_in_request") == "inline"
	// 1. déclaration de source
	srcPiece, _ := PieceJSON(Objet("noortrace_capture", Objet("channel", Chaine("otel"), "source", Chaine(alias))), false, MediaJSONExplicite)
	c.pieces["source"] = srcPiece
	var args, res *Piece
	var argsRed, resRed *Value
	intent := Nul()
	var pieceIntent *Piece
	codeModel, promptVersion := Nul(), Nul()
	var outil, decision string
	effets := TableauVide()
	if sorte == "inference" {
		req, resp := ObjetVide(), ObjetVide()
		for _, m := range attrs.Obj {
			switch {
			case estOUT(m.Key):
				resp.Obj = append(resp.Obj, Member{Key: m.Key, Val: Copier(m.Val)})
			case strings.HasPrefix(m.Key, "gen_ai."):
				req.Obj = append(req.Obj, Member{Key: m.Key, Val: Copier(m.Val)})
			}
		}
		// texte du prompt système T et requête (reference ou inline)
		var textes []string
		corps := Copier(req)
		rediger := func(v *Value) *Value {
			if enLigne {
				return pol.Appliquer("prompt_systeme", "", v).Valeur
			}
			return Chaine(JetonPromptOTel)
		}
		if si := req.Get("gen_ai.system_instructions"); si != nil {
			switch {
			case EstChaine(si):
				textes = append(textes, si.Str)
			case EstTableau(si):
				for _, e := range si.Arr {
					if EstObjet(e) && chaineDe(e, "type") == "text" && EstChaine(e.Get("content")) {
						textes = append(textes, e.Get("content").Str)
					}
				}
			}
			csi := corps.Get("gen_ai.system_instructions")
			if !enLigne {
				Definir(corps, "gen_ai.system_instructions", Chaine(JetonPromptOTel))
			} else if EstChaine(csi) {
				Definir(corps, "gen_ai.system_instructions", rediger(csi))
			} else if EstTableau(csi) {
				for _, e := range csi.Arr {
					if EstObjet(e) && chaineDe(e, "type") == "text" && EstChaine(e.Get("content")) {
						Definir(e, "content", rediger(e.Get("content")))
					}
				}
			}
		}
		if im := corps.Get("gen_ai.input.messages"); EstTableau(im) {
			for _, m := range im.Arr {
				if !EstObjet(m) || chaineDe(m, "role") != "system" {
					continue
				}
				if ps := m.Get("parts"); EstTableau(ps) {
					for _, p := range ps.Arr {
						if EstObjet(p) && chaineDe(p, "type") == "text" && EstChaine(p.Get("content")) {
							textes = append(textes, p.Get("content").Str)
							Definir(p, "content", rediger(p.Get("content")))
						}
					}
				}
			}
		}
		T := len(textes) > 0
		if T {
			pp, _ := PieceRedigeeTexte(pol, "prompt_systeme", "", strings.Join(textes, "\n"))
			c.pieces["system_prompt"] = pp
			promptVersion = Chaine(pp.SHA256Hex())
		}
		avant, _ := CanoniqueIntegral(req)
		pr, resReq, _ := PieceRedigeeJSON(pol, "requete", "", corps)
		pr.Redigee = string(pr.Octets) != string(avant) || (T && !enLigne)
		args = pr
		argsRed = resReq.Valeur
		prs, resRep, _ := PieceRedigeeJSON(pol, "reponse", "", resp)
		res = prs
		resRed = resRep.Valeur
		c.pieces["request"], c.pieces["response"] = args, res
		// intent : premier élément de gen_ai.output.messages de la réponse rédigée
		texteSortie := func(r *Value) (string, bool) {
			om := r.Get("gen_ai.output.messages")
			if !EstTableau(om) || len(om.Arr) == 0 {
				return "", false
			}
			var t []string
			if ps := om.Arr[0].Get("parts"); EstTableau(ps) {
				for _, p := range ps.Arr {
					if EstObjet(p) && chaineDe(p, "type") == "text" && EstChaine(p.Get("content")) {
						t = append(t, p.Get("content").Str)
					}
				}
			}
			if len(t) == 0 {
				return "", false
			}
			return strings.Join(t, "\n"), true
		}
		if t, ok := texteSortie(resRed); ok {
			clair, _ := texteSortie(resp)
			red := t != clair
			if red || utf8.RuneCountInString(t) > 4096 {
				pieceIntent = &Piece{Octets: []byte(t), Redigee: red, MediaType: MediaTexte}
				intent = pieceRef(pieceIntent, false)
			} else {
				intent = Chaine(t)
			}
		}
		// code.model
		M := ""
		if v := resRed.Get("gen_ai.response.model"); EstChaine(v) && v.Str != "" {
			M = v.Str
		} else if v := argsRed.Get("gen_ai.request.model"); EstChaine(v) && v.Str != "" {
			M = v.Str
		}
		c.modele = M
		if M != "" {
			fourn := ""
			if v := argsRed.Get("gen_ai.provider.name"); EstChaine(v) {
				fourn = v.Str
			} else if v := argsRed.Get("gen_ai.system"); EstChaine(v) {
				fourn = v.Str
			}
			if !reFournisseurOTel.MatchString(fourn) {
				fourn = "inconnu"
			}
			codeModel = Chaine(tronquer256(fourn + "/" + M))
		}
		// enveloppe : attributs hors gen_ai., portée contexte, sélecteur "*"
		env := sansAttributs(n, func(k string) bool { return !strings.HasPrefix(k, "gen_ai.") })
		pe := pieceEnveloppeOTel(pol, "", env)
		c.pieces["envelope"] = pe
		outil, decision = OutilModele, "sans_objet"
	} else {
		N := ""
		if v := attrs.Get("gen_ai.tool.name"); EstChaine(v) && v.Str != "" {
			N = v.Str
		} else if nm := chaineDe(n, "name"); strings.HasPrefix(nm, "execute_tool ") {
			N = strings.TrimPrefix(nm, "execute_tool ")
		} else if strings.HasPrefix(nm, "tools/call ") {
			N = strings.TrimPrefix(nm, "tools/call ")
		}
		c.nomDeclare = N
		outil = alias + "__" + N
		objet := N
		if !reNomOutilOTel.MatchString(N) || strings.Contains(N, "__") || strings.HasPrefix(N, "noortrace.") || utf8.RuneCountInString(outil) > 128 {
			outil = alias + "__" + NomInvalideOTel
			objet = NomInvalideOTel
		}
		c.nomOutil = outil
		valeurOuAbsent := func(cle string) *Value {
			if v := attrs.Get(cle); v != nil {
				return Copier(v)
			}
			return Objet(MarqueAbsentOTel, Chaine(cle))
		}
		pa, ra, _ := PieceRedigeeJSON(pol, "arguments", outil, valeurOuAbsent("gen_ai.tool.call.arguments"))
		pr, rr, _ := PieceRedigeeJSON(pol, "resultat", outil, valeurOuAbsent("gen_ai.tool.call.result"))
		args, res, argsRed, resRed = pa, pr, ra.Valeur, rr.Valeur
		c.pieces["arguments"], c.pieces["result"] = pa, pr
		env := sansAttributs(n, func(k string) bool { return k != "gen_ai.tool.call.arguments" && k != "gen_ai.tool.call.result" })
		pe := pieceEnveloppeOTel(pol, outil, env)
		c.pieces["envelope"] = pe
		decision = "autorise"
		// effets (EX-7.6, EX-6.36)
		reglage := psrc.Get("tools").Get(N)
		if g := reglage.Get("effects"); EstTableau(g) {
			effets, _ = evaluerGabarit(g, argsRed, resRed)
		} else {
			classe := "ecriture"
			if cl := reglage.Get("class"); EstChaine(cl) {
				classe = cl.Str
			} else if cd := psrc.Get("class_default"); EstChaine(cd) {
				classe = cd.Str
			}
			if classe == "ecriture" {
				effets.Arr = append(effets.Arr, Objet("system", Chaine(alias), "action", Chaine("ecriture"), "object", Chaine(objet), "amount", Nul(), "currency", Nul()))
			}
		}
	}
	if pieceIntent != nil {
		c.pieces["intent"] = pieceIntent
	}
	if _, ok := c.pieces["system_prompt"]; !ok {
		c.pieces["system_prompt"] = nil
	}
	if _, ok := c.pieces["intent"]; !ok {
		c.pieces["intent"] = nil
	}
	// délégation
	runID := Nul()
	if b := host.Get("accept_declared_delegation"); b != nil && b.Kind == KindBool && b.Bool {
		if v := attrs.Get("gen_ai.conversation.id"); EstChaine(v) && reRunIDOTel.MatchString(v.Str) && AucunDetecteur(pol, v.Str) {
			runID = Chaine(v.Str)
		}
	}
	// durée et erreur
	duree := int64(0)
	debut, _ := new(big.Int).SetString(chaineDe(n, "start_time_unix_nano"), 10)
	fin, _ := new(big.Int).SetString(chaineDe(n, "end_time_unix_nano"), 10)
	if debut != nil && fin != nil && debut.Sign() > 0 && fin.Sign() > 0 && fin.Cmp(debut) >= 0 {
		d := new(big.Int).Sub(fin, debut)
		d.Quo(d, big.NewInt(1000000))
		if d.Cmp(big.NewInt(MaxDureeMsOTel)) > 0 {
			d.SetInt64(MaxDureeMsOTel)
		}
		duree = d.Int64()
	}
	estErreur := false
	if code, ok := EntierDe(n.Get("status").Get("code")); ok && code == 2 {
		estErreur = true
	}
	if v := attrs.Get("error.type"); EstChaine(v) && v.Str != "" {
		estErreur = true
	}
	// policy.redaction (EX-10.20 : toutes les références, contexte compris)
	redige := args.Redigee || res.Redigee || c.pieces["source"].Redigee || c.pieces["envelope"].Redigee || (pieceIntent != nil && pieceIntent.Redigee)
	redaction := Nul()
	if redige {
		redaction = Chaine(pol.Nom)
	}
	c.champs = Objet(
		"delegation", Objet("launched_by", Copier(host.Get("launched_by")), "on_behalf_of", Copier(host.Get("on_behalf_of")), "scope", Copier(host.Get("scope")), "run_id", runID),
		"code", Objet("model", codeModel, "prompt_version", promptVersion, "policy_version", Nul(), "recorder", Chaine(VersionRecorder)),
		"intent", intent,
		"policy", Objet("rule", Nul(), "decision", Chaine(decision), "ticket", Nul(), "redaction", redaction),
		"approval", Nul(),
		"execution", Objet("tool", Chaine(outil), "arguments", pieceRef(args, false), "status", Chaine("executee"), "result", pieceRef(res, false),
			"duration_ms", Entier(duree), "is_error", Booleen(estErreur)),
		"effects", effets,
		"context", &Value{Kind: KindArray, Arr: []*Value{pieceRef(c.pieces["source"], true), pieceRef(c.pieces["envelope"], true)}},
	)
	return c
}

// evenement construit, hache et signe l'événement (7.2, 7.3, CT-1 §6).
func (c *constructionOTel) evenement(seq int64, ts, prev string, src *Value) *Value {
	ev := Objet("version", Entier(0), "seq", Entier(seq), "ts", Chaine(ts), "org_id", Chaine(OrgIDVecteurs), "journal_id", Chaine(JournalIDVecteurs()),
		"recorder_key_id", Chaine(CleTestOTel), "prev_hash", Chaine(prev))
	for _, m := range c.champs.Obj {
		ev.Obj = append(ev.Obj, Member{Key: m.Key, Val: Copier(m.Val)})
	}
	Definir(ev.Get("code"), "policy_version", Copier(src.Get("policy_version")))
	h, canon, err := HashEvenement(ev)
	if err != nil {
		Definir(ev, "hash", Chaine("! "+err.Error()))
		return ev
	}
	priv := ed25519.NewKeyFromSeed(GraineCleTest(CleTestOTel))
	sig := ed25519.Sign(priv, append(append([]byte{}, PrefixeSignatureEvenement...), canon...))
	Definir(ev, "hash", Chaine(Hex0x(h)))
	Definir(ev, "sig", Chaine(Hex0x(sig)))
	return ev
}

// Valeurs imprimées par l'exemple de 6.8.16 (recopiées).
var exemple6816 = struct {
	pieces map[string][2]string // clé : sha256, length
	hash   [2]string
	sig    [2]string
	prev   string
}{
	pieces: map[string][2]string{
		"0/system_prompt": {"0xd9908f3ea8908b3578e2ba5e95971616b9510c2c00accef44605cf1ffb7f8db5", "85"},
		"0/request":       {"0x69a9e553553b5c0bdfe6c3ee6b9bc45ebd1ce1b891682659cf192a681de34ea5", "376"},
		"0/response":      {"0x74df77a8761266e52028f81b17ea815dbb4c2b0a22f43647bd1ecc2c0a3f0730", "522"},
		"0/source":        {"0xda9c76bef505dd669a602c015f8c8f6d4ef13339aeeb6357edbf5a7ecbf87922", "66"},
		"0/envelope":      {"0x06cffdf0bf57b6b0d1f560223c777b31312ae3758a096b0fa750f4a7b542f511", "687"},
		"1/arguments":     {"0x9a3a2950fcddea1685d5f41cd3a7fa0d5085aa76c8bb127d186cae6439851090", "72"},
		"1/result":        {"0x2f2d9c5e977bede0ecd28d814bc7effec1844ed52e149d9a4f71dab1c228195a", "46"},
		"1/source":        {"0xda9c76bef505dd669a602c015f8c8f6d4ef13339aeeb6357edbf5a7ecbf87922", "66"},
		"1/envelope":      {"0xdd76be17ddfcd0dba01e9f10536830636a3d90c483781bd7578118fc7f2091b2", "783"},
	},
	hash: [2]string{"0x120b63ed9c35030f17764ebcee60d3192706089769f04e2084f86165c62235f0", "0xee35fdc3a3f8ce5caf5491cb73a8e01f64c98b2756a286f336d07769c9da570a"},
	sig: [2]string{"0x9bea66cf8fc441e2219131ac7458a7281ef9cea0449af661c06ed9efea6da2820173085b1767384e3403f55c882b9a104750c72bd808d009c216bf12c22eb503",
		"0xa99fd27260d49cc3260ccfa4a677a8ac257857a1bfc982be4247ec1d3000e72eb2e3f4498b4ed11c4910c86642a91624c57f1a7cf7b82fa869f81fcd5b42e403"},
	prev: "0x51fd37e0be1bd585252709bf83e7d51e317b51e0c5ff2142bfe5f4667be99aa8",
}

func comparerExemple6816(rap *Rapport, nom string, src *Value, s *sortieOTel) {
	f := FamilleOTel
	rap.Comparer(f, nom, "6.8.16 : hash précédent imprimé = SHA-256(\""+ProvenanceExemple+"\")", exemple6816.prev, Hex0x(SHA256([]byte(ProvenanceExemple))))
	rap.Comparer(f, nom, "6.8.16 : chain.prev_hash = hash précédent imprimé", exemple6816.prev, chaineDe(src, "chain", "prev_hash"))
	for i, sp := range s.spans {
		if i > 1 {
			break
		}
		for k, v := range exemple6816.pieces {
			if !strings.HasPrefix(k, strconv.Itoa(i)+"/") {
				continue
			}
			p := sp.pieces[strings.TrimPrefix(k, strconv.Itoa(i)+"/")]
			obt := "absente"
			if p != nil {
				obt = p.SHA256Hex() + " / " + strconv.Itoa(len(p.Octets))
			}
			rap.Comparer(f, nom, "6.8.16 : pièce "+k+" imprimée (sha256 / length)", v[0]+" / "+v[1], obt)
		}
		if sp.evenement != nil {
			rap.Comparer(f, nom, fmt.Sprintf("6.8.16 : hash imprimé de l'événement %d", i+1), exemple6816.hash[i], chaineDe(sp.evenement, "hash"))
			rap.Comparer(f, nom, fmt.Sprintf("6.8.16 : sig imprimée de l'événement %d", i+1), exemple6816.sig[i], chaineDe(sp.evenement, "sig"))
		}
	}
}
