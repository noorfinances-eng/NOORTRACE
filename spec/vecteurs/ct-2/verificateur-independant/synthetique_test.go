package main

// Arborescence ct-2 synthétique, dans la disposition de l'annexe B, pour
// exercer chaque famille de bout en bout. Les valeurs imprimées par la
// spécification (annexe A, 10.9, table de la RFC 8785) y sont des attendus
// indépendants ; les autres attendus sont produits par ce module (le test
// contrôle alors la lecture des fichiers et la cohérence entre familles, pas
// les calculs eux-mêmes, que les autres tests couvrent).

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type arbreSynthetique struct {
	t      *testing.T
	racine string
}

func (a *arbreSynthetique) ecrire(chemin string, octets []byte) {
	a.t.Helper()
	p := filepath.Join(a.racine, chemin)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		a.t.Fatal(err)
	}
	if err := os.WriteFile(p, octets, 0o644); err != nil {
		a.t.Fatal(err)
	}
}

func (a *arbreSynthetique) json(chemin string, v *Value) {
	a.t.Helper()
	c, err := CanoniqueIntegral(v)
	if err != nil {
		a.t.Fatal(err)
	}
	a.ecrire(chemin, append(c, '\n'))
}

func doit(t *testing.T, texte string) *Value {
	t.Helper()
	v, err := ParseJSON([]byte(texte))
	if err != nil {
		t.Fatalf("%v : %s", err, texte)
	}
	return v
}

func refPiece(p *Piece, avecMedia bool) *Value {
	r := Objet("sha256", Chaine(p.SHA256Hex()), "length", Entier(int64(len(p.Octets))), "redacted", Booleen(p.Redigee))
	if avecMedia && p.MediaType != "" {
		Definir(r, "media_type", Chaine(p.MediaType))
	}
	return r
}

func refBytes(p *Piece) *Value {
	r := refPiece(p, true)
	Definir(r, "bytes", Chaine(string(p.Octets)))
	return r
}

func enveloppe(dir, t, ligne string) string {
	c, _ := CanoniqueIntegral(Objet("dir", Chaine(dir), "t", Chaine(t), "line", Chaine(strings.TrimSuffix(ligne, "\n"))))
	return string(c) + "\n"
}

func construireArbre(t *testing.T) string {
	a := &arbreSynthetique{t: t, racine: t.TempDir()}
	pii := lireSpec(t, "pii-v1.json")
	pol := politiqueSpec(t)

	// ---- INDEX.md
	a.ecrire("INDEX.md", []byte(fmt.Sprintf("# Vecteurs CT-2\n\njournal_id : %s\n\nclé de pseudonymisation de test : %s\n\nnonce noortrace/vecteurs/v0/nonce/journal-demo/periode-1 : %s\n\nFamilles : jcs-integral, redaction, pieces-mcp, pieces-modele, evenements.\n\nCas de pieces-mcp/appels : `annexe-a/`, `erreur-jsonrpc/`, `approbation-annexe-a/`, `approbation-refus/`, `approbation-en-attente/`.\n",
		JournalIDVecteurs(), ClePseudoTestHex, NonceVecteurs(1))))
	copierFamillesRevision05(a)

	// ---- jcs-integral
	cas := TableauVide()
	for i, l := range TableRFC8785 {
		canon := Nul()
		entree := l.JSON
		if l.JSON == "" {
			entree = []string{"NaN", "Infinity"}[i%2]
		} else {
			canon = Chaine(l.JSON)
		}
		cas.Arr = append(cas.Arr, Objet("name", Chaine(fmt.Sprintf("rfc8785-%02d", i)), "input", Chaine(entree), "canonical", canon, "note", Chaine("table 1 de la RFC 8785")))
	}
	for i, c := range [][2]string{{`{"a":1.0}`, `{"a":1}`}, {`{"a":1e3}`, `{"a":1000}`}, {`{"a":9007199254740993}`, `{"a":9007199254740992}`}, {`{"a":1,"a":2}`, ""}, {`{"a":"\ud800"}`, ""}, {`{"b":"\u001F","a":0.0000001}`, `{"a":1e-7,"b":"\u001f"}`}} {
		canon := Nul()
		if c[1] != "" {
			canon = Chaine(c[1])
		}
		cas.Arr = append(cas.Arr, Objet("name", Chaine(fmt.Sprintf("ct1-%d", i)), "input", Chaine(c[0]), "canonical", canon, "note", Chaine("cas limite")))
	}
	a.json("jcs-integral/cas.json", cas)

	// ---- redaction
	a.ecrire("redaction/politique-pii-v1.json", pii)
	docPseudo := valeurSpec(t, "pii-v1.json")
	Definir(docPseudo, "name", Chaine("pii-pseudo-test"))
	Definir(docPseudo, "pseudonym_key", Objet("env", Chaine(VariableClePseudoTest), "encoding", Chaine("hex")))
	for _, r := range docPseudo.Get("rules").Arr {
		Definir(r, "action", Objet("kind", Chaine("pseudonyme")))
	}
	docPseudo.Get("rules").Arr = append([]*Value{doit(t, RegleChampPseudoTest)}, docPseudo.Get("rules").Arr...)
	a.json("redaction/politique-pseudonyme-test.json", docPseudo)
	// motifs exigés par B.3 (version 0.3), notes portant la règle a), b) ou c)
	a.json("redaction/motifs.json", doit(t, `[{"pattern":"\\b20[0-9]{2}\\b","admis":true,"note":"admis"},{"pattern":".","admis":false,"note":"refusé"},
	  {"pattern":"[0-9]+$","admis":true,"note":"retour arrière polynomial, borné par EX-10.23"},
	  {"pattern":"(?P<annee>20[0-9]{2})","admis":true,"note":"groupe nommé (?P<nom>…)"},
	  {"pattern":"^(a+)+$","admis":false,"note":"règle a) : OWASP"},{"pattern":"([a-zA-Z]+)*$","admis":false,"note":"règle a) : OWASP"},
	  {"pattern":"(a|aa)+$","admis":false,"note":"règle a) : OWASP"},{"pattern":"(a|a?)+$","admis":false,"note":"règle a) : OWASP"},
	  {"pattern":"(a|aa){1,1000}$","admis":false,"note":"règle a) : alternative sous un quantificateur borné"},
	  {"pattern":"(a{1,1000}){1,1000}$","admis":false,"note":"règle a) : répétition imbriquée bornée"},
	  {"pattern":"(\\w|\\d)+$","admis":false,"note":"règle a) : alternative qui se recouvre"},
	  {"pattern":"(?:[0-9]{4} ?){3}","admis":false,"note":"règle a) : forme bénigne"},
	  {"pattern":"(?:\\b)+x","admis":false,"note":"règle b) : groupe quantifié vide"},
	  {"pattern":"[0-9]{1000}x","admis":false,"note":"règle c) : taille 1 001"},
	  {"pattern":"[(?P<]x","admis":true,"note":"(?P< dans une classe","matches":[{"input":"Px","first":"Px"}]},
	  {"pattern":"a\\(?P<b","admis":true,"note":"parenthèse échappée","matches":[{"input":"aP<b","first":"aP<b"},{"input":"a<b","first":null}]},
	  {"pattern":"\\(?P<x>","admis":true,"note":"parenthèse échappée","matches":[{"input":"P<x>","first":"P<x>"}]},
	  {"pattern":"\\\\(?P<x>a)","admis":true,"note":"vrai groupe nommé","matches":[{"input":"\\a","first":"\\a"}]},
	  {"pattern":"a{01}","admis":false,"note":"zéro non significatif"},{"pattern":"[0-9]{04}","admis":false,"note":"zéro non significatif"},
	  {"pattern":"a{0,01}","admis":false,"note":"zéro non significatif"}]`))
	red := TableauVide()
	red.Arr = append(red.Arr, doit(t, `{"name":"exemple-10-9-arguments","policy":"pii-v1","scope":"arguments","tool":"sap.payments.create",
	  "input":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"},
	  "expected":{"piece":"{\"amount\":\"7400.00\",\"beneficiary_iban\":\"[REDIGE:iban]\",\"claim_id\":\"2026-77812\",\"currency\":\"CHF\"}",
	    "sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4","length":96,"redacted":true,
	    "matches":[{"rule":"identifiants-arguments-resultat","detector":"iban","count":1}]}}`))
	red.Arr = append(red.Arr, doit(t, `{"name":"exemple-10-9-resultat","policy":"pii-v1","scope":"resultat","tool":"sap.payments.create",
	  "input":{"note":"Virement au bénéficiaire CH93 0076 2011 6238 5295 7, assuré 756.1234.5678.97, joignable au +41 44 123 45 67 ou j.dupont@example.ch ; carte 3782 822463 10005."},
	  "expected":{"piece":"{\"note\":\"Virement au bénéficiaire [REDIGE:iban], assuré [REDIGE:avs], joignable au [REDIGE:telephone] ou [REDIGE:email] ; carte [REDIGE:carte].\"}",
	    "sha256":"0x89a34ad286014dee1e1030caf6d50d32327a77da216dfb4a19154f15b73d5f8e","length":148,"redacted":true,
	    "matches":[{"rule":"identifiants-arguments-resultat","detector":"iban","count":1},{"rule":"identifiants-arguments-resultat","detector":"avs","count":1},
	      {"rule":"identifiants-arguments-resultat","detector":"carte","count":1},{"rule":"identifiants-arguments-resultat","detector":"email","count":1},
	      {"rule":"identifiants-arguments-resultat","detector":"telephone","count":1}]}}`))
	pseudoPiece := `[PSEUDO:iban:50d46ea9a82b] et [PSEUDO:email:b8ac789204a6]`
	red.Arr = append(red.Arr, Objet("name", Chaine("pseudonyme-10-9"), "policy", Chaine("pii-pseudo-test"), "scope", Chaine("prompt_systeme"), "tool", Nul(),
		"input", Chaine("CH9300762011623852957 et j.dupont@example.ch"),
		"expected", Objet("piece", Chaine(pseudoPiece), "sha256", Chaine(Hex0x(SHA256([]byte(pseudoPiece)))), "length", Entier(int64(len(pseudoPiece))), "redacted", Booleen(true),
			"matches", doit(t, `[{"rule":"identifiants-modele","detector":"iban","count":1},{"rule":"identifiants-modele","detector":"email","count":1}]`))))
	a.json("redaction/cas.json", red)

	// ---- pieces-mcp : appel de l'annexe A (préfixe désactivé, alias sap)
	def := string(lireSpec(t, "annexe-a-definition.json"))
	h := enveloppe("in", "2026-11-03T13:52:40.000Z", `{"jsonrpc":"2.0","id":"h-1","method":"tools/list","params":{}}`) +
		enveloppe("out", "2026-11-03T13:52:40.010Z", `{"jsonrpc":"2.0","id":"h-1","result":{"tools":[`+strings.TrimSuffix(def, "\n")+`],"resultType":"complete"}}`) +
		enveloppe("in", "2026-11-03T13:52:40.600Z", string(lireSpec(t, "annexe-a-hote-requete.jsonl"))) +
		enveloppe("out", "2026-11-03T13:52:41.095Z", string(lireSpec(t, "annexe-a-hote-reponse.jsonl")))
	am := enveloppe("out", "2026-11-03T13:52:40.680Z", string(lireSpec(t, "annexe-a-amont-requete.jsonl"))) +
		enveloppe("in", "2026-11-03T13:52:41.092Z", string(lireSpec(t, "annexe-a-amont-reponse.jsonl")))
	a.ecrire("pieces-mcp/appels/annexe-a/hote.jsonl", []byte(h))
	a.ecrire("pieces-mcp/appels/annexe-a/amont.jsonl", []byte(am))
	a.json("pieces-mcp/appels/annexe-a/attendu.json", doit(t, `{"tool_announced":"sap.payments.create","tool_original":"sap.payments.create","server_alias":"sap","class":"ecriture",
	  "pieces":{"arguments":{"sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4","length":96,"redacted":true,
	      "bytes":"{\"amount\":\"7400.00\",\"beneficiary_iban\":\"[REDIGE:iban]\",\"claim_id\":\"2026-77812\",\"currency\":\"CHF\"}"},
	    "result":{"sha256":"0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c","length":109,"redacted":false,
	      "bytes":"{\"content\":[{\"text\":\"Paiement PAY-2026-55120 créé\",\"type\":\"text\"}],\"isError\":false,\"resultType\":\"complete\"}"},
	    "definition":{"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a","length":406,"redacted":false,"media_type":"application/json"},
	    "definition_current":null,
	    "list":{"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e","length":418,"redacted":false,"media_type":"application/json"}},
	  "context":[{"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a","length":406,"redacted":false,"media_type":"application/json","kind":"autre"},
	    {"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e","length":418,"redacted":false,"media_type":"application/json","kind":"autre"}],
	  "rejected":false,"is_error":false,"duration_ms":412,"error_rendered":null,"approval":null,"result_rendered":null,"note":"annexe A"}`))
	// approbation (EX-4.49, EX-7.16) : la requête de l'annexe A, réponse
	// d'evaluer de l'annexe A (ticket nouveau, mode erreur), ligne rendue
	// imprimée par l'annexe A (359 octets) ; puis un refus par la politique,
	// résultat exact d'EX-4.49, rendu à la même requête.
	attAppr := doit(t, `{"tool_announced":"sap.payments.create","tool_original":"sap.payments.create","server_alias":"sap","class":"ecriture",
	  "pieces":{"arguments":{"sha256":"0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4","length":96,"redacted":true,
	      "bytes":"{\"amount\":\"7400.00\",\"beneficiary_iban\":\"[REDIGE:iban]\",\"claim_id\":\"2026-77812\",\"currency\":\"CHF\"}"},
	    "result":null,
	    "definition":{"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a","length":406,"redacted":false,"media_type":"application/json"},
	    "definition_current":null,
	    "list":{"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e","length":418,"redacted":false,"media_type":"application/json"}},
	  "context":[{"sha256":"0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a","length":406,"redacted":false,"media_type":"application/json","kind":"autre"},
	    {"sha256":"0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e","length":418,"redacted":false,"media_type":"application/json","kind":"autre"}],
	  "rejected":false,"is_error":null,"duration_ms":null,"error_rendered":null,"approval":null,"result_rendered":null,
	  "protocols":{"host":"2026-07-28","server":"2026-07-28"},"note":"annexe A, mode erreur"}`)
	ligneSignal := strings.TrimSuffix(string(lireSpec(t, "annexe-a-signal-attente.jsonl")), "\n")
	Definir(attAppr, "approval", Objet("response", valeurSpec(t, "annexe-a-reponse-evaluer.json")))
	Definir(attAppr, "result_rendered", doit(t, ligneSignal).Get("result"))
	hAppr := enveloppe("in", "2026-11-03T13:41:06.000Z", `{"jsonrpc":"2.0","id":"h-1","method":"tools/list","params":{}}`) +
		enveloppe("out", "2026-11-03T13:41:06.010Z", `{"jsonrpc":"2.0","id":"h-1","result":{"tools":[`+strings.TrimSuffix(def, "\n")+`],"resultType":"complete"}}`) +
		enveloppe("in", "2026-11-03T13:41:07.000Z", string(lireSpec(t, "annexe-a-hote-requete.jsonl"))) +
		enveloppe("out", "2026-11-03T13:41:07.300Z", ligneSignal)
	a.ecrire("pieces-mcp/appels/approbation-annexe-a/hote.jsonl", []byte(hAppr))
	a.ecrire("pieces-mcp/appels/approbation-annexe-a/amont.jsonl", nil)
	a.json("pieces-mcp/appels/approbation-annexe-a/attendu.json", attAppr)
	refus := strings.TrimSuffix(string(lireSpec(t, "ex-4-49-refus.json")), "\n")
	attRefus := Copier(attAppr)
	Definir(attRefus, "approval", doit(t, `{"response":{"rule":"paiement hors CHF","decision":"refuse","ticket":null,"ticket_state":null,"approval":null,"approver_set":null}}`))
	Definir(attRefus, "result_rendered", doit(t, refus))
	hRefus := strings.Replace(hAppr, enveloppe("out", "2026-11-03T13:41:07.300Z", ligneSignal), enveloppe("out", "2026-11-03T13:41:07.300Z", `{"jsonrpc":"2.0","id":"h-77812-4","result":`+refus+`}`), 1)
	a.ecrire("pieces-mcp/appels/approbation-refus/hote.jsonl", []byte(hRefus))
	a.ecrire("pieces-mcp/appels/approbation-refus/amont.jsonl", nil)
	a.json("pieces-mcp/appels/approbation-refus/attendu.json", attRefus)
	// ticket en attente pour un hôte de l'ère héritée (requête sans _meta) :
	// « l'objet est le même sans resultType » (EX-4.49), texte de l'exemple
	signalHerite := strings.Replace(texteSpec(t, "ex-4-49-signal.json"), `"resultType":"complete",`, "", 1)
	attAttente := Copier(attAppr)
	Definir(attAttente, "approval", doit(t, `{"response":{"rule":"paiement > 5000 CHF","decision":"a_approuver","ticket":"apr-1192","ticket_state":"en_attente","approval":null,"approver_set":null}}`))
	Definir(attAttente, "result_rendered", doit(t, signalHerite))
	Definir(attAttente, "protocols", doit(t, `{"host":"2025-11-25","server":"2026-07-28"}`))
	hAttente := enveloppe("in", "2026-11-03T13:41:06.000Z", `{"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}}`) +
		enveloppe("out", "2026-11-03T13:41:06.010Z", `{"jsonrpc":"2.0","id":40,"result":{"tools":[`+strings.TrimSuffix(def, "\n")+`]}}`) +
		enveloppe("in", "2026-11-03T13:41:07.000Z", `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"sap.payments.create","arguments":{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}}}`) +
		enveloppe("out", "2026-11-03T13:41:07.008Z", `{"jsonrpc":"2.0","id":41,"result":`+signalHerite+`}`)
	a.ecrire("pieces-mcp/appels/approbation-en-attente/hote.jsonl", []byte(hAttente))
	a.ecrire("pieces-mcp/appels/approbation-en-attente/amont.jsonl", nil)
	a.json("pieces-mcp/appels/approbation-en-attente/attendu.json", attAttente)
	// erreur JSON-RPC du serveur
	defLue := doit(t, `{"name":"demo__claims.get","description":"Lit un dossier","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`)
	h2 := enveloppe("in", "2026-11-03T13:59:59.000Z", `{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}`) +
		enveloppe("out", "2026-11-03T13:59:59.010Z", `{"jsonrpc":"2.0","id":6,"result":{"tools":[`+doitIntegral(defLue)+`]}}`) +
		enveloppe("in", "2026-11-03T14:00:00.000Z", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"demo__claims.get","arguments":{"claim_id":"x","taux":1.50},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`) +
		enveloppe("out", "2026-11-03T14:00:00.100Z", `{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"Invalid params","data":{"champ":"claim_id"}}}`)
	am2 := enveloppe("out", "2026-11-03T14:00:00.010Z", `{"jsonrpc":"2.0","id":"e-000000000001","method":"tools/call","params":{"name":"claims.get","arguments":{"claim_id":"x","taux":1.50},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"noortrace-enregistreur","version":"0.1.0"}}}}`) +
		enveloppe("in", "2026-11-03T14:00:00.095Z", `{"jsonrpc":"2.0","id":"e-000000000001","error":{"code":-32602,"message":"Invalid params","data":{"champ":"claim_id"}}}`)
	a.ecrire("pieces-mcp/appels/erreur-jsonrpc/hote.jsonl", []byte(h2))
	a.ecrire("pieces-mcp/appels/erreur-jsonrpc/amont.jsonl", []byte(am2))
	pa, _, _ := PieceRedigeeJSON(pol, "arguments", "demo__claims.get", doit(t, `{"claim_id":"x","taux":1.50}`))
	pr, _, _ := PieceRedigeeJSON(pol, "resultat", "demo__claims.get", doit(t, `{"noortrace_jsonrpc_error":{"code":-32602,"message":"Invalid params","data":{"champ":"claim_id"}}}`))
	pdl, _ := PieceJSON(defLue, false, MediaJSONExplicite)
	pll, _ := PieceJSON(Objet("tools", &Value{Kind: KindArray, Arr: []*Value{defLue}}), false, MediaJSONExplicite)
	ctxRef := func(p *Piece) *Value { r := refPiece(p, true); Definir(r, "kind", Chaine("autre")); return r }
	a.json("pieces-mcp/appels/erreur-jsonrpc/attendu.json", Objet("tool_announced", Chaine("demo__claims.get"), "tool_original", Chaine("claims.get"), "server_alias", Chaine("demo"), "class", Chaine("lecture"),
		"rejected", Booleen(false), "context", &Value{Kind: KindArray, Arr: []*Value{ctxRef(pdl), ctxRef(pll)}},
		"pieces", Objet("arguments", refBytes(pa), "result", refBytes(pr), "definition", refBytes(pdl), "definition_current", Nul(), "list", refBytes(pll)),
		"is_error", Booleen(true), "duration_ms", Entier(85), "error_rendered", doit(t, `{"code":-32602,"message":"Invalid params","data":{"champ":"claim_id"}}`),
		"approval", Nul(), "result_rendered", Nul(), "note", Chaine("erreur JSON-RPC")))
	// agrégation
	a.json("pieces-mcp/agregation/serveurs.json", doit(t, `[{"alias":"demo","tools":[{"name":"payments.create","annotations":{"readOnlyHint":false}},{"name":"claims.get","annotations":{"readOnlyHint":true}},{"name":"noortrace.x"}]}]`))
	a.json("pieces-mcp/agregation/attendu.json", doit(t, `{"prefix":true,"announced":[{"server_alias":"demo","original":"claims.get","announced":"demo__claims.get","class":"lecture"},{"server_alias":"demo","original":"payments.create","announced":"demo__payments.create","class":"ecriture"}],
	  "rejected":[{"server_alias":"demo","original":"noortrace.x","reason":"nom_reserve"}],"pages":[["demo__claims.get","demo__payments.create"]]}`))

	// ---- pieces-modele : flux Anthropic
	req := doit(t, `{"model":"modele-demo-1","max_tokens":1024,"stream":true,"system":"Tu es l'agent sinistres. Contact : j.dupont@example.ch","messages":[{"role":"user","content":"Règle le sinistre 2026-77812, IBAN CH9300762011623852957"}]}`)
	a.json("pieces-modele/anthropic-messages-flux/requete.json", req)
	a.json("pieces-modele/anthropic-messages-flux/requete-entetes.json", doit(t, `{"anthropic-version":"2023-06-01"}`))
	a.ecrire("pieces-modele/anthropic-messages-flux/reponse.sse", []byte(fluxAnthropic))
	a.json("pieces-modele/anthropic-messages-flux/reponse-entetes.json", doit(t, `{"status":200,"content-type":"text/event-stream"}`))
	evs, _ := AnalyserSSE([]byte(fluxAnthropic))
	cons := ConsoliderAnthropic(evs)
	calc := &CalculModele{Format: FormatAnthropic, Libelle: "anthropic", Requete: req, Reponse: cons.Forme, Consolidation: cons, Statut: 200}
	calculerEchange(pol, calc)
	appels := TableauVide()
	for _, x := range calc.Appels {
		appels.Arr = append(appels.Arr, Objet("id", Chaine(x.ID), "name", Chaine(x.Nom), "arguments", x.Arguments))
	}
	a.json("pieces-modele/anthropic-messages-flux/attendu.json", Objet("format", Chaine(FormatAnthropic), "provider_label", Chaine("anthropic"), "consolidated", cons.Forme,
		"pieces", Objet("request", refBytes(calc.PieceRequete), "response", refBytes(calc.PieceReponse), "system_prompt", refBytes(calc.PiecePrompt)),
		"code_model", Chaine("anthropic/modele-demo-1"), "prompt_version", calc.PromptVersion, "intent", Chaine("Je règle le sinistre."),
		"tool_calls", appels, "is_error", Booleen(false), "incomplete", Booleen(false), "note", Chaine("flux")))

	// ---- evenements/journal-demo
	construireJournal(t, a, pol, pii)
	return a.racine
}

func construireJournal(t *testing.T, a *arbreSynthetique, pol *Politique, pii []byte) {
	jid := JournalIDVecteurs()
	priv := ed25519.NewKeyFromSeed(GraineCleTest("rec-test-01"))
	pieces := map[string]*Piece{}
	garder := func(p *Piece) *Piece { pieces[p.SHA256Hex()] = p; return p }
	politique := doit(t, `{"version":"demo-2026-11","approval":{"rules":[{"tool":"demo__payments.create","when":"amount > 5000","decision":"a_approuver"}],"mode":"erreur","hold_timeout_ms":null,"expire_after_ms":3600000,"timeout_ms":2000,"service":{"url":null,"socket":null,"token":null}},
	  "redaction":`+string(pii)+`,
	  "servers":{"demo":{"transport":{"type":"http","url":"http://outils-demo:8100/mcp","headers":{},"oauth":null,"tls":null},"protocol":"2026-07-28","class_default":"lecture","timeout_ms":null,
	    "tools":{"payments.create":{"class":"ecriture","timeout_ms":null,"effects":[{"system":"demo","action":"ecriture","object":"/result/content/0/text","extract":"PAY-[0-9]{4}-[0-9]{5}","amount":"/arguments/amount","currency":"/arguments/currency"}],"failure":null},
	      "claims.get":{"class":"lecture","timeout_ms":null,"effects":null,"failure":"passant"}},"uri_prefixes":[],"relay":null}},
	  "failure":{"ecriture":"bloquant","lecture":"passant","approval_service":{"ecriture":"bloquant","lecture":"passant"},"pending_max_events":10000,"pending_max_ms":300000}}`)
	a.json("evenements/journal-demo/politique.json", politique)
	cpol, _ := CanoniqueIntegral(politique)
	shaPol := Hex0x(SHA256(cpol))
	garder(&Piece{Octets: cpol, MediaType: MediaJSONExplicite})

	deleg := doit(t, `{"launched_by":"agent-demo","on_behalf_of":"service-sinistres","scope":"sinistres:lecture,paiement","run_id":"run-demo-1"}`)
	delegJournal := doit(t, `{"launched_by":"noortrace-enregistreur","on_behalf_of":null,"scope":"journal:administration","run_id":null}`)
	code := func(model, pv *Value) *Value {
		return Objet("model", model, "prompt_version", pv, "policy_version", Chaine("demo-2026-11"), "recorder", Chaine("0.1.0"))
	}
	politiqueEv := func(rule, decision, ticket *Value, red bool) *Value {
		r := Nul()
		if red {
			r = Chaine("pii-v1")
		}
		return Objet("rule", rule, "decision", decision, "ticket", ticket, "redaction", r)
	}
	var evs []*Value
	prev := Zero32
	echangesBruts := TableauVide()
	appelsBruts := TableauVide()
	ligneHote := func(id, outil, args string) string {
		return `{"jsonrpc":"2.0","id":"` + id + `","method":"tools/call","params":{"name":"` + outil + `","arguments":` + args + `,"_meta":{"noortrace/delegation":{"run_id":"run-demo-1"}}}}`
	}
	sceller := func(ts string, deleg, code, intent, policy, approval, execution, effects, context *Value) *Value {
		ev := Objet("version", Entier(0), "seq", Entier(int64(len(evs)+1)), "ts", Chaine(ts), "org_id", Chaine(OrgIDVecteurs), "journal_id", Chaine(jid),
			"recorder_key_id", Chaine("rec-test-01"), "prev_hash", Chaine(prev), "delegation", deleg, "code", code, "intent", intent, "policy", policy,
			"approval", approval, "execution", execution, "effects", effects, "context", context)
		c, err := Canonique(ev)
		if err != nil {
			t.Fatal(err)
		}
		hsh := Hex0x(SHA256Prefixe(PrefixeEvenement, c))
		sig := ed25519.Sign(priv, append(append([]byte{}, PrefixeSignatureEvenement...), c...))
		Definir(ev, "hash", Chaine(hsh))
		Definir(ev, "sig", Chaine(Hex0x(sig)))
		prev = hsh
		evs = append(evs, ev)
		return ev
	}
	exec := func(tool string, args, status, res, dur, ie *Value) *Value {
		return Objet("tool", Chaine(tool), "arguments", args, "status", status, "result", res, "duration_ms", dur, "is_error", ie)
	}
	enLigne := func(v *Value) *Value {
		c, _ := Canonique(v)
		return Objet("sha256", Chaine(Hex0x(SHA256(c))), "length", Entier(int64(len(c))), "redacted", Booleen(false), "value", v)
	}
	// seq 1 : politique
	sceller("2026-11-10T10:00:00.000Z", delegJournal, code(Nul(), Nul()), Nul(), politiqueEv(Nul(), Chaine("sans_objet"), Nul(), false), Nul(),
		exec(OutilPolitique, enLigne(Objet("policy_version", Chaine("demo-2026-11"), "policy_sha256", Chaine(shaPol))), Chaine("executee"), Nul(), Nul(), Nul()), TableauVide(), TableauVide())
	// échange de modèle (hors flux)
	echange := func(ts, sys, texte, outil, args string) *Value {
		req := doit(t, `{"model":"modele-demo-1","max_tokens":512,"system":`+doitIntegral(Chaine(sys))+`,"messages":[{"role":"user","content":"Règle le sinistre 2026-77812"}]}`)
		contenu := `[{"type":"text","text":` + doitIntegral(Chaine(texte)) + `}`
		if outil != "" {
			contenu += `,{"type":"tool_use","id":"toolu_` + fmt.Sprint(len(evs)) + `","name":"` + outil + `","input":` + args + `}`
		}
		rep := doit(t, `{"id":"msg_`+fmt.Sprint(len(evs))+`","type":"message","role":"assistant","model":"modele-demo-1","content":`+contenu+`],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":2}}`)
		c := &CalculModele{Format: FormatAnthropic, Libelle: "demo", Requete: req, Reponse: rep, Statut: 200}
		calculerEchange(pol, c)
		garder(c.PieceRequete)
		garder(c.PieceReponse)
		garder(c.PiecePrompt)
		intent := c.Intent
		if c.PieceIntent != nil {
			garder(c.PieceIntent)
		}
		red := c.PieceRequete.Redigee || c.PieceReponse.Redigee || EstObjet(intent) && intent.Get("redacted").Bool
		echangesBruts.Arr = append(echangesBruts.Arr, Objet("seq", Entier(int64(len(evs)+1)), "host", Chaine("agent-demo"), "host_group", Chaine("demo"), "run_id", Chaine("run-demo-1"),
			"format", Chaine(FormatAnthropic), "provider_label", Chaine("demo"), "route", Chaine("/v1/messages"), "t_complet", Chaine(ts),
			"request", req, "response_content_type", Chaine("application/json"), "response_body", Chaine(doitIntegral(rep))))
		return sceller(ts, deleg, code(c.CodeModel, c.PromptVersion), intent, politiqueEv(Nul(), Chaine("sans_objet"), Nul(), red), Nul(),
			exec(OutilModele, refPiece(c.PieceRequete, true), Chaine("executee"), refPiece(c.PieceReponse, true), Entier(800), Booleen(false)), TableauVide(), TableauVide())
	}
	e2 := echange("2026-11-10T10:00:01.000Z", "Tu es l'agent sinistres de démonstration.", "Je consulte le dossier.", "demo__claims.get", `{"claim_id":"2026-77812"}`)
	defLectureV := doit(t, `{"name":"demo__claims.get","description":"Lit un dossier","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`)
	defEcritureV := doit(t, `{"name":"demo__payments.create","description":"Cree un paiement","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false}}`)
	defLecture := garder(&Piece{Octets: []byte(doitIntegral(defLectureV)), MediaType: MediaJSONExplicite})
	defEcriture := garder(&Piece{Octets: []byte(doitIntegral(defEcritureV)), MediaType: MediaJSONExplicite})
	servie := &Value{Kind: KindArray, Arr: []*Value{defLectureV, defEcritureV}}
	pListe, _ := PieceJSON(Objet("tools", servie), false, MediaJSONExplicite)
	garder(pListe)
	ctxDef := func(p *Piece) *Value {
		r := refPiece(p, true)
		Definir(r, "kind", Chaine("autre"))
		l := refPiece(pListe, true)
		Definir(l, "kind", Chaine("autre"))
		return &Value{Kind: KindArray, Arr: []*Value{r, l}}
	}
	appel := func(seq int64, t, ligne string, herite *Value) {
		appelsBruts.Arr = append(appelsBruts.Arr, Objet("seq", Entier(seq), "host", Chaine("agent-demo"), "host_group", Chaine("demo"), "run_id", Chaine("run-demo-1"),
			"t_recu", Chaine(t), "host_line", Chaine(ligne), "inherits_from_seq", herite))
	}
	// seq 3 : lecture corrélée à seq 2
	argsL, _, _ := PieceRedigeeJSON(pol, "arguments", "demo__claims.get", doit(t, `{"claim_id":"2026-77812"}`))
	resL, _, _ := PieceRedigeeJSON(pol, "resultat", "demo__claims.get", doit(t, `{"resultType":"complete","content":[{"type":"text","text":"Dossier 2026-77812, bénéficiaire CH9300762011623852957"}],"isError":false}`))
	garder(argsL)
	garder(resL)
	appel(3, "2026-11-10T10:00:01.500Z", ligneHote("h-3", "demo__claims.get", `{"claim_id":"2026-77812"}`), Nul())
	sceller("2026-11-10T10:00:02.000Z", deleg, Copier(e2.Get("code")), Chaine("Je consulte le dossier."), politiqueEv(Nul(), Chaine("autorise"), Nul(), true), Nul(),
		exec("demo__claims.get", refPiece(argsL, true), Chaine("executee"), refPiece(resL, true), Entier(120), Booleen(false)), TableauVide(), ctxDef(defLecture))
	// seq 4 : échange dont l'appel porte un IBAN (rédigé dans la réponse)
	argsClairs := `{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}`
	e4 := echange("2026-11-10T10:00:03.000Z", "Tu es l'agent sinistres de démonstration.", "Je crée le paiement.", "demo__payments.create", argsClairs)
	// seq 5 : retenue, corrélée à seq 4
	argsE, _, _ := PieceRedigeeJSON(pol, "arguments", "demo__payments.create", doit(t, argsClairs))
	garder(argsE)
	ticket := Chaine("apr-demo-1")
	regle := Chaine("montant > 5000")
	appel(5, "2026-11-10T10:00:03.500Z", ligneHote("h-5", "demo__payments.create", argsClairs), Nul())
	s5 := sceller("2026-11-10T10:00:04.000Z", deleg, Copier(e4.Get("code")), Chaine("Je crée le paiement."), politiqueEv(regle, Chaine("a_approuver"), ticket, true), Nul(),
		exec("demo__payments.create", refPiece(argsE, true), Chaine("retenue"), Nul(), Nul(), Nul()), TableauVide(), ctxDef(defEcriture))
	// seq 6 : décision
	sigFactice := "0x" + strings.Repeat("11", 64) + "1b"
	approval := Objet("decision", Chaine("approuve"), "ticket", ticket, "request_hash", Chaine(chaineDe(s5, "hash")), "threshold", Objet("required", Entier(2), "size", Entier(3)),
		"approvers", doit(t, `["0x70997970c51812dc3a010c7d01b50e0d17dc79c8","0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"]`),
		"signatures", &Value{Kind: KindArray, Arr: []*Value{Chaine(sigFactice), Chaine(sigFactice)}}, "at", Chaine("2026-11-10T10:00:10.000Z"), "reason", Chaine("Pièces validées"))
	s6 := Objet("decision", Chaine("approuve"), "journal_id", Chaine(jid), "org_id", Chaine(OrgIDVecteurs), "request_hash", Chaine(chaineDe(s5, "hash")), "ticket", ticket)
	sceller("2026-11-10T10:00:10.000Z", deleg, Copier(s5.Get("code")), Nul(), politiqueEv(Nul(), Chaine("sans_objet"), ticket, false), Copier(approval),
		exec(OutilApprobation, enLigne(s6), Chaine("executee"), Nul(), Nul(), Nul()), TableauVide(), TableauVide())
	// seq 7 : écriture relayée après approbation : reprend de seq 5 intent, code et policy (EX-7.12)
	appel(7, "2026-11-10T10:00:11.000Z", ligneHote("h-7", "demo__payments.create", argsClairs), Entier(5))
	resE, _, _ := PieceRedigeeJSON(pol, "resultat", "demo__payments.create", doit(t, `{"resultType":"complete","content":[{"type":"text","text":"Paiement PAY-2026-00042 créé"}],"isError":false}`))
	garder(resE)
	s7 := sceller("2026-11-10T10:00:11.500Z", deleg, Copier(s5.Get("code")), Copier(s5.Get("intent")), politiqueEv(regle, Chaine("a_approuver"), ticket, true), Copier(approval),
		exec("demo__payments.create", refPiece(argsE, true), Chaine("executee"), refPiece(resE, true), Entier(412), Booleen(false)),
		doit(t, `[{"system":"demo","action":"ecriture","object":"PAY-2026-00042","amount":"7400.00","currency":"CHF"}]`), ctxDef(defEcriture))
	// seq 8 : fin de tour
	echange("2026-11-10T10:00:12.000Z", "Tu es l'agent sinistres de démonstration.", "Paiement créé.", "", "")

	// fichiers
	liste := TableauVide()
	for _, ev := range evs {
		liste.Arr = append(liste.Arr, ev)
	}
	a.json("evenements/journal-demo/evenements.json", liste)
	att := Objet("valide", Booleen(true), "events", TableauVide(), "policy_sha256", Chaine(shaPol))
	for _, ev := range evs {
		_, c, _ := HashEvenement(ev)
		att.Get("events").Arr = append(att.Get("events").Arr, Objet("seq", Copier(ev.Get("seq")), "hash", Copier(ev.Get("hash")), "sig", Copier(ev.Get("sig")),
			"prev_hash", Copier(ev.Get("prev_hash")), "canonical_length", Entier(int64(len(c)))))
	}
	// signal d'approbation rendu pour seq 5 en mode erreur, hôte de l'ère
	// héritée (requête sans protocolVersion) : sans resultType (EX-4.49, B.6)
	Definir(att, "result_rendered_seq_5", doit(t, `{"content":[{"type":"text","text":"noortrace: appel soumis a approbation ; ticket=apr-demo-1 ; state=en_attente"}],"isError":true,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"noortrace-enregistreur","version":"0.1.0"},"noortrace/approval":{"ticket":"apr-demo-1","state":"en_attente"}}}`))
	cA, _ := Canonique(s6)
	Definir(att, "A", s6)
	Definir(att, "D_A", Chaine(Hex0x(SHA256Prefixe(PrefixeApprobation, cA))))
	// intention de seq 7
	idI := "i-00000000000000000001-000000000001"
	in := Objet("intent_id", Chaine(idI), "upstream_id", Chaine("e-000000000007"), "host", Chaine("agent-demo"), "written_at", Chaine("2026-11-10T10:00:11.000Z"), "org_id", Chaine(OrgIDVecteurs), "journal_id", Chaine(jid),
		"tool", Chaine("demo__payments.create"), "arguments", refPiece(argsE, true), "ticket", ticket)
	lin, _ := CanoniqueIntegral(in)
	Definir(att, "intention_sha256", Chaine(Hex0x(SHA256(lin))))
	partiel := Objet("delegation", Copier(s7.Get("delegation")), "code", Copier(s7.Get("code")), "intent", Copier(s7.Get("intent")), "policy", Copier(s7.Get("policy")), "approval", Copier(s7.Get("approval")),
		"execution", Objet("tool", Chaine("demo__payments.create"), "arguments", Copier(s7.Get("execution").Get("arguments"))), "effects", TableauVide(), "context", Copier(s7.Get("context")))
	lcx, _ := CanoniqueIntegral(Objet("intent_context", Chaine(idI), "event", partiel))
	lev, _ := CanoniqueIntegral(Objet("lifted", Chaine(idI), "seq", Entier(7)))
	a.json("evenements/journal-demo/entrees.json", Objet("host", doit(t, `{"id":"agent-demo","host_group":"demo","launched_by":"agent-demo","on_behalf_of":"service-sinistres","scope":"sinistres:lecture,paiement","tool_name_template":"{tool_announced}","tool_name_sanitize":true}`),
		"exchanges", echangesBruts, "calls", appelsBruts, "served_list", servie))
	a.ecrire("evenements/journal-demo/intentions.ndjson", []byte(string(lin)+"\n"+string(lcx)+"\n"+string(lev)+"\n"))
	a.json("evenements/journal-demo/attendu.json", att)
	pj := TableauVide()
	for _, p := range pieces {
		r := refBytes(p)
		if p.MediaType == "" {
			Definir(r, "media_type", Nul())
			Retirer(r, "media_type")
		}
		pj.Arr = append(pj.Arr, r)
	}
	a.json("evenements/journal-demo/pieces.json", pj)
	a.json("evenements/journal-demo/cles.json", doit(t, `{"version":0,"org_id":"`+OrgIDVecteurs+`","journal_id":"`+jid+`","keys":[{"key_id":"rec-test-01","algorithm":"ed25519","public_key":"`+
		Hex0x(ClePubliqueDepuisGraine(GraineCleTest("rec-test-01")))+`","valid_from":"2026-11-01T00:00:00.000Z","valid_to":null,"source":"synthétique"}]}`))
	entete, _ := Canonique(Objet("noortrace_segment", Entier(0), "org_id", Chaine(OrgIDVecteurs), "journal_id", Chaine(jid), "first_seq", Entier(1), "prev_hash", Chaine(Zero32),
		"epoch", Entier(1), "recorder_key_id", Chaine("rec-test-01"), "instance_id", Chaine("enregistreur-demo"), "recorder", Chaine("0.1.0"), "opened_at", Chaine("2026-11-10T09:59:59.000Z")))
	seg := string(entete) + "\n"
	for _, ev := range evs {
		c, _ := Canonique(ev)
		seg += string(c) + "\n"
	}
	a.ecrire("evenements/journal-demo/segment.ndjson", []byte(seg))
}

func TestVecteursSynthetiques(t *testing.T) {
	racine := construireArbre(t)
	rap := VerifierVecteursCT2(racine, true)
	n, c, d, hp := rap.Comptes()
	t.Logf("%d valeur(s) recalculée(s), %d concordante(s), %d discordante(s), %d hors périmètre, %d erreur(s)", n, c, d, hp, len(rap.Erreurs))
	var discordances []string
	for _, x := range rap.Comparaisons {
		if !x.Concorde && !x.HorsPerimetre && x.Famille != FamilleConstantes {
			discordances = append(discordances, fmt.Sprintf("[%s] %s · %s\n  attendu %s\n  obtenu  %s\n  %s", x.Famille, x.Vecteur, x.Grandeur, x.Attendu, x.Obtenu, x.Note))
		}
	}
	if len(discordances) > 0 || len(rap.Erreurs) > 0 {
		t.Fatalf("discordances :\n%s\nerreurs : %v", strings.Join(discordances, "\n"), rap.Erreurs)
	}
	if os.Getenv("CT2_RAPPORT_SYNTHETIQUE") != "" {
		var sb strings.Builder
		rap.EcrireTexte(&sb, true)
		t.Log(sb.String())
	}
	if n < 300 {
		t.Errorf("trop peu de valeurs recalculées : %d", n)
	}
	// une altération est détectée : un octet du segment
	seg := filepath.Join(racine, "evenements", "journal-demo", "segment.ndjson")
	b, _ := os.ReadFile(seg)
	b[len(b)-3] ^= 1
	os.WriteFile(seg, b, 0o644)
	rap = VerifierVecteursCT2(racine, true)
	if _, _, d2, _ := rap.Comptes(); d2 <= d {
		t.Error("segment altéré non détecté")
	}
}

// Version 0.3 : un signal d'approbation dont les membres ne suivent pas
// l'ordre des exemples d'EX-4.49, ou l'ancienne erreur -32015 de la version
// 0.2 à sa place, sont détectés ; un motif d'OWASP ou à zéro non significatif
// déclaré admis, et une première correspondance fausse, aussi.
func TestAlterationsVersion03(t *testing.T) {
	racine := construireArbre(t)
	ecrire := func(rel, ancien, nouveau string) {
		t.Helper()
		p := filepath.Join(racine, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), ancien) {
			t.Fatalf("%s : %q introuvable", rel, ancien)
		}
		os.WriteFile(p, []byte(strings.Replace(string(b), ancien, nouveau, 1)), 0o644)
	}
	discordances := func() map[string]bool {
		out := map[string]bool{}
		for _, x := range VerifierVecteursCT2(racine, true).Comparaisons {
			if !x.Concorde && !x.HorsPerimetre {
				out[x.Vecteur] = true
			}
		}
		return out
	}
	if d := discordances(); len(d) != 0 {
		t.Fatalf("arbre de départ discordant : %v", d)
	}
	// ordre des membres : isError avant content
	ecrire("pieces-mcp/appels/approbation-refus/hote.jsonl", `\"content\":[{\"type\":\"text\",\"text\":\"noortrace: appel refuse par la politique\"}],\"isError\":true`,
		`\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"noortrace: appel refuse par la politique\"}]`)
	// ancienne erreur -32015 au lieu du signal
	b, _ := os.ReadFile(filepath.Join(racine, "pieces-mcp/appels/approbation-en-attente/hote.jsonl"))
	lignes := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	lignes[len(lignes)-1] = strings.TrimSuffix(enveloppe("out", "2026-11-03T13:41:07.008Z", `{"jsonrpc":"2.0","id":41,"error":{"code":-32015,"message":"noortrace: approbation requise","data":{"ticket":"apr-1192","state":"en_attente"}}}`), "\n")
	os.WriteFile(filepath.Join(racine, "pieces-mcp/appels/approbation-en-attente/hote.jsonl"), []byte(strings.Join(lignes, "\n")+"\n"), 0o644)
	// motif d'OWASP déclaré admis
	ecrire("redaction/motifs.json", `{"admis":false,"note":"règle a) : OWASP","pattern":"^(a+)+$"}`, `{"admis":true,"note":"règle a) : OWASP","pattern":"^(a+)+$"}`)
	// première correspondance d'un motif à « (?P< » qui n'ouvre pas de groupe :
	// celle d'un remplacement textuel par (?< ; quantificateur à zéro non
	// significatif déclaré admis
	ecrire("redaction/motifs.json", `{"first":"Px","input":"Px"}`, `{"first":null,"input":"Px"}`)
	ecrire("redaction/motifs.json", `{"admis":false,"note":"zéro non significatif","pattern":"a{01}"}`, `{"admis":true,"note":"zéro non significatif","pattern":"a{01}"}`)
	d := discordances()
	for _, v := range []string{"appels/approbation-refus", "appels/approbation-en-attente", "motifs.json[4] ^(a+)+$", `motifs.json[14] [(?P<]x matches[0] "Px"`, "motifs.json[18] a{01}"} {
		if !d[v] {
			t.Errorf("%s : altération non détectée (%v)", v, d)
		}
	}
}

// copierFamillesRevision05 recopie dans l'arbre synthétique les familles
// otel/, worm/ et cout-agent/ des vecteurs publiés (révision 0.5,
// annexes B.8 à B.10), indépendantes des autres familles, et ajoute à
// INDEX.md ce que B.7 y exige pour elles.
func copierFamillesRevision05(a *arbreSynthetique) {
	a.t.Helper()
	var cas []string
	for _, fam := range []string{"otel", "worm", "cout-agent"} {
		src := filepath.Join("..", fam)
		if _, err := os.Stat(src); err != nil {
			a.t.Skipf("vecteurs publiés absents (%s) : familles de la révision 0.5 non recopiables", src)
		}
		err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel("..", p)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			a.ecrire(rel, b)
			return nil
		})
		if err != nil {
			a.t.Fatal(err)
		}
	}
	for _, c := range sousRepertoires(filepath.Join("..", "otel")) {
		cas = append(cas, "`"+c+"/`")
	}
	p := filepath.Join(a.racine, "INDEX.md")
	b, _ := os.ReadFile(p)
	b = append(b, []byte("\n## `otel/`\n\n"+strings.Join(cas, ", ")+"\n\n## `worm/`\n\nBucket `"+BucketWormDemo+"`, préfixe `"+PrefixeWormDemo+
		"`, période `1794304800`.\n\n## `cout-agent/`\n\nPrix en unités symboliques.\n")...)
	a.ecrire("INDEX.md", b)
}
