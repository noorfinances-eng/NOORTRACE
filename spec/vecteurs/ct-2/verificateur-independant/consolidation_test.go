package main

// Formes consolidées de CT-2 §5.4.2 à §5.4.4 (EX-5.15 à EX-5.17) sur des flux
// écrits d'après les séquences que décrivent la spécification et l'annexe B.5.

import (
	"strings"
	"testing"
)

func consolider(t *testing.T, format, flux string) *Consolidation {
	t.Helper()
	evs, _ := AnalyserSSE([]byte(flux))
	c, err := Consolider(format, evs)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func formeAttendue(t *testing.T, c *Consolidation, attendu string) {
	t.Helper()
	v, err := ParseJSON([]byte(attendu))
	if err != nil {
		t.Fatal(err)
	}
	if !MemeValeur(c.Forme, v) {
		t.Errorf("forme obtenue  %s\nforme attendue %s", doitIntegral(c.Forme), doitIntegral(v))
	}
}

const fluxAnthropic = `event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","model":"modele-demo-1","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type": "ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Je règle "}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"le sinistre."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"demo__payments.create","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"amount\": \"7400.00\", "}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"rate\": 1.50}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}

event: message_stop
data: {"type":"message_stop"}

`

func TestConsolidationAnthropic(t *testing.T) {
	c := consolider(t, FormatAnthropic, fluxAnthropic)
	if c.EstErreur() {
		t.Fatalf("erreur inattendue : %+v", c)
	}
	formeAttendue(t, c, `{"id":"msg_01","type":"message","role":"assistant","model":"modele-demo-1",
	  "content":[{"type":"text","text":"Je règle le sinistre."},{"type":"tool_use","id":"toolu_01","name":"demo__payments.create","input":{"amount":"7400.00","rate":1.5}}],
	  "stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":42}}`)
	if s, _ := TexteAssistant(FormatAnthropic, c.Forme); s != "Je règle le sinistre." {
		t.Errorf("intent : %q", s)
	}
	a := AppelsOutils(FormatAnthropic, c.Forme)
	if len(a) != 1 || a[0].Nom != "demo__payments.create" || doitIntegral(a[0].Arguments) != `{"amount":"7400.00","rate":1.5}` {
		t.Errorf("appels : %+v", a)
	}
	if s, ok := TexteAvantAppel(FormatAnthropic, c.Forme, a[0]); !ok || s != "Je règle le sinistre." {
		t.Errorf("texte avant l'appel : %q", s)
	}
	// flux incomplet : coupé avant message_stop
	coupe := fluxAnthropic[:strings.Index(fluxAnthropic, "event: message_delta")]
	c = consolider(t, FormatAnthropic, coupe)
	if !c.Incomplet || !c.EstErreur() || chaineDe(c.Forme, "stop_reason") != "" || c.Forme.Get("noortrace_flux_incomplet") == nil {
		t.Errorf("incomplet : %s", doitIntegral(c.Forme))
	}
	// JSON d'outil invalide
	inv := strings.Replace(fluxAnthropic, `"\"rate\": 1.50}"`, `"\"rate\": "`, 1)
	c = consolider(t, FormatAnthropic, inv)
	b := c.Forme.Get("content").Arr[1]
	if doitIntegral(b.Get("input")) != `{}` || chaineDe(b, "noortrace_input_json_invalide") != `{"amount": "7400.00", "rate": ` {
		t.Errorf("JSON invalide : %s", doitIntegral(b))
	}
	// événement error
	er := strings.Replace(fluxAnthropic, "event: message_stop\ndata: {\"type\":\"message_stop\"}", "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}", 1)
	c = consolider(t, FormatAnthropic, er)
	if !c.Erreur || c.Incomplet || c.Forme.Get("noortrace_erreur_flux") == nil {
		t.Errorf("erreur en flux : %+v %s", c, doitIntegral(c.Forme))
	}
	// événement avant message_start : incomplet
	c = consolider(t, FormatAnthropic, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"+fluxAnthropic)
	if !c.Incomplet {
		t.Error("événement avant message_start : flux non marqué incomplet")
	}
}

const fluxChat = `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","system_fingerprint":"fp_1","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}],"obfuscation":"ab"}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[{"index":0,"delta":{"content":"Bon"},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[{"index":0,"delta":{"content":"jour"},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"demo__claims.get","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"claim_id\":"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_autre","function":{"arguments":"\"2026-77812\"}"}}]},"finish_reason":"tool_calls"}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`

func TestConsolidationChat(t *testing.T) {
	c := consolider(t, FormatChat, fluxChat)
	if c.EstErreur() {
		t.Fatalf("erreur inattendue : %+v", c)
	}
	formeAttendue(t, c, `{"id":"chatcmpl-1","created":1794045601,"model":"modele-exemple","system_fingerprint":"fp_1","object":"chat.completion",
	  "choices":[{"index":0,"message":{"role":"assistant","content":"Bonjour","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"demo__claims.get","arguments":"{\"claim_id\":\"2026-77812\"}"}}]},"finish_reason":"tool_calls"}],
	  "usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	if s, _ := TexteAssistant(FormatChat, c.Forme); s != "Bonjour" {
		t.Errorf("intent : %q", s)
	}
	// sans [DONE] : incomplet
	c = consolider(t, FormatChat, strings.Replace(fluxChat, "data: [DONE]\n\n", "", 1))
	if !c.Incomplet || c.Forme.Get("noortrace_flux_incomplet") == nil {
		t.Error("flux sans [DONE] non marqué incomplet")
	}
	// id différent du premier : incomplet
	c = consolider(t, FormatChat, strings.Replace(fluxChat, `"id":"chatcmpl-1","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[],`, `"id":"chatcmpl-2","object":"chat.completion.chunk","created":1794045601,"model":"modele-exemple","choices":[],`, 1))
	if !c.Incomplet {
		t.Error("id différent non marqué incomplet")
	}
}

const fluxResponses = `event: response.created
data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_1","object":"response","status":"in_progress","model":"modele-exemple","output":[]}}

event: response.output_item.done
data: {"type":"response.output_item.done","sequence_number":5,"output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Bonjour"}]}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","sequence_number":3,"delta":"Bon"}

event: response.completed
data: {"type":"response.completed","sequence_number":9,"response":{"id":"resp_1","object":"response","status":"completed","model":"modele-exemple","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Bonjour"}]},{"type":"function_call","call_id":"call_9","name":"demo__claims.get","arguments":"{\"claim_id\":\"2026-77812\"}"}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}}

`

func TestConsolidationResponses(t *testing.T) {
	c := consolider(t, FormatResponses, fluxResponses)
	if c.EstErreur() || chaineDe(c.Forme, "status") != "completed" {
		t.Fatalf("forme : %s", doitIntegral(c.Forme))
	}
	a := AppelsOutils(FormatResponses, c.Forme)
	if len(a) != 1 || a[0].ID != "call_9" || a[0].Position != 1 {
		t.Errorf("appels : %+v", a)
	}
	if s, ok := TexteAvantAppel(FormatResponses, c.Forme, a[0]); !ok || s != "Bonjour" {
		t.Errorf("texte avant l'appel : %q", s)
	}
	// coupé avant response.completed : forme de response.created, items terminés recopiés
	coupe := fluxResponses[:strings.Index(fluxResponses, "event: response.completed")]
	c = consolider(t, FormatResponses, coupe)
	formeAttendue(t, c, `{"id":"resp_1","object":"response","status":"in_progress","model":"modele-exemple","noortrace_flux_incomplet":true,
	  "output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Bonjour"}]}]}`)
	if !c.EstErreur() {
		t.Error("flux incomplet sans erreur")
	}
	// response.failed : fin normale, is_error
	c = consolider(t, FormatResponses, strings.ReplaceAll(fluxResponses, "response.completed", "response.failed"))
	if !c.Erreur || c.Incomplet {
		t.Errorf("failed : %+v", c)
	}
}

// Extraction (5.5) : prompt système, remplacement dans la requête, code.model.
func TestExtraction(t *testing.T) {
	req, _ := ParseJSON([]byte(`{"model":"m","system":[{"type":"text","text":"A"},{"type":"text","text":"B"}],"messages":[{"role":"user","content":"x"}]}`))
	if s, ok := PromptSysteme(FormatAnthropic, req); !ok || s != "A\nB" {
		t.Errorf("Anthropic : %q", s)
	}
	if doitIntegral(RemplacerPromptSysteme(FormatAnthropic, req)) != `{"messages":[{"content":"x","role":"user"}],"model":"m","system":"[REDIGE:prompt-systeme]"}` {
		t.Error(doitIntegral(RemplacerPromptSysteme(FormatAnthropic, req)))
	}
	req, _ = ParseJSON([]byte(`{"model":"m","messages":[{"role":"system","content":"S"},{"role":"user","content":"x"},{"role":"developer","content":[{"type":"text","text":"D"}]}]}`))
	if s, ok := PromptSysteme(FormatChat, req); !ok || s != "S\nD" {
		t.Errorf("Chat : %q", s)
	}
	req, _ = ParseJSON([]byte(`{"model":"m","instructions":"I","input":[{"role":"developer","content":"D"},{"role":"user","content":"x"}]}`))
	if s, ok := PromptSysteme(FormatResponses, req); !ok || s != "I\nD" {
		t.Errorf("Responses : %q", s)
	}
	if _, ok := PromptSysteme(FormatChat, req); ok {
		t.Error("prompt trouvé hors format")
	}
	rep, _ := ParseJSON([]byte(`{"model":"modele-reponse"}`))
	if doitIntegral(CodeModel("anthropic", req, rep)) != `"anthropic/modele-reponse"` || doitIntegral(CodeModel("openai", req, ObjetVide())) != `"openai/m"` ||
		doitIntegral(CodeModel("x", ObjetVide(), ObjetVide())) != `null` {
		t.Error("code.model")
	}
	long := strings.Repeat("é", 300)
	if s := CodeModel("p", ObjetVide(), Objet("model", Chaine(long))).Str; len([]rune(s)) != 256 {
		t.Errorf("troncature : %d caractères", len([]rune(s)))
	}
}

// EX-5.27 : données malformées ignorées et comptées, sans trou ni exception ;
// mêmes entrées que le test « données de flux malformées » de l'implémentation
// de référence.
func TestDonneesMalformees(t *testing.T) {
	sse := func(evs ...string) []EvenementSSE {
		var b strings.Builder
		for _, e := range evs {
			b.WriteString("data: " + e + "\n\n")
		}
		x, _ := AnalyserSSE([]byte(b.String()))
		return x
	}
	a := ConsoliderAnthropic(sse(`{"type":"message_start","message":{"id":"m","content":[]}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}`,
		`{"type":"content_block_start","index":1.5,"content_block":{"type":"text"}}`, `{"type":"content_block_start","index":5,"content_block":{"type":"text"}}`,
		`{"type":"content_block_start","index":0,"content_block":null}`, `{"type":"content_block_stop","index":-1}`, `[1,2]`, `pas du json`, `{"type":"message_stop"}`))
	if doitIntegral(a.Forme.Get("content")) != "[]" || a.EstErreur() || a.Ignores != 7 {
		t.Errorf("anthropic : %s erreur=%v ignorés=%d", doitIntegral(a.Forme), a.EstErreur(), a.Ignores)
	}
	c := ConsoliderChat(sse(`{"id":"c","choices":null}`, `{"id":"c","choices":[{"index":"0","delta":{}},null,{"index":0,"delta":{"tool_calls":[{"index":-1},{"index":0,"function":null,"id":null},{"index":0,"id":"t","function":{"name":"f","arguments":7}}]}}]}`, `[DONE]`))
	if got := doitIntegral(c.Forme.Get("choices").Arr[0].Get("message").Get("tool_calls")); got != `[{"function":{"arguments":"","name":"f"},"id":"t","index":0,"type":"function"}]` || c.EstErreur() {
		t.Errorf("chat : %s", got)
	}
	r := ConsoliderResponses(sse(`{"type":"response.in_progress","response":null}`, `{"type":"response.output_item.done","output_index":"1","item":{}}`, `{"type":"response.completed","response":{"id":"r","status":"completed","output":[]}}`))
	if chaineDe(r.Forme, "status") != "completed" || r.Ignores != 2 || r.EstErreur() {
		t.Errorf("responses : %s ignorés=%d", doitIntegral(r.Forme), r.Ignores)
	}
	// incomplet : un item au-delà de la longueur de output est ignoré (aucun trou)
	i := ConsoliderResponses(sse(`{"type":"response.in_progress","response":{"id":"r","output":[]}}`, `{"type":"response.output_item.done","output_index":2,"item":{"id":"z"}}`, `{"type":"response.output_item.done","output_index":0,"item":{"id":"a"}}`))
	if doitIntegral(i.Forme.Get("output")) != `[{"id":"a"}]` {
		t.Errorf("responses incomplet : %s", doitIntegral(i.Forme.Get("output")))
	}
	// tampon créé au premier input_json_delta d'un bloc qui n'est pas tool_use (EX-5.15 pas 3)
	s := ConsoliderAnthropic(sse(`{"type":"message_start","message":{"id":"m","content":[]}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"s","name":"web_search","input":{}}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"q\":1}"}}`, `{"type":"content_block_stop","index":0}`, `{"type":"message_stop"}`))
	if doitIntegral(s.Forme.Get("content").Arr[0].Get("input")) != `{"q":1}` {
		t.Errorf("server_tool_use : %s", doitIntegral(s.Forme))
	}
}
