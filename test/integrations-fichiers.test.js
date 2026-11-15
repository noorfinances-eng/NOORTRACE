// Fichiers d'intégration de CT-2 §19.5 (19.5.1 à 19.5.11), lus dans le texte
// de la spécification, sans moteur de conteneurs ni réseau : ce qu'EX-19.5
// exige de chaque fichier publié (table « chemin, capturé, interposé ou
// déclaratif, pas capturé » et règle de non-double capture), la cohérence des
// configurations des hôtes de bureau (19.5.1 Claude Desktop, 19.5.2 Claude
// Code, 19.5.3 Cursor, 19.5.6 autres hôtes) avec la configuration de
// démonstration de §19.1 (ports, chemin, jetons, assainissement des noms), et
// l'égalité des versions que chaque fichier cite avec les épingles des verrous
// (CT-2 §6.4, précondition des TI-4 à TI-11 : « à la version épinglée par
// CT-2 §6.4 »). Les hôtes de bureau n'ont pas de scénario automatique ici
// (applications absentes de l'environnement de construction) : cet essai est
// leur part vérifiable ; la part interactive est rattachée avec son motif
// (rapport).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { RACINE } from "./fixtures/integrations/outils.mjs";

const CT2 = fs.readFileSync(path.join(RACINE, "spec", "CT-2-enregistreur.md"), "utf8").split("\n");
const PAQUET = JSON.parse(fs.readFileSync(path.join(RACINE, "package.json"), "utf8"));
const CI = yaml.load(fs.readFileSync(path.join(RACINE, ".github", "workflows", "ci.yml"), "utf8"));
const DEMO = JSON.parse(fs.readFileSync(path.join(RACINE, "demo", "configuration-demo.json"), "utf8"));
const TITRES = {
  "19.5.1": "Claude Desktop",
  "19.5.2": "Claude Code",
  "19.5.3": "Cursor",
  "19.5.4": "SDK Agents d'OpenAI",
  "19.5.5": "LangGraph / LangChain",
  "19.5.6": "Autres hôtes",
  "19.5.7": "Gemini",
  "19.5.8": "CrewAI",
  "19.5.9": "LlamaIndex",
  "19.5.10": "LiteLLM",
  "19.5.11": "Agent instrumenté OpenTelemetry",
};

/** Lignes d'une sous-section `#### 19.5.n …`, jusqu'au titre suivant. */
function section(n) {
  const debut = CT2.findIndex((l) => l.startsWith(`#### ${n} `));
  expect(debut, `titre de ${n}`).to.be.greaterThan(0);
  let fin = debut + 1;
  while (fin < CT2.length && !/^#{3,4} /.test(CT2[fin])) fin++;
  const texte = CT2.slice(debut, fin).join("\n");
  // `plat` : le texte sur une ligne (une phrase de la spécification peut être coupée par un retour à la ligne).
  return { debut, fin, lignes: CT2.slice(debut, fin), texte, plat: texte.replace(/\s+/g, " ") };
}

/** Blocs de code (langue, texte) d'une suite de lignes. */
function blocs(lignes) {
  const b = [];
  for (let i = 0; i < lignes.length; i++) {
    const m = /^```(\w*)\s*$/.exec(lignes[i]);
    if (!m) continue;
    const j = lignes.indexOf("```", i + 1);
    b.push({ langue: m[1], texte: lignes.slice(i + 1, j).join("\n") });
    i = j;
  }
  return b;
}

/** Tables « | Chemin | Capturé | Nature | Pas capturé | » d'une suite de lignes : lignes de cellules. */
function tablesChemins(lignes) {
  const t = [];
  for (let i = 0; i < lignes.length; i++) {
    if (lignes[i].trim() !== "| Chemin | Capturé | Nature | Pas capturé |") continue;
    expect(lignes[i + 1]).to.match(/^\|---\|---\|---\|---\|$/);
    const rangs = [];
    for (let j = i + 2; j < lignes.length && lignes[j].startsWith("|"); j++) rangs.push(lignes[j].split("|").slice(1, -1).map((c) => c.trim()));
    t.push(rangs);
  }
  return t;
}

/** Épingle `nom==version` d'un fichier .in. */
function epingle(fichier, nom) {
  const texte = fs.readFileSync(path.join(RACINE, fichier), "utf8");
  const m = new RegExp(`^${nom.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:\\[[^\\]]*\\])?==([0-9][^\\s#]*)`, "m").exec(texte);
  return m ? m[1] : null;
}

const VERROUS_ADAPTATEURS = "paquets/sdk-python/verrous";
const VERROUS_INTEGRATIONS = "test/fixtures/integrations/verrous";

describe("CT-2 §19.5 : fichiers d'intégration, par hôte (EX-19.5), lus dans le texte, sans moteur de conteneurs", function () {
  describe("EX-19.5 : chaque fichier porte la table « chemin, capturé, nature, pas capturé » et sa règle de non-double capture", function () {
    for (const [n, titre] of Object.entries(TITRES)) {
      it(`${n} ${titre} : une table de chemins dont chaque rang est interposé, déclaratif ou vide (—), et la règle de non-double capture (ou le renvoi à EX-19.5 pour la table commune)`, function () {
        const s = section(n);
        expect(CT2[s.debut]).to.include(titre);
        const tables = tablesChemins(s.lignes);
        expect(tables.length, `tables de ${n}`).to.equal(1);
        const rangs = tables[0];
        expect(rangs.length).to.be.greaterThan(1);
        for (const r of rangs) {
          expect(r.length, `rang ${r[0]}`).to.equal(4);
          expect(r[2], `nature du chemin « ${r[0]} »`).to.match(/interposé|déclaratif|^—$/);
        }
        // Au moins un chemin interposé (frontal MCP ou passerelle) dans chaque fichier d'hôte ou de cadre ; l'ingestion OpenTelemetry est déclarative d'abord.
        if (n !== "19.5.11") expect(rangs.some((r) => /interposé/.test(r[2]))).to.equal(true);
        else expect(rangs[0][2]).to.include("déclaratif");
        const regle = n === "19.5.6" ? /Table commune à ces hôtes \(EX-19\.5\)/ : /non-double capture|n'est pas déclaré|ne le déclare pas aussi|ne sont pas enveloppés ;.*\(EX-6\.17, EX-19\.5\)|l'ignore \(EX-6\.17, EX-19\.5\)|EX-6\.34/;
        expect(s.plat, `règle de non-double capture de ${n}`).to.match(regle);
      });
    }

    it("les hôtes de 19.5.6 sont décrits en une ligne chacun (VS Code, Devin Desktop, Microsoft Agent Framework, Semantic Kernel, Google ADK, Gemini CLI, Codex CLI), chacun avec son entrée MCP, et la page porte la date de sa lecture", function () {
      const s = section("19.5.6");
      for (const h of ["VS Code", "Devin Desktop", "Microsoft Agent Framework", "Semantic Kernel", "Google ADK", "Gemini CLI", "Codex CLI"]) expect(s.texte).to.include(h);
      expect(s.texte).to.include("`.vscode/mcp.json`");
      expect(s.texte).to.include("mcp_config.json`");
      expect(s.texte).to.include("MCPStreamableHTTPTool");
      expect(s.texte).to.include("MCPStreamableHttpPlugin");
      expect(s.texte).to.include("McpToolset");
      expect(s.texte).to.include("`httpUrl`");
      expect(s.texte).to.include("`[mcp_servers.noortrace]`");
      expect(s.texte).to.include("chaque page d'intégration publiée porte la date de sa lecture");
    });
  });

  describe("19.5.1 à 19.5.3 : configurations des hôtes de bureau, cohérentes avec la configuration de démonstration de §19.1", function () {
    const sante = (chemin) => chemin;

    it("19.5.1 Claude Desktop : claude_desktop_config.json valide, serveur stdio noortrace-connecteur --socket /run/noortrace/mcp.sock (la prise mcp.socket de la démonstration) ; les échanges de modèle ne sont pas capturés sans réglage d'URL de base, et la table le dit", function () {
      const s = section("19.5.1");
      const json = blocs(s.lignes).filter((b) => b.langue === "json");
      expect(json.length).to.equal(1);
      const cfg = JSON.parse(json[0].texte);
      expect(cfg.mcpServers.noortrace.command).to.equal("/usr/local/bin/noortrace-connecteur");
      expect(cfg.mcpServers.noortrace.args).to.deep.equal(["--socket", "/run/noortrace/mcp.sock"]);
      expect(DEMO.mcp.socket).to.equal("/run/noortrace/mcp.sock");
      const rangs = tablesChemins(s.lignes)[0];
      expect(rangs[0][0]).to.include("Frontal MCP");
      expect(rangs[0][2]).to.include("bloquant pour les écritures");
      expect(rangs[1][3]).to.include("les échanges de modèle d'un hôte qui ne passe pas par la passerelle");
      expect(s.texte).to.include("Les noms d'outils contenant un point sont refusés par l'API Messages");
    });

    it("19.5.2 Claude Code : .mcp.json (type http, http://127.0.0.1:8300/mcp, Authorization: Bearer ${NOORTRACE_TOKEN}) et bloc env (ANTHROPIC_BASE_URL http://127.0.0.1:8400, ANTHROPIC_API_KEY = jeton de la passerelle, ANTHROPIC_CUSTOM_HEADERS X-Noortrace-Run-Id, trafic non essentiel coupé) ; ports et chemin de la démonstration ; route x-api-key, gabarit mcp__noortrace__ et assainissement cohérents avec 15.3 et §19.1", function () {
      const s = section("19.5.2");
      const json = blocs(s.lignes).filter((b) => b.langue === "json").map((b) => JSON.parse(b.texte));
      expect(json.length).to.equal(2);
      const [mcp, env] = json;
      expect(mcp.mcpServers.noortrace).to.deep.equal({ type: "http", url: "http://127.0.0.1:8300/mcp", headers: { Authorization: "Bearer ${NOORTRACE_TOKEN}" } });
      expect(env.env).to.deep.equal({ ANTHROPIC_BASE_URL: "http://127.0.0.1:8400", ANTHROPIC_API_KEY: "${NOORTRACE_TOKEN_PASSERELLE}", ANTHROPIC_CUSTOM_HEADERS: "X-Noortrace-Run-Id: ${NOORTRACE_RUN_ID}", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" });
      // Ports et chemin : ceux de la configuration de démonstration (§19.1).
      expect(DEMO.mcp.http.listen).to.equal("0.0.0.0:8300");
      expect(DEMO.mcp.http.path).to.equal("/mcp");
      expect(DEMO.model.listen).to.equal("0.0.0.0:8400");
      const route = DEMO.policy.model.routes.find((r) => r.path === "/v1/messages");
      expect(route).to.include({ format: "anthropic-messages", credentials: "propre", auth_header: "x-api-key" });
      expect(s.texte).to.include("`auth_header: \"x-api-key\"`");
      expect(s.texte).to.include("`ANTHROPIC_AUTH_TOKEN`");
      expect(s.texte).to.include("`tool_name_template: \"mcp__noortrace__{tool_announced}\"`");
      expect(s.texte).to.include("`tool_name_sanitize: true`");
      expect(DEMO.mcp.hosts[0].tool_name_sanitize).to.equal(true);
      expect(DEMO.model.hosts[0].host_group).to.equal(DEMO.mcp.hosts[0].host_group);
      expect(s.texte).to.include("Le relais du jeton de l'hôte vers le fournisseur n'a jamais");
    });

    it("19.5.3 Cursor : .cursor/mcp.json valide (url http://127.0.0.1:8300/mcp, Authorization: Bearer ${env:NOORTRACE_TOKEN}), variante stdio par le connecteur, échanges de modèle seulement par un mandataire d'interception (mode icap ou miroir), et la table le dit", function () {
      const s = section("19.5.3");
      const json = blocs(s.lignes).filter((b) => b.langue === "json");
      expect(json.length).to.equal(1);
      const cfg = JSON.parse(json[0].texte);
      expect(cfg.mcpServers.noortrace).to.deep.equal({ url: "http://127.0.0.1:8300/mcp", headers: { Authorization: "Bearer ${env:NOORTRACE_TOKEN}" } });
      const stdio = /`(\{ "mcpServers": \{ "noortrace": \{ "type": "stdio",[\s\S]*?\} \} \})`/.exec(s.texte.replace(/\n/g, " "));
      expect(stdio, "variante stdio").to.not.equal(null);
      const v = JSON.parse(stdio[1]);
      expect(v.mcpServers.noortrace).to.deep.equal({ type: "stdio", command: "/usr/local/bin/noortrace-connecteur", args: ["--socket", "/run/noortrace/mcp.sock"] });
      const rangs = tablesChemins(s.lignes)[0];
      expect(rangs[1][0]).to.include("mandataire d'interception");
      expect(rangs[1][3]).to.include("sans mandataire d'interception");
      expect(sante(s.texte)).to.include("mode `icap`");
    });
  });

  describe("versions citées par les fichiers de 19.5 égales aux épingles des verrous (CT-2 §6.4, précondition des TI-4 à TI-11)", function () {
    it("19.5.4 : openai-agents 0.24.0 (verrou des adaptateurs) et @openai/agents 0.21.0 (package.json)", function () {
      const s = section("19.5.4").texte;
      expect(s).to.include("Paquet `openai-agents` 0.24.0");
      expect(epingle(`${VERROUS_ADAPTATEURS}/openai-agents.in`, "openai-agents")).to.equal("0.24.0");
      expect(s).to.include("`@openai/agents` 0.21.0");
      expect(PAQUET.devDependencies["@openai/agents"]).to.equal("0.21.0");
    });

    it("19.5.5 : langchain 1.4.7, langgraph 1.2.17, langchain-core 1.7.0 (verrou des adaptateurs et verrou d'intégration) ; @langchain/mcp-adapters 2.x (package.json)", function () {
      const s = section("19.5.5").texte;
      expect(s).to.include("`langchain` 1.4.7, `langgraph` 1.2.17");
      expect(s).to.include("`langchain-core` 1.7.0");
      for (const f of [`${VERROUS_ADAPTATEURS}/langchain.in`, `${VERROUS_INTEGRATIONS}/langchain.in`]) {
        expect(epingle(f, "langchain"), f).to.equal("1.4.7");
        expect(epingle(f, "langgraph"), f).to.equal("1.2.17");
        expect(epingle(f, "langchain-core"), f).to.equal("1.7.0");
      }
      expect(PAQUET.devDependencies["@langchain/mcp-adapters"]).to.match(/^2\.\d+\.\d+$/);
      // langchain-openai (ChatOpenAI(base_url=…) de 19.5.5) : épinglé par le verrou d'intégration, publié plus de deux semaines avant le verrouillage.
      expect(epingle(`${VERROUS_INTEGRATIONS}/langchain.in`, "langchain-openai")).to.equal("1.7.3");
    });

    it("19.5.7 : google-genai 2.33.0 (verrou d'intégration) ; §6.4 : anthropic 2.3.0 et mcp 2.3.0 (verrou d'intégration)", function () {
      expect(section("19.5.7").texte).to.include("Paquets `google-genai` 2.33.0");
      expect(epingle(`${VERROUS_INTEGRATIONS}/gemini.in`, "google-genai")).to.equal("2.33.0");
      const six = CT2.slice(CT2.findIndex((l) => l.startsWith("### 6.4 ")), CT2.findIndex((l) => l.startsWith("### 6.5 "))).join("\n");
      expect(six).to.include("`anthropic` 2.3.0");
      expect(six).to.include("`mcp` 2.3.0");
      expect(epingle(`${VERROUS_INTEGRATIONS}/anthropic.in`, "anthropic")).to.equal("2.3.0");
      expect(epingle(`${VERROUS_INTEGRATIONS}/anthropic.in`, "mcp")).to.equal("2.3.0");
      expect(epingle(`${VERROUS_INTEGRATIONS}/gemini.in`, "mcp")).to.equal("2.3.0");
    });

    it("19.5.7 et §6.4 : les SDK JavaScript officiels @google/genai 2.31.0 et @anthropic-ai/sdk 1.3.0 sont installés à ces versions exactes par le travail integrations de .github/workflows/ci.yml (npm install --no-save --ignore-scripts), hors de package.json, comme le texte de 19.5.7 le dit", function () {
      const SDK = [["@google/genai", "2.31.0"], ["@anthropic-ai/sdk", "1.3.0"]];
      const s = section("19.5.7").plat;
      expect(s).to.include("`@google/genai` 2.31.0 et `@anthropic-ai/sdk` 1.3.0 (6.4), ne sont pas des dépendances du dépôt : le travail `integrations` de l'intégration continue (`.github/workflows/ci.yml`) les installe à ces versions exactes (`npm install --no-save --ignore-scripts`), hors de `package.json`");
      // Le travail integrations installe chacun à sa version exacte, sans plage, sans script d'installation, sans écrire package.json.
      const etapes = (CI.jobs?.integrations?.steps ?? []).filter((e) => typeof e.run === "string" && /\bnpm install\b/.test(e.run));
      expect(etapes.length, "étape npm install du travail integrations").to.equal(1);
      const ligne = etapes[0].run.split("\n").find((l) => /\bnpm install\b/.test(l)).trim().split(/\s+/);
      expect(ligne.slice(0, 2)).to.deep.equal(["npm", "install"]);
      expect(ligne).to.include.members(["--no-save", "--ignore-scripts"]);
      expect(ligne.filter((x) => !x.startsWith("-")).slice(2).sort()).to.deep.equal(SDK.map(([n, v]) => `${n}@${v}`).sort());
      // Aucun des deux n'est une dépendance du dépôt (arbitrage de la chaîne d'approvisionnement).
      for (const [n] of SDK) expect([PAQUET.dependencies?.[n], PAQUET.devDependencies?.[n], PAQUET.optionalDependencies?.[n]], n).to.deep.equal([undefined, undefined, undefined]);
    });

    it("19.5.8 : crewai 1.15.30 (verrou des adaptateurs)", function () {
      expect(section("19.5.8").texte).to.include("Paquet `crewai` 1.15.30");
      expect(epingle(`${VERROUS_ADAPTATEURS}/crewai.in`, "crewai")).to.equal("1.15.30");
    });

    it("19.5.9 : llama-index-core 0.14.25 et llama-index-tools-mcp 0.6.0 (les deux verrous), llama-index-llms-openai 0.8.3 (verrou d'intégration)", function () {
      const s = section("19.5.9").texte;
      expect(s).to.include("Paquets `llama-index-core` 0.14.25");
      expect(s).to.include("`llama-index-tools-mcp` 0.6.0");
      expect(s).to.include("`llama-index-llms-openai` 0.8.3");
      for (const f of [`${VERROUS_ADAPTATEURS}/llamaindex.in`, `${VERROUS_INTEGRATIONS}/llamaindex.in`]) {
        expect(epingle(f, "llama-index-core"), f).to.equal("0.14.25");
        expect(epingle(f, "llama-index-tools-mcp"), f).to.equal("0.6.0");
      }
      expect(epingle(`${VERROUS_INTEGRATIONS}/llamaindex.in`, "llama-index-llms-openai")).to.equal("0.8.3");
    });

    it("19.5.10 : litellm 1.106.4 (verrous bibliothèque et mandataire)", function () {
      expect(section("19.5.10").texte).to.include("Paquet `litellm` 1.106.4");
      expect(epingle(`${VERROUS_ADAPTATEURS}/litellm.in`, "litellm")).to.equal("1.106.4");
      expect(epingle(`${VERROUS_ADAPTATEURS}/litellm-mandataire.in`, "litellm")).to.equal("1.106.4");
    });

    it("19.5.11 : opentelemetry-sdk 1.45.1 et opentelemetry-exporter-otlp-proto-http 1.45.1 (verrou d'intégration) ; le code Python du fichier emploie OTLPSpanExporter(endpoint, headers, timeout) et ALWAYS_ON", function () {
      const s = section("19.5.11");
      expect(s.texte).to.include("`opentelemetry-sdk`\n1.45.1");
      expect(s.texte).to.include("`opentelemetry-exporter-otlp-proto-http` 1.45.1");
      expect(epingle(`${VERROUS_INTEGRATIONS}/otel.in`, "opentelemetry-sdk")).to.equal("1.45.1");
      expect(epingle(`${VERROUS_INTEGRATIONS}/otel.in`, "opentelemetry-exporter-otlp-proto-http")).to.equal("1.45.1");
      const py = blocs(s.lignes).find((b) => b.langue === "python");
      expect(py.texte).to.include("OTLPSpanExporter(");
      expect(py.texte).to.include('headers={"x-noortrace-token"');
      expect(py.texte).to.include("timeout=30");
      expect(py.texte).to.include("sampler=ALWAYS_ON");
    });

    it("19.5.11 : les paquets Node.js que le fichier dit employés (@opentelemetry/sdk-trace-base 2.12.0, @opentelemetry/exporter-trace-otlp-http 0.223.0) sont des dépendances de développement de package.json à ces versions exactes ; les paquets 0.300.0 qu'il nomme ne sont pas des dépendances du dépôt", function () {
      const s = section("19.5.11").plat;
      expect(s).to.include("Node.js (révision 0.11) `@opentelemetry/sdk-trace-base` 2.12.0 et `@opentelemetry/exporter-trace-otlp-http` 0.223.0 (OTLP/HTTP en JSON), dépendances de développement du dépôt (`package.json`)");
      expect(s).to.include("`@opentelemetry/sdk-node` et `@opentelemetry/exporter-trace-otlp-proto` 0.300.0");
      expect(s).to.include("ne sont ni des dépendances du dépôt ni éprouvés");
      expect(PAQUET.devDependencies["@opentelemetry/sdk-trace-base"]).to.equal("2.12.0");
      expect(PAQUET.devDependencies["@opentelemetry/exporter-trace-otlp-http"]).to.equal("0.223.0");
      for (const n of ["@opentelemetry/sdk-node", "@opentelemetry/exporter-trace-otlp-proto"]) expect([PAQUET.dependencies?.[n], PAQUET.devDependencies?.[n]], n).to.deep.equal([undefined, undefined]);
    });
  });
});
