// Pilote du travailleur de la page de vérification (CT-6 §18, EX-18.5,
// EX-18.8, EX-18.9). Il suit wasm_exec.js dans travailleur.js.
//
// 1. Il reçoit une fois les octets de l'artefact, calcule leur SHA-256 et le
//    compare à EMPREINTE_WASM avant toute compilation ; s'ils diffèrent, il ne
//    compile rien (EX-18.5).
// 2. Pour chaque vérification, il installe l'arbre en lecture seule du prélude
//    et fait deux exécutions, chacune dans une instance neuve du module
//    compilé : rapport lisible, puis --json (EX-18.9).
// Les deux constantes ci-dessous sont écrites par la construction.
(() => {
  const EMPREINTE_WASM = "@@EMPREINTE_WASM@@";
  const VERSION_VERIFICATEUR = "@@VERSION@@";
  const PROGRAMME = "noortrace-verifier";

  let module = null;
  let refus = null;
  let recu = false;
  let file = Promise.resolve();
  let executionEnCours = null;

  const etiquette = (v) => Object.prototype.toString.call(v);

  function hexadecimal(tampon) {
    const octets = new Uint8Array(tampon);
    let h = "0x";
    for (const o of octets) h += o.toString(16).padStart(2, "0");
    return h;
  }

  function cause(e) {
    if (e && typeof e.message === "string" && e.message !== "") return `${e.name ?? "Error"}: ${e.message}`;
    return String(e);
  }

  async function recevoirArtefact(message) {
    if (recu) {
      self.postMessage({ type: "non_faite", cause: "artefact déjà reçu" });
      return;
    }
    recu = true;
    if (etiquette(message.octets) !== "[object ArrayBuffer]") {
      refus = "artefact absent du message";
      self.postMessage({ type: "non_faite", cause: refus });
      return;
    }
    const calculee = hexadecimal(await crypto.subtle.digest("SHA-256", message.octets));
    if (calculee !== EMPREINTE_WASM) {
      refus = `artefact altéré : empreinte ${calculee} au lieu de ${EMPREINTE_WASM}`;
      self.postMessage({ type: "artefact_altere", calculee, attendue: EMPREINTE_WASM });
      return;
    }
    try {
      module = await WebAssembly.compile(message.octets);
    } catch (e) {
      refus = `compilation refusée : ${cause(e)}`;
      self.postMessage({ type: "non_faite", cause: refus });
      return;
    }
    self.postMessage({ type: "artefact_pret", version: VERSION_VERIFICATEUR, empreinte: calculee });
  }

  /** Arguments d'EX-18.8, dans l'ordre, sans --json. */
  function argumentsDe(options, presents) {
    const a = [PROGRAMME, "dossier"];
    if (options.ancres === true) {
      if (!presents.has("ancres.json")) throw new TypeError("option ancres sans fichier ancres.json");
      a.push("--ancres", "ancres.json");
    } else if (presents.has("ancres.json")) {
      throw new TypeError("fichier ancres.json sans l'option ancres");
    }
    if (options.entetes === true) {
      if (!presents.has("entetes-bitcoin.json")) throw new TypeError("option entetes sans fichier entetes-bitcoin.json");
      a.push("--entetes-bitcoin", "entetes-bitcoin.json");
    } else if (presents.has("entetes-bitcoin.json")) {
      throw new TypeError("fichier entetes-bitcoin.json sans l'option entetes");
    }
    if (options.exiger !== null && options.exiger !== undefined) {
      if (typeof options.exiger !== "string") throw new TypeError("option exiger qui n'est pas une chaîne");
      a.push("--exiger", options.exiger);
    }
    if (options.langue !== "fr" && options.langue !== "en") throw new TypeError("option langue hors de fr, en");
    a.push("--langue", options.langue);
    if (options.detail === true) a.push("--detail");
    return a;
  }

  /** Une exécution dans une instance neuve ; rend { arguments, code, sortie, erreur }. */
  async function executer(argv) {
    const go = new Go();
    go.argv = argv.slice();
    go.env = {};
    let code = null;
    go.exit = (c) => {
      code = c;
    };
    NOORTRACE_ARBRE.ouvrirSorties();
    try {
      const instance = await WebAssembly.instantiate(module, go.importObject);
      await new Promise((resoudre, rejeter) => {
        executionEnCours = rejeter;
        go.run(instance).then(resoudre, rejeter);
      });
    } finally {
      executionEnCours = null;
      // Minuteries que le programme a programmées et laissées en place en
      // sortant : wasm_exec.js les tient dans go._scheduledTimeouts ; leur
      // échéance, après la sortie, lèverait « Go program has already exited »
      // pendant l'exécution suivante. Elles sont annulées ici.
      for (const id of go._scheduledTimeouts.values()) clearTimeout(id);
      go._scheduledTimeouts.clear();
    }
    const { sortie, erreur } = NOORTRACE_ARBRE.fermerSorties();
    if (!Number.isInteger(code)) throw new Error("exécution achevée sans code de sortie");
    return { arguments: argv, code, sortie, erreur };
  }

  async function verifier(message) {
    if (module === null) {
      self.postMessage({ type: "non_faite", cause: refus ?? "artefact non reçu" });
      return;
    }
    const executions = [];
    try {
      const fichiers = message.fichiers;
      const repertoires = message.repertoires ?? [];
      if (!Array.isArray(fichiers) || !Array.isArray(repertoires)) throw new TypeError("message de vérification mal formé");
      const liste = fichiers.map((f) => ({
        chemin: f.chemin,
        octets: etiquette(f.octets) === "[object ArrayBuffer]" ? new Uint8Array(f.octets) : f.octets,
      }));
      const presents = new Set(liste.map((f) => f.chemin));
      const options = message.options ?? {};
      const lisible = argumentsDe(options, presents);
      NOORTRACE_ARBRE.installer(liste, repertoires);
      executions.push(await executer(lisible));
      executions.push(await executer([...lisible, "--json"]));
    } catch (e) {
      NOORTRACE_ARBRE.fermerSorties();
      NOORTRACE_ARBRE.retirer();
      self.postMessage({ type: "non_faite", cause: cause(e) });
      return;
    }
    NOORTRACE_ARBRE.retirer();
    const transferts = [];
    for (const x of executions) transferts.push(x.sortie.buffer, x.erreur.buffer);
    self.postMessage({ type: "resultat", executions }, transferts);
  }

  // Une erreur que le moteur lève hors d'une promesse pendant une exécution
  // (dans une reprise de Go par setTimeout) met fin à cette exécution sans code.
  self.addEventListener("error", (ev) => {
    if (executionEnCours !== null) {
      ev.preventDefault();
      executionEnCours(ev.error ?? new Error(ev.message));
    }
  });
  self.addEventListener("unhandledrejection", (ev) => {
    if (executionEnCours !== null) {
      ev.preventDefault();
      executionEnCours(ev.reason);
    }
  });

  self.addEventListener("message", (ev) => {
    const message = ev.data;
    file = file.then(async () => {
      if (message === null || typeof message !== "object") return;
      if (message.type === "artefact") await recevoirArtefact(message);
      else if (message.type === "verifier") await verifier(message);
    }).catch((e) => {
      self.postMessage({ type: "non_faite", cause: cause(e) });
    });
  });
})();
