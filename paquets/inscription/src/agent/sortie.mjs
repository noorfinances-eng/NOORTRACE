// Sortie d'une commande (CT-4 EX-7.4 ; schéma
// `operations-registre-v0#/$defs/sortie`) : `checks` dans l'ordre où la
// commande exécute les vérifications, `result` et `exit_code` liés (table
// d'EX-7.4), `error` `{ code, check, message }` ou null, `outputs`.
//
// Une vérification exécutée plusieurs fois par une même commande (OP-11,
// CP-1 à CP-6 et OP-12 pour chaque transaction de `inscrire-client`) ne
// figure qu'une fois, à sa première place, en échec si l'une de ses
// exécutions a échoué : c'est la forme que rend l'outil de référence sur les
// mêmes entrées (épreuve d'EX-7.24).

// La sortie se valide contre la copie du paquet d'`operations-registre-v0`
// (révision 0.7 de CT-4 : commande `paquet-client` et ses codes), non contre
// celle que porte `@noortrace/ancrage/registre`, qui ne les connaît pas.
import { IDS, valider } from "../commun/schemas.mjs";

const CODES = Object.freeze({ reussi: 0, deja_fait: 0, refuse: 1, echoue: 1, inutilisable: 2, incertain: 3 });

/** Erreur qui termine une commande avec une sortie de `result` donné. */
export class FinCommande extends Error {
  constructor(result, code, check, message, outputs = {}) {
    super(message);
    this.name = "FinCommande";
    this.result = result;
    this.code = code;
    this.check = check;
    this.outputs = outputs;
  }
}

/** Constructeur de sortie. */
export class Sortie {
  constructor(command, ctx = null) {
    this.command = command;
    this.checks = [];
    this.outputs = {};
    // Sortie courante du travail : une erreur imprévue (nœud) en cours de commande garde les vérifications faites.
    if (ctx) ctx.sortieCourante = this;
  }

  /** Consigne une vérification (`reussi`, `echoue`, `non_execute`), une fois par identifiant. */
  noter(id, statut, detail = "") {
    const d = String(detail ?? "").slice(0, 1024);
    const present = this.checks.find((c) => c.id === id);
    if (!present) {
      this.checks.push({ id, status: statut, detail: d });
      return;
    }
    if (statut === "echoue" && present.status !== "echoue") {
      present.status = "echoue";
      present.detail = d;
    }
  }

  /** Consigne une vérification réussie. */
  reussie(id) {
    this.noter(id, "reussi");
  }

  /** Termine sur un échec de vérification : la vérification est consignée `echoue`, puis la commande s'arrête. */
  echec(id, result, code, message, outputs = {}) {
    if (id) this.noter(id, "echoue", message);
    const fin = new FinCommande(result, code, id, message, outputs);
    fin.sortie = this.depuisFin(fin);
    throw fin;
  }

  /** Termine sans consigner de vérification (erreur dont `check` peut être nommé sans avoir été exécuté, EX-7.16). */
  arreter(result, code, check, message, outputs = {}) {
    const fin = new FinCommande(result, code, check, message, outputs);
    fin.sortie = this.depuisFin(fin);
    throw fin;
  }

  /** Document de sortie. */
  rendre(result, { error = null, outputs = this.outputs } = {}) {
    const s = { version: 0, command: this.command, result, exit_code: CODES[result], checks: this.checks, error, outputs };
    const v = valider(`${IDS.operations}#/$defs/sortie`, s);
    if (!v.valide) throw new Error(`sortie hors schéma : ${v.erreurs.join(" ; ")}`);
    return s;
  }

  /** Sortie d'une `FinCommande`. */
  depuisFin(fin) {
    return this.rendre(fin.result, { error: fin.code ? { code: fin.code, check: fin.check ?? null, message: String(fin.message || fin.code).slice(0, 2048) } : null, outputs: fin.outputs ?? {} });
  }
}
