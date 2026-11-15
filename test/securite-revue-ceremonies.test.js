// Bibliothèque de référence de CT-7 (scripts/lib/securite.mjs, verifierCeremonie)
// : corrections de la revue de sécurité interne de l'étape 8 appliquées avec la
// révision 0.5 de CT-7 :
// CR-4, performed_by est un officiant, un detenteur_part ou un membre (un
// temoin, un auditeur ou un observateur n'exécute aucune étape, EX-5.2) ;
// CR-5, une clé rsa a un module d'au moins 3 072 bits (CLE-10, CT-5 AN-31).
//
// Chaque essai éprouve ensuite un mutant de la règle (copie de scripts/lib
// sous NOORTRACE_TMP, règle retirée, oracle en échec, copie détruite). Racine
// des scripts éprouvés : le dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { pvExemple, COMPTES } from "../scripts/vecteurs/ct7/ceremonies.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];

const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "securite.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-securite-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, "scripts", "lib", "securite.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

/** Clé privée du compte Hardhat dont l'adresse est celle du participant. */
const cleDe = (p) => Object.values(COMPTES).find((c) => c.adresse === p.address).cle;
const signer = (S, pv) => S.signerCeremonie(pv, Object.fromEntries(pv.participants.map((p) => [p.id, cleDe(p)])));
const juger = (S, pv) => S.verifierCeremonie(J.texteJSON(signer(S, pv)));
const statut = (r, id) => r.statuses.find((s) => s.id === id);
const participant = (id, name, role, compte) => ({ id, name, role, affiliation: "essai de la revue", address: COMPTES[compte].adresse });
const spki = (bits) => crypto.generateKeyPairSync("rsa", { modulusLength: bits }).publicKey.export({ type: "spki", format: "der" });
const cleRsa = (modele, der) => ({ ...modele, key_id: "tsa-interne-essai", usage: "tsa_interne", algorithm: "rsa", generated_in: "module", public_key: "0x" + der.toString("hex"), fingerprint: J.sha256(der), address: null, backup: { scheme: "aucune", k: null, n: null, holders: [] } });

describe("CT-7, référence : CR-4, l'exécutant d'une étape est un officiant, un détenteur de part ou un membre (révision 0.5, EX-5.2)", function () {
  this.timeout(60000);
  let S;
  before(async function () {
    S = await importer(RACINE);
  });
  // Le témoin p2 exécute l'étape 1, témoignée par un second témoin p4 ; un observateur p4 exécute l'étape 2, témoignée par p2.
  const temoinExecutant = () => {
    const pv = pvExemple();
    pv.participants.push(participant("p4", "Témoin (compte de test 5)", "temoin", 5));
    pv.steps[0].performed_by = "p2";
    pv.steps[0].witnessed_by = ["p4"];
    return pv;
  };
  const observateurExecutant = () => {
    const pv = pvExemple();
    pv.participants.push(participant("p4", "Observateur (compte de test 5)", "observateur", 5));
    pv.steps[1].performed_by = "p4";
    return pv;
  };
  const oracle = (M) => {
    const a = juger(M, temoinExecutant());
    const b = juger(M, observateurExecutant());
    return JSON.stringify(a.failed) === '["CR-4"]' && /exécutant p2 de rôle temoin/.test(statut(a, "CR-4").detail) && JSON.stringify(b.failed) === '["CR-4"]' && /exécutant p4 de rôle observateur/.test(statut(b, "CR-4").detail);
  };
  it("un témoin ou un observateur qui exécute une étape fait échouer CR-4, et CR-4 seule ; l'exemple de §5.10 et un détenteur de part exécutant restent valides", function () {
    expect(oracle(S)).to.equal(true);
    expect(juger(S, pvExemple()).verdict).to.equal("valide");
    const pv = pvExemple();
    pv.participants.push(participant("p4", "Détenteur de part (compte de test 5)", "detenteur_part", 5));
    pv.steps[1].performed_by = "p4";
    const r = juger(S, pv);
    expect(statut(r, "CR-4").status, r.failed.join(", ")).to.equal("reussi");
  });
  it("mutant CR-4 : sans la règle du rôle de l'exécutant, les deux procès-verbaux passent CR-4 (tué par l'oracle)", async function () {
    const M = await importer(mutant("cr4", '    else if (!["officiant", "detenteur_part", "membre"].includes(role(st.performed_by))) faute("CR-4", `étape ${st.n} : exécutant ${st.performed_by} de rôle ${role(st.performed_by)} (officiant, detenteur_part ou membre attendu, EX-5.2)`);\n', ""));
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-7, référence : CR-5, module RSA d'au moins 3 072 bits pour une clé rsa (révision 0.5, CLE-10, CT-5 AN-31)", function () {
  this.timeout(60000);
  let S;
  before(async function () {
    S = await importer(RACINE);
  });
  const avecCle = (bits) => {
    const pv = pvExemple();
    pv.keys[0] = cleRsa(pv.keys[0], spki(bits));
    return pv;
  };
  const oracle = (M) => {
    const r = juger(M, avecCle(2048));
    return statut(r, "CR-5").status === "echoue" && /module RSA de 2048 bits, 3 072 au moins attendus/.test(statut(r, "CR-5").detail) && statut(juger(M, avecCle(3072)), "CR-5").status === "reussi";
  };
  it("une clé tsa_interne rsa de 2 048 bits fait échouer CR-5 en nommant la taille du module ; 3 072 bits passent CR-5 ; analyserSpki rend la taille du module", function () {
    expect(oracle(S)).to.equal(true);
    expect(S.analyserSpki(spki(2048)).bits).to.equal(2048);
    expect(S.analyserSpki(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ type: "spki", format: "der" })).bits).to.equal(null);
  });
  it("mutant CR-5 : sans la borne du module, la clé de 2 048 bits passe CR-5 (tué par l'oracle)", async function () {
    const M = await importer(mutant("cr5", "        else if (k.algorithm === \"rsa\" && !(spki.bits >= 3072)) faute(\"CR-5\", `${q} : module RSA de ${spki.bits ?? \"?\"} bits, 3 072 au moins attendus (CLE-10)`);\n", ""));
    expect(oracle(M)).to.equal(false);
  });
});
