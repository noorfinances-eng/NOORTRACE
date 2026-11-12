// Contrôle 8 de CT-6 (§11.4 à §11.7, N-4 de §12.4) sur les trois parties
// exportées (`registre.json`, `certificat-commit.json`, `validateurs.json`),
// avec le manifeste de la période et l'ancre `registry` du réviseur : R-1 à
// R-10, N-4, statut (EX-11.20), avertissements AV-R-1 à AV-R-3, énoncé
// (EX-11.22). Écrit depuis le texte de CT-6, sur les primitives de
// `@noortrace/ancrage/registre` (hachage du bloc BFT, racine des reçus,
// certificat, journaux) ; aucune lecture du réseau : tout se recalcule hors
// ligne (CT-6 §11.1).

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { hacherManifeste, empreinteAncre, octetsVersHex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

const IDS = ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"];
const CONTRAT_DU_ROLE = { cloture: "period_registry", ancre: "attestation_registry", inscription: "recorder_registry", ancre_point_de_controle: "attestation_registry" };
const NOM_CONTRAT = { period_registry: "PeriodRegistry", attestation_registry: "AttestationRegistry", recorder_registry: "RecorderRegistry" };

function lirePartie(repertoire, nom) {
  const chemin = path.join(repertoire, nom);
  let st;
  try {
    st = fs.lstatSync(chemin);
  } catch {
    return { absente: true };
  }
  if (!st.isFile() || st.size > 16 * 1024 * 1024) return { erreur: "fichier non ordinaire ou au-delà de 16 Mio" };
  try {
    return { valeur: lireJsonStrict(fs.readFileSync(chemin)) };
  } catch (e) {
    return { erreur: `JSON illisible (${e.message})` };
  }
}

/** Statut agrégé d'une vérification sur plusieurs objets (CT-6 §11.4). */
function agreger(statuts) {
  if (statuts.some((s) => s.status === "echoue")) return statuts.find((s) => s.status === "echoue");
  if (statuts.some((s) => s.status === "non_execute")) return statuts.find((s) => s.status === "non_execute");
  return null;
}

const heure = (secondes) => new Date(Number(secondes) * 1000).toISOString().replace(/\.000Z$/, "Z");

/**
 * Exécute le contrôle 8. `parties` : répertoire ; `manifeste` : le manifeste
 * de la période (objet) ; `registry` : l'ancre `registry` (CT-6 §12.2) ou
 * null ; `recorders` : `recorders[]` de l'ancre ; `cles` : clés du dossier
 * (`[{ key_id, public_key }]`, comme `cles.json`). Rend `{ status,
 * verifications, n4, warnings, statement, summary }`.
 */
export function controle8({ parties, manifeste, registry, recorders = [], cles = [] }) {
  const v = Object.fromEntries(IDS.map((id) => [id, { id, status: "non_execute", reason: null, detail: "" }]));
  const poser = (id, status, reason, detail) => Object.assign(v[id], { status, reason, detail: String(detail ?? "").slice(0, 1024) });
  const warnings = [];
  const reg = lirePartie(parties, "registre.json");
  const cert = lirePartie(parties, "certificat-commit.json");
  const vals = lirePartie(parties, "validateurs.json");
  let manifesteValide = manifeste && typeof manifeste === "object" && typeof manifeste.org_id === "string" && typeof manifeste.journal_id === "string";
  let periodHash = null;
  try {
    periodHash = manifesteValide ? hacherManifeste(manifeste) : null;
  } catch {
    manifesteValide = false;
  }

  // R-1 : parties conformes et appariées.
  const entrees = reg.valeur?.entries ?? [];
  const certificats = cert.valeur?.certificates ?? [];
  {
    const defauts = [];
    if (reg.absente || cert.absente) defauts.push("registre.json ou certificat-commit.json absent");
    if (reg.erreur) defauts.push(`registre.json : ${reg.erreur}`);
    if (cert.erreur) defauts.push(`certificat-commit.json : ${cert.erreur}`);
    if (reg.valeur && !R.verifierRegistreV0(reg.valeur).valide) defauts.push("registre.json non conforme à son schéma");
    if (cert.valeur && !R.verifierCertificatCommitV0(cert.valeur).valide) defauts.push("certificat-commit.json non conforme à son schéma");
    if (defauts.length === 0) {
      const hauteurs = certificats.map((c) => R.quantiteVersEntier(c.height, (1n << 64n) - 1n));
      for (const e of entrees) {
        const h = R.quantiteVersEntier(e.block.number, (1n << 64n) - 1n);
        if (hauteurs.filter((x) => x === h).length !== 1) defauts.push(`bloc ${e.block.number} : pas exactement un certificat`);
        const recu = e.receipts[e.transaction_index];
        if (!recu || !recu.logs[e.log_index]) defauts.push(`bloc ${e.block.number} : transaction_index ou log_index hors des reçus`);
      }
      for (const h of hauteurs) if (!entrees.some((e) => R.quantiteVersEntier(e.block.number, (1n << 64n) - 1n) === h)) defauts.push(`certificat de hauteur ${h} sans entrée`);
    }
    if (defauts.length > 0) {
      poser("R-1", "echoue", null, defauts.join(" ; "));
      for (const id of IDS.slice(1)) poser(id, "non_execute", "prerequis_en_echec", "R-1 en échec");
      return { status: "echoue", verifications: Object.values(v), n4: null, warnings, statement: null, summary: `contrôle 8 en échec : ${defauts[0]}` };
    }
    poser("R-1", "reussi", null, `registre.json (${entrees.length} entrées) et certificat-commit.json (${certificats.length} certificats) conformes et appariés`);
  }

  const jeuxAncre = registry ? R.lireJeux({ validator_sets: registry.validator_sets }) : null;
  const parHauteur = new Map(certificats.map((c) => [Number(R.quantiteVersEntier(c.height, (1n << 64n) - 1n)), c]));

  // R-2, R-4, R-5 par certificat.
  const r2 = [];
  const r4 = [];
  const r5 = [];
  const parCert = new Map();
  for (const [h, c] of parHauteur) {
    const j = jeuxAncre ? R.jeuPourHauteur(jeuxAncre, h) : null;
    const etat = { r2: null, r5: null, signataires: [], jeu: j };
    if (!registry || !j) etat.r2 = { status: "non_execute", reason: "ancre_absente" };
    else if (octetsVersHex(j.jeu.hash) !== String(c.valsetHash).toLowerCase()) etat.r2 = { status: "echoue", reason: null, detail: `bloc ${h} : valsetHash différent du jeu de l'ancre` };
    else etat.r2 = { status: "reussi" };
    r2.push(etat.r2);
    if (!registry) r4.push({ status: "non_execute", reason: "ancre_absente" });
    else r4.push(c.chainId === registry.chain_id ? { status: "reussi" } : { status: "echoue", reason: null, detail: `bloc ${h} : chainId ${c.chainId} différent de ${registry.chain_id}` });
    if (etat.r2.status !== "reussi") etat.r5 = { status: "non_execute", reason: etat.r2.reason ?? "prerequis_en_echec" };
    else {
      const res = R.verifierCertificat(c, { bftChainId: c.chainId, hauteur: BigInt(h), blockHash: c.blockHash, jeu: j.jeu });
      etat.r5 = res.ok ? { status: "reussi" } : { status: "echoue", reason: null, detail: `bloc ${h} : ${res.raison}` };
      etat.signataires = res.ok ? res.signataires : [];
      for (const a of res.avertissements ?? []) if (!warnings.includes("AV-R-2")) warnings.push("AV-R-2"), void a;
    }
    r5.push(etat.r5);
    parCert.set(h, etat);
  }
  const ecrire = (id, liste, okDetail) => {
    const pire = agreger(liste);
    if (pire) poser(id, pire.status, pire.reason ?? null, pire.detail ?? "");
    else poser(id, "reussi", null, okDetail);
  };
  const n = certificats.length;
  ecrire("R-2", r2, registry ? `jeu de l'ancre : hachage égal au valsetHash des ${n} certificats` : "");
  // R-3 : validateurs.json.
  if (vals.absente) poser("R-3", "non_execute", "partie_absente", "validateurs.json absent");
  else if (vals.erreur || !R.verifierValidateursV0(vals.valeur).valide) poser("R-3", "echoue", null, "validateurs.json illisible ou non conforme à son schéma");
  else {
    const jeuxDeclares = R.lireJeux(vals.valeur);
    const defaut = [...parHauteur].find(([h, c]) => {
      const j = jeuxDeclares ? R.jeuPourHauteur(jeuxDeclares, h) : null;
      return !j || octetsVersHex(j.jeu.hash) !== String(c.valsetHash).toLowerCase();
    });
    if (defaut) poser("R-3", "echoue", null, `bloc ${defaut[0]} : validateurs.json ne déclare pas le jeu qui a signé`);
    else poser("R-3", "reussi", null, `validateurs.json déclare le jeu de valsetHash de chacun des ${n} certificats`);
  }
  ecrire("R-4", r4, registry ? `chainId ${registry.chain_id} égal à celui de l'ancre, pour les ${n} certificats` : "");
  ecrire("R-5", r5, `${n} certificats : proposition et precommits valides, quorum atteint`);

  // R-6, R-7, R-8 par entrée.
  const r6 = [];
  const r7 = [];
  const r8 = [];
  const parEntree = entrees.map((e) => {
    const h = Number(R.quantiteVersEntier(e.block.number, (1n << 64n) - 1n));
    const c = parHauteur.get(h);
    const bft = R.hachageBlocBft(e.block);
    const hash = bft ? octetsVersHex(bft.hash) : null;
    const ok6 = hash !== null && hash === e.block.hash && hash === String(c.blockHash).toLowerCase() && R.quantiteVersEntier(c.height, (1n << 64n) - 1n) === BigInt(h);
    r6.push(ok6 ? { status: "reussi" } : { status: "echoue", detail: `bloc ${h} : BFTBlockHash recalculé différent` });
    let ok7 = false;
    try {
      const recus = e.receipts.map((x) => R.lireRecu(x));
      ok7 = recus.every(Boolean) && octetsVersHex(R.racineRecus(recus)) === e.block.receiptsRoot;
    } catch {
      ok7 = false;
    }
    r7.push(ok7 ? { status: "reussi" } : { status: "echoue", detail: `bloc ${h} : receiptsRoot recalculé différent` });
    const journal = e.receipts[e.transaction_index].logs[e.log_index];
    let ok8 = null;
    if (ok6 && ok7) {
      if (!registry) r8.push({ status: "non_execute", reason: "ancre_absente" });
      else {
        ok8 = journal.address === registry.contracts[CONTRAT_DU_ROLE[e.role]];
        r8.push(ok8 ? { status: "reussi" } : { status: "echoue", detail: `bloc ${h} : journal émis par ${journal.address}, non par ${NOM_CONTRAT[CONTRAT_DU_ROLE[e.role]]}` });
      }
    } else r8.push({ status: "non_execute", reason: "prerequis_en_echec" });
    return { e, h, journal, ok67: ok6 && ok7, cert: parCert.get(h) };
  });
  ecrire("R-6", r6, `BFTBlockHash recalculé égal au blockHash certifié et à block.hash, pour les ${entrees.length} blocs`);
  ecrire("R-7", r7, `receiptsRoot recalculé égal à celui de l'en-tête, pour les ${entrees.length} blocs`);
  ecrire("R-8", r8, "journaux émis aux adresses de l'ancre");

  // R-9 : clôture et ancre de la période.
  const ancre = parEntree.find((x) => x.e.role === "ancre");
  const cloture = parEntree.find((x) => x.e.role === "cloture");
  const r9 = [];
  const fingerprint = manifesteValide ? empreinteAncre(manifeste.org_id, manifeste.journal_id, periodHash) : null;
  for (const x of [cloture, ancre]) {
    if (!x) continue;
    if (!x.ok67 || !manifesteValide) {
      r9.push({ status: "non_execute", reason: "prerequis_en_echec" });
      continue;
    }
    const j = R.decoderJournal(x.e.role, x.journal);
    if (x.e.role === "cloture") {
      const ok = j && j.periodHash === periodHash && j.orgId === manifeste.org_id && j.journalId === manifeste.journal_id && j.root === manifeste.root
        && j.periodStart === BigInt(manifeste.period_start) && j.periodEnd === BigInt(manifeste.period_end) && j.firstSeq === BigInt(manifeste.first_seq)
        && j.lastSeq === BigInt(manifeste.last_seq) && j.version === 0n && BigInt(manifeste.version) === 0n && j.publishedAt === R.quantiteVersEntier(x.e.block.timestamp, (1n << 64n) - 1n);
      r9.push(ok ? { status: "reussi" } : { status: "echoue", detail: "PeriodSubmitted différent du manifeste de la période" });
    } else {
      const ok = j && j.fingerprint === fingerprint && j.docType === R.DOC_TYPE_PERIODE;
      r9.push(ok ? { status: "reussi" } : { status: "echoue", detail: "Anchored : empreinte ou docType différents" });
    }
  }
  ecrire("R-9", r9, `PeriodSubmitted égal au manifeste, publishedAt égal à l'horodatage du bloc ; Anchored : empreinte ${fingerprint} = keccak256(org_id ‖ journal_id ‖ periodHash), docType de période`);

  // R-10 : inscriptions.
  const inscriptions = parEntree.filter((x) => x.e.role === "inscription");
  const emetteur = ancre && ancre.ok67 ? R.decoderJournal("ancre", ancre.journal)?.issuer ?? null : null;
  const cleManifeste = manifesteValide ? cles.find((k) => k.key_id === manifeste.recorder_key_id) ?? null : null;
  let inscriptionManifeste = null;
  if (inscriptions.length === 0) poser("R-10", "non_execute", "partie_absente", "aucune entrée inscription");
  else if (!manifesteValide) poser("R-10", "non_execute", "prerequis_en_echec", "manifeste inexploitable");
  else {
    const defauts = [];
    const sousEmetteur = [];
    const autres = [];
    for (const x of inscriptions) {
      if (!x.ok67) continue;
      const j = R.decoderJournal("inscription", x.journal);
      if (!j || j.orgId !== manifeste.org_id || j.journalId !== manifeste.journal_id) {
        defauts.push(`bloc ${x.h} : RecorderRegistered d'une autre organisation ou d'un autre journal`);
        continue;
      }
      const k = cles.find((c) => c.public_key === j.ed25519PubKey);
      if (!k) {
        defauts.push(`bloc ${x.h} : clé Ed25519 absente des clés du dossier`);
        continue;
      }
      if (cleManifeste && k.key_id === cleManifeste.key_id) (emetteur && j.chainKey === emetteur ? sousEmetteur : autres).push({ x, j });
    }
    if (emetteur && cleManifeste && sousEmetteur.length === 0 && autres.length > 0) defauts.push("aucune inscription de la clé du manifeste sous l'émetteur de l'ancre");
    if (autres.length > 0 && sousEmetteur.length > 0) warnings.push("AV-R-3");
    if (cleManifeste && sousEmetteur.length === 0 && autres.length === 0) warnings.push("AV-R-1");
    if (defauts.length > 0) poser("R-10", "echoue", null, defauts.join(" ; "));
    else {
      inscriptionManifeste = sousEmetteur[0] ?? null;
      poser("R-10", "reussi", null, inscriptionManifeste
        ? `RecorderRegistered au bloc ${inscriptionManifeste.x.h} : ${cleManifeste.key_id}, clé du manifeste, inscrite sous ${emetteur}, émetteur de l'ancre`
        : "inscriptions de clés du dossier");
    }
  }

  // N-4 : clé de chaîne de la clé du manifeste déclarée par l'ancre.
  let n4 = null;
  const declaree = manifesteValide ? recorders.findIndex((r) => r.org_id === manifeste.org_id && r.journal_id === manifeste.journal_id && r.key_id === manifeste.recorder_key_id && r.chain_key) : -1;
  if (declaree >= 0) {
    const ck = recorders[declaree].chain_key;
    if (!ancre || !ancre.ok67) n4 = { status: "non_execute", reason: "prerequis_en_echec", detail: "entrée ancre sans R-6 et R-7" };
    else if (ancre.cert?.r5?.status !== "reussi") n4 = { status: "non_execute", reason: ancre.cert?.r5?.reason ?? "prerequis_en_echec", detail: "certificat de l'ancre sans quorum vérifié" };
    else if (emetteur === ck) n4 = { status: "reussi", detail: `émetteur de l'ancre ${emetteur} égal à la chain_key de ${manifeste.recorder_key_id} dans l'ancre (/recorders/${declaree})` };
    else n4 = { status: "echoue", detail: `émetteur de l'ancre ${emetteur} différent de la chain_key ${ck} de ${manifeste.recorder_key_id}` };
  }

  // Statut (EX-11.20).
  const liste = Object.values(v);
  let status;
  if (liste.some((x) => x.status === "echoue") || n4?.status === "echoue") status = "echoue";
  else if (["R-1", "R-2", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9"].every((id) => v[id].status === "reussi")) status = "reussi";
  else status = "non_execute";

  // Énoncé (EX-11.22) et résumé.
  let statement = null;
  if (status === "reussi" && cloture && ancre) {
    const jc = R.decoderJournal("cloture", cloture.journal);
    const ja = R.decoderJournal("ancre", ancre.journal);
    let fr = `sur le registre ${registry.chain_id}, la clôture de cette période (organisation ${manifeste.org_id}, journal ${manifeste.journal_id}) figure au bloc ${cloture.h} (heure déclarée par le bloc : ${heure(BigInt(cloture.e.block.timestamp))} UTC), émise par le contrat PeriodRegistry ${registry.contracts.period_registry}, et son ancre ${ja.fingerprint} au bloc ${ancre.h} (heure déclarée ${heure(BigInt(ancre.e.block.timestamp))} UTC), émise par AttestationRegistry ${registry.contracts.attestation_registry} pour l'émetteur ${ja.issuer}`;
    let en = `on registry ${registry.chain_id}, the closing of this period (organisation ${manifeste.org_id}, journal ${manifeste.journal_id}) is in block ${cloture.h} (time declared by the block: ${heure(BigInt(cloture.e.block.timestamp))} UTC), emitted by contract PeriodRegistry ${registry.contracts.period_registry}, and its anchor ${ja.fingerprint} in block ${ancre.h} (declared time ${heure(BigInt(ancre.e.block.timestamp))} UTC), emitted by AttestationRegistry ${registry.contracts.attestation_registry} for issuer ${ja.issuer}`;
    void jc;
    if (v["R-10"].status === "reussi" && inscriptionManifeste) {
      fr += `, clé de chaîne inscrite au bloc ${inscriptionManifeste.x.h} pour la clé d'enregistreur ${manifeste.recorder_key_id}`;
      en += `, chain key registered in block ${inscriptionManifeste.x.h} for recorder key ${manifeste.recorder_key_id}`;
    }
    if (n4?.status === "reussi") {
      fr += `, que le réviseur tient pour la clé de chaîne de ${manifeste.recorder_key_id}`;
      en += `, which the reviewer holds as the chain key of ${manifeste.recorder_key_id}`;
    }
    // Proposition de signature : certificats groupés par jeu de l'ancre, groupes dans l'ordre de leur plus petite hauteur.
    const groupes = new Map();
    for (const [h, etat] of [...parCert].sort((a, b) => a[0] - b[0])) {
      const cle = octetsVersHex(etat.jeu.jeu.hash);
      if (!groupes.has(cle)) groupes.set(cle, { jeu: etat.jeu, hauteurs: [], n: Infinity });
      const g = groupes.get(cle);
      g.hauteurs.push(h);
      g.n = Math.min(g.n, etat.signataires.length);
    }
    const joindre = (l, et) => (l.length === 1 ? String(l[0]) : `${l.slice(0, -1).join(", ")} ${et} ${l[l.length - 1]}`);
    const gs = [...groupes.values()];
    const morceau = (g, k, langue) => {
      const N = g.jeu.jeu.validateurs.length;
      const hash = octetsVersHex(g.jeu.jeu.hash);
      const src = g.jeu.source ?? "";
      if (langue === "fr") {
        if (gs.length === 1) return `chacun de ces blocs est signé par ${g.n} des ${N} validateurs du jeu ${hash} que le réviseur déclare (${src})`;
        const sujet = g.hauteurs.length === 1 ? `le bloc ${g.hauteurs[0]}` : `les blocs ${joindre(g.hauteurs, "et")}`;
        const verbe = k === 0 ? (g.hauteurs.length === 1 ? " est signé par" : " sont signés par") : " par";
        return `${sujet}${verbe} ${g.n} des ${N} validateurs du jeu ${hash} que le réviseur déclare (${src})`;
      }
      if (gs.length === 1) return `each of these blocks is signed by ${g.n} of the ${N} validators of set ${hash} declared by the reviewer (${src})`;
      const sujet = g.hauteurs.length === 1 ? `block ${g.hauteurs[0]}` : `blocks ${joindre(g.hauteurs, "and")}`;
      const verbe = k === 0 ? (g.hauteurs.length === 1 ? " is signed by" : " are signed by") : " by";
      return `${sujet}${verbe} ${g.n} of the ${N} validators of set ${hash} declared by the reviewer (${src})`;
    };
    fr += ` ; ${joindre(gs.map((g, k) => morceau(g, k, "fr")), "et")}`;
    en += `; ${joindre(gs.map((g, k) => morceau(g, k, "en")), "and")}`;
    statement = { fr, en };
  }
  const roles = [...parEntree].sort((a, b) => a.h - b.h).map((x) => `${{ inscription: "inscription", ancre: "ancre", cloture: "clôture", ancre_point_de_controle: "ancre de point" }[x.e.role]} bloc ${x.h}`);
  const tailles = [...parCert.values()].map((e) => `${e.signataires.length} validateurs sur ${e.jeu ? e.jeu.jeu.validateurs.length : "?"}`);
  const summary = `${registry?.chain_id ?? "registre"} : ${roles.join(", ")}, ${new Set(tailles).size === 1 ? `${tailles[0]} à chaque bloc` : tailles.join(", ")}`;
  return { status, verifications: liste, n4, warnings, statement, summary };
}
