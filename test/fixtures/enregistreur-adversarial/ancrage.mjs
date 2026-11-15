// Mutants du paquet @noortrace/ancrage (CT-9 EX-10.5) et montage du composant
// d'ancrage d'un paquet donné (référence ou mutant) sur le décor des essais du
// composant (test/fixtures/ancrage-composant/outils.mjs : horloge réglable,
// autorités RFC 3161 internes, le principal et le secours en TLS mutuel), pour
// les tests adversariaux TA-41 et TA-62 de CT-9.
//
// Un mutant est une copie de paquets/ancrage (src, bin, package.json) dans un
// répertoire temporaire, où `node_modules` de la racine et `node_modules` du
// paquet sont des liens symboliques vers ceux du dépôt ; chaque remplacement
// nomme la chaîne retirée, qui doit apparaître exactement une fois dans le
// fichier copié. Le mutant est importé par son chemin de fichier : ses
// modules et ceux du dépôt coexistent dans le processus. Le dépôt n'est
// jamais modifié.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as N from "@noortrace/noyau";
import { RACINE } from "../enregistreur-coeur/outils.mjs";
import { attenteCalme, monterComposant, remisePoint, remiseCloture } from "../ancrage-composant/outils.mjs";

export const PAQUET_ANCRAGE = path.join(RACINE, "paquets", "ancrage");

/** Paquet du dépôt (la référence) : { racine, paquet, importer(rel) }, `rel` relatif à `src/`. */
export const REFERENCE_ANCRAGE = Object.freeze({
  racine: RACINE,
  paquet: PAQUET_ANCRAGE,
  importer: (rel) => import(pathToFileURL(path.join(PAQUET_ANCRAGE, "src", rel)).href),
});

const MUTANTS = [];

/**
 * Mutant du paquet @noortrace/ancrage (CT-9 EX-10.5).
 * @param {string} nom
 * @param {{fichier: string, ancien: string, nouveau: string}[]} remplacements `fichier` relatif à paquets/ancrage/src
 * @param {string} [tmp]
 */
export function mutantPaquetAncrage(nom, remplacements, tmp = process.env.NOORTRACE_TMP ?? os.tmpdir()) {
  const racine = fs.mkdtempSync(path.join(tmp, `noortrace-mutant-ancrage-${nom}-`));
  MUTANTS.push(racine);
  const paquet = path.join(racine, "paquets", "ancrage");
  fs.mkdirSync(paquet, { recursive: true });
  for (const d of ["src", "bin"]) fs.cpSync(path.join(PAQUET_ANCRAGE, d), path.join(paquet, d), { recursive: true });
  fs.copyFileSync(path.join(PAQUET_ANCRAGE, "package.json"), path.join(paquet, "package.json"));
  fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(racine, "node_modules"));
  // Dépendances propres du paquet (version de @noble/curves que la racine ne porte pas) : même lien.
  if (fs.existsSync(path.join(PAQUET_ANCRAGE, "node_modules"))) fs.symlinkSync(path.join(PAQUET_ANCRAGE, "node_modules"), path.join(paquet, "node_modules"));
  for (const r of remplacements) {
    const f = path.join(paquet, "src", r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
    fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
  }
  return { racine, paquet, importer: (rel) => import(pathToFileURL(path.join(paquet, "src", rel)).href) };
}

/** Détruit les mutants fabriqués. */
export function detruireMutantsAncrage() {
  for (const r of MUTANTS.splice(0)) fs.rmSync(r, { recursive: true, force: true });
}

const TOUTES_LES_MINUTES = Object.fromEntries(Array.from({ length: 59 }, (_, i) => [i + 1, 1]));

/**
 * Monte le décor et le composant d'ancrage d'un paquet : sans registre ni
 * OpenTimestamps, un événement par minute, jeton de la période demandé au
 * principal (TLS mutuel), relève par le secours après
 * `rfc3161.manifest.fallback_after_s` (300 s). `secret` : octets présentés
 * comme valeur résolue du secret d'accès des deux prestataires authentifiés
 * (défaut : le certificat client du décor).
 * @param {{importer: (rel: string) => Promise<object>}} paquet référence ou mutant
 * @param {{dir: string, periode: number, secret?: (clientPem: Uint8Array) => Uint8Array}} o
 */
export async function monterAncrage(paquet, o) {
  const { creerComposantAncrage } = await paquet.importer("composant.mjs");
  const { ErreurTransport } = await paquet.importer("rfc3161/index.mjs");
  const m = await monterComposant({ dir: o.dir, periodStart: o.periode, evenements: TOUTES_LES_MINUTES, ErreurTransport, surcharges: { opentimestamps: { enabled: false } } });
  if (m.condition) return { condition: m.condition };
  if (o.secret) for (const pointeur of [...m.secrets.keys()]) m.secrets.set(pointeur, o.secret(m.secrets.get(pointeur)));
  const composant = creerComposantAncrage({
    configuration: m.configuration,
    profil: "test",
    checkpointIntervalEnregistreur: 60,
    contexte: { ...m.contexte, epoque: 1 },
    horloge: m.horloge,
    aleatoire: m.aleatoire,
    journal: m.journal,
    clients: { rfc3161: { transport: m.transport }, ots: { transport: m.calendriers.transport } },
    options: {},
  });
  const calme = attenteCalme(composant);
  await composant.demarrer();
  const T0 = o.periode * 1000;
  return {
    condition: null,
    m,
    composant,
    calme,
    /** Remet les points alignés de la période, l'horloge avançant à chaque instant, puis le point de clôture et la clôture. */
    async jouerPeriode() {
      for (const point of m.serie.points.slice(0, -1)) {
        const t = N.decoderHorodatage(point.checkpoint_ts);
        if (t < T0) continue;
        await m.horloge.aller(t, calme);
        m.remis.push(point);
        const r = await composant.remettrePoint(remisePoint(point));
        if (!r.admis) throw new Error(`point refusé : ${point.checkpoint_ts}`);
        await calme();
      }
      const cloture = m.serie.points.at(-1);
      await m.horloge.aller(N.decoderHorodatage(cloture.checkpoint_ts), calme);
      m.remis.push(cloture);
      if (!(await composant.remettrePoint(remisePoint(cloture))).admis) throw new Error("point de clôture refusé");
      if (!(await composant.remettreCloture(remiseCloture(m.serie))).admis) throw new Error("clôture refusée");
      await calme();
    },
    jetonPeriode: () => composant.demandes().find((d) => d.kind === "jeton_periode") ?? null,
    async fermer() {
      if (composant.etat().demarre && !composant.etat().arrete) await composant.arreter({ attendre: false }).catch(() => {});
      await m.fermer();
    },
  };
}

/** Texte de tous les fichiers ordinaires sous un répertoire (octets lus un pour un), chemins compris. */
export function texteDesFichiers(rep) {
  if (!fs.existsSync(rep)) return [];
  return fs.readdirSync(rep, { recursive: true }).map((f) => path.join(rep, f)).filter((f) => fs.statSync(f).isFile()).map((f) => ({ fichier: f, texte: fs.readFileSync(f).toString("latin1") }));
}

/** Texte d'une valeur JSON où des octets (Uint8Array) seraient restés : chaque suite d'octets est rendue caractère pour caractère. */
export function texteAvecOctets(valeur) {
  return JSON.stringify(valeur, (_k, v) => {
    if (v instanceof Uint8Array) return Buffer.from(v).toString("latin1");
    // Un Buffer arrive ici déjà rendu par son toJSON : { type: "Buffer", data: [...] }.
    if (v !== null && typeof v === "object" && v.type === "Buffer" && Array.isArray(v.data)) return Buffer.from(v.data).toString("latin1");
    return v;
  });
}
