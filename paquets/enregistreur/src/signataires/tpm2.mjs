// TPM 2.0 : enveloppe de la classe C seulement (CT-2 §11.2, EX-11.9) : la
// graine de 32 octets est scellée (`tpm2_create -i`, politique
// `tpm2_createpolicy --policy-pcr -l sha256:…`) et descellée au démarrage par
// `tpm2_unseal -p pcr:sha256:…`, liée aux PCR choisis par le client.
//
// Pas (outils tpm2-tools, processus séparés ; aucune graine sur disque) :
//   tpm2_createprimary -C o -g sha256 -G ecc -c <rép>/primaire.ctx
//   tpm2_load -C <rép>/primaire.ctx -u <public_file> -r <private_file> -c <rép>/objet.ctx
//   tpm2_unseal -c <rép>/objet.ctx -p pcr:<pcrs>          → graine sur stdout
// Le parent est la clé primaire du propriétaire au gabarit par défaut de
// `tpm2_createprimary` pour ECC et SHA-256 : la cérémonie doit sceller sous le
// même parent (lecture 180). `<rép>` est un répertoire privé (0700) supprimé
// après le descellement. Le TPM est désigné par `TPM2TOOLS_TCTI` de
// l'environnement du démon (à défaut, le gestionnaire de ressources du
// noyau, défaut des outils).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { ErreurSignataire } from "./commun.mjs";

function executer(programme, args, o) {
  return new Promise((res, rej) => {
    const p = spawn(programme, args, { env: o.env, stdio: ["ignore", "pipe", "pipe"] });
    const sortie = [];
    let erreur = "";
    const minuteur = setTimeout(() => p.kill("SIGKILL"), o.delaiMs);
    p.stdout.on("data", (d) => sortie.push(d));
    p.stderr.on("data", (d) => (erreur += d));
    p.on("error", (e) => {
      clearTimeout(minuteur);
      rej(new ErreurSignataire(`${programme} : ${e.code ?? e.message}`, { code: "outil" }));
    });
    p.on("exit", (code, signal) => {
      clearTimeout(minuteur);
      if (code === 0) return res(Buffer.concat(sortie));
      // La sortie d'erreur des outils ne contient pas la graine (rien n'est descellé en cas d'échec).
      const ligne = erreur.split("\n").find((l) => /ERROR|error/.test(l)) ?? "";
      rej(new ErreurSignataire(`${path.basename(programme)} : ${signal ?? `code ${code}`}${ligne ? ` (${ligne.trim().slice(0, 160)})` : ""}`, { code: "outil" }));
    });
  });
}

/**
 * Descelle la graine d'un objet scellé (EX-11.9).
 * @param {object} p
 * @param {{public_file: string, private_file: string, pcrs: string}} p.wrap (fichiers de la clé, lecture 177)
 * @param {NodeJS.ProcessEnv} [p.env] environnement des outils (TPM2TOOLS_TCTI)
 * @param {number} [p.delaiMs] délai de chaque outil
 * @param {string} [p.outils] répertoire des outils (défaut : PATH)
 * @returns {Promise<Uint8Array>}
 */
export async function desceller(p) {
  const env = p.env ?? { PATH: process.env.PATH ?? "", ...(process.env.TPM2TOOLS_TCTI ? { TPM2TOOLS_TCTI: process.env.TPM2TOOLS_TCTI } : {}) };
  const o = { env, delaiMs: p.delaiMs ?? 5000 };
  const outil = (n) => (p.outils ? path.join(p.outils, n) : n);
  const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-tpm-"));
  fs.chmodSync(rep, 0o700);
  // Sans gestionnaire de ressources entre les outils et le TPM, chaque outil
  // laisse ses objets transitoires et ses sessions chargés : ils sont purgés
  // après chaque pas (sans effet sous un gestionnaire de ressources).
  const purger = async () => {
    await executer(outil("tpm2_flushcontext"), ["-t"], o).catch(() => {});
    await executer(outil("tpm2_flushcontext"), ["-s"], o).catch(() => {});
    await executer(outil("tpm2_flushcontext"), ["-l"], o).catch(() => {});
  };
  try {
    await executer(outil("tpm2_createprimary"), ["-C", "o", "-g", "sha256", "-G", "ecc", "-c", path.join(rep, "primaire.ctx")], o);
    await purger();
    await executer(outil("tpm2_load"), ["-C", path.join(rep, "primaire.ctx"), "-u", p.wrap.public_file, "-r", p.wrap.private_file, "-c", path.join(rep, "objet.ctx")], o);
    await purger();
    const graine = await executer(outil("tpm2_unseal"), ["-c", path.join(rep, "objet.ctx"), "-p", `pcr:${p.wrap.pcrs}`], o);
    const g = new Uint8Array(graine);
    graine.fill(0);
    return g;
  } finally {
    await purger();
    fs.rmSync(rep, { recursive: true, force: true });
  }
}
