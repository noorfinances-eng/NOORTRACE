// Lot WORM : contrôle réel des rôles du support (CT-2 EX-12.32, EX-18.9,
// EX-12.36, EX-12.38) contre un serveur S3 qui applique les politiques
// d'accès IAM et Object Lock (MinIO, image épinglée par condensé, lancée dans
// Docker) derrière un mandataire TLS. Chaque rôle reçoit sa propre politique
// (écrivain, gardien de pose, gardien de levée, lecteur ; l'administrateur
// est le compte racine) ; les refus sont ceux du serveur (403 AccessDenied),
// non une comparaison de références dans l'outil.
// Sans Docker ou sans l'image, chaque cas est mis en attente et son titre
// nomme la condition : « serveur S3 appliquant les politiques IAM
// indisponible ».

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, principalCtl, lireRegistres, controleWorm,
  OperationsS3, identifiantsS3, AccesS3, requeteS3Copie, requeteS3Gel, requeteS3Lire, requeteS3LireGel, requeteS3ConfigurationVerrou,
  requeteS3LireConfiguration, requeteS3Liste, codeErreurS3, contentMd5,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  IMAGES, dockerDisponible, demarrerS3Iam, roleIam, arreterTout, certificats, mandataireTls, creerBucketVerrouille, identifiantsRole, fichierSecret,
} from "./fixtures/enregistreur-worm/outils.mjs";

const RAPIDE = [20, 20, 20];
const horloge = (decalage) => ({ murale: () => Date.now() + decalage, monotone: () => performance.now() + 1e7 + decalage });
const versHeureSuivante = () => 3600000 - (Date.now() % 3600000) + 2000;
const PREFIXE = "journal-iam/";
const SOUS_PREFIXES = ["segments/", "manifestes/", "points/", "ancres/", "pieces/"];

/** Politiques des rôles d'EX-18.9 (noms d'actions S3), limitées au bucket et au préfixe. */
function politiques(bucket) {
  const objets = `arn:aws:s3:::${bucket}/${PREFIXE}*`;
  const lectures = { Effect: "Allow", Action: ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectLegalHold"], Resource: [objets] };
  const liste = (avecConfig) => ({ Effect: "Allow", Action: ["s3:ListBucketVersions", ...(avecConfig ? ["s3:GetBucketObjectLockConfiguration"] : [])], Resource: [`arn:aws:s3:::${bucket}`] });
  return {
    // EX-12.32 : copier sous les seuls sous-préfixes copiés, lire, lister,
    // lire rétention, gel et configuration de verrouillage ; rien d'autre.
    ecrivain: {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Action: ["s3:PutObject"], Resource: SOUS_PREFIXES.map((s) => `arn:aws:s3:::${bucket}/${PREFIXE}${s}*`) }, lectures, liste(true)],
    },
    // Gardien de pose : `s3:PutObjectLegalHold` (sans la restriction à ON, que
    // ce serveur n'applique pas : voir le dernier cas) ; écrire sous gels/.
    "gardien-pose": {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Action: ["s3:PutObjectLegalHold"], Resource: [objets] },
        { Effect: "Allow", Action: ["s3:PutObject"], Resource: [`arn:aws:s3:::${bucket}/${PREFIXE}gels/*`] },
        lectures, liste(true),
      ],
    },
    // Gardien de levée : `s3:PutObjectLegalHold` ; écrire sous gels/ les seuls
    // enregistrements levee et levee_resultat (préférence d'EX-18.9).
    "gardien-levee": {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Action: ["s3:PutObjectLegalHold"], Resource: [objets] },
        { Effect: "Allow", Action: ["s3:PutObject"], Resource: [`arn:aws:s3:::${bucket}/${PREFIXE}gels/*-levee.json`, `arn:aws:s3:::${bucket}/${PREFIXE}gels/*-levee_resultat.json`] },
        lectures, liste(true),
      ],
    },
    // Lecteur : les cinq droits de lecture du tableau d'EX-18.9.
    lecteur: { Version: "2012-10-17", Statement: [lectures, liste(false)] },
  };
}

describe("lot WORM : rôles du support appliqués par un serveur S3 à politiques IAM (EX-12.32, EX-18.9)", function () {
  this.timeout(600000);
  const docker = dockerDisponible([IMAGES.s3iam]);
  let dir;
  let s3;
  let tls;
  let prox;
  const ev = {};

  before(async function () {
    if (!docker.ok) return;
    dir = repertoireTemporaire("noortrace-worm-iam-");
    s3 = await demarrerS3Iam(`noortrace-test-worm-iam-${process.pid}`);
    tls = certificats(path.join(dir, "tls"));
    prox = await mandataireTls(tls, { port: s3.port });
    const bucket = `noortrace-iam-${process.pid}`;
    await creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: 4018, mode: "COMPLIANCE" });
    for (const [role, p] of Object.entries(politiques(bucket))) await roleIam(s3.nom, role, p);
    const d = path.join(dir, "journal");
    const { config, env } = configurationDev(d, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-iam-${process.pid}`))) });
    config.storage.seal.worm = {
      type: "s3-object-lock", bucket, prefix: PREFIXE, mode: "compliance", retain_days: 4018,
      credentials: { file: fichierSecret(path.join(d, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) },
      endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false,
    };
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleWorm] });
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env });
    const fichier = path.join(d, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(config));
    Object.assign(ev, { d, bucket, config: v.config, env, secrets: s.secrets, fichier, worm: v.config.storage.seal.worm });
  });

  after(async function () {
    await prox?.fermer();
    arreterTout();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(function () {
    if (!docker.ok) {
      this.currentTest.title += ` — en attente : serveur S3 appliquant les politiques IAM indisponible (${docker.condition})`;
      this.skip();
    }
  });

  const acces = (role, secret) => {
    const id = JSON.parse(identifiantsRole(role));
    return new AccesS3({ endpoint: prox.origine, region: "us-east-1", bucket: ev.bucket, identifiants: { access_key_id: id.access_key_id, secret_access_key: secret ?? id.secret_access_key }, tls: { ca: tls.caPem } });
  };
  const ref = (role) => JSON.stringify({ file: fichierSecret(path.join(ev.d, "secrets", role), identifiantsRole(role)) });
  const refus = (r) => ({ statut: r.statut, code: codeErreurS3(r.corps) });
  const sortie = () => {
    const l = [];
    return { l, flux: { write: (t) => l.push(t) } };
  };
  async function ctl(args) {
    const out = sortie();
    const err = sortie();
    const code = await principalCtl(args, { stdout: out.flux, stderr: err.flux, env: ev.env, tls: { ca: tls.caPem }, delais: RAPIDE });
    return { code, sortie: out.l.join(""), erreur: err.l.join(""), journal: err.l.filter((x) => x.startsWith("{")).map((x) => JSON.parse(x)) };
  }
  const supprimer = (cle, versionId, entetes = []) => ({ method: "DELETE", target: `/${cle.split("/").map(encodeURIComponent).join("/")}${versionId ? `?versionId=${encodeURIComponent(versionId)}` : ""}`, headers: entetes, body: null });
  const retention = (cle, versionId) => {
    const corps = new TextEncoder().encode(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>`);
    return { method: "PUT", target: `/${cle.split("/").map(encodeURIComponent).join("/")}?retention&versionId=${encodeURIComponent(versionId)}`, headers: [["Content-MD5", contentMd5(corps)]], body: corps };
  };
  const politiqueBucket = () => {
    const corps = new TextEncoder().encode(JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: ["*"] }, Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${ev.bucket}/*`] }] }));
    return { method: "PUT", target: "/?policy", headers: [], body: corps };
  };

  it("EX-12.32 : le démon, avec les identifiants du rôle Écrivain, copie chaque segment fermé, le manifeste, sa signature et la série des points ; verrou relu conforme (COMPLIANCE, 4 018 jours) ; aucune copie en échec", async function () {
    const a = await Coeur.demarrer({ config: ev.config, secrets: ev.secrets, worm: supportWormDepuisConfiguration(ev.config, ev.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE }), horloge: horloge(0) });
    ev.P = Math.floor(a.horlogeBrute.murale() / 3600000) * 3600;
    await a.arreter();
    const worm = supportWormDepuisConfiguration(ev.config, ev.secrets, { tls: { ca: tls.caPem }, delais: RAPIDE });
    const b = await Coeur.demarrer({ config: ev.config, secrets: ev.secrets, worm, horloge: horloge(versHeureSuivante()) });
    await b.tic();
    await worm.vider();
    ev.repertoire = b.repertoire;
    await b.arreter();
    ev.registre = (await lireRegistres(path.join(ev.repertoire, "worm"))).map((x) => x.ligne);
    const p10 = String(ev.P).padStart(10, "0");
    const cles = ev.registre.map((l) => l.key);
    expect(cles).to.include.members([`${PREFIXE}manifestes/periode-${p10}.json`, `${PREFIXE}manifestes/periode-${p10}.sig`, `${PREFIXE}points/periode-${p10}.ndjson`]);
    expect(cles.some((k) => k.startsWith(`${PREFIXE}segments/seg-0000000000000001-`))).to.equal(true);
    const admin = new OperationsS3({ worm: ev.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
    for (const l of ev.registre) {
      expect(l.lock.verdict, `${l.key} ${JSON.stringify(l.lock)}`).to.equal("conforme");
      const et = await admin.etat(l.key, l.version_id);
      expect(et.entetes["x-amz-object-lock-mode"], l.key).to.equal("COMPLIANCE");
    }
    const journal = fs.readFileSync(ev.config.supervision.ops_log.path, "utf8");
    expect(journal).to.not.contain('"event":"worm_copy_failed"');
  });

  it("EX-12.32 : le serveur refuse au rôle Écrivain (403 AccessDenied) d'écrire sous <prefix>gels/ ou hors des sous-préfixes copiés, de supprimer (marqueur ou version, avec ou sans contournement), de poser un gel, une rétention, la configuration de verrouillage ou une politique de bucket ; il lui accorde lecture, liste, lecture du gel et de la configuration", async function () {
    const e = acces("ecrivain");
    const seg = ev.registre.find((l) => l.key.includes("/segments/"));
    const octets = new TextEncoder().encode("contenu hostile\n");
    const refuse = (r) => expect(refus(r), JSON.stringify(refus(r))).to.deep.equal({ statut: 403, code: "AccessDenied" });
    refuse(await e.envoyer(requeteS3Copie(`${PREFIXE}gels/00000000000000000000000000000000/0001-pose.json`, octets), { hacher: true }));
    refuse(await e.envoyer(requeteS3Copie(`${PREFIXE}autre/objet`, octets), { hacher: true }));
    refuse(await e.envoyer(requeteS3Copie(`hors-prefixe/${seg.key}`, octets), { hacher: true }));
    refuse(await e.envoyer(supprimer(seg.key, null)));
    refuse(await e.envoyer(supprimer(seg.key, seg.version_id)));
    refuse(await e.envoyer(supprimer(seg.key, seg.version_id, [["x-amz-bypass-governance-retention", "true"]])));
    refuse(await e.envoyer(requeteS3Gel(seg.key, seg.version_id, true), { hacher: true }));
    refuse(await e.envoyer(retention(seg.key, seg.version_id), { hacher: true }));
    refuse(await e.envoyer(requeteS3ConfigurationVerrou(1, "GOVERNANCE"), { hacher: true }));
    refuse(await e.envoyer(politiqueBucket(), { hacher: true }));
    // Accordés : lecture d'une version, liste des versions, configuration, gel.
    const lu = await e.envoyer(requeteS3Lire(seg.key, seg.version_id));
    expect(lu.statut).to.equal(200);
    expect(N.sha256Hex(new Uint8Array(lu.corps))).to.equal(seg.sha256);
    expect((await e.envoyer(requeteS3Liste({ prefix: PREFIXE }))).statut).to.equal(200);
    expect((await e.envoyer(requeteS3LireConfiguration())).statut).to.equal(200);
    const g = await e.envoyer(requeteS3LireGel(seg.key, seg.version_id));
    // Droit accordé : jamais gelée, la version n'a pas de gel à lire (MinIO :
    // 400 NoSuchObjectLockConfiguration), ce qui n'est pas un refus d'accès.
    expect(refus(g)).to.deep.equal({ statut: 400, code: "NoSuchObjectLockConfiguration" });
    // Rien n'a changé : une seule version de la clé, aucune sous gels/.
    const admin = new OperationsS3({ worm: ev.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
    expect((await admin.listerVersions(seg.key)).versions.filter((v) => v.key === seg.key)).to.have.length(1);
    expect((await admin.listerVersions(`${PREFIXE}gels/`)).versions).to.deep.equal([]);
  });

  it("signature : secret faux → 403 SignatureDoesNotMatch ; identifiant inconnu → 403 InvalidAccessKeyId", async function () {
    const seg = ev.registre.find((l) => l.key.includes("/segments/"));
    expect(refus(await acces("ecrivain", "secret-faux-0000").envoyer(requeteS3Lire(seg.key, seg.version_id)))).to.deep.equal({ statut: 403, code: "SignatureDoesNotMatch" });
    expect(refus(await acces("inconnu").envoyer(requeteS3Lire(seg.key, seg.version_id)))).to.deep.equal({ statut: 403, code: "InvalidAccessKeyId" });
  });

  it("EX-18.9 : le rôle Lecteur lit et liste ; toute écriture lui est refusée par le serveur (copie, gel, suppression) ; worm reconstruire avec ses identifiants réussit (code 0)", async function () {
    const l = acces("lecteur");
    const seg = ev.registre.find((x) => x.key.includes("/segments/"));
    expect((await l.envoyer(requeteS3Lire(seg.key, seg.version_id))).statut).to.equal(200);
    expect((await l.envoyer(requeteS3Liste({ prefix: PREFIXE }))).statut).to.equal(200);
    for (const r of [requeteS3Copie(`${PREFIXE}segments/autre.ndjson`, new TextEncoder().encode("x")), requeteS3Gel(seg.key, seg.version_id, true), supprimer(seg.key, seg.version_id)]) {
      expect(refus(await l.envoyer(r, { hacher: true }))).to.deep.equal({ statut: 403, code: "AccessDenied" });
    }
    const dest = path.join(dir, "reconstruit-lecteur");
    const r = await ctl(["worm", "reconstruire", "--configuration", ev.fichier, "--vers", dest, "--identifiants", ref("lecteur"), "--registre-copies", path.join(ev.repertoire, "worm")]);
    expect(r.code, r.erreur).to.equal(0);
    expect(fs.existsSync(path.join(dest, ev.config.recorder.org_id.slice(2), ev.config.recorder.journal_id.slice(2), "journal.json"))).to.equal(true);
  });

  it("gel juridique sous politiques réelles (12.11, EX-12.38, EX-18.9) : le Lecteur ne peut pas poser (le serveur refuse l'écriture sous gels/, code 4, rien n'est gelé) ; pose par le gardien de pose, demande de levée, levée par le gardien de levée (une autre personne) ; versions ON puis OFF", async function () {
    const admin = new OperationsS3({ worm: ev.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: tls.caPem }, delais: RAPIDE });
    const commun = ["--configuration", ev.fichier, "--registre-copies", path.join(ev.repertoire, "worm")];
    const parLecteur = await ctl(["worm", "gel", "poser", ...commun, "--identifiants", ref("lecteur"), "--identite", "lecteur@client.example", "--de", String(ev.P), "--a", String(ev.P), "--motif", "Essai hostile"]);
    expect(parLecteur.code, parLecteur.erreur).to.equal(4);
    expect(parLecteur.journal.some((x) => x.data?.http_status === 403 || x.data?.raison === "droit_manquant"), parLecteur.erreur).to.equal(true);
    expect((await admin.listerVersions(`${PREFIXE}gels/`)).versions).to.deep.equal([]);
    for (const l of ev.registre) expect(admin.etatGel(await admin.lireGel(l.key, l.version_id)), l.key).to.not.equal("on");

    const pose = await ctl(["worm", "gel", "poser", ...commun, "--identifiants", ref("gardien-pose"), "--identite", "a.gardien@client.example", "--de", String(ev.P), "--a", String(ev.P), "--motif", "Litige IAM"]);
    expect(pose.code, pose.erreur).to.equal(0);
    const gel = pose.sortie.trim();
    const enreg = JSON.parse(Buffer.from((await admin.lire(`${PREFIXE}gels/${gel}/0001-pose.json`)).corps).toString("utf8"));
    const objets = Buffer.from((await admin.lire(enreg.objects.key)).corps).toString("utf8").trim().split("\n").map((x) => JSON.parse(x));
    expect(objets.length).to.be.at.least(3);
    for (const o of objets) expect(admin.etatGel(await admin.lireGel(o.key, o.version_id)), o.key).to.equal("on");
    // Le gardien de levée ne peut pas écrire un enregistrement de pose (politique limitée à -levee*.json).
    const faux = await acces("gardien-levee").envoyer(requeteS3Copie(`${PREFIXE}gels/${gel}/0009-pose.json`, new TextEncoder().encode("{}")), { hacher: true });
    expect(refus(faux)).to.deep.equal({ statut: 403, code: "AccessDenied" });
    const demande = await ctl(["worm", "gel", "demander-levee", "--configuration", ev.fichier, "--identifiants", ref("gardien-pose"), "--identite", "a.gardien@client.example", "--gel", gel, "--motif", "Litige clos"]);
    expect(demande.code, demande.erreur).to.equal(0);
    const levee = await ctl(["worm", "gel", "lever", "--configuration", ev.fichier, "--identifiants", ref("gardien-levee"), "--identite", "b.gardien@client.example", "--gel", gel, "--demande", demande.sortie.trim()]);
    expect(levee.code, levee.erreur).to.equal(0);
    for (const o of objets) expect(admin.etatGel(await admin.lireGel(o.key, o.version_id)), o.key).to.equal("off");
    const etat = await ctl(["worm", "gel", "etat", "--configuration", ev.fichier, "--identifiants", ref("lecteur"), "--gel", gel]);
    expect(etat.code, etat.erreur).to.equal(0);
    expect(JSON.parse(etat.sortie)).to.include({ actif: false, garde: "respectee" });
  });

  it("COMPLIANCE appliqué : même le compte racine (Administrateur) ne supprime pas une version verrouillée, avec ou sans contournement ; la version reste lisible", async function () {
    const racine = acces("administrateur");
    const seg = ev.registre.find((l) => l.key.includes("/segments/"));
    for (const h of [[], [["x-amz-bypass-governance-retention", "true"]]]) {
      const r = await racine.envoyer(supprimer(seg.key, seg.version_id, h));
      expect(r.statut, JSON.stringify(refus(r))).to.be.within(400, 499);
    }
    const lu = await racine.envoyer(requeteS3Lire(seg.key, seg.version_id));
    expect(lu.statut).to.equal(200);
    expect(N.sha256Hex(new Uint8Array(lu.corps))).to.equal(seg.sha256);
  });

  it("constat (R13-F30, EX-18.9) : sur ce serveur, une politique qui restreint s3:PutObjectLegalHold par la clé s3:object-lock-legal-hold = ON refuse la pose comme la levée (403) ; la restriction à la seule pose n'y est donc pas vérifiable, et le gardien de pose détient le droit entier", async function () {
    await roleIam(s3.nom, "gardien-pose-restreint", {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Action: ["s3:PutObjectLegalHold"], Resource: [`arn:aws:s3:::${ev.bucket}/${PREFIXE}*`], Condition: { StringEquals: { "s3:object-lock-legal-hold": "ON" } } },
        { Effect: "Allow", Action: ["s3:GetObjectLegalHold"], Resource: [`arn:aws:s3:::${ev.bucket}/${PREFIXE}*`] },
      ],
    });
    const g = acces("gardien-pose-restreint");
    const seg = ev.registre.find((l) => l.key.includes("/segments/"));
    const pose = await g.envoyer(requeteS3Gel(seg.key, seg.version_id, true), { hacher: true });
    const levee = await g.envoyer(requeteS3Gel(seg.key, seg.version_id, false), { hacher: true });
    expect(refus(pose)).to.deep.equal({ statut: 403, code: "AccessDenied" });
    expect(refus(levee)).to.deep.equal({ statut: 403, code: "AccessDenied" });
    // Témoin : le gardien de pose sans condition pose bien (200).
    const temoin = await acces("gardien-pose").envoyer(requeteS3Gel(seg.key, seg.version_id, true), { hacher: true });
    expect(temoin.statut).to.equal(200);
  });
});
