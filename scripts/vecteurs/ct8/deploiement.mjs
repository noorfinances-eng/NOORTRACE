// Familles `conteneurs`, `controle-prealable` et `dimensionnement` des
// vecteurs de CT-8 (spec/CT-8-deploiement-et-exploitation.md, sections 4, 6
// et 9, annexes A.3 à A.5) : spec/vecteurs/ct-8/{conteneurs,controle-prealable,dimensionnement}/.
//
// conteneurs/          images.json (copie de deploiement/images/images.json),
//                      et pour chacun des 36 cas <cas>.yaml et
//                      <cas>.attendu.json (conteneurs-v0 $defs/cas, attendu =
//                      rapport de verifierConteneurs) ; chaque cas invalide est
//                      un fichier de référence dont une seule chaîne est
//                      remplacée (le remplacement échoue si la chaîne manque) ;
// controle-prealable/  33 cas (controle-prealable-v0 $defs/cas) : observations
//                      de 6.3 ou leur variante de production, un relevé
//                      changé, attendu = évaluation (EX-6.2, EX-6.3) ;
// dimensionnement/     16 cas de 9.6 (dimensionnement-v0 $defs/cas), attendu
//                      = sortie du calculateur (DM-1 à DM-22, EX-9.3).
//
// Dates fixes, adresses des plages de documentation de la RFC 5737,
// condensé fictif reconnaissable (32 fois « ab ») : deux exécutions donnent
// les mêmes octets (EX-A.1).

import fs from "node:fs";
import path from "node:path";
import * as D from "../../lib/deploiement.mjs";

const GIO = 2 ** 30;
const clone = (x) => structuredClone(x);

const lireDeploiement = (...p) => fs.readFileSync(path.join(D.RACINE, "deploiement", ...p), "utf8");

/** Effacer puis recréer le répertoire d'une famille. */
function repertoireNeuf(rep) {
  fs.rmSync(rep, { recursive: true, force: true });
  fs.mkdirSync(rep, { recursive: true });
}

/** Remplacement unique d'une chaîne, qui doit être présente. */
function remplacer(texte, avant, apres) {
  if (!texte.includes(avant)) throw new Error(`conteneurs : chaîne absente du fichier de référence : ${JSON.stringify(avant.slice(0, 80))}`);
  return texte.replace(avant, apres);
}

const groupe = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
/** Nombre décimal à la française : partie entière groupée par milliers, virgule décimale. */
const decimal = (texte) => {
  const [e, f] = String(texte).split(".");
  return groupe(e) + (f === undefined ? "" : "," + f);
};

// ---------------------------------------------------------------------------
// conteneurs/ (A.3)
// ---------------------------------------------------------------------------

/** Les 36 cas d'A.3 : [nom, texte, description]. */
function casConteneurs() {
  const R = lireDeploiement("compose", "rapide.yaml");
  const P = lireDeploiement("compose", "production.yaml");
  const r = (a, b) => remplacer(R, a, b);
  return [
    ["valide-rapide", R, "Fichier de référence deploiement/compose/rapide.yaml, sans changement : conforme."],
    ["valide-production", P, "Fichier de référence deploiement/compose/production.yaml, sans changement : conforme."],
    ["valide-production-condenses", P.replace(/image: (noortrace\/[a-z-]+):([0-9a-z.-]+)\n/g, (m, n, t) => `image: ${n}:${t}@sha256:${"ab".repeat(32)}\n`), "production.yaml dont chaque image noortrace/* est complétée par @sha256: suivi de 32 fois « ab » (condensé fictif, jamais celui d'une image) : conforme, toutes les images par condensé."],
    ["yaml-cle-dupliquee", r('    user: "10001:10001"\n', '    user: "10001:10001"\n    user: "10001:10001"\n'), "Clé user répétée dans le service enregistreur : le YAML ne s'analyse pas sans ambiguïté (CO-1, yaml_invalide)."],
    ["service-non-decrit", r("  verificateur:\n", "  inconnu:\n"), "Service verificateur renommé inconnu, absent de images.json (CO-1, service_non_decrit)."],
    ["image-latest", r("noortrace/enregistreur:0.1.0", "noortrace/enregistreur:latest"), "Image noortrace/enregistreur:latest, étiquette mutable (CO-2)."],
    ["image-sans-etiquette", r("noortrace/enregistreur:0.1.0", "noortrace/enregistreur"), "Image noortrace/enregistreur sans étiquette ni condensé (CO-2)."],
    ["construction-presente", r("    image: noortrace/enregistreur:0.1.0\n", "    image: noortrace/enregistreur:0.1.0\n    build: .\n"), "Clé build: . ajoutée au service enregistreur (CO-3)."],
    ["utilisateur-root", r('user: "10001:10001"', 'user: "0:0"'), "Service enregistreur sous le compte 0:0 (CO-4, utilisateur_non_conforme)."],
    ["utilisateur-absent", r('    user: "10001:10001"\n', ""), "Clé user retirée du service enregistreur : le compte serait celui de l'image (CO-4, utilisateur_absent)."],
    ["racine-inscriptible", r('    command: ["--configuration", "/etc/noortrace/configuration.json"]\n    read_only: true\n', '    command: ["--configuration", "/etc/noortrace/configuration.json"]\n    read_only: false\n'), "read_only: false pour le service enregistreur : racine inscriptible (CO-5)."],
    ["capacite-ajoutee", r("    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports", "    cap_drop:\n      - ALL\n    cap_add:\n      - NET_ADMIN\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports"), "cap_add: [NET_ADMIN] pour le service enregistreur, capacité absente de sa description (CO-6)."],
    ["sans-no-new-privileges", r("    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports", "    restart: unless-stopped\n    ports"), "security_opt retiré du service enregistreur : no-new-privileges absent (CO-7)."],
    ["privilegie", r("    restart: unless-stopped\n    ports", "    restart: unless-stopped\n    privileged: true\n    ports"), "privileged: true pour le service enregistreur (CO-8)."],
    ["reseau-hote", r("    restart: unless-stopped\n    network_mode: none\n    volumes:\n      - type: volume\n        source: approbation-etat", "    restart: unless-stopped\n    network_mode: host\n    volumes:\n      - type: volume\n        source: approbation-etat"), "network_mode: host pour le service approbation (CO-8, reseau_hote)."],
    ["secret-en-environnement", r("    environment:\n      TMPDIR: /run/temporaire\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports", '    environment:\n      TMPDIR: /run/temporaire\n      NOORTRACE_TOKEN_HOTE: "0123456789abcdef"\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports'), "Variable NOORTRACE_TOKEN_HOTE posée dans l'environnement du service enregistreur : un secret en clair (CO-9)."],
    ["secret-hors-repertoire", r("file: ./secrets/cle-mac-relais", "file: /etc/noortrace/cle-mac-relais"), "Secret de premier niveau cle-mac-relais lu dans /etc/noortrace, hors de ./secrets/ (CO-9, secret_hors_repertoire)."],
    ["port-toutes-interfaces", r('"127.0.0.1:8300:8300"', '"8300:8300"'), "Port 8300 publié sans adresse, donc sur toutes les interfaces de l'hôte (CO-10)."],
    ["port-non-decrit", r('"127.0.0.1:8500:8500"', '"127.0.0.1:9999:9999"'), "Port 9999 publié, absent de la description du service enregistreur (CO-10, port_non_decrit)."],
    ["socket-du-moteur", r("      - type: bind\n        source: ./config/rapide/configuration.json", "      - type: bind\n        source: /var/run/docker.sock\n        target: /run/noortrace/moteur.sock\n        bind:\n          create_host_path: false\n      - type: bind\n        source: ./config/rapide/configuration.json"), "Montage lié de la prise du moteur /var/run/docker.sock dans le service enregistreur (CO-11, montage_interdit)."],
    ["configuration-inscriptible", r("        target: /etc/noortrace/configuration.json\n        read_only: true\n", "        target: /etc/noortrace/configuration.json\n"), "read_only retiré du montage de la configuration, décrite en lecture seule (CO-11, volume_inscriptible)."],
    ["sonde-par-interpreteur", r('test: ["CMD", "/usr/local/bin/noortrace-ctl", "sonde", "--url", "http://127.0.0.1:8500/readyz"]', 'test: ["CMD-SHELL", "curl -f http://127.0.0.1:8500/readyz"]'), "Sonde du service enregistreur en CMD-SHELL, qui passe par /bin/sh (CO-12, sonde_non_conforme)."],
    ["dependance-sans-condition", remplacer(P, "    depends_on:\n      approbation:\n        condition: service_healthy\n", "    depends_on:\n      - approbation\n"), "depends_on de l'enregistreur de production.yaml en forme courte (- approbation), sans condition d'état sain (CO-12, dependance_sans_condition)."],
    ["outil-redemarre", r('    restart: "no"\n', "    restart: unless-stopped\n"), "restart: unless-stopped pour l'outil verificateur, qui redémarrerait en boucle (CO-13)."],
    ["verificateur-en-reseau", r('    restart: "no"\n    network_mode: none\n', '    restart: "no"\n    networks:\n      - sortie\n'), "Réseau sortie donné au verificateur, qui n'a pas de réseau (CO-14, reseau_attendu_aucun)."],
    ["reseau-outils-non-interne", remplacer(P, "  outils:\n    internal: true\n", "  outils: {}\n"), "Réseau outils de production.yaml déclaré outils: {}, non interne (CO-14, reseau_non_interne)."],
    ["services-vides", r(R.slice(R.indexOf("services:\n"), R.indexOf("\nnetworks:\n") + 1), "services: {}\n"), "Clé services vide : aucun service à vérifier (CO-1, services_absents) ; CO-2 à CO-14 non exécutées (prerequis_en_echec)."],
    ["inclusion-refusee", r("name: noortrace-rapide\n", "name: noortrace-rapide\n\ninclude:\n  - autre.yaml\n"), "Clé include de premier niveau, qui chargerait un fichier non examiné (CO-1, cle_premier_niveau_non_admise) ; CO-2 à CO-14 non exécutées (prerequis_en_echec)."],
    ["groupe-absent", r('    user: "10001:10001"\n    group_add:\n      - "10010"\n', '    user: "10001:10001"\n'), "group_add retiré de l'enregistreur : le compte n'aurait pas le groupe 10010 du répertoire des prises (CO-4, groupe_non_conforme)."],
    ["confinement-retire", r("    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports", "    security_opt:\n      - no-new-privileges:true\n      - seccomp:unconfined\n    restart: unless-stopped\n    ports"), "seccomp:unconfined ajouté au security_opt de l'enregistreur : filtre des appels système retiré (CO-7, confinement_desactive)."],
    ["extension-de-service", r("    image: noortrace/enregistreur:0.1.0\n", "    image: noortrace/enregistreur:0.1.0\n    extends:\n      file: autre.yaml\n      service: base\n"), "Clé extends dans l'enregistreur, qui importerait les clés d'un service non examiné (CO-8, cle_interdite_extends)."],
    ["variable-non-decrite", r("    environment:\n      TMPDIR: /run/temporaire\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports", "    environment:\n      TMPDIR: /run/temporaire\n      LANG: C\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports"), "Variable LANG posée dans l'environnement de l'enregistreur, hors de la liste fermée de sa description (CO-9, variable_non_decrite)."],
    ["secret-en-ligne-de-commande", r('    command: ["--prise", "/run/noortrace/approbation.sock", "--pair", "noortrace", "--etat", "/var/lib/noortrace-approbation"]\n', '    command: ["--prise", "/run/noortrace/approbation.sock", "--pair", "noortrace", "--etat", "/var/lib/noortrace-approbation", "--jeton", "0123456789abcdef"]\n'), "Option --jeton suivie d'une valeur en clair, et non d'un chemin /run/secrets/, sur la ligne de commande du service approbation (CO-9, secret_en_ligne_de_commande)."],
    ["secret-partage-entre-comptes", remplacer(P, "      - jeton-console-vers-service-console\n      - oidc-client\n", "      - jeton-console-vers-service-approbation\n      - oidc-client\n"), "La console (compte 10003) reçoit le fichier jeton-console-vers-service-approbation du service (compte 10002) : un fichier n'a qu'un propriétaire, l'un des deux ne pourrait pas le lire (CO-9, secret_partage_entre_comptes et secret_non_decrit)."],
    ["montage-remontee", r("        source: ./config/rapide/configuration.json\n", "        source: ./config/../../../../var/run/docker.sock\n"), "Source de montage lié ./config/../../../../var/run/docker.sock : un préfixe admis suivi de « .. » mène à la prise du moteur (CO-11, montage_interdit)."],
    ["volume-lie-hote", r("volumes:\n  journal: {}\n", "volumes:\n  journal:\n    driver: local\n    driver_opts:\n      type: none\n      o: bind\n      device: /\n"), "Volume nommé journal défini par driver_opts (type none, o bind, device /) : un montage de la racine de l'hôte sous un nom de volume (CO-11, volume_lie_hote)."],
  ];
}

export function genererConteneurs(rep) {
  repertoireNeuf(rep);
  const texteImages = lireDeploiement("images", "images.json");
  fs.writeFileSync(path.join(rep, "images.json"), texteImages);
  const description = JSON.parse(texteImages);
  const schema = D.chargerSchema("conteneurs");
  const cas = [];
  for (const [nom, texte, desc] of casConteneurs()) {
    const fichier = `${nom}.yaml`;
    const attendu = D.verifierConteneurs(texte, description, fichier);
    const doc = { description: desc, file: fichier, attendu };
    const erreurs = D.validerSchemaDeploiement(doc, schema, { fragment: "#/$defs/cas" });
    if (erreurs.length) throw new Error(`conteneurs/${nom} : non conforme à conteneurs-v0 $defs/cas : ${JSON.stringify(erreurs.slice(0, 3))}`);
    const echecs = attendu.checks.filter((c) => c.status === "echoue");
    if (nom.startsWith("valide") !== (echecs.length === 0)) throw new Error(`conteneurs/${nom} : verdict inattendu ${attendu.verdict}`);
    if (!nom.startsWith("valide") && echecs.length !== 1) throw new Error(`conteneurs/${nom} : ${echecs.length} vérifications en échec, une seule attendue (A.3)`);
    fs.writeFileSync(path.join(rep, fichier), texte);
    fs.writeFileSync(path.join(rep, `${nom}.attendu.json`), D.texteJSON(doc));
    cas.push({ nom, description: desc, attendu });
  }
  return { cas };
}

export function sectionConteneurs({ cas }) {
  const L = ["## conteneurs", ""];
  L.push("Fichiers Compose de CT-8 §4 confrontés à la description des images, annexe");
  L.push("A.3. `images.json` est la copie de `deploiement/images/images.json` ; chaque");
  L.push("cas a son fichier `<cas>.yaml` et `<cas>.attendu.json` (schéma");
  L.push("`conteneurs-v0#/$defs/cas`), dont `attendu` est le rapport exact de");
  L.push("`scripts/deploiement/verifier-conteneurs.mjs`, SHA-256 du fichier compris.");
  L.push("Chaque cas invalide est un fichier de référence dont une seule chaîne est");
  L.push("remplacée, et qui échoue à une seule vérification.");
  L.push("");
  L.push("Commande de chaque cas, depuis la racine du dépôt (code 0 pour un fichier");
  L.push("conforme, 1 sinon) :");
  L.push("");
  L.push("```bash");
  L.push("node scripts/deploiement/verifier-conteneurs.mjs spec/vecteurs/ct-8/conteneurs/<cas>.yaml \\");
  L.push("  --images spec/vecteurs/ct-8/conteneurs/images.json --json");
  L.push("```");
  L.push("");
  L.push("| Cas | Ce qui change | Code | Verdict | Vérification en échec |");
  L.push("|---|---|---|---|---|");
  for (const c of cas) {
    const echecs = c.attendu.checks.filter((x) => x.status === "echoue").map((x) => `${x.id} (${x.findings.map((f) => `${f.service ?? "—"} : \`${f.code}\``).join(", ")})`).join(" ; ") || "—";
    L.push(`| \`${c.nom}\` | ${c.description} | ${c.attendu.verdict === "conforme" ? 0 : 1} | \`${c.attendu.verdict}\` | ${echecs} |`);
  }
  return L.join("\n");
}

// ---------------------------------------------------------------------------
// controle-prealable/ (A.4)
// ---------------------------------------------------------------------------

/** Observations de 6.3 : hôte qui prépare l'installation rapide avec la configuration de 7.3 (adresses de la RFC 5737). */
export const OBSERVATIONS_RAPIDE = Object.freeze({
  version: 0,
  checked_at: "2026-10-27T09:00:00.000Z",
  tool: "0.1.0",
  platform: "linux",
  arch: "x64",
  cpus: 4,
  memory_bytes: 8 * GIO,
  storage: { path: "/var/lib/docker/volumes", fstype: "ext4", free_bytes: 50 * GIO },
  clock: { source: "chrony", synchronized: true, error_bound_ms: 3.2 },
  ports: [8300, 8400, 8500].map((port) => ({ address: "127.0.0.1", port, free: true })),
  dns: [
    { name: "outils.interne.example", addresses: ["192.0.2.21"] },
    { name: "api.anthropic.com", addresses: ["198.51.100.31"] },
    { name: "api.openai.com", addresses: ["198.51.100.32"] },
    { name: "a.pool.opentimestamps.org", addresses: ["203.0.113.41"] },
    { name: "b.pool.opentimestamps.org", addresses: ["203.0.113.42"] },
  ],
  egress: [
    { flow: "FL-7", host: "outils.interne.example", port: 443, result: "ouvert" },
    { flow: "FL-8", host: "api.anthropic.com", port: 443, result: "ouvert" },
    { flow: "FL-8", host: "api.openai.com", port: 443, result: "ouvert" },
    { flow: "FL-18", host: "a.pool.opentimestamps.org", port: 443, result: "ouvert" },
    { flow: "FL-18", host: "b.pool.opentimestamps.org", port: 443, result: "ouvert" },
  ],
  proxy: { declared: false, environment_set: false },
  rights: {
    uid: 1000,
    secrets_dir_mode: 0o700,
    secret_files: ["cle-enregistreur", "cle-mac-relais", "jeton-hote", "jeton-passerelle"].map((name) => ({ name, mode: 0o400, uid: 10001, expected_uid: 10001 })),
    config_mode: 0o400,
    config_uid: 10001,
    config_expected_uid: 10001,
  },
  engine: { engine_ok: true, compose_ok: true },
  compose: { file_sha256: null, failed: [], all_images_by_digest: false },
  declarations: { write_cache_protected: false },
});

/** Variante de production (A.4) : 8 processeurs, 16 Gio, 1 200 Gio libres, ports publiés sur 192.0.2.40, images par condensé, cache déclaré. */
export function observationsProduction() {
  const o = clone(OBSERVATIONS_RAPIDE);
  o.cpus = 8;
  o.memory_bytes = 16 * GIO;
  o.storage.free_bytes = 1200 * GIO;
  o.internal_address = { address: "192.0.2.40", on_host: true };
  o.ports = [{ address: "127.0.0.1", port: 8500, free: true }, { address: "192.0.2.40", port: 8300, free: true }, { address: "192.0.2.40", port: 8400, free: true }];
  o.compose.all_images_by_digest = true;
  o.declarations.write_cache_protected = true;
  return o;
}

/** Seuil d'espace de production des cas : local_bytes de l'exemple de 9.5 (cas dimensionnement/reference). */
export const SEUIL_EXEMPLE = 1039011288480;

/** Les 33 cas d'A.4 : { nom, profile, seuil (production), only, changer, description }. */
const CAS_CONTROLE = [
  ["pret-rapide", "rapide", (o) => o, "Observations de 6.3, sans changement : prêt avec avertissement, IP-13 non exécutée faute de déclaration du cache, non bloquante en rapide."],
  ["pret-production", "production", (o) => o, "Variante de production, seuil d'espace égal à local_bytes de l'exemple de 9.5 : prêt."],
  ["architecture-non-prise-en-charge", "rapide", (o) => { o.arch = "ia32"; }, "Architecture ia32 au lieu de x64 : IP-1 échoue."],
  ["memoire-insuffisante", "rapide", (o) => { o.memory_bytes = 2 * GIO; }, "2 Gio de mémoire, sous la cible de 4 Gio : IP-2 échoue."],
  ["espace-insuffisant", "production", (o) => o, "Seuil d'espace de 2 000 Gio, au-delà des 1 200 Gio libres : IP-3 échoue.", 2000 * GIO],
  ["production-sans-dimensionnement", "production", (o) => o, "Production sans dimensionnement : IP-3 non exécutée (dimensionnement_absent), bloquante.", null],
  ["stockage-nfs", "rapide", (o) => { o.storage.fstype = "nfs4"; }, "Stockage sur nfs4, système de fichiers refusé : IP-4 échoue."],
  ["systeme-de-fichiers-non-eprouve", "rapide", (o) => { o.storage.fstype = "zfs"; }, "Stockage sur zfs, ni admis ni refusé : IP-4 en avertissement."],
  ["horloge-non-synchronisee-rapide", "rapide", (o) => { o.clock = { source: "chrony", synchronized: false, error_bound_ms: null }; }, "Horloge non synchronisée en rapide : IP-5 échoue, non bloquante."],
  ["horloge-non-synchronisee-production", "production", (o) => { o.clock = { source: "timedatectl", synchronized: false, error_bound_ms: null }; }, "Horloge non synchronisée en production (timedatectl) : IP-5 échoue, bloquante."],
  ["horloge-ecart-trop-grand", "production", (o) => { o.clock.error_bound_ms = 2500; }, "Borne d'erreur de l'horloge de 2 500 ms, au-delà de clock.warn_skew_ms (1 000) : IP-5 échoue (ecart_trop_grand)."],
  ["horloge-sans-outil-production", "production", (o) => { o.clock = { source: "aucune", synchronized: null, error_bound_ms: null }; }, "Aucun outil de synchronisation trouvé en production : IP-5 non exécutée, bloquante."],
  ["horloge-borne-inconnue-production", "production", (o) => { o.clock = { source: "timedatectl", synchronized: true, error_bound_ms: null }; }, "Horloge synchronisée selon timedatectl, sans borne d'erreur connue : IP-5 en avertissement (borne_inconnue), qui n'est pas un échec."],
  ["horloge-non-relevee", "production", (o) => { o.clock = null; }, "Horloge non relevée (clock null) : IP-5 non exécutée (mesure_absente), bloquante en production."],
  ["port-occupe", "rapide", (o) => { o.ports[2].free = false; }, "Port 8500 de 127.0.0.1 déjà occupé : IP-6 échoue."],
  ["adresse-toutes-interfaces", "production", (o) => { o.internal_address = { address: "0.0.0.0", on_host: false }; for (const p of o.ports) if (p.address === "192.0.2.40") Object.assign(p, { address: "0.0.0.0", free: false }); }, "NOORTRACE_IP_INTERNE vaut 0.0.0.0 : les ports de production seraient publiés sur toutes les interfaces (IP-6, adresse_toutes_interfaces)."],
  ["adresse-hors-hote", "production", (o) => { o.internal_address = { address: "198.51.100.40", on_host: false }; for (const p of o.ports) if (p.address === "192.0.2.40") Object.assign(p, { address: "198.51.100.40", free: false }); }, "NOORTRACE_IP_INTERNE n'est l'adresse d'aucune interface de l'hôte (IP-6, adresse_hors_hote)."],
  ["nom-non-resolu", "rapide", (o) => { o.dns[0].addresses = []; o.egress[0].result = "dns"; }, "Serveur d'outils outils.interne.example non résolu : IP-7 échoue, et IP-8 (dns)."],
  ["sortie-bloquee", "rapide", (o) => { o.egress[3].result = "delai"; }, "Calendrier a.pool.opentimestamps.org en délai : IP-8 échoue (delai)."],
  ["tls-refuse", "production", (o) => { o.egress[1].result = "tls"; }, "Poignée de main TLS refusée vers api.anthropic.com : IP-8 échoue (tls)."],
  ["mandataire-non-declare", "production", (o) => { o.proxy.environment_set = true; }, "HTTPS_PROXY posé sans --mandataire : IP-9 en avertissement, qui n'est pas un échec."],
  ["secret-lisible-par-le-groupe", "rapide", (o) => { o.rights.secret_files[0].mode = 0o440; }, "Secret cle-enregistreur en 0440, lisible par le groupe : IP-10 échoue (secrets_lisibles)."],
  ["configuration-lisible-par-autrui", "rapide", (o) => { o.rights.config_mode = 0o444; }, "Configuration en 0444 : IP-10 échoue (configuration_lisible_par_autrui)."],
  ["secret-mauvais-proprietaire", "rapide", (o) => { o.rights.secret_files[1].uid = 1000; }, "Secret cle-mac-relais propriété du compte 1000 au lieu de 10001 : IP-10 échoue (secret_proprietaire_incorrect)."],
  ["secret-mode-non-conforme", "rapide", (o) => { o.rights.secret_files[2].mode = 0o700; }, "Secret jeton-hote en 0700 : ni 0400 ni 0600, même sans droit de groupe ni d'autrui (IP-10, secret_mode_non_conforme)."],
  ["secret-partage-entre-comptes", "production", (o) => { o.rights.secret_files.push({ name: "jeton-console-vers-service", mode: 0o400, uid: 10002, expected_uid: null }); }, "Fichier de secret jeton-console-vers-service qu'admettent des services de comptes différents : un fichier n'a qu'un propriétaire (IP-10, secret_partage_entre_comptes)."],
  ["configuration-mauvais-proprietaire", "rapide", (o) => { o.rights.config_uid = 0; }, "Configuration en 0400 propriété du compte 0 au lieu de 10001 (IP-10, configuration_proprietaire_incorrect)."],
  ["execute-par-root-admis", "rapide", (o) => { o.rights.uid = 0; }, "Outil lancé sous le compte 0 (sudo, pas IR-4) : admis, prêt avec le seul avertissement d'IP-13."],
  ["compose-absent", "rapide", (o) => { o.engine.compose_ok = false; }, "docker compose version en échec : IP-11 échoue (compose_absent)."],
  ["conteneurs-non-conformes", "rapide", (o) => { o.compose.failed = ["CO-5"]; }, "Fichier Compose dont CO-5 échoue : IP-12 échoue."],
  ["images-sans-condense-production", "production", (o) => { o.compose.all_images_by_digest = false; }, "Une image sans condensé en production : IP-12 échoue (condense_requis)."],
  ["cache-non-declare-production", "production", (o) => { o.declarations.write_cache_protected = false; }, "Aucune déclaration du cache d'écriture en production : IP-13 échoue."],
  ["systeme-seulement-production", "production", (o) => o, "Production, --seulement IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13 (pas IC-5) : les six autres non demandées, non bloquantes ; prêt avec avertissements.", undefined, ["IP-1", "IP-2", "IP-4", "IP-5", "IP-6", "IP-11", "IP-13"]],
];

export function genererControle(rep) {
  repertoireNeuf(rep);
  const schema = D.chargerSchema("controle-prealable");
  const cas = [];
  for (const [nom, profile, changer, description, seuilDonne, only] of CAS_CONTROLE) {
    const obs = profile === "rapide" ? clone(OBSERVATIONS_RAPIDE) : observationsProduction();
    changer(obs);
    const doc = { description, profile };
    let seuil;
    if (profile === "production" && !only) {
      seuil = seuilDonne === undefined ? SEUIL_EXEMPLE : seuilDonne;
      doc.storage_free_min_bytes = seuil;
    }
    if (only) doc.only = only;
    doc.observations = obs;
    doc.attendu = D.evaluerControle(obs, D.exigencesProfil(profile, { storageFreeMinBytes: profile === "production" ? seuil ?? null : undefined, only: only ?? null }));
    const erreurs = D.validerSchemaDeploiement(doc, schema, { fragment: "#/$defs/cas" });
    if (erreurs.length) throw new Error(`controle-prealable/${nom} : non conforme à controle-prealable-v0 $defs/cas : ${JSON.stringify(erreurs.slice(0, 3))}`);
    fs.writeFileSync(path.join(rep, `${nom}.json`), D.texteJSON(doc));
    cas.push({ nom, ...doc });
  }
  return { cas };
}

export function sectionControle({ cas }) {
  const L = ["## controle-prealable", ""];
  L.push("Évaluation du contrôle préalable de CT-8 §6, annexe A.4. Chaque");
  L.push("`<cas>.json` (schéma `controle-prealable-v0#/$defs/cas`) porte le profil,");
  L.push("les observations d'un hôte (celles de 6.3, ou leur variante de production :");
  L.push("8 processeurs, 16 Gio, 1 200 Gio libres, ports publiés sur `192.0.2.40`, images");
  L.push("par condensé, cache déclaré), le seuil d'espace (`storage_free_min_bytes`)");
  L.push("ou la liste `only` quand le cas les fixe, et le rapport attendu. Chaque cas");
  L.push("change un relevé.");
  L.push("");
  L.push("Commande de chaque cas (`--observations` admet un fichier de cas : ses");
  L.push("observations, son seuil et sa liste `only` sont repris) ; la sortie `--json`");
  L.push("égale `attendu`, et le code de sortie est `attendu.exit_code` :");
  L.push("");
  L.push("```bash");
  L.push("node scripts/deploiement/controle-prealable.mjs --profil <profil> \\");
  L.push("  --observations spec/vecteurs/ct-8/controle-prealable/<cas>.json --json");
  L.push("```");
  L.push("");
  L.push("| Cas | Profil | Ce qui change | Code | Verdict | Vérifications non réussies |");
  L.push("|---|---|---|---|---|---|");
  for (const c of cas) {
    const nr = c.attendu.checks.filter((x) => x.status !== "reussi").map((x) => `${x.id} \`${x.status}\`${x.reason ? ` (\`${x.reason}\`)` : ""}${x.blocking ? "" : ", non bloquante"}`).join(" ; ") || "—";
    L.push(`| \`${c.nom}\` | \`${c.profile}\` | ${c.description} | ${c.attendu.exit_code} | \`${c.attendu.verdict}\` | ${nr} |`);
  }
  return L.join("\n");
}

// ---------------------------------------------------------------------------
// dimensionnement/ (A.5)
// ---------------------------------------------------------------------------

/** Entrées de l'exemple de 9.5 : un journal de dix agents semblables à l'exemple de CT-2 §16.4. */
export function entreesExemple() {
  return {
    version: 0,
    hours_per_year: 8760,
    coefficients: {},
    journals: [
      {
        id: "sinistres",
        count: 1,
        activity: { agents: 10, events_per_hour: 120, active_hours: 2920, peak_factor: 4, event_bytes: 2560, piece_bytes_per_event: 6144, pieces_per_event: 2, write_share: 0.1, ops_log_bytes_per_event: 512 },
        storage: {
          events_years: 10,
          local_days: 4018,
          pieces_days: 4018,
          segment_max_bytes: 268435456,
          min_free_bytes: 1073741824,
          pending_max_bytes: 268435456,
          ops_log: { rotate_max_bytes: 104857600, keep_files: 30 },
          fsync: { group_max_events: 64, group_max_wait_ms: 5 },
          worm: { retain_days: 4018, copies: 1, pieces_in_worm: false, ops_log_in_worm: false },
        },
        anchoring: { checkpoint_interval_s: 60, rfc3161_interval_s: 300, a: 1, r: 0, provider_role: "second_rang", registry_checkpoints: "nouveaux_evenements", ots_checkpoint: "aucun", retention_years: 10, crl_per_token: 2, crl_bytes: 833, acquisition_bytes: 2048 },
        memory: { max_concurrent: 96, request_max_bytes: 16777216, response_max_bytes: 16777216, base_bytes: null },
      },
    ],
  };
}

/** Les 16 cas de 9.6 : [nom, changement, description]. */
const CAS_DIMENSIONNEMENT = [
  ["reference", () => {}, "Exemple de 9.5, sans changement."],
  ["sans-worm", (e) => { e.journals[0].storage.worm = null; }, "Aucun support WORM (storage.worm = null)."],
  ["deux-copies-worm-et-pieces", (e) => { e.journals[0].storage.worm.copies = 2; e.journals[0].storage.worm.pieces_in_worm = true; }, "Deux copies WORM sur des supports distincts, pièces copiées."],
  ["points-chez-principal", (e) => { e.journals[0].anchoring.provider_role = "principal"; }, "Points contresignés par le prestataire principal (provider_role = principal)."],
  ["contresignature-a-la-minute", (e) => { e.journals[0].anchoring.rfc3161_interval_s = 60; e.journals[0].anchoring.provider_role = "principal"; }, "Contresignature à la minute (c_T = 60) par le prestataire principal."],
  ["ots-mi-periode", (e) => { e.journals[0].anchoring.ots_checkpoint = "mi_periode"; }, "Preuve OpenTimestamps d'un point à mi-période."],
  ["sans-ancre-des-points", (e) => { e.journals[0].anchoring.registry_checkpoints = "aucun"; e.journals[0].anchoring.rfc3161_interval_s = 3600; }, "Aucune ancre des points au registre (registry.checkpoints = aucun), c_T = 3 600."],
  ["pieces-purgees", (e) => { e.journals[0].storage.pieces_days = 365; }, "Pièces conservées localement 365 jours (D_lp = 365)."],
  ["debit-au-dela-de-la-cible", (e) => { const a = e.journals[0].activity; a.agents = 50; a.events_per_hour = 10000; a.active_hours = 8760; }, "50 agents, 10 000 événements par heure, actifs 8 760 heures : pointe au-delà de la cible de 500 événements par seconde."],
  ["cent-journaux", (e) => { e.journals[0].count = 100; }, "Cent journaux de ce type (J = 100)."],
  ["deux-types-de-journaux", (e) => { const j2 = clone(e.journals[0]); j2.id = "souscription"; j2.count = 3; j2.activity.agents = 2; j2.activity.events_per_hour = 30; e.journals.push(j2); }, "Plus trois journaux souscription de deux agents à 30 événements par heure."],
  ["journal-inactif", (e) => { e.journals[0].activity.events_per_hour = 0; e.journals[0].anchoring.a = 0; }, "Journal sans activité (e = 0, a = 0) : le maximum d'ancres est gardé (DM-7 est une borne)."],
  ["points-toutes-les-dix-secondes", (e) => { e.journals[0].anchoring.checkpoint_interval_s = 10; }, "Un point toutes les dix secondes (c_K = 10)."],
  ["refus-cadence-non-diviseur", (e) => { e.journals[0].anchoring.checkpoint_interval_s = 70; }, "c_K = 70, qui ne divise pas 3 600 : refus (EX-9.3)."],
  ["refus-retention-ancres", (e) => { e.journals[0].anchoring.retention_years = 5; }, "Rétention des pièces d'horodatage de 5 ans, sous 10 : refus (EX-9.3)."],
  ["refus-depassement-capacite", (e) => { const a = e.journals[0].activity; a.agents = 1000000; a.events_per_hour = 100000; e.journals[0].count = 1000; }, "Un million d'agents à 100 000 événements par heure, mille journaux : une sortie entière dépasserait 2^53 − 1 : refus (EX-9.3, depassement_capacite)."],
];

export function genererDimensionnement(rep) {
  repertoireNeuf(rep);
  const schema = D.chargerSchema("dimensionnement");
  const cas = [];
  for (const [nom, changer, description] of CAS_DIMENSIONNEMENT) {
    const entrees = entreesExemple();
    changer(entrees);
    const doc = { description, entrees, attendu: D.dimensionner(entrees) };
    const erreurs = D.validerSchemaDeploiement(doc, schema, { fragment: "#/$defs/cas" });
    if (erreurs.length) throw new Error(`dimensionnement/${nom} : non conforme à dimensionnement-v0 $defs/cas : ${JSON.stringify(erreurs.slice(0, 3))}`);
    fs.writeFileSync(path.join(rep, `${nom}.json`), D.texteJSON(doc));
    cas.push({ nom, ...doc });
  }
  return { cas };
}

export function sectionDimensionnement({ cas }) {
  const L = ["## dimensionnement", ""];
  L.push("Calculateur de CT-8 §9, annexe A.5 : les seize cas de 9.6, qui font varier");
  L.push("l'exemple de 9.5 un paramètre à la fois. Chaque `<cas>.json` (schéma");
  L.push("`dimensionnement-v0#/$defs/cas`) porte les entrées et la sortie exacte");
  L.push("(`attendu`).");
  L.push("");
  L.push("Commande de chaque cas (`--entrees` admet un fichier de cas : ses `entrees`");
  L.push("sont reprises) ; la sortie `--json` égale `attendu`, code 0, ou 1 pour un");
  L.push("refus d'EX-9.3 :");
  L.push("");
  L.push("```bash");
  L.push("node scripts/deploiement/dimensionner.mjs --entrees spec/vecteurs/ct-8/dimensionnement/<cas>.json --json");
  L.push("```");
  L.push("");
  L.push("| Cas | Ce qui change | Code | `local_bytes` (Gio) | `worm_bytes` (Gio) | Jetons qualifiés / autres par an | Transactions par heure ; part |");
  L.push("|---|---|---|---|---|---|---|");
  for (const c of cas) {
    const s = c.attendu;
    if (!s.valid) {
      L.push(`| \`${c.nom}\` | ${c.description} | 1 | refus : ${s.errors.map((e) => `\`${e.code}\``).join(", ")} | | | |`);
      continue;
    }
    const t = s.totals;
    L.push(`| \`${c.nom}\` | ${c.description} | 0 | ${decimal(D.gio(t.local_bytes))} | ${t.worm_bytes === 0 ? "0" : decimal(D.gio(t.worm_bytes))} | ${groupe(t.tokens_qualified_per_year)} / ${groupe(t.tokens_other_per_year)} | ${decimal(t.registry_tx_per_hour_max)} ; ${decimal(t.registry_capacity_share)} |`);
  }
  return L.join("\n");
}
