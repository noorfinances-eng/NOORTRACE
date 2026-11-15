// Les deux cas de démonstration du plan (CT-9 TE-1 « assurance » : agent de
// souscription en assurance de personnes, annexe III du règlement, point 5 c ;
// TE-2 « administration » : agent qui instruit des demandes de prestations
// publiques, point 5 a), joués de la capture au dossier vérifié sur
// l'infrastructure de la démonstration de référence (demo/compose.yaml avec
// la surcharge demo/cas/compose.cas.yaml), avec :
//
// - le service d'approbation réel de CT-3 (image noortrace/approbation) et le
//   serveur de console réel (paquets/console) : les deux approbateurs
//   s'inscrivent à l'annuaire par preuve de possession et signent leur
//   décision depuis l'écran Ticket, dans Chromium, avec le portefeuille
//   EIP-1193 simulé des essais de l'étape 6 (TE-1, pas 2 : « Approuver depuis
//   la console avec deux comptes de test ») ; l'approbateur de la
//   démonstration ne vote pas ;
// - le serveur RFC 3161 interne de CT-8 §7 (image noortrace/tsa-interne) pour
//   le jeton de la période (contrôle 4) ; le registre de développement de la
//   démonstration (contrôle 8) ; aucune preuve OpenTimestamps (contrôle 5 non
//   exécuté : la chaîne regtest de l'étape 5 n'est pas jouable dans les
//   images) ;
// - la vérification hors ligne des dossiers exportés par les deux
//   vérificateurs de CT-6 (référence JavaScript, binaire Go de
//   NOORTRACE_VERIFIER_BIN) dans un espace de noms réseau vide (`unshare -n`)
//   sur l'hôte, hors des conteneurs ; le paquet réviseur de CT-8 §13 construit
//   avec le vérificateur joint et une attestation de périmètre signée par les
//   deux comptes de test, vérifié en une commande.
//
// En attente, condition nommée, sans démon Docker, sans les neuf images, sans
// openssl ou sans Chromium. Aucun essai ne joint un réseau public : les
// réseaux de la composition sont internes ; la console, le fournisseur OIDC
// simulé et le navigateur sont sur la boucle locale de l'hôte.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  CAS_DIR, DEMO, RACINE, appelCanalConsole, attendre, binaireGo, configurationCas, construirePaquet, controles, enAttente, envCas, etatCas, lancerConsoleSurPrise, portLibre, preparer, raison,
  repertoireTemporaire, sansReseauDisponible, signerAttestation, verifications, verifierAttestation, verifierDeuxSansReseau, verifierPaquetSansReseau, CompositionCas,
} from "./fixtures/cas/outils.mjs";
import { demarrerFournisseur } from "./fixtures/exploitation-console/fournisseur-oidc.mjs";
import { materielTls } from "./fixtures/exploitation-console/serveur/outils.mjs";
import { Personne, inscrireAdresse, lancerChromium, validerAdresse, voter } from "./fixtures/exploitation-console/parcours/navigateur.mjs";
import { compte } from "./fixtures/exploitation-console/parcours/inscription.mjs";

const EXIGER = process.env.NOORTRACE_EXIGER_CHROMIUM === "1";
const CLES_APPROBATEURS = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-3", "constantes.json"), "utf8")).accounts.filter((a) => [1, 2, 3].includes(a.index)).map((a) => a.private_key.slice(2));
const ADRESSES = [compte(1).adresse, compte(2).adresse];
/** Demandes `personal_sign` d'un vote (D_A : 32 octets) faites au portefeuille d'une personne (les preuves d'inscription exclues). */
const signaturesDeVote = (p) => p.portefeuille.requetes(null, "personal_sign").filter((x) => x.params[0].length === 66).map((x) => x.params);

/**
 * Le parcours d'un cas : mêmes pas, oracles propres au cas.
 * @param {{cas: string, te: string, decision: "approuve"|"refuse", motif: string, outilRevue: string, outilsLecture: string[], regleRevue: string, sequence: Array, exports: string[]}} spec
 */
function parcours(spec) {
  const { cas, te } = spec;
  const CONFIG = configurationCas(cas);
  const ENV = envCas(cas);
  const s = { attente: null, personnes: [], consoles: [] };

  before(async function () {
    this.timeout(900000);
    const etat = etatCas();
    if (!etat.ok) {
      s.attente = etat.condition;
      return;
    }
    const ch = await lancerChromium();
    if (!ch.navigateur) {
      if (EXIGER) throw new Error(`NOORTRACE_EXIGER_CHROMIUM=1 : ${ch.raison}`);
      s.attente = `Chromium indisponible : ${ch.raison}`;
      return;
    }
    s.navigateur = ch.navigateur;
    s.travail = repertoireTemporaire(`noortrace-cas-${cas}-`);
    s.projet = `noortrace-cas-${cas}-${process.pid}`;
    s.tls = materielTls(path.join(s.travail, "tls"));
    if (!s.tls) throw new Error("matériel TLS : openssl a échoué");
    s.secretOidc = crypto.randomBytes(24).toString("hex");
    s.fournisseur = await demarrerFournisseur({ cert: s.tls.cert, key: s.tls.key, clientId: "console-demonstration", secret: s.secretOidc, hote: "127.0.0.1" });
    s.issuer = s.fournisseur.issuer;
    s.identite = (sujet) => `oidc ${s.issuer} ${sujet}`;
    s.portConsole = await portLibre();
    s.origine = `https://127.0.0.1:${s.portConsole}`;
    s.port = await portLibre();
    // IR-2, IR-3 du passage : autorité du serveur interne, document d'ancrage, configuration du service pour cette console.
    s.preparation = preparer("preparer", { cas, travail: s.travail, projet: s.projet, origineConsole: s.origine, issuer: s.issuer, port: s.port });
    s.c = new CompositionCas({ cas, nom: s.projet, port: s.port, travail: s.travail });
    // Tout sauf l'agent, l'exploitation et le vérificateur de la démonstration de référence (profil reference).
    s.c.lancer(["enregistreur", "horodatage"]);
    for (const svc of ["approbation", "enregistreur", "horodatage"]) await s.c.sain(svc, 240000);
    s.prise = s.c.priseConsole();
    await attendre(() => fs.existsSync(s.prise), 30000, "prise du canal de la console");
    s.console = await lancerConsoleSurPrise({ dir: path.join(s.travail, "console"), port: s.portConsole, tls: s.tls, prise: s.prise, jeton: "demo-jeton-console-approbateur-demo", issuer: s.issuer, secretClient: s.secretOidc });
    s.consoles.push(s.console);
  });

  after(async function () {
    this.timeout(300000);
    for (const p of s.personnes) await p.fermer();
    if (s.navigateur) await s.navigateur.close();
    for (const c of s.consoles) await c.arreter().catch(() => {});
    if (s.fournisseur) await s.fournisseur.fermer().catch(() => {});
    if (s.c) {
      if (process.env.NOORTRACE_GARDER_CAS === "1") {
        for (const svc of ["agent-demo", "exploitation-demo", "approbateur-demo", "enregistreur", "approbation", "horodatage"]) fs.writeFileSync(path.join(s.travail, `journal-${svc}.log`), s.c.journal(svc));
      } else s.c.demonter();
    }
    if (s.travail && process.env.NOORTRACE_GARDER_CAS !== "1") fs.rmSync(s.travail, { recursive: true, force: true });
  });

  function pret(ctx) {
    if (s.attente) {
      enAttente(ctx, s.attente);
      return false;
    }
    return true;
  }

  const personne = async (sujet, comptes) => {
    const p = await new Personne({ navigateur: s.navigateur, fournisseur: s.fournisseur, origine: s.origine, sujet, comptes }).ouvrir();
    s.personnes.push(p);
    return p;
  };
  const evenements = () => s.c.evenements(CONFIG);

  it(`${te}, préparation : la composition du cas tourne sur les images de la démonstration de référence (surcharge, aucune image reconstruite) ; service d'approbation réel sans réseau, serveur RFC 3161 interne sain, clé de l'enregistreur inscrite au registre pour le journal du cas par le seul détenteur des clés de chaîne, qui ne vote pas ; serveur de console réel relié à la prise du canal de la console du service, santé prête`, async function () {
    if (!pret(this)) return;
    const { c } = s;
    expect(s.preparation).to.include({ cas, journal_id: ENV.NOORTRACE_CAS_JOURNAL_ID, org_id: ENV.NOORTRACE_CAS_ORG_ID, console_origin: s.origine });
    expect(s.preparation.administrators).to.deep.equal([s.identite("admin-1")]);
    for (const svc of ["outils-demo", "modele-demo", "approbateur-demo", "registre-dev", "enregistreur", "approbation", "horodatage"]) {
      const i = c.inspecter(svc);
      expect(i.Config.Image, svc).to.match(/^noortrace\//);
      const env = i.Config.Env.join("\n").toLowerCase();
      for (const k of CLES_APPROBATEURS) expect(env.includes(k), `${svc} : clé d'approbateur dans l'environnement`).to.equal(false);
    }
    expect(c.inspecter("approbation").HostConfig.NetworkMode).to.equal("none");
    expect(c.inspecter("horodatage").HostConfig.NetworkMode).to.equal(`container:${c.inspecter("enregistreur").Id}`);
    const lignes = c.journal("approbateur-demo").split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
    const inscrite = lignes.find((l) => l.event === "cle_inscrite");
    expect(inscrite, c.journal("approbateur-demo")).to.include({ registre: "RecorderRegistry", journal_id: ENV.NOORTRACE_CAS_JOURNAL_ID });
    expect(lignes.find((l) => l.event === "pret").role).to.include("aucun vote");
    expect(lignes.filter((l) => ["vote_inscrit", "approbateur_inscrit"].includes(l.event))).to.deep.equal([]);
    const demarrage = c.journalExploitation().find((l) => l.event === "startup");
    expect(demarrage.data).to.include({ class: "D", backend: "file", recorder_key_id: "rec-test-01", model_mode: "passerelle", epoch: 1 });
    expect(s.console.config.service).to.include({ url: null, socket: s.prise });
    expect(s.console.pret).to.include({ pret: true });
  });

  it(`${te}, pas 2 (inscription depuis la console) : dans Chromium, les deux approbateurs (identités OIDC simulées) inscrivent chacun l'adresse de leur compte de test par preuve de possession avec le portefeuille EIP-1193 simulé, et l'administrateur les valide depuis l'écran Annuaire ; l'annuaire du service d'approbation (lu par sa prise) porte les deux adresses actives ; aucune erreur de script, aucune autre origine jointe`, async function () {
    if (!pret(this)) return;
    s.ap1 = await personne("approbateur-1", [1]);
    s.ap2 = await personne("approbateur-2", [2]);
    s.admin = await personne("admin-1", []);
    const t1 = await inscrireAdresse(s.ap1, ADRESSES[0]);
    const t2 = await inscrireAdresse(s.ap2, ADRESSES[1]);
    for (const t of [t1, t2]) expect(t).to.contain(s.origine);
    await validerAdresse(s.admin, ADRESSES[0]);
    await validerAdresse(s.admin, ADRESSES[1]);
    const vue = await appelCanalConsole(s.prise, "demo-jeton-console-approbateur-demo", "annuaire", { session_identity: s.identite("admin-1") });
    expect(vue.statut, JSON.stringify(vue.corps)).to.equal(200);
    const actives = Object.fromEntries(vue.corps.entries.map((e) => [e.session_identity, e.addresses.filter((a) => a.state === "active").map((a) => a.address)]));
    expect(actives).to.deep.equal({ [s.identite("approbateur-1")]: [ADRESSES[0]], [s.identite("approbateur-2")]: [ADRESSES[1]] });
    for (const p of [s.ap1, s.ap2, s.admin]) {
      expect(p.erreurs, p.sujet).to.deep.equal([]);
      expect(p.autresOrigines, p.sujet).to.deep.equal([]);
    }
  });

  it(`${te}, pas 1 : l'agent scénarisé du cas (image agent-demo, programme du cas) joue le tour par l'enregistreur seul : échanges de modèle, ${spec.outilsLecture.length} lectures autorisées, puis l'écriture ${spec.outilRevue} soumise à approbation : signal en_attente, événement retenue sous la règle « ${spec.regleRevue} », ticket ouvert au service (consulté par la prise du canal de la console avec la session d'un approbateur)`, async function () {
    if (!pret(this)) return;
    const { c } = s;
    c.lancer(["agent-demo"]);
    s.retenue = await attendre(() => evenements().find((e) => e.execution?.status === "retenue"), 120000, "événement retenue", 2000);
    expect(s.retenue.execution.tool).to.equal(spec.outilRevue);
    expect(s.retenue.policy).to.include({ decision: "a_approuver", rule: spec.regleRevue });
    s.ticket = s.retenue.policy.ticket;
    expect(s.ticket).to.match(/^apr-/);
    const avant = evenements();
    const lectures = avant.filter((e) => spec.outilsLecture.includes(e.execution?.tool));
    expect(lectures.map((e) => [e.execution.tool, e.execution.status, e.policy.decision])).to.deep.equal(spec.outilsLecture.map((t) => [t, "executee", "autorise"]));
    expect(avant.filter((e) => e.execution?.tool === "noortrace.modele.echange").length).to.be.at.least(2);
    expect(c.journal("agent-demo")).to.include(`${spec.outilRevue} : en attente d'approbation (ticket ${s.ticket})`);
    const vue = await appelCanalConsole(s.prise, "demo-jeton-console-approbateur-demo", "consulter", { ticket: s.ticket, session_identity: s.identite("approbateur-1") });
    expect(vue.statut, JSON.stringify(vue.corps)).to.equal(200);
    expect(vue.corps.retained_event.hash).to.equal(s.retenue.hash);
    expect(vue.corps.eligible).to.include.members(ADRESSES);
    expect(vue.corps.request.tool_announced).to.equal(spec.outilRevue);
  });

  it(`${te}, pas 2 (décision depuis la console avec deux comptes de test) : chacun des deux approbateurs ouvre /tickets/<id> dans Chromium et signe « ${spec.decision} » (un seul personal_sign [D_A, adresse] chacun) ; le serveur de console relaie deux voter au service (200) ; décision au seuil scellée par le démon (${spec.decision}, deux signatures recouvrées aux deux adresses inscrites) ; ${spec.decision === "approuve" ? "la ré-émission de l'agent est relayée : executee qui porte l'approbation" : "l'appel n'est pas relayé : aucun événement executee pour le ticket, l'agent en informe le modèle et poursuit"} ; l'agent termine avec le code 0 sans avoir joint ni le serveur d'outils ni le simulateur directement`, async function () {
    if (!pret(this)) return;
    const { c } = s;
    for (const [p, i] of [[s.ap1, 1], [s.ap2, 2]]) {
      const v = await voter(p, s.ticket, { decision: spec.decision, motif: spec.motif });
      expect(v, p.sujet).to.include({ resultat: "vote_inscrit", code: null });
      const A = { decision: spec.decision, journal_id: CONFIG.recorder.journal_id, org_id: CONFIG.recorder.org_id, request_hash: s.retenue.hash, ticket: s.ticket };
      const da = N.octetsVersHex(N.condenseApprobation(A));
      expect(v.ecran).to.contain(da);
      expect(signaturesDeVote(p)).to.deep.equal([[da, compte(i).adresse]]);
    }
    expect(s.console.lignes().filter((l) => l.event === "relais" && l.data.methode === "voter").map((l) => l.data.statut)).to.deep.equal([200, 200]);
    s.decision = await attendre(() => evenements().find((e) => e.execution?.tool === "noortrace.approbation.decision" && e.policy?.ticket === s.ticket), 60000, "décision scellée", 2000);
    expect(s.decision.approval).to.include({ decision: spec.decision, ticket: s.ticket, request_hash: s.retenue.hash });
    expect([...s.decision.approval.approvers].sort()).to.deep.equal([...ADRESSES].sort());
    expect(s.decision.approval.at).to.equal(s.decision.ts);
    const A = { decision: spec.decision, journal_id: CONFIG.recorder.journal_id, org_id: CONFIG.recorder.org_id, request_hash: s.retenue.hash, ticket: s.ticket };
    const recouvrees = s.decision.approval.signatures.map((sig) => N.recouvrerAdresseEip191(N.condenseApprobation(A), N.hexVersOctets(sig, 65)).adresse);
    expect(recouvrees).to.deep.equal(s.decision.approval.approvers);
    s.codeAgent = c.attendre("agent-demo", 300000);
    expect(s.codeAgent, c.journal("agent-demo")).to.equal(0);
    const ev = evenements();
    s.evenements = ev;
    expect(ev.map((e) => [e.execution.tool, e.execution.status, e.policy.decision, e.approval?.decision ?? null])).to.deep.equal(spec.sequence);
    if (spec.decision === "approuve") {
      s.executee = ev.find((e) => e.execution.tool === spec.outilRevue && e.execution.status === "executee");
      expect(s.executee.approval.ticket).to.equal(s.ticket);
      expect(s.executee.approval.signatures).to.deep.equal(s.decision.approval.signatures);
      expect(c.journal("agent-demo")).to.include(`${spec.outilRevue} : exécuté après approbation`);
    } else {
      // Aucun événement `executee` de l'outil pour ce ticket (la décision scellée, elle, est un événement sur soi `executee`).
      expect(ev.filter((e) => e.execution.tool === spec.outilRevue && e.execution.status === "executee" && e.approval?.ticket === s.ticket)).to.deep.equal([]);
      const refusee = ev.find((e) => e.execution.status === "refusee");
      expect(refusee.approval).to.include({ decision: "refuse", ticket: s.ticket });
      expect(c.journal("agent-demo")).to.include(`ticket ${s.ticket} refuse : l'appel n'est pas répété, le modèle en est informé`);
    }
    for (const e of ev) expect(e.recorder_key_id).to.equal("rec-test-01");
    expect(ev[0].code.policy_version).to.equal(CONFIG.policy.version);
    expect(c.journal("agent-demo")).to.include("agent-demo : l'agent ne joint que l'enregistreur");
    const agent = c.inspecter("agent-demo");
    expect(Object.keys(agent.NetworkSettings.Networks)).to.deep.equal([c.ressource("hotes")]);
    expect(agent.Config.Image).to.equal("noortrace/agent-demo:0.1.0");
    expect(agent.State.ExitCode).to.equal(0);
    for (const p of [s.ap1, s.ap2, s.admin]) {
      expect(p.erreurs, p.sujet).to.deep.equal([]);
      expect(p.autresOrigines, p.sujet).to.deep.equal([]);
    }
  });

  it(`${te}, pas 2 et 3 (exploitation) : clôture de la période, demande de clôture signée au seuil par le détenteur des clés de chaîne et relayée au registre (period_submitted), jeton RFC 3161 de la période du serveur interne, export des dossiers ${spec.exports.join(" et ")} (CT-2 §15.7) ; fichier d'ancres du réviseur écrit avec l'AC du serveur interne et une CRL postérieure à la clôture`, async function () {
    if (!pret(this)) return;
    const { c } = s;
    // --no-deps : l'agent, terminé, ne doit pas être relancé par la dépendance service_completed_successfully.
    const up = c.dc(["up", "--detach", "--no-deps", "exploitation-demo"], { timeout: 120000 });
    expect(up.status, up.stderr).to.equal(0);
    const code = c.attendre("exploitation-demo", 300000);
    expect(code, c.journal("exploitation-demo")).to.equal(0);
    s.contexte = c.contexte();
    expect(s.contexte.closure.timestamped, JSON.stringify(s.contexte.closure)).to.equal(true);
    expect(s.contexte.closure.submitted_block).to.be.a("number");
    expect(s.contexte.exports.map((x) => x.nom)).to.deep.equal(spec.exports);
    const journal = c.journalExploitation();
    expect(journal.filter((l) => l.event === "period_closed_early")).to.have.lengthOf(1);
    expect(journal.filter((l) => l.event === "period_submitted")).to.have.lengthOf(1);
    expect(journal.find((l) => l.event === "period_timestamped" && l.data.request_id === `jeton_periode:${s.contexte.closure.period_hash}`).data).to.include({ provider: "tsa-interne" });
    s.ancres = preparer("ancres", { cas, travail: s.travail, projet: s.projet }).ancres;
    const a = JSON.parse(fs.readFileSync(s.ancres, "utf8"));
    expect(a.tsa_authorities).to.have.lengthOf(1);
    expect(a.revocation.crls).to.have.lengthOf(1);
    expect(a.recorders[0]).to.include({ journal_id: CONFIG.recorder.journal_id, org_id: CONFIG.recorder.org_id, key_id: "rec-test-01" });
    s.dossiers = {};
    for (const x of s.contexte.exports) s.dossiers[x.nom] = c.extraire("exports", x.destination, path.join(s.travail, "dossiers", x.nom));
  });

  it(`${te}, pas 3 (oracle) : chaque dossier exporté, vérifié hors ligne sur l'hôte dans un espace de noms réseau vide par le vérificateur JavaScript de référence et par le binaire Go : code 0, verdict valide, contrôles 1, 2, 3, 4, 6 et 8 réussis, 7 réussi quand l'événement porte une approbation, 5 non exécuté (preuve OpenTimestamps absente : aucun calendrier), aucune vérification en échec ; A-1 à A-4 réussies sur le dossier de la décision, A-4 non exécutée (piece_hors_dossier, CT-6 EX-5.18) sur celui de l'appel ; point couvrant ancré (K-1 réussie, entrée ancre_point_de_controle du registre) ; mêmes statuts et même énoncé entre les deux vérificateurs ; la décision, ses auteurs et son instant sont dans le journal (CT-1 §5)`, function () {
    if (!pret(this)) return;
    const bin = binaireGo();
    s.rapports = {};
    s.evenementsDossiers = {};
    for (const [nom, dossier] of Object.entries(s.dossiers)) {
      const evenement = JSON.parse(fs.readFileSync(path.join(dossier, "evenement.json"), "utf8"));
      s.evenementsDossiers[nom] = evenement;
      const r = verifierDeuxSansReseau(dossier, { ancres: s.ancres });
      const juger = (v, quoi) => {
        expect(v.lisible.code, `${quoi} ${nom} : ${v.lisible.stderr}\n${v.lisible.stdout}`).to.equal(0);
        expect(v.json.code, `${quoi} ${nom}`).to.equal(0);
        const rap = v.rapport;
        expect(rap.verdict, `${quoi} ${nom}`).to.equal("valide");
        expect(rap.failed_checks, `${quoi} ${nom}`).to.deep.equal([]);
        const ct = controles(rap);
        expect([ct[1], ct[2], ct[3], ct[4], ct[6], ct[8]], `${quoi} ${nom} : ${JSON.stringify(ct)}`).to.deep.equal(Array(6).fill("reussi"));
        expect(ct[5], `${quoi} ${nom}`).to.equal("non_execute");
        expect(raison(rap, 5)).to.equal("partie_absente");
        const k = verifications(rap);
        expect(rap.event.seq, `${quoi} ${nom}`).to.equal(evenement.seq);
        if (evenement.approval !== null) {
          expect(ct[7], `${quoi} ${nom}`).to.equal("reussi");
          expect(rap.facts.approval, `${quoi} ${nom}`).to.include({ decision: evenement.approval.decision, ticket: evenement.approval.ticket, required: 2, size: 3 });
          expect([k["A-1"], k["A-2"], k["A-3"]], `${quoi} ${nom}`).to.deep.equal(["reussi", "reussi", "reussi"]);
          if (nom.startsWith("decision")) expect(k["A-4"], `${quoi} ${nom}`).to.equal("reussi");
          else {
            expect(k["A-4"], `${quoi} ${nom}`).to.equal("non_execute");
            expect(raison(rap, "A-4")).to.equal("piece_hors_dossier");
          }
        }
        expect(k["K-1"], `${quoi} ${nom}`).to.equal("reussi");
        expect(k["R-10"], `${quoi} ${nom}`).to.equal("reussi");
        expect(rap.facts.registry.entries.map((e) => e.role)).to.include.members(["inscription", "cloture", "ancre", "ancre_point_de_controle"]);
        expect(rap.facts.recorder_keys.event_key_id).to.equal("rec-test-01");
        return rap;
      };
      const js = juger(r.js, "vérificateur JavaScript");
      expect(r.js.lisible.sans_reseau).to.equal(sansReseauDisponible());
      s.rapports[nom] = { js };
      if (r.go) {
        const go = juger(r.go, "binaire Go");
        expect(controles(go)).to.deep.equal(controles(js));
        expect(verifications(go)).to.deep.equal(verifications(js));
        expect(go.statement).to.deep.equal(js.statement);
        s.rapports[nom].go = go;
      }
    }
    // La décision, ses auteurs et son instant, dans le journal (CT-1 §5) : l'événement de décision du journal est celui des dossiers.
    const decision = s.evenements.find((e) => e.execution.tool === "noortrace.approbation.decision");
    expect(decision.approval.approvers).to.have.lengthOf(2);
    expect(decision.approval.at).to.equal(decision.ts);
    expect(decision.approval.decision).to.equal(spec.decision);
    const dossierDecision = Object.keys(s.dossiers).find((n) => n.startsWith("decision"));
    expect(s.rapports[dossierDecision].js.event.seq).to.equal(decision.seq);
    expect(s.rapports[dossierDecision].js.facts.approval).to.include({ decision: spec.decision, ticket: s.ticket });
    expect(s.rapports[dossierDecision].js.facts.approval.approvers).to.deep.equal(decision.approval.approvers);
    if (!sansReseauDisponible()) enAttente(this, "unshare -n indisponible : vérification faite sans espace de noms réseau vide");
    if (!bin) enAttente(this, "binaire du vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérificateur JavaScript jugé seul");
  });

  it(`${te}, pas 3 (paquet réviseur, CT-8 §13) : attestation de périmètre du cas signée par les deux comptes de test (AT-1 à AT-4 retenues avec le jeu) ; paquet construit avec les dossiers du cas, le fichier d'ancres, le manifeste d'instance du registre en pièce et le vérificateur joint ; vérifié en une commande sans réseau avec son empreinte et les ancres du réviseur : code 0, PR-1 à PR-12 réussies, chaque dossier valide avec l'énoncé de CT-6 ; même paquet reconstruit octet pour octet`, function () {
    if (!pret(this)) return;
    const jeu = { threshold: CONFIG.policy.approval.rules.approver_set.threshold, members: CONFIG.policy.approval.rules.approver_set.members, source: "jeu statique de la politique du cas : comptes Hardhat 1 à 3 (clés de test publiques)" };
    const att = signerAttestation({ attestation: path.join(CAS_DIR, cas, "attestation-perimetre-cas.json"), cles: [compte(1).cle, compte(2).cle], jeu, dir: path.join(s.travail, "attestation") });
    const va = verifierAttestation(att.signee, att.jeu);
    expect(va.code, va.stdout + va.stderr).to.equal(0);
    const dir = path.join(s.travail, "paquet");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const description = {
      version: 0,
      label: `Paquet réviseur du cas de démonstration « ${cas} » (CT-9 ${te}) : journal ${ENV.NOORTRACE_CAS_JOURNAL} de ${ENV.NOORTRACE_CAS_ORG}, période close ${new Date(s.contexte.closure.period_start * 1000).toISOString()}`,
      created_at: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
      prepared_by: `exploitant du cas de démonstration « ${cas} »`,
      dossiers: Object.values(s.dossiers).map((d) => ({ source: d, anchors: s.ancres, bitcoin_headers: null })),
      attestation: { signed: att.signee, approver_set: att.jeu },
      pieces: [path.join(DEMO, "instance-registre.json")],
      include_verifier: true,
    };
    const p1 = construirePaquet({ dir, description, nom: "paquet.tar" });
    expect(p1.code, p1.stderr + p1.stdout).to.equal(0);
    const p2 = construirePaquet({ dir, description, nom: "paquet-bis.tar" });
    expect(p2.code, p2.stderr).to.equal(0);
    expect(p2.sha256).to.equal(p1.sha256);
    const v = verifierPaquetSansReseau(p1.paquet, { ancres: s.ancres, empreinte: p1.sha256, conserver: path.join(dir, "extrait") });
    expect(v.lisible.code, v.lisible.stdout + v.lisible.stderr).to.equal(0);
    expect(v.json.code, v.json.stdout + v.json.stderr).to.equal(0);
    const rap = v.rapport;
    expect(rap.checks.map((c) => [c.id, c.status])).to.deep.equal(Array.from({ length: 12 }, (_, i) => [`PR-${i + 1}`, "reussi"]));
    expect(rap.dossiers.map((d) => [d.verdict, d.exit_code, d.anchors?.source, d.observation_mode])).to.deep.equal(Object.keys(s.dossiers).map(() => ["valide", 0, "ligne_de_commande", false]));
    expect(rap.package_status).to.equal("intact");
    expect(v.lisible.stdout).to.include("[VALIDE]");
    expect(fs.existsSync(path.join(dir, "extrait", "paquet-reviseur", "MANIFESTE.json"))).to.equal(true);
    s.paquet = { sha256: p1.sha256, rapport: rap };
    if (!sansReseauDisponible()) enAttente(this, "unshare -n indisponible : vérification du paquet faite sans espace de noms réseau vide");
  });

  if (spec.apres) spec.apres(s, () => pret);
}

/** Les événements sur soi (échange de modèle, politique, décision) portent policy.decision « sans_objet » (CT-1 §5). */
const ECHANGE = ["noortrace.modele.echange", "executee", "sans_objet", null];
const POLITIQUE = ["noortrace.journal.politique", "executee", "sans_objet", null];

describe("CT-9 TE-1 : cas de démonstration « assurance » (annexe III, point 5 c) : agent de souscription en assurance de personnes, de la capture au dossier vérifié, approbation depuis la console réelle avec deux comptes de test", function () {
  this.timeout(1800000);
  parcours({
    cas: "assurance", te: "TE-1", decision: "approuve", motif: "Classe C de la grille et majoration conformes au questionnaire : acceptation",
    outilRevue: "souscription__souscription.decider", regleRevue: "decision defavorable : revue",
    outilsLecture: ["souscription__propositions.search", "souscription__propositions.get", "souscription__risque.classer"],
    sequence: [
      POLITIQUE, ECHANGE, ["souscription__propositions.search", "executee", "autorise", null], ECHANGE, ["souscription__propositions.get", "executee", "autorise", null], ECHANGE,
      ["souscription__risque.classer", "executee", "autorise", null], ECHANGE, ["souscription__souscription.decider", "retenue", "a_approuver", null], ["noortrace.approbation.decision", "executee", "sans_objet", "approuve"],
      ["souscription__souscription.decider", "executee", "a_approuver", "approuve"], ECHANGE,
    ],
    exports: ["appel-approuve", "decision-approuvee"],
    apres: (s, pret) => {
      it("TE-1 : l'écriture approuvée porte une classe de risque et une majoration en pour cent, rien qui se paie ni devise (règles de contenu des cas) ; ses effets déclarés n'ont ni amount ni currency", function () {
        if (!pret()(this)) return;
        const ev = s.executee;
        expect(ev.effects).to.deep.equal([{ system: "souscription", action: "ecriture", object: "PRP-2026-00431", amount: null, currency: null }]);
        expect(JSON.stringify(ev)).to.not.match(/\b(CHF|EUR|USD)\b/);
      });
    },
  });
});

describe("CT-9 TE-2 : cas de démonstration « administration » (annexe III, point 5 a) : agent qui instruit des demandes de prestations publiques, refus signé depuis la console réelle avec deux comptes de test, dossier du refus et dossier d'un appel autorisé", function () {
  this.timeout(1800000);
  parcours({
    cas: "administration", te: "TE-2", decision: "refuse", motif: "Une pièce manquante n'établit pas l'inéligibilité : demander la pièce, ne pas notifier de refus",
    outilRevue: "prestations__decision.notify", regleRevue: "decision sur le droit : revue",
    outilsLecture: ["prestations__demandes.search", "prestations__demandes.get", "prestations__pieces.verifier"],
    sequence: [
      POLITIQUE, ECHANGE, ["prestations__demandes.search", "executee", "autorise", null], ECHANGE, ["prestations__demandes.get", "executee", "autorise", null], ECHANGE,
      ["prestations__pieces.verifier", "executee", "autorise", null], ECHANGE, ["prestations__decision.notify", "retenue", "a_approuver", null], ["noortrace.approbation.decision", "executee", "sans_objet", "refuse"],
      // La ré-émission de l'agent après le refus est scellée comme un événement `refusee` (CT-1 §5), jamais relayée.
      ["prestations__decision.notify", "refusee", "a_approuver", "refuse"], ECHANGE, ["prestations__decision.notify", "executee", "autorise", null], ECHANGE,
    ],
    exports: ["decision-refusee", "appel-autorise"],
    apres: (s, pret) => {
      it("TE-2 : le dossier du refus porte approval.decision = refuse, signé par les deux adresses ; l'appel refusé n'a aucun événement executee ; le dossier de l'appel autorisé (notification de pièces à compléter, règle « demande de pieces ») est un executee sans approbation, contrôle 7 non exécuté pour sa raison", function () {
        if (!pret()(this)) return;
        const refus = s.evenementsDossiers["decision-refusee"];
        expect(refus.approval).to.include({ decision: "refuse", ticket: s.ticket });
        expect(refus.approval.approvers).to.have.lengthOf(2);
        expect(s.rapports["decision-refusee"].js.facts.approval).to.include({ decision: "refuse", ticket: s.ticket });
        expect(s.evenements.filter((e) => e.execution.tool === "prestations__decision.notify" && e.execution.status === "executee" && e.approval !== null)).to.deep.equal([]);
        const autorise = s.evenementsDossiers["appel-autorise"];
        expect(autorise.execution).to.include({ tool: "prestations__decision.notify", status: "executee" });
        expect(autorise.policy).to.include({ decision: "autorise", rule: "demande de pieces", ticket: null });
        expect(autorise.approval).to.equal(null);
        expect(controles(s.rapports["appel-autorise"].js)[7]).to.equal("non_execute");
        expect(autorise.effects).to.deep.equal([{ system: "prestations", action: "ecriture", object: "DEM-2026-01877", amount: null, currency: null }]);
      });
    },
  });
});
