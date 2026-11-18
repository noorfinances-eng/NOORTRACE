# Changelog

All notable changes to noortrace are recorded here. The format follows
Keep a Changelog; versions follow semantic versioning once the first release
is tagged.

## Unreleased

- Build step 8, supplements of 2026-11-18: wording of the screens (étape 8,
  compléments du 2026-11-18 : langage des écrans). After the owner's
  decision of 2026-11-18, every text of the three tools that people look at,
  the approval console, the verification page and the client onboarding
  tool, is rewritten for a reader who has not read the specifications:
  each screen says what it is for and what to do next, each failure says
  what happened, whether anything was sent, and what to do, and its code
  comes last, in small type. A sentence that a specification fixes word for
  word is kept as it is and shown under a plain sentence that says the same
  thing and no more. One word has one meaning across the three tools
  (fingerprint, evidence dossier, recorded action, log, recorder, proof of
  date, public registry, signing address, number of approvals required);
  "demande" is what an approver decides in the console, so the onboarding
  tool now says "document à faire signer par le client" for what the client
  signs. Two rules are lifted by the owner, each written in a dated
  supplement with its safeguards. Approval console (CT-3 EX-9.4): a value of
  the request that the console cannot verify is now shown in the summary
  card, with its value and its mark, in a separate group headed "À contrôler
  par vous-même", and nowhere else; the opening sentence is still made only
  of verified values, and the display model and the computation of the marks
  do not change. A fixed table gives a plain label to the last segment of
  some argument paths (twenty segments, twelve labels); the exact path stays
  displayed beside it and the label enters no check. Also in the console: a
  ticket still open on which the signed-in person has already voted says so
  at the top ("Vous avez approuvé cette demande le … Elle attend encore
  1 approbation.") and keeps both decisions on offer, of equal weight, under
  "Changer ma décision", since a new vote replaces the former one (EX-7.26);
  the list says in words whether and until when a request can still be
  contested, and says nothing for a rule without a contest window
  (EX-12.21); the bar names the signed-in person and the identity service,
  both readable without opening anything, the canonical session identity
  staying whole in a folded block (EX-13.7); after a decision is confirmed
  the page brings the wallet choice into view and selects no wallet; a
  decided ticket says what was decided and what follows, without claiming
  that the action was carried out. Nothing that EX-9.4 requires before a
  signature is folded; "Approuver" and "Refuser" keep the same weight.
  After a second cold reading of the console: four plain instructions are
  displayed, word for word, on the signing screen before the signature
  button (compare the beginning and the end of the code shown by the
  wallet, validate if it is the same, refuse in the wallet otherwise), and
  the seven original instructions stay whole, unchanged, in a reference
  block opened on demand, with the grouped form of the code and the second
  code (EX-9.20, EX-9.18); the fingerprint of the digest and the whole
  digest stay displayed before the button. In the list, a request that
  awaits a decision shows its amount when the console could verify it,
  composed by the same function as on the request screen (read-only views
  of at most ten open requests, EX-13.3), and each instant says what it is;
  a request on which the signed-in person has already decided leaves "À
  décider", is no longer counted there, and is ranged with the other
  requests in progress under "Vous avez déjà approuvé cette demande." (or
  "refusé"), where it can still be opened and the decision changed. The
  code of a state that is not a failure (no decision chosen yet, no wallet
  chosen yet, request closed to votes) moves to the technical detail block,
  and the code of a failure stays at the end of its sentence (EX-13.29); an
  approved request says "La console ne sait pas si l'agent logiciel l'a déjà
  exécutée" and where to find out.
  Verification page (CT-6 EX-18.9): under the verdict word, a plain sentence
  fixed per exit code, above the exact wording of the verifier, which is
  neither changed nor shortened; a plain sentence fixed per warning above
  its exact text, and none for a warning outside the table; the verdict
  still comes from the exit code alone and the page computes no status;
  "valid" is not turned into "authentic". The statement is shown whole, one
  block per clause, the copied text being the statement character for
  character; two new headings, "Ce que ce résultat ne dit pas" (lines taken
  from CT-6 §7.2 and §7.4) and "Et maintenant ?"; after a report the steps
  shrink to one line and the notice of EX-18.2, still displayed word for
  word and never folded, moves below the result (risk written in the text);
  the two optional files are named in plain words and the page says what
  their absence prevents. After a second cold reading of the page (EX-18.9,
  points 14 to 19): what the page adds can only restrict what the exit code
  says, never extend it, and is taken from the JSON report alone. Under exit
  code 0 the full presentation is kept only for eight passed controls
  without warning; otherwise the result is tinted amber and a fixed mention
  follows the verdict word in the title (", mais tout n'est pas prouvé",
  ", avec des réserves", or both), with a sentence that names what the
  dossier does not prove; a passed control that a warning concerns reads
  "Réussi, avec réserve"; two warnings with the same identifier are said
  once, all their exact texts staying displayed; a block "En résumé" copies
  a few fields of the report into fixed templates (sequence number of the
  action, name of the tool called, copied as it is, untranslated, in
  fixed-width type, declared period, signatures of the approval, "no later
  than" instant of the time-stamping authority), each line only when its
  field reads and its control passed, and says that only the exact text
  below is authoritative; the detail of a failed check is said on the line
  of its control; under exit code 2 the page says which piece is at fault;
  the line above a report reads "Dossier examiné", and a refusal is titled
  after what was chosen ("Fichier refusé", "Dossier de fichiers refusé").
  Onboarding tool (CT-4 EX-7.25, EX-7.26): steps
  named by plain verbs, an instruction for the next action (what, why, what
  to have at hand, what happens after the click), sixty-nine refusals
  explained, the client record shortened; no account is preselected to send
  a signed document, and what the route receives is unchanged; while a step
  sent by the tool itself awaits its answer the only instruction is to
  resume that send, and a step done on the client's side gets a neutral
  instruction; three input helpers fill a field without sending anything
  (the file of the supporting document is hashed in the browser and never
  leaves it; local date and time are converted to UTC and the converted
  value is shown; a random short name); the mention "confirmation hors bande
  absente" stays word for word under its plain sentence. After a second cold
  reading of the tool: a confirmation is recorded in two clicks, "Relire
  avant de noter" checking the input and showing what will be recorded, and
  only "C'est exact, noter la confirmation" sending it, the body sent being
  unchanged; one label has one meaning ("Réponse à aller chercher" when a
  send started from the tool waits to be resumed, "En attente du registre"
  and "En attente chez le client" when the person has nothing to do); the
  two steps that the client carries out read "À faire par le client"; the
  package screen says in four lines what the package contains, what it does
  not contain, to whom it is handed and what the client checks; no duration
  is promised for an answer of the public registry ("quelques minutes
  d'ordinaire").
  After a third cold reading of the three tools: in the console, the signing
  screen shows the two codes in large type, side by side, headings and codes
  aligned whatever the font, under plain headings ("Code de contrôle de
  votre décision"; "Autre forme de ce code", with "Certaines applications
  l'affichent en plus du long code."); the four plain instructions compare
  each line shown by the wallet with one code only, never with either of the
  two (EX-9.20, point 3), and keep no acronym, English word or technical
  bracket; withdrawing from or recusing on a request sits with the rest of
  the request, never between the wallet choice and the signature; a legend
  says that "vérifié" means the value is the one the software agent sent,
  unchanged since, not that it is right, and asks the approver to compare
  the amount, the account and the payee with the supporting documents;
  "contester" is explained once per screen; a request that has gathered its
  approvals says what can still happen to it instead of "expires if not
  approved"; after the person's own vote, both decisions sit in a block
  folded by default; the directory marks each action that cannot be undone
  "définitif" beside its button and again in its confirmation; the requester
  line says that the console cannot check who launched the agent. On the
  verification page, the verdict word and its mention read as one title, at
  the same size, the sentence of what is not proven right below, in bold;
  the exit code and its meaning head the "Pour les spécialistes" section;
  the sentence of a control not done says what to ask for and from whom,
  from the reason in the report and the files added at step 2, the exact
  reason following in brackets; each reservation states its consequence;
  after a refusal "Vérifier" is inactive and the refusal is said where the
  refused file was chosen; the safety instruction of step 2 is at body size.
  In the onboarding tool, a signed document is sent by a button that names
  the sender ("Envoyer par notre compte d'envoi"), with no choice to make,
  sending by a test reference being a separate, tucked-away action; each
  recorder record is pasted as it is into its own box and the page builds
  the list, an empty first box being refused with the reason (the tool
  registers only the recorders of the dossier, which is prepared once);
  resuming a send is called "Aller chercher la réponse du registre public"
  everywhere, since it only reads the registry; each step of the
  confirmation form has its own sentence, and the form is folded when no
  confirmation is expected; "Copier" buttons sit beside the address of the
  technical account and each fingerprint to compare or pass on. The bodies
  sent to the routes are byte-identical to those of the former screens. The
  continuous integration of the previous commit failed on two console tests
  (decision buttons outside the first screen, signing screen brought under
  the top bar), and two onboarding tests failed the same way: the runner has
  no Inter font and renders with a wider fallback (DejaVu Sans), as most
  users would. The pages are fixed, not the tests: the console bar stays on
  one line at 1280 pixels, the page reads the real height of the bar instead
  of a constant before bringing a block under it, and the decision and
  signature buttons stay in the first screen at 1280 × 800 with the fallback
  font, at 760 pixels at most; the onboarding client record takes the screen
  width and puts the button of an instruction without a field beside its
  sentences. Every browser test of the three tools is run with the fonts of
  the machine and with a simulation of the runner's fonts; no threshold is
  relaxed, and no test depends on the font.
  No dependency,
  font, image or external resource is added; no content security policy,
  header or subresource-integrity rule is loosened; the console and the
  verification page still store nothing; the common theme block is
  unchanged, byte for byte; the published digests of the console pages are
  recomputed by the package's build script. Specifications: dated
  supplements in CT-3 (EX-9.4, EX-9.18, EX-9.20, EX-12.21, EX-13.3,
  EX-13.7, EX-13.29, 13.1), CT-6 (EX-18.2, EX-18.5, EX-18.7, EX-18.9) and
  CT-4 (EX-7.25, EX-7.26), those of CT-3 and CT-6 rewritten in place after
  the third reading; no control rule,
  schema, report, exit code or vector changes; the line citations of CT-7,
  CT-8 and CT-9 follow the moved texts. Tests:
  `test/exploitation-console-langage-chromium.test.js` (new), and new cases
  in `test/exploitation-console-presentation-chromium.test.js`,
  `test/verification-page-presentation.test.js`,
  `test/inscription-presentation.test.js` and
  `test/inscription-presentation-chromium.test.js`: the tables of the pages
  are, word for word, those of the specifications (labels of CT-3 EX-9.4;
  sentences per exit code and per warning of CT-6 EX-18.9, in both
  languages); no technician's word is read at the first level of any screen,
  against a published list per tool; each new test is red on the former
  screens and green on the new ones, with mutants killed (an unverifiable
  value among the verified ones, the sentence of another exit code under
  "Valide", an invented sentence for an unknown warning, a preselected
  sender, a file hashed with another algorithm, an already decided request
  left under "À décider", a tool name shown when control 1 did not pass).
  Label oracles are replaced
  by the new exact text; the behaviour oracles that change do so with the
  supplement beside them. CI: the new console file joins the Chromium step
  of the console through its file pattern; the new cases of the
  verification page run in the three engines in the presentation step, with
  no pending test. Test plan (CT-9): the new tests are attached to TE-13,
  TE-22 and TE-23; catalogue regenerated twice, byte-identical. After the
  third reading, new cases in the same files (codes aligned, recusing never
  between wallet and signature, legend of "vérifié", "définitif", reason of
  a control not done per added file, consequence of each reservation,
  inactive button after a refusal, sender named by the button, one box per
  recorder record, copy buttons), each red on the former screens and green
  on the new ones, with mutants killed; the whole set is green with both
  fonts.
- Build step 8, supplements of 2026-11-17: presentation of the screens
  (étape 8, compléments du 2026-11-17 : présentation des écrans). The three
  tools that people look at, the approval console, the verification page and
  the client onboarding tool, are redrawn at once after the owner's decision
  of 2026-11-17: each screen now opens with the essential in one plain
  sentence and the action to take, then what is needed to decide, and keeps
  identifiers, digests and raw codes in a folded technical block. Codes are
  said in everyday French, with the code still readable; every state is a
  word and an icon, never a colour alone. A common theme, one block of
  tokens and components that is byte-identical in the three style sheets,
  gives two states, dark and light: the page opens in the one the system
  asks for and a button switches it; the console and the verification page
  store nothing, the onboarding tool remembers the choice (`noor.theme`,
  its only use of browser storage); printing is always light. No font file,
  no image, no external resource and no dependency is added, and no content
  security policy, header or subresource-integrity rule is loosened; the
  published digests of the pages are recomputed by the packages' build scripts.
  Approval console (CT-3 EX-9.4, 13.1): a ticket opens with a summary made
  only of values that the display model has verified (tool, requester,
  rule, and an amount when both of its leaves are verified), shows beside
  it the values exactly as signed, and names every leaf it leaves out with
  its mark; nothing that EX-9.4 requires before a signature is folded;
  "Approuver" and "Refuser" are two buttons of equal weight, side by side,
  visible without scrolling in a 1280 × 800 window when no warning lengthens
  the card; the reason is typed at the confirmation of the decision, under
  its warning, and stays displayed until the signature; the instructions of
  EX-9.20 may be folded before the choice and are shown in full on the
  signing screen; a decided ticket no longer offers recusal or withdrawal,
  and the result of a withdrawal stays on screen; the light state is set
  before the first paint. Verification page (CT-6 §18): a verdict word drawn
  from the exit code alone, then the eight controls read from the JSON
  report, never shown as passed unless the report says so, and the warnings;
  the readable report, the JSON report and the equivalent command line are
  offered in folded blocks, opened for printing; the page computes no status
  and shows no list when it cannot read the report exactly; the list of
  published files does not change. Onboarding tool: steps, states and
  errors in words, the next action stated, exact values kept in the folded
  detail, and what commits the operator (document digest, manifest digest,
  out-of-band confirmation) never folded. Specifications: dated supplements
  in CT-3 (EX-9.4, 13.1) and CT-6 (18.3, EX-18.5, EX-18.6, EX-18.7, EX-18.9,
  EX-18.11); no control rule, schema, report, exit code or vector changes;
  the line citations of CT-7, CT-8 and CT-9 follow the moved texts. Tests:
  `test/theme-commun.test.js` (identity of the common block),
  `test/exploitation-console-presentation-chromium.test.js`,
  `test/verification-page-presentation.test.js`,
  `test/inscription-presentation.test.js` and
  `test/inscription-presentation-chromium.test.js`, each red on the former
  screens and green on the new ones, with mutants killed (an unverified
  amount entering the summary, a control not run shown as passed, a folded
  commitment); the existing screen tests keep their content oracles. CI: the
  onboarding screens and the presentation of the verification page run in
  the browser job, with no pending test. Test plan (CT-9): the new tests are
  attached to TE-13, TE-22 and TE-23; catalogue regenerated twice,
  byte-identical. Tests of the verification page, two weaknesses of the
  tests seen in Firefox and WebKit, the page not being at fault: the colour
  scheme preference is set on the page itself before navigation, not only on
  the browser context; a directory is chosen through one shared helper that
  sets its own listener for the `input` event before the call, because the
  browser driver sends the choice before it sets its own listener and then
  waits for an event that may already have fired. When the helper has seen
  the event, the test goes on and says so on the error output; when it has
  not, the test fails with what it observed. No retry, no oracle changed.
  Theme test of the verification page: under Firefox the browser driver
  drops the emulated colour scheme when a document served under
  `Cross-Origin-Opener-Policy: same-origin` is reloaded, so the reloaded page
  saw, and rightly followed, the engine's own preference. The test now reads
  what the engine announces to the page; when it differs from the emulated
  preference it says so on the error output, sets the preference again and
  requires the page to follow it. In every engine the state required after
  the reload is the system's, opposite to the choice made before; the reload
  is tested in both directions (light chosen under a dark system, dark
  chosen under a light one), `window.name` is checked empty with the
  storages, and the choice is checked to hold once the system changes have
  reached the page. A page that would remember the choice is caught with
  and without the loss.

- Build step 8, supplements of 2026-11-17 (étape 8, compléments du
  2026-11-17). Registry (CT-4, EX-8.14): a sender never signs below the
  nonce that follows its last send whose inclusion is recorded, so a send
  made one block after an inclusion, while the nodes are a block apart, no
  longer reuses a consumed nonce; the nonce read from the RPC points is
  cross-checked on two points by the reference tool and the onboarding agent,
  as the anchoring component already did; the onboarding agent computes the
  `CREATE` address of the set on the nonce it signs. Cross-references: every
  `l. N` citation of one specification by another (tables of CT-7, CT-8 and
  CT-9, and citations outside the tables) is checked against its anchor by
  the cross-reference tools and by `test/renvois-lignes.test.js`. Tests: the
  TA-106 scenario waits for a stored checkpoint before the hard stop; the
  measurement-harness test states that it needs a directory on a real disk
  and always removes its directory; the front-end review tests wait for the
  relayed call, the refusal line and the relayed notification instead of a
  fixed 50 ms delay. CI: the anchoring job installs promtool
  3.5.0 from the official archive, so the alerting-rule test of the period
  anchor runs there; the storage rows of the fault matrix (TE-16) that need
  root run under sudo in the superuser job. Test plan (CT-9) regenerated twice,
  byte-identical, and replayed by its clean-room Go verifier with no
  discrepancy.

- Build step 8, supplements of 2026-11-16 (étape 8, compléments du
  2026-11-16). The owner's decisions of 2026-11-16 are applied and the
  passages that the review left open are written into the specifications,
  each in a dated supplement of the current revision (no revision number
  changes). Recorder (CT-2): stronger masking of card numbers, e-mail
  addresses and telephone numbers (shorter candidates, 10.3.4 to 10.3.6),
  example addresses moved under `ch.example`; mirror mode secured (loopback by
  default, client certificate or closed list of sources, mandatory in
  production, socket mode 0600 or 0660 with peer proof); resumption into a
  new journal (`noortrace-ctl journal successeur`, link recorded in the
  registry and the operations log); Unix socket paths bounded to 103 bytes
  and strict command lines for every delivered program; requests outside the
  routes in `icap` and `miroir` modes declared, never blocked. Approvals
  (CT-3): never-validated directory entries expire
  (`registration_entry_ttl_ms`, internal `expirer` operation); a presented
  challenge is withdrawn; replay of an exported directory with undecodable
  instants; the vector index names every case of twenty directories, and the
  form of its lines is fixed. Registry (CT-4): admission guard due before
  production; a chain key serves a single organisation, checked by the
  reference tool, the onboarding agent and the anchoring relay, with retries
  on rate-limited reads. Anchoring (CT-5): the reference and the anchoring
  component now agree on every published trace and on a seeded randomised
  confrontation in sixteen modes (restart order, chain-key lock per journal,
  OP-9 check for period anchors, classification of registry refusals, period
  anchor after its points, retained key, point anchors in retry); qualified
  status restored by `noortrace-ctl ancrage retablir-qualification`;
  sixty-two scheduler traces, twenty-five with queues, and a new
  `configuration/` family of twenty-five cases. Verifier (CT-6): the F3
  statement names the request (`request_hash`) and the ticket. Security
  (CT-7): ten
  accepted risks of version 0 named outside the threat model (RA-87 to
  RA-96, section 3.5.1). Deployment (CT-8): the "attached copy" path of the
  reviewer package is withdrawn; the production Compose file passes
  `--image-attendue` and mounts the expected image; the backup archive is
  written as a stream. Test plan (CT-9): eleven entries without a
  closing formula settled (TA-41, TM-30 and TM-44 executable, TA-88 and TM-32
  with a reasoned formula), seven new entries (341), 2,494 identifiers
  covered; cross-reference line numbers of the CT-7 and CT-8 tables
  recalculated. Vectors of CT-1 to CT-8 regenerated twice, byte-identical,
  and replayed by the clean-room Go verifiers of CT-1 to CT-4, CT-7 and CT-8
  and by the CT-5 consistency verifier, with no discrepancy.

- Build step 8, internal security review and its corrections. Every component
  was reviewed by internal reviewers working blind (310 findings, consolidated
  into owner decisions and correction batches). Approval bypass fixed: the
  approval protocol is revised (owner's decision 1, option a, with its
  addendum): each `evaluer` response carries nine members, among them
  `policy_version`, `policy_sha256` and `approval_sha256` computed by the
  service, and the core refuses a decision taken under a policy other than the
  one it holds, relaying nothing until the `charger` of the pinned version has
  succeeded (CT-2 EX-7.15). Corrections across the core library, recorder,
  approval service, console, onboarding agent, anchoring component, registry
  tool, deployment files, observability rules (99 rules, the "first
  occurrence" form of CT-8 EX-10.6) and the verifier's Go binary, each with
  the test that reproduces it. Specification revisions: CT-1 0.6, CT-2 0.11,
  CT-3 0.8, CT-4 0.8, CT-5 0.10, CT-6 0.9, CT-7 0.5, CT-8 0.8, CT-9 0.10;
  recorded changes MC-60 onwards. All test vectors regenerated from the
  generators in dependency order (two generations byte-identical); the seven
  clean-room Go verifiers (CT-1 to CT-4, CT-7 to CT-9) and the CT-5 Go
  verifier replayed on them, all concordant once the CT-5 module was aligned
  with CT-5 0.10. Owner's decision 9 (option a): parts of the CT-5 Go module
  were found identical to the JavaScript reference (RFC 3161 request and
  response reading, scheduler registry), so it is no longer presented as
  independent; it is a vector-consistency verifier, no longer counted among
  the independent confrontations (CT-9 EX-13.2: seven modules; TA-66: six),
  its directory keeps the historical name `verificateur-independant/`, and
  its CI step is renamed without changing what it runs; third-party
  confrontations (OpenSSL, python-opentimestamps, opentelemetry-proto,
  transparency-dev/merkle)
  replayed, with the inputs OpenSSL refuses to decode named as tool limits.
  Adversarial tests of the review merged into `test/adversarial.test.js`
  (112 tests: delivered packages, demonstration, plan scenarios), the CT-9
  catalogue updated (288 executable entries), and a CI guard that fails on any
  pending test whose condition is not one of the named admitted ones. Still
  open, on the owner's decisions: decisions 2, 4, 5, 8, 14 and 29, the
  group of accepted risks and the question on CT-3 EX-13.13; their passages
  keep the published text. Docker-based campaigns (images rebuilt,
  demonstration, cases, integrations, failures) are not part of this entry.

- Build step 7, packages, observability and runbooks. Six container images
  `noortrace/*` (recorder, file-attribute companion, approval service,
  console, stdio bridge, verifier) are built from `conteneurs/`: no shell, no
  `/usr/bin/env`, Node.js 22.23.4 and only the programs each needs (`flock`,
  `chattr`, `lsattr`) on a minimal base pinned by digest, entry point the
  program itself; two builds without cache, from two copies of the sources,
  give the same digests (`scripts/deploiement/construire-images.mjs`).
  Nothing is published: no image, tag, release or package leaves the build
  machine. The recorder gains `noortrace-ctl sonde`, `etat` and
  `close-period --now` (which ends the journal, development only); its file
  lease no longer needs a shell; a chain key of class B or C is held by a key
  management service, and the emergency rotation of the chain key alone is
  relayed to the registry from threshold-signed requests. The approval
  service's socket directory shared by two accounts (`3770`) is accepted; the
  attribute companion fails loudly when it cannot read; `d_registre` is
  observed once per anchor. Reference observability
  (`deploiement/observabilite/`): 88 alerting rules with a firing and a
  silent case each, checked by promtool 3.5.0 in CI, a log extractor, a rule
  generator and a probe. Installation and operations tooling: host
  preparation for the reference system, systemd templates for the scheduled
  tasks, backup and restore with the deterministic archive and its minutes,
  operations-log archiving, runbook copies checked against CT-8. A release is
  prepared without publishing (`scripts/publication/`, `version.yml`): two
  reproducible builds of the verifier for amd64 and arm64, `SHA256SUMS`,
  release note and unsigned provenance; signing waits for a decision on the
  key. The full installation, steps IC-1 to IC-18 of CT-8, ran on a bench
  without public network access in 58 minutes, the first evidence folder
  accepted by both verifiers; the bench is not the reference system.
  The quick installation now obtains a real RFC 3161 closing token: by the
  owner's decision, its placeholder provider is replaced by the internal,
  non-qualified timestamping server of `paquets/ancrage`, accepted as the
  principal provider outside production only (production still refuses it,
  with its reason). A seventh image, `noortrace/tsa-interne`, runs it in the
  recorder's network namespace (`horodatage` service, initialised by the
  `horodatage-init` tool, no secret), and `configurer-rapide.mjs` copies its
  CA certificate into the anchoring document. The quick installation ran from
  step IR-1 to IR-8 with Docker and no public network: check 4 passed with
  the internal server's token in both verifiers, check 5 was not run (no
  OpenTimestamps proof without network).
  CT-2 0.10, CT-3 0.7, CT-5 0.9, CT-6 0.8, CT-8 0.7, CT-9 0.9; recorded
  changes MC-42 onwards. CI: actions pinned by commit, Node.js
  22.23.4, a promtool step and an `images` job (double build and image
  tests, no publication).
- npm advisories in the development dependencies. `mocha` moves to 12.0.3 and
  `@nomicfoundation/hardhat-toolbox-mocha-ethers` to 4.0.0, which brings
  `@nomicfoundation/hardhat-mocha` 4.0.1; `overrides` scoped to mocha pin
  `glob` 14.0.3 and `minimatch` 11.0.3, outside the ranges of
  GHSA-3g3m-2fjr-6pw4 and GHSA-g3hv-75wg-m249; two more overrides pin the
  transitive `brace-expansion` 5.0.12 and `@isaacs/nonrecursive-glob-match`
  1.0.3, so that no package added by this change was published less than two
  weeks before it. This clears the five mocha
  entries of `npm audit` (`serialize-javascript`, `diff`, `glob`, `minimatch`
  and `mocha` itself). Every development dependency is now pinned to an exact
  version; Hardhat stays at 3.20.0. The 13 remaining high-severity entries all
  come from one zod 3 advisory (GHSA-mrhx-c7xc-m3w5) that no Hardhat 3 release
  lets us fix yet; `SECURITY.md` records why it is kept and when to revisit
  it. The CI job `tests` now runs `npm audit --omit=dev --audit-level=low` and
  fails on any advisory that reaches a production dependency.
- Build step 6, the operating console and what surrounds it. `paquets/console`:
  the approval console of CT-3 §13, in three parts — a library run unchanged
  under Node and in the browser, shared with the approval service; a console
  server without framework (OIDC, local accounts outside production, sessions
  in memory, authenticated relay to the approval service, health and probe);
  static pages loaded with their integrity, where an approver enrols an address
  by proof of possession and signs a decision in their own wallet. The approval
  service (`paquets/approbation`) gains the console channel, the persisted
  approver directory, signed webhook notifications and its configuration
  document. Client onboarding (`paquets/inscription`): an operator web
  interface that holds no key and a separate agent that holds them, driving the
  CT-4 steps with the same outputs as the reference tool and producing the
  client package, which the client checks on receipt. The recorder exports an
  evidence folder on request (`noortrace-ctl dossier exporter`), atomically,
  into a dedicated exports directory. The verification page
  (`paquets/verification-web`) runs the Go verifier compiled to WebAssembly in
  a browser worker and shows the same report as the binary, byte for byte.
  The step's criterion is demonstrated end to end (CT-9 TE-13): an approver
  signs a decision from the console, and the exported folder passes both
  verifiers with `--exiger 7`, timestamp and registry controls included. A CI
  job runs the console, the page in Chromium, Firefox and WebKit, and the
  criterion without the development network. Specification revisions CT-2 0.9,
  CT-3 0.6, CT-4 0.7, CT-6 0.7, CT-8 0.5 and CT-9 0.8, recorded as MC-27 to
  MC-39 in the design-freeze register.
- Build step 3, the development registry. `npm run e2e:registre`
  (`scripts/e2e/parcours-registre.mjs`) replays the CT-4 §7 walkthrough on the
  local noorcore network for a fictitious client: onboarding, key
  registration, root anchoring, period closure, capture of blocks, receipts,
  commit certificates and validator sets, export of the registry parts, and
  control 8 of CT-6 run by both the JavaScript reference and the Go verifier,
  which agree exactly. `test/registre-dev.test.js` runs it when a noorcore
  binary with `noor_getCommitCertificate` is present and is pending otherwise.
  The registry node image is rebuilt with that method, its two base images
  pinned by digest, and it rebuilds to the same digest. A block of 64 anchor
  transactions was filled and the capture of one transaction measured
  (CT-9 TM-31, report under `spec/vecteurs/ct-9/mesures/`). The CT-9 vector
  generator now keeps campaign reports under `mesures/`, as EX-11.11 requires.
  Recorded as MC-5 in the design-freeze register.
- Build step 2, the offline verifier binary `noortrace-verifier`, written in
  Go from the CT-6 text alone (`verificateur/`): the eight checks, including
  RFC 3161 timestamp tokens, OpenTimestamps proofs with their Bitcoin header
  chain, and registry blocks with their commit certificates; the trust-anchor
  file, the JSON and readable reports, the bilingual statement. Go 1.27.3,
  vendored dependencies (`golang.org/x/crypto`, decred `secp256k1`), no cgo.
  Every evidence folder of the CT-1 and CT-6 vectors is replayed against its
  expected result with no discrepancy; two builds in different directories
  and caches give the same bytes; the four no-network proofs of CT-6 EX-14.5
  pass. A CI job runs all three. CT-9: TV-55 is now runnable; recorded as
  MC-3 in the design-freeze register.
- Build step 1, the production core library `@noortrace/noyau`
  (`paquets/noyau/`, npm workspace): strict JSON and canonical form, hashing,
  Ed25519 and EIP-191 signatures, chaining, RFC 6962 Merkle trees and RFC 9162
  consistency proofs, period manifests, checkpoints, the perimeter attestation
  and every evidence-folder check of CT-1. Written from the CT-1 text alone,
  without reading the reference implementation, so that a defect of the oracle
  cannot be copied into the product. It replays all 684 CT-1 vector files
  (`test/noyau-vecteurs.test.js`, with an inventory test), and the CT-9
  property tests TU-12 run on it with `fast-check` 4.10.2
  (`test/noyau-proprietes.test.js`). Runtime dependencies: `@noble/curves` and
  `@noble/hashes` 2.4.0, exact. The CT-9 change is recorded as MC-1 in the
  design-freeze register.
- Design frozen as version 1.0 (first gate of the project plan), 2 November
  2026. A manifest records the SHA-256 of every file under `spec/`
  (`spec/figeage/conception-v1.0.sha256`, `sha256sum` format); every later
  change, addition or removal is recorded in a register of numbered entries
  with the digest of each file before and after
  (`spec/figeage/modifications.json`). `npm run conception:figeage` replays the
  register against the manifest and fails on any unrecorded change; CI runs it.
  The status of the nine specifications in `spec/README.md` now reads "frozen".

- CT-9, the test plan, version 0.1, the last of the nine design
  specifications: eight test levels (unit and property tests on the core,
  conformance to the published vectors, interoperability of exports, APIs and
  integrations, end-to-end runs of the two demonstration cases, adversarial
  tests, measurements, blind replays, code review), each with its rules and
  the build step that makes it runnable. A machine-readable catalogue
  (`spec/vecteurs/ct-9/catalogue.json`, schema `plan-de-tests-v0`) is the
  single source of 321 tests, each with its preconditions, steps and oracle:
  189 are runnable today and cite 359 existing tests or CI steps word for
  word, 132 are to be written at a named step of the build. One adversarial
  test per threat of CT-7 (98) and five plan scenarios state which answer is
  removed and what then fails; 58 of them run today against copies of the
  reference code with the answer removed (62 copies, all detected). Three
  answers of CT-7 are not yet coded in the reference implementation (bounded
  read of the MCP delegation, refusal of custody class D in production, the
  "dated by declaration only" reserve of a minutes record); their tests are
  written and will fail until the recorder is built. Every target of CT-2,
  CT-5 and CT-8 is listed with its source and failure threshold; no
  measurement is invented. A common protocol for blind replays, a full replay
  on a blank machine, and the mapping of each criterion of the second gate to
  tests and a computable verdict complete the plan.
- CT-9 coverage tool (`scripts/tests/couverture.mjs`, `npm run
  tests:couverture`) run by the tests and continuous integration: 2,332
  requirements and checks of CT-1 to CT-8, 2,193 covered by a test, 139 by a
  named justification, none uncovered; 98 of 98 threats with an adversarial
  test; 117 of 117 references to CT-9 answered; the tables of the text equal
  the catalogue. Measurement-report checker (`scripts/tests/mesures.mjs`).
  Vectors `spec/vecteurs/ct-9` (`npm run vecteurs:ct9`), regenerated twice to
  the same bytes, a Go verifier written from the specification alone and an
  independent Python recount, both without discrepancy. New tests
  `test/plan-de-tests.test.js` and `test/adversarial.test.js`; no existing
  test changed. No CT-1 to CT-8 specification or vector changes.
- `README.md`, `README.fr.md`, `ARCHITECTURE.md` (version 0.12) and
  `spec/README.md` mention CT-9.
- CT-8, deployment and operations, version 0.1: topologies and packages (what
  runs at the client, in a cloud tenant or at a Swiss host, and what stays
  with the NOORTRACE operator); reference Compose files for the quick install
  and for production, described image by image and checked statically by 14
  rules (CO-1 to CO-14) without building or running a container; 31 network
  flows, each tied to the requirement that needs it, with a default-deny
  rule; a host pre-check of 13 points (IP-1 to IP-13), blocking or advisory
  by profile; a quick install in eight steps with a 900-second budget and a
  full production install in eighteen steps with a 450-minute budget, each
  step with its command, expected result and check, including the WORM
  support, the key ceremony of CT-7, the first verified folder and the
  perimeter attestation; calculated sizing (DM-1 to DM-22) with a worked
  example and 15 cases, each coefficient cited or marked as to be measured;
  observability (collection points, alert rules, dashboard) and eight incident
  runbooks (writer stopped, lease lost, degraded anchoring, time-stamp
  provider unreachable, WORM copy lost, clock jump, registry RPC unreachable,
  suspected key compromise) with invariants, gates and exit checks; backup
  and recovery without breaking the chain (RPO/RTO as targets, two recovery
  paths, ticket-prefix epoch change), updates, minutes of operating acts
  (PV-1 to PV-10) and a chained log of consultations and accesses (CA-1 to
  CA-6); an observation mode where the approval policy is evaluated but never
  applied and no failure delays a relayable call; a deterministic reviewer
  package (`MANIFESTE.json`, fixed tar metadata) verified offline in one
  command (PR-1 to PR-12), with the instructions handed to the reviewer in
  French and English; three blind-reading tests with their grids, to be run
  by CT-9. Section 15 lists what this version does not cover: the images
  themselves, the host-preparation script, the observability files, a backup
  tool, a second WORM support, the installs themselves, which have not been
  executed because the recorder does not exist yet; every duration and
  capacity is a target. Eight new schemas (`conteneurs-v0`,
  `controle-prealable-v0`, `dimensionnement-v0`,
  `proces-verbal-exploitation-v0`, `consultation-v0`,
  `verification-journal-v0`, `rapport-observation-v0`, `paquet-reviseur-v0`).
- CT-2, the recorder, revision 0.6, and CT-3, approvals, revision 0.4, both
  minimal and compatible: the observation mode (`observation` value of the
  wait mode, reserved rule forms, `-observation` policy suffix and test
  approvers in CT-2; `evaluerObservation`, evaluation without effect, answer
  without ticket and the ` [observation <x>]` mark of `policy.rule` in CT-3).
  `configuration-enregistreur-v0` extended compatibly; `politique-approbation-v0`
  reserves one rule name. No CT-1 format and no CT-1 to CT-7 vector changes.
- CT-8 reference code and tools: `deploiement/` (Compose files, image
  descriptions, quick-install configuration), `scripts/deploiement/` (host
  pre-check, sizing calculator, Compose checks, quick configuration,
  deployment archive, log-directory verification, observation report,
  minutes, consultations, CT-8 cross-reference checker: 115 references, 115
  rows), `scripts/paquet-reviseur/` (build and verify), libraries
  `scripts/lib/deploiement.mjs`, `exploitation.mjs`, `paquet.mjs`, and
  `evaluerObservation` in `scripts/lib/approbation.mjs`. Vectors
  `spec/vecteurs/ct-8` (`npm run vecteurs:ct8`: containers, pre-check, sizing,
  observation, logs, minutes, consultations, two reading grids, 13 package
  archives), regenerated twice to the same bytes; a Go verifier written from
  the specification alone recomputes 5,183 values, all matching, 65 outside
  its scope. Package archives are confronted with GNU tar 1.35, Python 3.13
  `tarfile` and `sha256sum`, the consultation log with an independent Python
  reading, without discrepancy. Continuous integration adds the CT-8 steps
  (regeneration, Compose checks, cross-references, tools, Go verifier, a
  complete package built twice and verified offline by its embedded copy).
  `js-yaml` 4.3.2 becomes an exact development dependency.
- `README.md`, `README.fr.md`, `ARCHITECTURE.md` (version 0.11) and `NOTICE`
  (a complete reviewer package redistributes ethers under the MIT license)
  mention CT-8.
- CT-7, security and compliance, version 0.1: a threat model by component (14
  components, 98 threats, each with its answer citing exact requirements, its
  detection, its residual risk and the test CT-9 must write; 82 accepted risks,
  each named, bounded and assigned), consolidating without contradiction the
  threat tables of CT-2 to CT-6 and answering every reference to CT-7 in the
  other specifications; the inventory of keys and secrets with their custody
  class, rotation, revocation and response to compromise; the key ceremony and
  its minutes record (`ceremonie-cles-v0`), signed by every participant over a
  digest with its own domain prefix and checked offline (CR-1 to CR-12); the
  recorder's mandatory events on itself, and what CT-7 asks of CT-2 as
  proposals; the perimeter attestation (`attestation-perimetre-v0`), signed by
  members of the client's approver set and reported as declared, never as
  proven; a compliance matrix (`matrice-conformite-v0`: 10 texts, 58 rows, each
  with the exact quotation of the primary source, what the evidence covers,
  what remains with the client and its status) presented as a technical
  mapping, not legal advice; six model audit clauses. Schema
  `modele-menace-v0` for the threat model.
- CT-1, formats, revision 0.4, and CT-6, the verifier, revision 0.3: an
  optional fourteenth evidence folder part `attestation-perimetre.json`, a
  compatible extension of `dossier-v0`, with checks AT-1 to AT-7 filed under
  checks 6 and 7 without changing their status or any verdict, the
  `facts.perimeter` member of the report and a statement fragment; 20 new CT-1
  folders and 5 new CT-6 folders, existing vectors unchanged except `INDEX.md`.
  The CT-1 Go verifier, and its copy in the CT-2 verifier, now recompute 2,985
  values, 2,923 matching, none discordant, 62 outside their scope.
- CT-7 reference code (`scripts/lib/securite.mjs`, `scripts/verify/ceremonie.mjs`)
  and a cross-reference checker (`scripts/conformite/verifier-renvois.mjs`) run
  by the tests and continuous integration: every requirement cited by the
  threat model and the matrix exists, and the tables of the text equal their
  JSON files. Vectors `spec/vecteurs/ct-7` (`npm run vecteurs:ct7`) and a new Go
  verifier written from the specification alone: 1,241 values recomputed, all
  matching, 32 outside its scope. Signatures of attestations (100) and
  ceremony minutes (130) are confronted with ethers 6.17.0 and eth-account
  0.14.0, without discrepancy.
- CT-5 confrontation: the published `reponses.txt` and `coherence.txt` outputs
  are replayed and carry one more block, for the new CT-6 folder that reuses an
  already confronted checkpoint part.
- `README.fr.md` and `ARCHITECTURE.md`: regulatory statements aligned on the
  primary texts read for CT-7 (DORA for financial entities; FINMA
  communication 08/2024; OPDo art. 4 para. 1 and 5 since 1 December 2025;
  EU AI Act dates of application, 2 December 2027 and 2 August 2028; Olico
  art. 9 para. 1 let. b, without a compliance claim).
- CT-3, approvals, revision 0.3: a named person, authenticated by the
  client's identity system, approves from their session while the signature
  is still made by their own key in their own wallet, never by a server; the
  signed object of a vote is unchanged (`A`, `D_A`, EIP-191 version `0x45`).
  The revision specifies the canonical session identity and
  re-authentication; the organisation's approver directory, one active
  address per person; enrolment of an address by proof of possession (a
  readable `personal_sign` text, distinct from any vote, validated by another
  administrator), rotation and revocation; four signing paths (browser wallet
  through EIP-1193 and EIP-6963, hardware wallet through it, WalletConnect v2
  when the organisation opts in, encrypted key file) with each failure and its
  answer; the console's local check, which recomputes `A`, `JCS(A)` and `D_A`
  and refuses to have anything else signed; and the console channel to the
  service, which refuses a vote from an address other than the session's
  (new refusal reason `session_non_autorisee`). New schemas
  `console-approbation-v0`, `annuaire-approbateurs-v0` and
  `console-service-v0`; `ticket-v0` extended compatibly.
- CT-3 reference console: a dependency-free library
  (`scripts/lib/console.mjs`), a static page (`console/`) under a strict
  content security policy with subresource integrity, and an end-to-end test
  in Chromium through Playwright 1.56.1, run in continuous integration by a
  new `console-chromium` job that fails instead of skipping. A deterministic
  differential test (`test/console-primitives.test.js`) compares the
  library's hashing, key derivation, encryption and secp256k1 primitives with
  node:crypto, @noble/hashes, @noble/curves and ethers: 2,673 comparisons, no
  difference. The library's secp256k1 signing is not constant-time; CT-3
  §14.9 states the risk and recommends a hardware wallet. New vector families
  `annuaire/` and `console/` and a reading test `acceptation-console/`;
  existing CT-3 vectors unchanged except `INDEX.md`. The CT-3 Go verifier
  recomputes 7,149 values, all matching, 84 outside its scope. Every
  signature and key file of the vectors is confronted with ethers 6.17.0 and
  eth-account 0.14.0, without discrepancy.
- CT-4, the registry, revision 0.4, textual only: the registry digests
  (`periodDigest`, `registerDigest`, `revokeDigest`) are signed outside the
  CT-3 console, by the `signer` command of the CT-4 reference tool or any tool
  that meets CT-4 EX-7.10; version 0 ships no tool that signs them in an
  approver's wallet. No CT-4 vector changes.
- CT-5, anchoring: annex EX-A.7 now names the two continuous integration jobs
  that reach the network beyond installing dependencies (`confrontation` and
  `console-chromium`). Text only.
- CT-2, the recorder, revision 0.5: Gemini `generateContent` and
  `streamGenerateContent` move to version 0 at the model gateway (routes,
  `x-goog-api-key`, `alt=sse` streams, consolidation, extraction, errors in the
  provider's format), and the SDK accepts the `gemini` format; Python and
  TypeScript SDKs with adapters for LangChain and LangGraph, CrewAI,
  LlamaIndex, the OpenAI Agents SDK and LiteLLM, with a rule against double
  capture; ingestion of OpenTelemetry GenAI traces over OTLP/HTTP (JSON and
  protobuf), recorded as declarative; a legal hold on the WORM copies, placed
  and released outside the daemon, released by two people, the writer never
  allowed to delete or release; a per-agent cost formula whose unit prices are
  parameters; integration files for Gemini, CrewAI, LlamaIndex and LiteLLM.
  Changes of behaviour in production: WORM copies in `governance` mode and of
  type `gcs-object-retention`, accepted in revision 0.4, are refused, and so is
  the new `legal_hold_on_write` member.
  Schemas `worm-v0` and `cout-agent-v0`; `configuration-enregistreur-v0`
  extended compatibly.
- CT-2 reference code (`scripts/lib/capture.mjs`, `otel.mjs`, `worm.mjs`,
  `cout-agent.mjs`) and new vector families (`pieces-modele/gemini-*`, `otel/`,
  `worm/`, `cout-agent/`); existing CT-2 vectors unchanged except `INDEX.md`.
  The CT-2 Go verifier recomputes 6,036 values, 6,030 matching, none
  discordant, 6 outside its scope. Gemini payloads are confronted with the
  official google-genai 2.33.0 library and OTLP requests with
  opentelemetry-proto 1.45.1, in continuous integration as well.

- CT-5, anchoring, version 0.2: signed checkpoints every 60 seconds aligned on
  the period start, each one that commits to a new event anchored in the
  registry (at most 62 anchors per hour and journal, the manifest included),
  and at most one every 300 seconds countersigned by an RFC 3161 authority,
  which bounds the rewrite window for the date to 300 seconds plus the token
  delay; the hourly qualified closure is unchanged. The specification covers
  the RFC 3161 and OpenTimestamps clients with retries, fallbacks and response
  checks, an optional non-qualified internal server, the scheduler with its
  durable queue and restart rules, the registry anchors of checkpoints,
  monitoring with the four components of each token delay, the series
  completeness check against the registry (the next period's series served
  too, order checked within each series), providers and their measurable
  qualified status, and a cost formula whose unit price is a parameter.
  Schemas `ancrage-v0` and `planificateur-ancrage-v0`.
- CT-5 reference scheduler (`scripts/lib/ancrage.mjs`) with an injected clock,
  deterministic vectors (`spec/vecteurs/ct-5`, `npm run vecteurs:ct5`: 21
  normative traces, requests, responses, proofs, cost and completeness cases),
  and a Go verifier written from the specification alone (corrected at build
  step 8: partly copied from the reference, it is a vector-consistency
  verifier, not an independent one, CT-5 A.5): 3,255 values
  recomputed, 3,227 matching, none discordant, 28 third-party tool verdicts
  outside its scope. Requests and responses are confronted with OpenSSL,
  proofs with the official OpenTimestamps library, and consistency proofs with
  transparency-dev/merkle v0.0.2.
- CT-1, formats, revision 0.3: the checkpoint (`point-de-controle-v0`), its
  hash and signature prefixes, the RFC 9162 consistency proof, the rewrite
  window, and an optional thirteenth evidence folder part
  `points-de-controle.json` with checks K-1 to K-6; ten new CT-1 folders. The
  CT-1 Go verifier recomputes 2,885 values, 2,883 matching, none discordant,
  2 outside its scope; its copy inside the CT-2 verifier is updated to match.
- CT-2, the recorder, revision 0.4: production of checkpoints, the
  `checkpoint_interval_s` key and the `anchoring.ancrage` reference; the CT-2
  vectors are unchanged.
- CT-4, the registry, revision 0.3: the checkpoint `docType` label only.
- CT-6, the verifier, revision 0.2: the checkpoint part is checked (K-7 to K-9
  for its anchors, R-11 for a registry inclusion), the statement gains the
  checkpoint fragment with the bound it proves, and the JSON report gains
  `facts.checkpoint`; eighteen new CT-6 folders.

- CT-4, the registry, version 0.2: the dedicated noorcore instance (genesis
  rules checked at start-up, identifiers, validators and quorum, pinned versions,
  instance manifest), fee-less gas and the admission guard that production
  validators must put in front of their RPC (per-client authentication and
  quota, balance and nonce checks) against mempool poisoning by balance-less
  senders, the contracts and their conventions (`docType`, signed digests and
  signature ordering, anchor fingerprints, ABI and transaction encoding),
  client onboarding step by step, day-to-day operations, the commit
  certificate and its capture (CP-1 to CP-6) for `registre.json`,
  `certificat-commit.json` and `validateurs.json`, container topologies, and
  the substitution rule (SU-1 to SU-7) that decides at gate 4 between partner
  validators and a signed database journal. Schemas `instance-registre-v0`,
  `inscription-client-v0` and `operations-registre-v0`.
- CT-4 reference tool (`scripts/registre/noortrace-registre.mjs`, `npm run
  registre`) and conventions library (`scripts/lib/conventions-registre.mjs`),
  deterministic vectors (`spec/vecteurs/ct-4`, `npm run vecteurs:ct4`), and a
  Go verifier written from the specification alone: 2,147 values recomputed,
  all matching, 158 outside its scope. Continuous integration regenerates the
  CT-4 vectors and runs that verifier. The acceptance criterion was met three
  times: a reader with only the specification onboarded a client, anchored a
  root and closed a period on the development network.
- Text only: CT-1 §8 and §10.4, CT-2 EX-11.13 point control 8 to CT-6 instead
  of CT-4; `scripts/lib/noortrace.mjs` gains an optional `setAdmin` for
  `bootstrapOrg` (default unchanged) and `scripts/lib/journal.mjs` an
  inventory of schema keywords outside its validator's subset.
- CT-2, the recorder, version 0.3: aligned with CT-3. The approval service
  interface (`charger`, `evaluer`, `ouvrir`, `decisions`, `acquitter`,
  `consommer`, `expiration`), the refusal to seal a held call for a ticket
  already decided, relay checks RL-1 to RL-4 with a keyed relay MAC over the
  plain arguments, SG-7 (no self-approval), validation of
  `policy.approval.rules` against `politique-approbation-v0` before sealing,
  and the approver set kept and exported in `approbations.json`.
- Breaking: following the MCP 2026-07-28 error code policy, the recorder's
  JSON-RPC error codes move from `-32010`…`-32017` to `-31010`…`-31017`, and
  `-32015` is withdrawn: a pending, refused or expired approval is now a tool
  error result (`isError: true`) carrying the ticket and its state in its text
  and in `_meta["noortrace/approval"]`.
- CT-2 redaction patterns: a structural check refuses the patterns with
  exponential backtracking, and `limits.redaction_budget_ms` now bounds every
  pattern evaluation; a write or approval-bound call whose arguments exceed it
  is refused before relay.
- CT-2 vectors updated accordingly (`pieces-mcp`, `journal-demo` rendered
  signal, `redaction/motifs.json`); the CT-2 Go verifier recomputes 2,512
  values, 2,506 matching, none discordant, 6 outside its scope.
- CT-3, approvals, version 0.2: a JSON rule language (`politique-approbation-v0`)
  selecting a tool and typed predicates on its arguments by JSON Pointer, with
  exact decimal comparison and no floating point; three levels, automatic,
  time-boxed window and per-call review, projected on the CT-1 values without
  any new one; a contest window before an approval is delivered; the ticket
  lifecycle (`ticket-v0`), escalation, expiry and recognised re-issue; the
  approver set pinned by the policy, read from the client's CuratorSet when the
  ticket opens and confirmed again before the decision, with a threshold that
  cannot drop while waiting; what the approver sees before signing; separation
  of duties; the approval service interface and the console requirements.
  Closes open decision 4: the proxy answers at once with a tool error result
  (`isError`) carrying the ticket and its state (`erreur` mode) by default.
- CT-3 reference implementation (`scripts/lib/approbation.mjs`), deterministic
  vectors (`spec/vecteurs/ct-3`, `npm run vecteurs:ct3`) with ten acceptance
  cases, and a Go verifier written from the specification alone: 4,718 values
  recomputed, all matching, 83 outside its scope. Continuous integration regenerates the CT-3 vectors
  and runs that verifier.
- CT-6 vector generator: it now deletes only the entries it writes and refuses
  an output directory that holds anything else, or `--sortie` without a value.
- Text only: `ARCHITECTURE.md` 0.5 (approval levels, pinned approver set,
  open decision 4 closed; the AI Act asks at least six months for logs,
  art. 19(1) and 26(6), its art. 18 ten years being for provider
  documentation); CT-1 §8 points `policy_sha256` to CT-2 EX-8.11.
- CT-6, the verifier, version 0.1: trust model (the evidence folder is
  declarative, only the reviewer's trust anchors are trusted), the eight checks
  with numbered verifications (T- for RFC 3161, O- for OpenTimestamps, R- for the
  registry, N- for anchors, V- for verdicts), verdicts and the one-sentence
  statement that asserts only what was proven, what each verdict proves and does
  not prove, human and JSON output, reproducible network-free Go build of the
  future binary, requirements on CT-4 and CT-5. The three anchors now bind the
  period manifest hash (`periodHash`), which commits to the Merkle root.
- Schemas: `rapport-verification-v0`, `ancres-confiance-v0`,
  `entetes-bitcoin-v0`, `registre-v0`, `validateurs-v0`.
- Verifier (`scripts/verify/dossier.mjs`): checks 4, 5 and 8 implemented in
  JavaScript (`scripts/lib/horodatage.mjs`, `ots.mjs`, `registre.mjs`,
  `verificateur.mjs`); new options `--ancres`, `--entetes-bitcoin`, `--pieces`,
  `--second-manifeste`, `--exiger`, `--langue`, `--detail`; new exit code 3
  (required check not executed).
- Breaking: the `--json` output of `scripts/verify/dossier.mjs` now follows the
  `rapport-verification-v0` schema (`valide` becomes `verdict`,
  `controlesEnEchec` becomes `failed_checks`, `nonExecutesBloquants` becomes
  `blocking_unexecuted`, `controles` becomes `checks`, `evenement` becomes
  `event`). Exit codes and failed checks of the 40 CT-1 folders are unchanged.
- CT-6 test vectors: RFC 3161 tokens from a test authority, OpenTimestamps proofs
  on a synthetic Bitcoin header chain, registry data captured once on the
  development network, 50 complete evidence folders, 12 trust-anchor files;
  recomputed without discrepancy by OpenSSL 3.0.13, python-opentimestamps 0.4.5
  and go-ethereum v1.17.0 with the noorcore block hash.
- Continuous integration: deterministic regeneration of the CT-6 vectors and a
  third-party confrontation job (OpenSSL, python-opentimestamps).
- Text only: CT-1 §14 (decision 5) and `ARCHITECTURE.md` (open decision 5) no
  longer tie a revision of the export format to reviewer interviews; a revision
  from the gate 1 review or from the prototype produces version 1.
- CT-2, the recorder, version 0.2: MCP proxy (tool aggregation, `tools/call`
  relayed byte by byte over stdio and Streamable HTTP, no token passthrough),
  model API gateway as the nominal capture mode with ICAP and passive mirroring
  as alternatives (Anthropic Messages, OpenAI Chat Completions and Responses,
  streamed and not), SDK limits, full RFC 8785 canonical form for payloads,
  redaction before hashing with a versioned policy and checksum-backed detectors
  (`pii-v1` published), recorder key custody classes A to D, append-only NDJSON
  storage with an intent log, single-writer lease with fencing, a failure matrix,
  configuration and redaction-policy JSON schemas. Closes open decisions 2 and 3
  of the architecture.
- CT-2 test vectors, JavaScript implementation of the computable parts and a
  second clean-room Go verifier: every value of the vectors is recomputed by both
  implementations with no discrepancy.
- CT-1: a note in §5.5 on payload serialisation (CT-2 §8); the link to the
  internal project plan is replaced by a plain mention.
- CT-1: event model v0, canonical form (RFC 8785 with integer-only numbers),
  SHA-256 hashing and Ed25519 signing with domain prefixes, hash-chained
  journal, RFC 6962 Merkle periods with the zero root for empty periods,
  period manifests, evidence folder v0, offline verifier (checks 1, 2, 3, 6, 7),
  deterministic test vectors, JavaScript reference and clean-room Go verifier.
- Registry contracts: PeriodRegistry (derived from noorchain-core's
  PoSSRegistry, with continuity per journal and per-organisation uniqueness),
  RecorderRegistry, ThresholdSignatures (its signature loop follows
  PoSSRegistry's); AttestationRegistry, CuratorSet and CuratorSetRegistry reused
  unchanged from noorchain-core.
- Offline verifier of BFT commit certificates (`noor_getCommitCertificate`),
  byte-for-byte parity with the node's signing scheme.
- Dedicated development instance of the registry node, container image, study of
  what a follower node provides.
- Apache-2.0 licence, English README, contribution and security policies.
- Continuous integration: full test suite, deterministic regeneration of the CT-1
  and CT-2 vectors, and both clean-room Go verifiers run against them on every
  push.
