# Image noortrace/registre-dev de la démonstration de référence (CT-2 §19.1) :
# instance de développement du registre, quatre validateurs noorcore dans un
# seul conteneur, contrats déployés au démarrage. Contexte : la racine du
# dépôt, filtré par Dockerfile.dockerignore.
#
#   npm run compile                      # hh-artifacts/ : codes de création des contrats
#   node demo/construire-images.mjs --images registre-dev
#
# Image de démonstration : jamais publiée, et NON reconstructible depuis le
# seul dépôt public. Le binaire du nœud vient de l'image locale
# noortrace/noorcore:618fcef-noortrace (chain/docker/Dockerfile au commit
# épinglé de noorchain-core, avec le correctif `noor_getCommitCertificate`,
# qui n'est pas dans le dépôt : chain/patches/LISEZMOI.md). Elle est désignée
# ici par son étiquette et son condensé local, et le SHA-256 du binaire est
# contrôlé à la construction ; qui n'a pas cette image ne construit pas
# registre-dev.
#
# Les autres images de base sont épinglées par étiquette exacte ET condensé
# (relevé dans conteneurs/enregistreur/Dockerfile). Les codes de création
# des contrats viennent de hh-artifacts/ (`npm run compile`, solc 0.8.20,
# optimiseur à 200 passes) : seuls les membres `bytecode` de cinq fichiers
# entrent dans l'image, réunis dans codes-creation.json. Heure des fichiers
# et de l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu :
#   /usr/local/bin/noorcore                  binaire du nœud (glibc de Debian 12)
#   /usr/local/bin/node                      Node.js 22.23.4 de l'image node épinglée
#   /usr/share/doc/nodejs/LICENSE            licence de Node.js (SHA-256 vérifié)
#   /opt/noortrace/                          npm ci --omit=dev des paquets ancrage et noyau,
#                                            conteneurs/registre-dev/ et conteneurs/demo-commun/
#   /opt/noortrace-demo/alloc-dev.json       genèse du réseau de développement (chain/config/)
#   /opt/noortrace-demo/codes-creation.json  codes de création des cinq contrats
#   /usr/local/bin/noortrace-registre-dev       lien vers le programme (point d'entrée)
#   /etc/passwd                              noortrace-registre-dev (10025)
#   /var/lib/noorcore                        10025:10025 0700 (données des quatre validateurs)
#   /run/temporaire                          1777 (TMPDIR)
# Port : 8545 (JSON-RPC du validateur 1). Compte : 10025:10025.

FROM noortrace/noorcore:618fcef-noortrace@sha256:4e6cb6795d49d1f39a69bd2b9ce097ede675f36fa842ebb07ef88c8e3fd50d52 AS noeud

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
WORKDIR /opt/noortrace
COPY package.json package-lock.json ./
COPY paquets/ paquets/
RUN --mount=type=secret,id=ca_bundle \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi; \
    npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts --no-audit --no-fund --no-update-notifier \
      --workspace=paquets/ancrage --cache /tmp/npm-cache --logs-dir /tmp/npm-journaux; \
    rm -rf /tmp/npm-cache /tmp/npm-journaux
COPY conteneurs/commun/preparer-application.sh /usr/local/sbin/preparer-application
COPY conteneurs/demo-commun/chaine.mjs conteneurs/demo-commun/
COPY conteneurs/registre-dev/registre-dev.mjs conteneurs/registre-dev/
COPY conteneurs/registre-dev/passwd conteneurs/registre-dev/group LICENSE NOTICE chain/config/alloc-dev.json /contexte/
COPY hh-artifacts/contracts/ /contexte/artefacts/
COPY --from=noeud /usr/local/bin/noorcore /contexte/noorcore
RUN set -eu; \
    preparer-application /opt/noortrace; \
    prog=conteneurs/registre-dev/registre-dev.mjs; \
    [ "$(head -n 1 $prog)" = "#!/usr/bin/env node" ] || { echo "ligne de lancement inattendue : $prog" >&2; exit 1; }; \
    sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' $prog; \
    chmod 0755 $prog; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/opt/noortrace-demo /out/var/lib /out/run; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    echo "759df4c7a7f087bdb92c63633cf817e613272b2b36d7966869e1c21a77a7d350  /contexte/noorcore" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    install -m 0755 /contexte/noorcore /out/usr/local/bin/noorcore; \
    install -m 0644 /contexte/alloc-dev.json /out/opt/noortrace-demo/alloc-dev.json; \
    node -e 'const fs=require("fs");const o={};for(const n of ["AttestationRegistry","CuratorSet","CuratorSetRegistry","PeriodRegistry","RecorderRegistry"]){const a=JSON.parse(fs.readFileSync(`/contexte/artefacts/${n}.sol/${n}.json`,"utf8"));if(!/^0x([0-9a-f]{2})+$/.test(a.bytecode)||Object.keys(a.linkReferences).length)throw new Error(`code de création de ${n} inattendu`);o[n]=a.bytecode}fs.writeFileSync("/out/opt/noortrace-demo/codes-creation.json",JSON.stringify(o)+"\n",{mode:0o644})'; \
    ln -s /opt/noortrace/conteneurs/registre-dev/registre-dev.mjs /out/usr/local/bin/noortrace-registre-dev; \
    install -d -o 10025 -g 10025 -m 0700 /out/var/lib/noorcore; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out /opt/noortrace/conteneurs -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/registre-dev" \
      org.opencontainers.image.description="Instance de développement du registre pour la démonstration de référence (CT-2 §19.1) : quatre validateurs noorcore, contrats déployés au démarrage" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace /opt/noortrace
COPY --from=construction /out/ /
WORKDIR /
USER 10025:10025
ENTRYPOINT ["/usr/local/bin/noortrace-registre-dev"]
