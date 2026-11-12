# Image noortrace/enregistreur (CT-8 EX-3.5, EX-3.6, EX-3.13) : démon
# `noortrace` (CT-2), `noortrace-ctl`, composant d'ancrage (CT-5) en fil
# distinct. Contexte de construction : la racine du dépôt ; seuls les fichiers
# que Dockerfile.dockerignore laisse passer y entrent.
#
#   node scripts/deploiement/construire-images.mjs --images enregistreur
#
# Images de base épinglées par étiquette exacte ET condensé (EX-3.13,
# R9-F30), publiées plus de deux semaines avant leur adoption :
#   - node:22.23.4-bookworm-slim, index du 2026-10-21 (la même étiquette a été
#     repoussée le 2026-10-28 et le 2026-11-05 ; c'est l'index du 21 octobre
#     qui est retenu) : Node.js 22.23.4, npm 10.9.9, flock(1) d'util-linux
#     2.38.1, glibc de Debian 12 ;
#   - gcr.io/distroless/cc-debian12:nonroot, index du 2026-08-21 : glibc,
#     libstdc++ et libgcc de Debian 12, autorités TLS ; ni interpréteur de
#     commandes, ni gestionnaire de paquets, ni /usr/bin/env.
# L'heure des fichiers et de l'image est SOURCE_DATE_EPOCH (date du commit),
# que le script de construction passe avec l'option rewrite-timestamp de
# l'exportateur.
#
# Contenu de l'image finale :
#   /usr/local/bin/node                 Node.js de l'image node épinglée
#   /usr/share/doc/nodejs/LICENSE      licence de Node.js : /usr/local/LICENSE de
#                                       l'image node, égal (SHA-256 vérifié à la
#                                       construction) au LICENSE de l'archive
#                                       officielle node-v22.23.4-linux-x64.tar.xz,
#                                       dont /usr/local/bin/node est aussi le binaire
#   /opt/noortrace/                     npm ci --omit=dev des paquets
#                                       enregistreur, ancrage et noyau
#   /usr/local/bin/noortrace, noortrace-ctl, … liens vers paquets/*/bin/*, dont
#                                       la ligne de lancement nomme
#                                       /usr/local/bin/node (aucun /usr/bin/env)
#   /usr/bin/flock                      bail `file` (CT-2 §13.2, sans /bin/sh)
#   /etc/passwd, /etc/group             noortrace (10001), noortrace-approbation
#                                       (10002) : `peer_user` (CT-2 EX-18.8)
#   /var/lib/noortrace                  10001:10001 0700 (storage.root)
#   /var/log/noortrace                  10001:10001 0750 (journal d'exploitation)
#   /run/noortrace                      0:10010 3770 (prises, EX-3.5 ; bit
#                                       collant exigé par le démon, CT-2
#                                       EX-4.39 : voir la demande de révision)
#   /var/lib/noortrace-exports          10001:10005 2750 (exports, EX-3.5)
#   /run/temporaire                     1777 (TMPDIR, tmpfs dans Compose)
# Point d'entrée : le programme `noortrace` (EX-3.6) ; `command` n'en porte que
# les arguments. Compte par défaut : 10001:10001.
#
# Ce que l'image ne contient pas : python3 (classe A de clé, PKCS#11, CT-2
# EX-11.10), tpm2-tools (enveloppe TPM 2.0 de la classe C). Les classes B, C
# (Azure) et D sont servies ; la classe A et le TPM exigent une image dérivée
# (adaptation du client, CT-8 table d'IC-14).

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
WORKDIR /opt/noortrace
COPY package.json package-lock.json ./
COPY paquets/ paquets/
# Installation de production : dépendances de l'espace de travail
# paquets/enregistreur seulement, ni développement, ni facultatives, ni pairs,
# aucun script d'installation ; intégrité de chaque archive par
# package-lock.json. Le secret ca_bundle (facultatif, jamais écrit dans une
# couche) sert seulement derrière un mandataire qui réécrit TLS.
RUN --mount=type=secret,id=ca_bundle \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi; \
    npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts --no-audit --no-fund --no-update-notifier \
      --workspace=paquets/enregistreur --cache /tmp/npm-cache --logs-dir /tmp/npm-journaux; \
    rm -rf /tmp/npm-cache /tmp/npm-journaux
COPY conteneurs/commun/preparer-application.sh /usr/local/sbin/preparer-application
COPY conteneurs/enregistreur/passwd conteneurs/enregistreur/group LICENSE NOTICE /contexte/
RUN set -eu; \
    preparer-application /opt/noortrace; \
    install -d -m 0755 /out/etc /out/usr/bin /out/usr/local/bin /out/usr/share/doc/noortrace /out/usr/share/doc/util-linux /out/var/lib /out/var/log /out/run /out/etc/noortrace; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    install -m 0755 /usr/bin/flock /out/usr/bin/flock; \
    install -m 0644 /usr/share/doc/util-linux/copyright /out/usr/share/doc/util-linux/copyright; \
    for prog in noortrace noortrace-ctl noortrace-connecteur noortrace-miroir noortrace-attributs; do \
      ln -s /opt/noortrace/paquets/enregistreur/bin/$prog /out/usr/local/bin/$prog; \
    done; \
    for prog in noortrace-ancrage noortrace-tsa-interne; do \
      ln -s /opt/noortrace/paquets/ancrage/bin/$prog /out/usr/local/bin/$prog; \
    done; \
    install -d -o 10001 -g 10001 -m 0700 /out/var/lib/noortrace; \
    install -d -o 10001 -g 10001 -m 0750 /out/var/log/noortrace; \
    install -d -o 0 -g 10010 -m 3770 /out/run/noortrace; \
    install -d -o 10001 -g 10005 -m 2750 /out/var/lib/noortrace-exports; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/enregistreur" \
      org.opencontainers.image.description="Démon noortrace (CT-2), noortrace-ctl et composant d'ancrage (CT-5)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace /opt/noortrace
COPY --from=construction /out/ /
WORKDIR /
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/noortrace"]
