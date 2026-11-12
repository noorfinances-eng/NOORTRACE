# Image noortrace/approbation (CT-8 EX-3.5, EX-3.6, EX-3.13) : service
# d'approbation (CT-3 §12), `noortrace-approbation --config`,
# `valider-configuration` et `sonde`. Contexte : la racine du dépôt, filtré
# par Dockerfile.dockerignore. Le paquet dépend de @noortrace/console (et
# celui-ci de @noortrace/approbation) : l'image porte les deux paquets.
#
#   node scripts/deploiement/construire-images.mjs --images approbation
#
# Images de base épinglées par étiquette exacte ET condensé (EX-3.13,
# R9-F30), publiées plus de deux semaines avant leur adoption (relevé dans
# conteneurs/enregistreur/Dockerfile) : node:22.23.4-bookworm-slim,
# index du 2026-10-21 ; gcr.io/distroless/cc-debian12:nonroot, index du
# 2026-08-21 (ni interpréteur de commandes, ni /usr/bin/env). Heure des
# fichiers et de l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu propre à l'image :
#   /usr/local/bin/noortrace-approbation  lien vers paquets/approbation/bin/
#   /etc/passwd                           noortrace-approbation (10002) et
#                                         noortrace (10001), pair de la prise
#                                         du noyau (CT-2 EX-18.8, EX-3.5)
#   /var/lib/noortrace-approbation        10002:10002 0700 (state_dir, CT-3 EX-10.12)
#   /run/noortrace                        0:10010 3770 (prises, EX-3.5, avec le
#                                         bit collant que le démon exige, CT-2
#                                         EX-4.39 ; mêmes
#                                         droits que l'image de l'enregistreur)
#   /run/temporaire                       1777 (TMPDIR)
#   /usr/share/doc/nodejs/LICENSE  licence de Node.js, /usr/local/LICENSE de l'image
#                                  node, vérifiée à la construction (SHA-256) égale
#                                  à celle de l'archive officielle de la version,
#                                  dont /usr/local/bin/node est le binaire (même
#                                  relevé que conteneurs/enregistreur/Dockerfile)
# Point d'entrée : `noortrace-approbation` (EX-3.6). Compte : 10002:10002.

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
WORKDIR /opt/noortrace
COPY package.json package-lock.json ./
COPY paquets/ paquets/
RUN --mount=type=secret,id=ca_bundle \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi; \
    npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts --no-audit --no-fund --no-update-notifier \
      --workspace=paquets/approbation --cache /tmp/npm-cache --logs-dir /tmp/npm-journaux; \
    rm -rf /tmp/npm-cache /tmp/npm-journaux
COPY conteneurs/commun/preparer-application.sh /usr/local/sbin/preparer-application
COPY conteneurs/approbation/passwd conteneurs/approbation/group LICENSE NOTICE /contexte/
RUN set -eu; \
    preparer-application /opt/noortrace; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/var/lib /out/run /out/etc/noortrace-approbation; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    ln -s /opt/noortrace/paquets/approbation/bin/noortrace-approbation /out/usr/local/bin/noortrace-approbation; \
    install -d -o 10002 -g 10002 -m 0700 /out/var/lib/noortrace-approbation; \
    install -d -o 0 -g 10010 -m 3770 /out/run/noortrace; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/approbation" \
      org.opencontainers.image.description="Service d'approbation (CT-3 §12)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace /opt/noortrace
COPY --from=construction /out/ /
WORKDIR /
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/noortrace-approbation"]
