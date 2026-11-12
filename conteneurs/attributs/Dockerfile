# Image noortrace/attributs (CT-8 EX-3.9, EX-3.6, EX-3.13) : compagnon qui pose
# les attributs a et i (CT-2 EX-12.18), `noortrace-attributs --racine <r>
# [--intervalle-s <n>]` et `noortrace-attributs sonde`. Seul service admis
# sous le compte 0, avec LINUX_IMMUTABLE, FOWNER et DAC_READ_SEARCH, sans
# réseau. Le programme est celui du paquet enregistreur
# (src/worm/attributs.mjs) : l'image installe ce paquet comme celle de
# l'enregistreur et n'en lie que le compagnon.
#
#   node scripts/deploiement/construire-images.mjs --images attributs
#
# Images de base épinglées par étiquette exacte ET condensé (EX-3.13,
# R9-F30), publiées plus de deux semaines avant leur adoption (relevé dans
# conteneurs/enregistreur/Dockerfile) : node:22.23.4-bookworm-slim,
# index du 2026-10-21 ; gcr.io/distroless/cc-debian12:nonroot, index du
# 2026-08-21 (ni interpréteur de commandes, ni /usr/bin/env). Heure des
# fichiers et de l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu propre à l'image :
#   /usr/local/bin/noortrace-attributs   lien vers paquets/enregistreur/bin/
#   /usr/bin/chattr, /usr/bin/lsattr     e2fsprogs 1.47.0 de l'image node, avec
#                                        libe2p.so.2 et libcom_err.so.2
#   /var/lib/noortrace                   10001:10001 0700 : mêmes droits que
#                                        l'image de l'enregistreur, parce que le
#                                        compagnon peut être le premier à
#                                        monter le volume neuf `journal`
#   /run/temporaire                      1777 (TMPDIR : état pour la sonde)
#   /usr/share/doc/nodejs/LICENSE  licence de Node.js, /usr/local/LICENSE de l'image
#                                  node, vérifiée à la construction (SHA-256) égale
#                                  à celle de l'archive officielle de la version,
#                                  dont /usr/local/bin/node est le binaire (même
#                                  relevé que conteneurs/enregistreur/Dockerfile)
# Point d'entrée : `noortrace-attributs` (EX-3.6). Compte : 0:0.

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
WORKDIR /opt/noortrace
COPY package.json package-lock.json ./
COPY paquets/ paquets/
RUN --mount=type=secret,id=ca_bundle \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca_bundle; fi; \
    npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts --no-audit --no-fund --no-update-notifier \
      --workspace=paquets/enregistreur --cache /tmp/npm-cache --logs-dir /tmp/npm-journaux; \
    rm -rf /tmp/npm-cache /tmp/npm-journaux
COPY conteneurs/commun/preparer-application.sh /usr/local/sbin/preparer-application
COPY conteneurs/attributs/passwd conteneurs/attributs/group LICENSE NOTICE /contexte/
RUN set -eu; \
    preparer-application /opt/noortrace; \
    install -d -m 0755 /out/etc /out/usr/bin /out/usr/local/bin /out/lib/x86_64-linux-gnu /out/var/lib /out/run \
      /out/usr/share/doc/noortrace /out/usr/share/doc/e2fsprogs /out/usr/share/doc/libext2fs2 /out/usr/share/doc/libcom-err2; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    install -m 0755 /usr/bin/chattr /usr/bin/lsattr /out/usr/bin/; \
    install -m 0644 /lib/x86_64-linux-gnu/libe2p.so.2.3 /lib/x86_64-linux-gnu/libcom_err.so.2.1 /out/lib/x86_64-linux-gnu/; \
    ln -s libe2p.so.2.3 /out/lib/x86_64-linux-gnu/libe2p.so.2; \
    ln -s libcom_err.so.2.1 /out/lib/x86_64-linux-gnu/libcom_err.so.2; \
    for p in e2fsprogs libext2fs2 libcom-err2; do install -m 0644 /usr/share/doc/$p/copyright /out/usr/share/doc/$p/copyright; done; \
    ln -s /opt/noortrace/paquets/enregistreur/bin/noortrace-attributs /out/usr/local/bin/noortrace-attributs; \
    install -d -o 10001 -g 10001 -m 0700 /out/var/lib/noortrace; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/attributs" \
      org.opencontainers.image.description="Compagnon des attributs a et i (CT-8 EX-3.9, CT-2 EX-12.18)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace /opt/noortrace
COPY --from=construction /out/ /
WORKDIR /
USER 0:0
ENTRYPOINT ["/usr/local/bin/noortrace-attributs"]
