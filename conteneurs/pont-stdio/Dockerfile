# Image noortrace/pont-stdio (CT-8 EX-3.7, EX-3.8, EX-3.6, EX-3.13) : pont
# d'un serveur d'outils stdio vers Streamable HTTP, et le serveur de fichiers
# minimal du pont d'exemple `pont-fichiers` de production.yaml (décision D-13 :
# écrit dans le dépôt, aucun code tiers). Programmes :
# conteneurs/pont-stdio/noortrace-pont-stdio.mjs et serveur-fichiers.mjs,
# modules de Node.js seulement (aucune dépendance npm).
#
#   node scripts/deploiement/construire-images.mjs --images pont-stdio
#
# Images de base épinglées par étiquette exacte ET condensé (EX-3.13) :
# node:22.23.4-bookworm-slim, index du 2026-10-21 (Node.js seulement) ;
# gcr.io/distroless/cc-debian12:nonroot, index du 2026-08-21. Heure des
# fichiers et de l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu propre à l'image :
#   /usr/local/bin/noortrace-pont-stdio              lien vers /opt/noortrace-pont/
#   /opt/mcp/server-filesystem/bin/server-filesystem lien vers le serveur de
#                                                    fichiers (chemin de la
#                                                    commande de production.yaml)
#   /etc/passwd                                      mcp-fichiers (10101)
#   /srv/pieces                                      10101:10101 0750 (point de
#                                                    montage des données)
#   /run/temporaire                                  1777 (TMPDIR)
#   /usr/share/doc/nodejs/LICENSE  licence de Node.js, /usr/local/LICENSE de l'image
#                                  node, vérifiée à la construction (SHA-256) égale
#                                  à celle de l'archive officielle de la version,
#                                  dont /usr/local/bin/node est le binaire (même
#                                  relevé que conteneurs/enregistreur/Dockerfile)
# Point d'entrée : `noortrace-pont-stdio` (EX-3.6). Compte : 10101:10101 ; un
# autre pont (`pont-<alias>`) prend son propre compte par `user` (EX-3.5).

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
COPY conteneurs/pont-stdio/noortrace-pont-stdio.mjs conteneurs/pont-stdio/serveur-fichiers.mjs /opt/noortrace-pont/
COPY conteneurs/pont-stdio/passwd conteneurs/pont-stdio/group LICENSE NOTICE /contexte/
RUN set -eu; \
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH exigée (date du commit)}"; \
    cd /opt/noortrace-pont; \
    chown -R 0:0 .; chmod 0755 .; \
    for prog in noortrace-pont-stdio.mjs serveur-fichiers.mjs; do \
      [ "$(head -n 1 $prog)" = "#!/usr/bin/env node" ] || { echo "ligne de lancement inattendue : $prog" >&2; exit 1; }; \
      sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' $prog; \
      chmod 0755 $prog; \
    done; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/opt/mcp/server-filesystem/bin /out/srv /out/run; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    ln -s /opt/noortrace-pont/noortrace-pont-stdio.mjs /out/usr/local/bin/noortrace-pont-stdio; \
    ln -s /opt/noortrace-pont/serveur-fichiers.mjs /out/opt/mcp/server-filesystem/bin/server-filesystem; \
    install -d -o 10101 -g 10101 -m 0750 /out/srv/pieces; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/* /out/opt/mcp/server-filesystem/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out /opt/noortrace-pont -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/pont-stdio" \
      org.opencontainers.image.description="Pont stdio vers Streamable HTTP et serveur de fichiers minimal (CT-8 EX-3.7)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace-pont /opt/noortrace-pont
COPY --from=construction /out/ /
WORKDIR /
USER 10101:10101
ENTRYPOINT ["/usr/local/bin/noortrace-pont-stdio"]
