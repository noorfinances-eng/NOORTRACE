# Image noortrace/agent-demo de la démonstration de référence (CT-2 §19.1) :
# agent scénarisé (CT-2 §19.2, pas 2 à 8) : client MCP de l'ère 2026-07-28 et client de l'API Messages, qui ne joint que l'enregistreur.
# Contexte : la racine du dépôt, filtré par Dockerfile.dockerignore.
#
#   node demo/construire-images.mjs --images agent-demo
#
# Image de démonstration : elle n'entre dans aucun déploiement et n'est pas
# publiée. Même méthode de construction que les images de CT-8 (EX-3.13) :
# images de base épinglées par étiquette exacte ET condensé, publiées plus de
# deux semaines avant leur adoption (relevé dans
# conteneurs/enregistreur/Dockerfile) : node:22.23.4-bookworm-slim, index du
# 2026-10-21 ; gcr.io/distroless/cc-debian12:nonroot, index du 2026-08-21 (ni
# interpréteur de commandes, ni /usr/bin/env). Heure des fichiers et de
# l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu :
#   /usr/local/bin/node                    Node.js 22.23.4 de l'image node épinglée
#   /usr/share/doc/nodejs/LICENSE          licence de Node.js (SHA-256 vérifié)
#   /opt/noortrace-demo/agent-demo.mjs   le programme, sans dépendance
#   /usr/local/bin/noortrace-agent-demo  lien vers le programme (point d'entrée)
#   /etc/passwd                            noortrace-agent-demo (10023)
#   /run/temporaire                        1777 (TMPDIR)
# Port : aucun. Compte : 10023:10023.

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
COPY conteneurs/agent-demo/agent-demo.mjs /opt/noortrace-demo/
COPY conteneurs/agent-demo/passwd conteneurs/agent-demo/group LICENSE NOTICE /contexte/
RUN set -eu; \
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH exigée (date du commit)}"; \
    cd /opt/noortrace-demo; \
    chown -R 0:0 .; chmod 0755 .; \
    [ "$(head -n 1 agent-demo.mjs)" = "#!/usr/bin/env node" ] || { echo "ligne de lancement inattendue : agent-demo.mjs" >&2; exit 1; }; \
    sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' agent-demo.mjs; \
    chmod 0755 agent-demo.mjs; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/run; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    ln -s /opt/noortrace-demo/agent-demo.mjs /out/usr/local/bin/noortrace-agent-demo; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out /opt/noortrace-demo -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/agent-demo" \
      org.opencontainers.image.description="Agent scénarisé de la démonstration de référence (CT-2 §19.2)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace-demo /opt/noortrace-demo
COPY --from=construction /out/ /
WORKDIR /
USER 10023:10023
ENTRYPOINT ["/usr/local/bin/noortrace-agent-demo"]
