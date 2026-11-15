# Image noortrace/verificateur-demo de la démonstration de référence (CT-2 §19.1,
# §19.4) : le service `verificateur`, qui ne fait que vérifier. Elle réunit
# le binaire `noortrace-verifier` (CT-6), construit par la recette de
# référence, et le programme qui attend le dossier exporté, lance le
# binaire et imprime la sortie de CT-2 §19.4. Contexte : la racine du
# dépôt, filtré par Dockerfile.dockerignore.
#
#   node demo/construire-images.mjs --images verificateur-demo
#
# Image de démonstration : elle n'entre dans aucun déploiement et n'est pas
# publiée. L'image noortrace/verificateur de CT-8 ne contient que le binaire
# (ni Node.js ni interpréteur) : elle ne peut ni attendre le dossier ni
# imprimer la sortie de la démonstration, d'où cette image.
#
# Construction du binaire : celle de conteneurs/verificateur/Dockerfile (CT-6
# EX-14.6, verificateur/scripts/construire.sh : go1.27.3, -trimpath,
# -buildvcs=false, -mod=vendor, CGO_ENABLED=0, aucun téléchargement), dans
# golang:1.27.3-bookworm, index du 2026-10-21. Node.js et l'image finale :
# relevé dans conteneurs/enregistreur/Dockerfile. Heure des fichiers et de
# l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu :
#   /usr/local/bin/noortrace-verifier          binaire linux/amd64, version 0.1.0
#   /usr/local/bin/node                        Node.js 22.23.4 de l'image node épinglée
#   /usr/share/doc/nodejs/LICENSE              licence de Node.js (SHA-256 vérifié)
#   /usr/share/doc/noortrace/                  LICENSE, NOTICE, LICENCES-TIERCES (CT-6 EX-14.10)
#   /opt/noortrace-demo/verificateur-demo.mjs   le programme, sans dépendance
#   /usr/local/bin/noortrace-verificateur-demo   lien vers le programme (point d'entrée)
#   /etc/passwd                                noortrace-verificateur (10005)
#   /var/lib/noortrace-exports                 10001:10005 2750 : mêmes droits que l'image de
#                                              l'enregistreur (volume `exports` partagé, CT-8
#                                              EX-3.5), monté ici en lecture seule
#   /run/temporaire                            1777 (TMPDIR)
# Aucun port, aucun réseau. Compte : 10005:10005.

FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS binaire
ARG SOURCE_DATE_EPOCH
COPY verificateur/ /src/verificateur/
RUN set -eu; \
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH exigée (date du commit)}"; \
    cd /src/verificateur; \
    install -d -m 0755 /out/usr/local/bin /out/usr/share/doc/noortrace; \
    bash scripts/construire.sh -v 0.1.0 -p linux/amd64 -o /out/usr/local/bin/noortrace-verifier; \
    chown 0:0 /out/usr/local/bin/noortrace-verifier; chmod 0755 /out/usr/local/bin/noortrace-verifier; \
    install -m 0644 LICENCES-TIERCES /out/usr/share/doc/noortrace/

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS construction
ARG SOURCE_DATE_EPOCH
COPY conteneurs/verificateur-demo/verificateur-demo.mjs /opt/noortrace-demo/
COPY conteneurs/verificateur-demo/passwd conteneurs/verificateur-demo/group LICENSE NOTICE /contexte/
COPY --from=binaire /out/ /out/
RUN set -eu; \
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH exigée (date du commit)}"; \
    cd /opt/noortrace-demo; \
    chown -R 0:0 .; chmod 0755 .; \
    [ "$(head -n 1 verificateur-demo.mjs)" = "#!/usr/bin/env node" ] || { echo "ligne de lancement inattendue : verificateur-demo.mjs" >&2; exit 1; }; \
    sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' verificateur-demo.mjs; \
    chmod 0755 verificateur-demo.mjs; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/var/lib /out/run; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    ln -s /opt/noortrace-demo/verificateur-demo.mjs /out/usr/local/bin/noortrace-verificateur-demo; \
    install -d -o 10001 -g 10005 -m 2750 /out/var/lib/noortrace-exports; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out /opt/noortrace-demo -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/verificateur-demo" \
      org.opencontainers.image.description="Service verificateur de la démonstration de référence (CT-2 §19.4) : binaire noortrace-verifier et impression du résultat" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace-demo /opt/noortrace-demo
COPY --from=construction /out/ /
WORKDIR /
USER 10005:10005
ENTRYPOINT ["/usr/local/bin/noortrace-verificateur-demo"]
