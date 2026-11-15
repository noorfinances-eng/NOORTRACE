# Image noortrace/approbateur-demo de la démonstration de référence (CT-2 §19.2) :
# le service qui joue les approbateurs, seul détenteur des clés de
# démonstration des comptes Hardhat 1 à 3. Contexte : la racine du dépôt,
# filtré par Dockerfile.dockerignore.
#
#   node demo/construire-images.mjs --images approbateur-demo
#
# Image de démonstration : elle n'entre dans aucun déploiement et n'est pas
# publiée. Même méthode de construction que les images de CT-8 (EX-3.13) :
# images de base épinglées par étiquette exacte ET condensé (relevé dans
# conteneurs/enregistreur/Dockerfile) ; heure des fichiers et de l'image :
# SOURCE_DATE_EPOCH (date du commit).
#
# Contenu :
#   /usr/local/bin/node                         Node.js 22.23.4 de l'image node épinglée
#   /usr/share/doc/nodejs/LICENSE               licence de Node.js (SHA-256 vérifié)
#   /opt/noortrace/                             npm ci --omit=dev des paquets ancrage et
#                                               noyau (signatures, condensés du registre,
#                                               transactions, capture), et les programmes
#                                               conteneurs/approbateur-demo/ et conteneurs/demo-commun/
#   /usr/local/bin/noortrace-approbateur-demo   lien vers le programme (point d'entrée)
#   /etc/passwd                                 noortrace-approbateur-demo (10024)
#   /var/lib/noortrace-demandes                 10024:10001 2770 : répertoire d'échange des
#                                               demandes de signature, partagé avec
#                                               l'exploitation de la démonstration (10001)
#   /run/noortrace-console                      0:10010 3770 : prise du canal de la console du
#                                               service d'approbation (mêmes droits que le
#                                               répertoire des prises de CT-8 EX-3.5 ; ce
#                                               service démarre avant le service d'approbation
#                                               et donne ses droits au volume neuf)
#   /run/temporaire                             1777 (TMPDIR ; marque « prêt »)
# Compte : 10024:10024.

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
COPY conteneurs/approbateur-demo/approbateur-demo.mjs conteneurs/approbateur-demo/
COPY conteneurs/approbateur-demo/passwd conteneurs/approbateur-demo/group LICENSE NOTICE /contexte/
RUN set -eu; \
    preparer-application /opt/noortrace; \
    prog=conteneurs/approbateur-demo/approbateur-demo.mjs; \
    [ "$(head -n 1 $prog)" = "#!/usr/bin/env node" ] || { echo "ligne de lancement inattendue : $prog" >&2; exit 1; }; \
    sed -i '1s|^#!/usr/bin/env node$|#!/usr/local/bin/node|' $prog; \
    chmod 0755 $prog; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/var/lib /out/run; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE /out/usr/share/doc/noortrace/; \
    echo "c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4  /usr/local/LICENSE" | sha256sum --strict --quiet -c -; \
    echo "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90  /usr/local/bin/node" | sha256sum --strict --quiet -c -; \
    install -d -m 0755 /out/usr/share/doc/nodejs; \
    install -m 0644 /usr/local/LICENSE /out/usr/share/doc/nodejs/LICENSE; \
    ln -s /opt/noortrace/conteneurs/approbateur-demo/approbateur-demo.mjs /out/usr/local/bin/noortrace-approbateur-demo; \
    install -d -o 10024 -g 10001 -m 2770 /out/var/lib/noortrace-demandes; \
    install -d -o 0 -g 10010 -m 3770 /out/run/noortrace-console; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    for lien in /out/usr/local/bin/*; do [ -f "$lien" ] || { echo "lien cassé : $lien" >&2; exit 1; }; done; \
    find /out /opt/noortrace/conteneurs -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/approbateur-demo" \
      org.opencontainers.image.description="Approbateurs de la démonstration de référence (CT-2 §19.2), seul détenteur des clés de démonstration des comptes Hardhat 1 à 3" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
COPY --from=construction /usr/local/bin/node /usr/local/bin/node
COPY --from=construction /opt/noortrace /opt/noortrace
COPY --from=construction /out/ /
WORKDIR /
USER 10024:10024
ENTRYPOINT ["/usr/local/bin/noortrace-approbateur-demo"]
