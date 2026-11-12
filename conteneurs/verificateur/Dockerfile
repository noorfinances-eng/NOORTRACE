# Image noortrace/verificateur (CT-8 EX-3.6, EX-3.13 ; CT-6 §8, §14) : binaire
# autonome `noortrace-verifier`, sans réseau, qui lit le volume des exports en
# lecture seule (service `verificateur` des fichiers Compose, profil `outils`).
# C'est le vérificateur de CT-8 (images.json) ; le service `verificateur` de la
# démonstration de CT-2 §19.1, qui lance clôture et export par le réseau, n'est
# pas cette image (écart E-12 de l'étape 7).
#
#   node scripts/deploiement/construire-images.mjs --images verificateur
#
# Construction : la recette de référence de CT-6 EX-14.6, telle que l'applique
# verificateur/scripts/construire.sh (go1.27.3, -trimpath, -buildvcs=false,
# -mod=vendor, CGO_ENABLED=0, GOAMD64=v1, -buildid= vide, aucun
# téléchargement), dans l'image de construction de CT-6 EX-14.7, la même que le
# travail de version (.github/workflows/version.yml) :
#   - golang:1.27.3-bookworm, index du 2026-10-21 (étiquette repoussée le
#     2026-11-05 ; l'index du 21 octobre est retenu) ;
#   - image finale gcr.io/distroless/static-debian12:nonroot, index du
#     2026-08-21 : ni interpréteur de commandes, ni bibliothèque C.
# Heure des fichiers et de l'image : SOURCE_DATE_EPOCH (date du commit).
#
# Contenu :
#   /usr/local/bin/noortrace-verifier      binaire linux/amd64, version 0.1.0
#   /usr/share/doc/noortrace/              LICENSE, NOTICE, LICENCES-TIERCES
#                                          (CT-6 EX-14.10)
#   /etc/passwd                            noortrace-verificateur (10005)
#   /var/lib/noortrace-exports             10001:10005 2750 : mêmes droits que
#                                          l'image de l'enregistreur (volume
#                                          `exports` partagé, EX-3.5)
#   /run/temporaire                        1777 (TMPDIR)
# Point d'entrée : `noortrace-verifier` (EX-3.6). Compte : 10005:10005.

FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS construction
ARG SOURCE_DATE_EPOCH
COPY verificateur/ /src/verificateur/
COPY conteneurs/verificateur/passwd conteneurs/verificateur/group LICENSE NOTICE /contexte/
RUN set -eu; \
    : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH exigée (date du commit)}"; \
    cd /src/verificateur; \
    install -d -m 0755 /out/etc /out/usr/local/bin /out/usr/share/doc/noortrace /out/var/lib /out/run; \
    bash scripts/construire.sh -v 0.1.0 -p linux/amd64 -o /out/usr/local/bin/noortrace-verifier; \
    chown 0:0 /out/usr/local/bin/noortrace-verifier; chmod 0755 /out/usr/local/bin/noortrace-verifier; \
    install -m 0644 /contexte/passwd /out/etc/passwd; \
    install -m 0644 /contexte/group /out/etc/group; \
    install -m 0644 /contexte/LICENSE /contexte/NOTICE LICENCES-TIERCES /out/usr/share/doc/noortrace/; \
    install -d -o 10001 -g 10005 -m 2750 /out/var/lib/noortrace-exports; \
    install -d -o 0 -g 0 -m 1777 /out/run/temporaire; \
    find /out -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=0.1.0
ARG REVISION=inconnue
LABEL org.opencontainers.image.title="noortrace/verificateur" \
      org.opencontainers.image.description="Vérificateur noortrace-verifier (CT-6), binaire autonome sans réseau" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
COPY --from=construction /out/ /
WORKDIR /
USER 10005:10005
ENTRYPOINT ["/usr/local/bin/noortrace-verifier"]
