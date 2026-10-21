# Image conteneur du nœud noorcore pour NOORTRACE.
#
# Pourquoi une image : le binaire de chain/runtime/bin/noorcore est construit sur
# la machine de développement, avec le Go qui s'y trouve ; cette image fige la
# même construction (Go épinglé, commit de noorchain-core épinglé, `go build
# ./core`) dans un artefact que l'on peut livrer tel quel à un validateur ou à un
# client qui veut un suiveur chez lui. Les drapeaux de lancement viennent TOUS de
# la commande : l'image n'a pas de mode par défaut, parce que noorcore lancé sans
# drapeaux démarre une chaîne locale de banc d'essai (rôle « follower » sans
# `-follow-rpc`, chaîne 2121, données dans ./data), ce qui n'est jamais ce que
# l'on veut en production.
#
#   docker build -t noortrace/noorcore:d3e7ec0 chain/docker
#   docker build --build-arg NOORCORE_COMMIT=<sha> -t noortrace/noorcore:<tag> chain/docker
#
# Voir chain/docker/README.md pour l'exécution (validateur, suiveur), les
# volumes, les ports et les variables.

# --- versions épinglées -------------------------------------------------------
# GO_VERSION est la version imposée par le go.mod de noorchain-core (« go 1.26.9 ») ;
# avec GOTOOLCHAIN=local plus bas, un go.mod qui demanderait plus récent fait
# échouer la construction au lieu de télécharger une autre chaîne en silence.
ARG GO_VERSION=1.26.9
ARG NOORCORE_REPO=https://github.com/noorfinances-eng/noorchain-core.git
ARG NOORCORE_COMMIT=d3e7ec030b4060ceb3e924d49731054cb2cc2963

# --- étape 1 : construction ----------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS build
ARG NOORCORE_REPO
ARG NOORCORE_COMMIT
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1
WORKDIR /src

# Clone à profondeur 1 du commit demandé (pas d'une branche : un commit ne bouge
# pas), puis vérification que la tête est bien ce commit.
#
# Deux secrets BuildKit facultatifs, jamais écrits dans une couche :
#   github_token  jeton d'accès au dépôt noorchain-core, qui est PRIVÉ ; passé
#                 en en-tête HTTP de la seule commande fetch
#                 (docker build --secret id=github_token,src=…) ;
#   ca_bundle     UNIQUEMENT derrière un mandataire d'entreprise qui réécrit
#                 TLS : l'autorité à faire confiance, pour git et pour go, sans
#                 jamais désactiver la vérification.
# Absents, rien ne change : le fetch est anonyme et la confiance TLS est celle
# de l'image Go.
RUN --mount=type=secret,id=ca_bundle \
    --mount=type=secret,id=github_token \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then \
        export SSL_CERT_FILE=/run/secrets/ca_bundle GIT_SSL_CAINFO=/run/secrets/ca_bundle; \
    fi; \
    auth=""; \
    if [ -s /run/secrets/github_token ]; then \
        auth="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$(cat /run/secrets/github_token)" | base64 -w0)"; \
    fi; \
    git init -q .; \
    git remote add origin "$NOORCORE_REPO"; \
    git -c http.extraheader="$auth" fetch -q --depth 1 origin "$NOORCORE_COMMIT"; \
    git checkout -q --detach FETCH_HEAD; \
    tete="$(git rev-parse HEAD)"; \
    [ "$tete" = "$NOORCORE_COMMIT" ] || { echo "clone à $tete, attendu $NOORCORE_COMMIT" >&2; exit 1; }; \
    echo "noorchain-core au commit $tete, $(grep '^go ' go.mod)"

# `go build ./core`, comme chain/scripts/build-noorcore.sh. -trimpath retire les
# chemins de l'étape de construction du binaire ; les caches de modules et de
# compilation sont des montages BuildKit, jamais copiés dans l'image.
RUN --mount=type=secret,id=ca_bundle \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    if [ -s /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    go version; \
    go build -trimpath -o /out/usr/local/bin/noorcore ./core; \
    mkdir -p /out/var/lib/noorcore; \
    /out/usr/local/bin/noorcore -h 2>&1 | head -n 3 || true

# --- étape 2 : image finale ----------------------------------------------------
# distroless « base » (Debian 12, comme l'étape de construction) : glibc, les
# autorités TLS et tzdata, rien d'autre (ni shell, ni gestionnaire de paquets).
# Le binaire est lié dynamiquement à la libc parce que la cryptographie secp256k1
# de go-ethereum passe par cgo ; alpine (musl) exigerait une couche de
# compatibilité, debian 12 des deux côtés garantit la même libc. L'étiquette
# `nonroot` fournit l'utilisateur 65532:65532.
FROM gcr.io/distroless/base-debian12:nonroot
ARG NOORCORE_REPO
ARG NOORCORE_COMMIT
LABEL org.opencontainers.image.title="noorcore" \
      org.opencontainers.image.description="Nœud noorcore (noorchain-core) pour l'instance NOORTRACE : validateur BFT ou suiveur RPC" \
      org.opencontainers.image.source="${NOORCORE_REPO}" \
      org.opencontainers.image.revision="${NOORCORE_COMMIT}"

COPY --from=build /out/usr/local/bin/noorcore /usr/local/bin/noorcore
# Le répertoire de données est créé vide et appartient à l'utilisateur non
# root ; un volume anonyme en hérite. Un montage lié (bind) doit appartenir à
# 65532:65532 sur l'hôte (voir README.md).
COPY --from=build --chown=65532:65532 /out/var/lib/noorcore /var/lib/noorcore
VOLUME /var/lib/noorcore
WORKDIR /var/lib/noorcore

# Documentation seulement : les adresses d'écoute réelles viennent des drapeaux
# -rpc-addr, -health-addr, -metrics-addr et -p2p-addr. Dans un conteneur en
# réseau ponté, écouter sur 0.0.0.0 exige -allow-public-bind.
EXPOSE 8545 8080 9090 30303

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/noorcore"]
# Pas de CMD : aucun mode par défaut, les drapeaux viennent de la commande.
