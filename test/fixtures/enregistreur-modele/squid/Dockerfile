# Image de test du mandataire d'interception Squid avec OpenSSL et ssl-bump,
# pour l'épreuve d'intégration ICAP TI-19 de CT-9 (CT-2 §19.6, CT-8 §5.3) :
# test/enregistreur-modele-squid.test.js la construit si elle manque.
#
#   docker build -t noortrace/squid-openssl:6.13-2-deb13u3 test/fixtures/enregistreur-modele/squid
#
# Pourquoi cette image : Squid ne fait l'interception TLS (ssl-bump) qu'avec
# OpenSSL ; le paquet `squid` de Debian et d'Ubuntu est construit avec GnuTLS
# (`--with-gnutls`), sans ssl-bump. Debian publie la construction OpenSSL sous
# le paquet `squid-openssl`.
#
# Versions épinglées : l'image de base par son condensé (index multi-plateforme
# servi par le registre : l'étiquette n'est qu'une indication lisible) ; les
# paquets par leur version exacte, lus dans un instantané daté de l'archive
# Debian (snapshot.debian.org), qui garde chaque version publiée : la
# construction est la même demain qu'aujourd'hui. L'intégrité des paquets est
# celle d'apt (fichier Release signé par l'archive, sommes SHA-256).
#
# Mandataire sortant à inspection TLS (facultatif) : un tel mandataire n'admet
# souvent que CONNECT, donc le schéma https ; son autorité est passée en secret
# de construction, jamais copiée dans l'image :
#   docker build --network host --build-arg HTTPS_PROXY=<mandataire> \
#     --secret id=autorite_sortante,src=<fichier PEM> -t <étiquette> <ce répertoire>
# Sans ce secret, l'archive est lue en http (intégrité vérifiée par apt).

FROM mirror.gcr.io/library/debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# Instantané de l'archive Debian et version exacte de squid-openssl (Debian 13,
# mise à jour 6.13-2+deb13u3, publiée le 2026-09-06).
ARG INSTANTANE=20261015T000000Z
ARG VERSION_SQUID=6.13-2+deb13u3

RUN --mount=type=secret,id=autorite_sortante,required=false,mode=0444 \
    set -eu; \
    rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; \
    schema=http; \
    if [ -s /run/secrets/autorite_sortante ]; then \
      schema=https; \
      echo "Acquire::https::CaInfo \"/run/secrets/autorite_sortante\";" > /etc/apt/apt.conf.d/99-autorite-sortante; \
    fi; \
    echo "deb [check-valid-until=no] ${schema}://snapshot.debian.org/archive/debian/${INSTANTANE} trixie main" > /etc/apt/sources.list.d/instantane.list; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      "squid-openssl=${VERSION_SQUID}" "squid-common=${VERSION_SQUID}" ca-certificates openssl; \
    rm -f /etc/apt/apt.conf.d/99-autorite-sortante; \
    rm -rf /var/lib/apt/lists/*; \
    squid -v | grep -q -- '--with-openssl'

# La configuration (SQUID_CONF), l'autorité d'interception et l'autorité du
# fournisseur simulé sont montées par le test ; la base des certificats
# générés est créée au lancement (security_file_certgen -c).
ENV SQUID_CONF=/etc/squid/squid.conf
EXPOSE 3128
CMD ["sh", "-c", "rm -rf /var/spool/squid/ssl_db && /usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB && chown -R proxy:proxy /var/spool/squid && exec squid -N -d 1 -f \"$SQUID_CONF\""]
