# Caddy with the Cloudflare DNS plugin, built here rather than pulled from a
# third-party image. DNS-01 is the only way to get a cert for the mail host
# without touching ports 80/443, which belong to poste.io.
ARG CADDY_VERSION=2.11.7
FROM caddy:${CADDY_VERSION}-builder-alpine@sha256:ef9b65adf9a224770c6d5f6d1ae1bf99bc3caaa78d8c4bae3ea949ee6984f301 AS build
RUN xcaddy build --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:${CADDY_VERSION}-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
COPY --from=build /usr/bin/caddy /usr/bin/caddy
# Listens on 8443 only, so it needs no file capability. Stripping it lets the
# container run with cap_drop: ALL as a non-root user.
RUN setcap -r /usr/bin/caddy 2>/dev/null || true
