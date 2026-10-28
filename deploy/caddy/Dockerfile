# Caddy with the Cloudflare DNS plugin, built here rather than pulled from a
# third-party image. DNS-01 is the only way to get a cert for the mail host
# without touching ports 80/443, which belong to poste.io.
ARG CADDY_VERSION=2.11.7
FROM caddy:${CADDY_VERSION}-builder-alpine AS build
RUN xcaddy build --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:${CADDY_VERSION}-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
# Listens on 8443 only, so it needs no file capability. Stripping it lets the
# container run with cap_drop: ALL as a non-root user.
RUN setcap -r /usr/bin/caddy 2>/dev/null || true
