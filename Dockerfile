# syntax=docker/dockerfile:1

# The server depends on the core by path (../../veilway) and the web app on the design system (../../veilway-ui), so both are cloned beside this repo, at the refs given here.
FROM alpine:3.22 AS sources
ARG VEILWAY_REF=main
ARG VEILWAY_UI_REF=main
# hadolint ignore=DL3018
RUN apk add --no-cache git \
 && git clone --depth 1 --branch "$VEILWAY_REF" https://github.com/veilway-project/veilway.git /src/veilway \
 && git clone --depth 1 --branch "$VEILWAY_UI_REF" https://github.com/veilway-project/veilway-ui.git /src/veilway-ui

FROM node:22-alpine AS web
WORKDIR /src/veilway-panel/web
COPY --from=sources /src/veilway-ui /src/veilway-ui
# npm links the design system and does not install its own dependencies (fonts, charts), so the build cannot resolve them without this.
RUN for d in i18n ui; do (cd /src/veilway-ui/packages/$d && npm ci --no-audit --no-fund) || exit 1; done
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1-alpine AS build
# hadolint ignore=DL3018
RUN apk add --no-cache build-base perl
WORKDIR /src/veilway-panel/server
COPY --from=sources /src/veilway /src/veilway
COPY server/ ./
COPY --from=web /src/veilway-panel/web/dist /src/veilway-panel/web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/veilway-panel/server/target \
    cargo build --release --locked --bin veilway-panel && cp target/release/veilway-panel /veilway-panel

FROM alpine:3.22
RUN mkdir -p /etc/veilway-panel /var/lib/veilway-panel \
 && chown 65532:65532 /etc/veilway-panel /var/lib/veilway-panel
COPY --from=build /veilway-panel /usr/local/bin/veilway-panel
USER 65532:65532
WORKDIR /var/lib/veilway-panel
VOLUME ["/etc/veilway-panel", "/var/lib/veilway-panel"]
LABEL org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["veilway-panel", "run", "--config", "/etc/veilway-panel/panel.json"]
