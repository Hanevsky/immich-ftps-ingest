FROM node:22.23.2-alpine3.24

ARG IMMICH_CLI_VERSION=3.1.0

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

RUN apk add --no-cache ca-certificates findutils util-linux \
    && npm install --global --omit=dev --ignore-scripts "@immich/cli@${IMMICH_CLI_VERSION}" \
    && npm cache clean --force \
    && addgroup -g 10001 app \
    && adduser -D -H -u 10001 -G app -s /sbin/nologin app \
    && mkdir -p /app /data /run/immich-certs /state \
    && chown -R app:app /app /data /state

WORKDIR /app

COPY --chown=app:app --chmod=0555 import-loop.sh /app/import-loop.sh
RUN sed -i 's/\r$//' /app/import-loop.sh

USER 10001:10001

ENTRYPOINT ["/app/import-loop.sh"]
