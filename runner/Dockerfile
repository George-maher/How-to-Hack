# Runner service image.
#
# Contains the Docker CLI (to start one-shot scanner containers) and nothing
# else: no PHP, no database client, no Redis client, no compiler. It is the only
# component allowed to start a container, and it can only start registry tools.
FROM node:20-alpine

RUN apk add --no-cache docker-cli ca-certificates \
    && addgroup -g 10001 runner \
    && adduser -u 10001 -G runner -s /sbin/nologin -D runner

WORKDIR /app

# No runtime dependencies to install.
COPY --chown=runner:runner package.json ./
COPY --chown=runner:runner src ./src

USER runner

ENV NODE_ENV=production \
    RUNNER_PORT=8080 \
    RUNNER_HOST=0.0.0.0

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O- "http://127.0.0.1:${RUNNER_PORT}/health" >/dev/null || exit 1

CMD ["node", "src/index.mjs"]
