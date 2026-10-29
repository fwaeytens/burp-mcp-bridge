# Tiny deterministic HTTP target. Multi-arch base so it runs on arm64 (the
# sandbox) and amd64 (CI) alike.
FROM node:22-alpine

WORKDIR /app
COPY server.js .

ENV TARGET_PORT=80
EXPOSE 80

# Node's built-in http only; no npm install step.
CMD ["node", "server.js"]
