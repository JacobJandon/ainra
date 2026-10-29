# SPDX-License-Identifier: Apache-2.0 OR MIT
# The hosted verifier (D-079). Build from the repository root, naming the commit it was built from:
#   docker build -f services/verify/Dockerfile --build-arg AINRA_BUILD=$(git rev-parse HEAD) -t ainra-verify .
# Run with the directory, roots and verifier key mounted read-only:
#   docker run -p 8787:8787 -v $PWD/trust:/trust:ro ainra-verify \
#     --directory /trust/directory.json --roots /trust/roots.json --key /trust/verifier.key
# /v1/about reports AINRA_BUILD, so a caller can tell which code answered.
FROM node:22.11.0-slim
ARG AINRA_BUILD=unknown
WORKDIR /app
COPY packages/sdk-ts /app/packages/sdk-ts
# Dev dependencies (the TypeScript compiler) are needed to build, then pruned; NODE_ENV is set only afterwards.
RUN cd packages/sdk-ts && npm ci --no-audit --no-fund && npm run build && npm prune --omit=dev
ENV AINRA_BUILD=${AINRA_BUILD} NODE_ENV=production
COPY services/verify/server.mjs /app/services/verify/server.mjs
USER node
EXPOSE 8787
ENTRYPOINT ["node", "services/verify/server.mjs", "--bind", "0.0.0.0"]
