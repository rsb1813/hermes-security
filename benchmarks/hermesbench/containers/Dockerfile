# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        python3 \
        ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global --no-audit --no-fund @openai/codex@0.150.0-alpha.8 \
    && codex --version \
    && npm cache clean --force

COPY containers/codex_auth_runtime.py /usr/local/bin/codex_auth_runtime.py
COPY schemas/prediction-response.schema.json /workspace/schema/prediction-response.schema.json
COPY schemas/hunt-discovery-response.schema.json /workspace/schema/hunt-discovery-response.schema.json
COPY schemas/hunt-verification-response.schema.json /workspace/schema/hunt-verification-response.schema.json

RUN chmod 0755 /usr/local/bin/codex_auth_runtime.py \
    && chmod 0444 /workspace/schema/prediction-response.schema.json /workspace/schema/hunt-discovery-response.schema.json /workspace/schema/hunt-verification-response.schema.json

RUN groupadd --gid 10001 hermesbench \
    && useradd --uid 10001 --gid 10001 --no-create-home hermesbench \
    && mkdir -p /workspace/scratch \
    && chown 10001:10001 /workspace/scratch

ENV HOME=/workspace/scratch

USER 10001:10001
WORKDIR /workspace/scratch

CMD ["sh"]
