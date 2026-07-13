# syntax=docker/dockerfile:1.7

ARG LLM_GUARD_API_IMAGE=laiyer/llm-guard-api:latest

FROM ${LLM_GUARD_API_IMAGE} AS xet-enabled

RUN python -m pip install --user --no-cache-dir "huggingface_hub[hf_xet]"

FROM xet-enabled AS model-cache

ARG PRELOAD_MODELS=true

COPY --chown=user:user config/scanners.json /tmp/preload_scanners.json
COPY --chown=user:user scripts/preload_models.py /tmp/preload_models.py

ENV NLTK_DATA=/home/user/nltk_data

RUN --mount=type=cache,target=/home/user/.cache/huggingface-build,uid=1000,gid=1000 \
    --mount=type=cache,target=/home/user/nltk_data-build,uid=1000,gid=1000 \
    --mount=type=cache,target=/home/user/.cache/pip,uid=1000,gid=1000 \
    mkdir -p /home/user/.cache/huggingface /home/user/nltk_data && \
    if [ "$PRELOAD_MODELS" = "true" ]; then \
      rm -rf /home/user/.cache/huggingface /home/user/nltk_data; \
      HF_HOME=/home/user/.cache/huggingface-build \
      NLTK_DATA=/home/user/nltk_data-build \
      PIP_CACHE_DIR=/home/user/.cache/pip \
      python /tmp/preload_models.py --config /tmp/preload_scanners.json; \
      mkdir -p /home/user/.cache; \
      cp -a /home/user/.cache/huggingface-build /home/user/.cache/huggingface; \
      cp -a /home/user/nltk_data-build /home/user/nltk_data; \
    else \
      printf 'Skipping model preload. Runtime may download models.\n'; \
    fi

FROM xet-enabled

ARG PRELOAD_MODELS=true
ARG RUN_OFFLINE=false

COPY --from=model-cache --chown=user:user /home/user/.cache/huggingface /home/user/.cache/huggingface
COPY --from=model-cache --chown=user:user /home/user/nltk_data /home/user/nltk_data
COPY --chown=user:user api /home/user/app/api
COPY --chown=user:user entrypoint.sh /home/user/app/entrypoint.sh

RUN chmod +x /home/user/app/entrypoint.sh

ENV NLTK_DATA=/home/user/nltk_data

ENV HF_HUB_OFFLINE=${RUN_OFFLINE} \
    TRANSFORMERS_OFFLINE=${RUN_OFFLINE} \
    HF_DATASETS_OFFLINE=${RUN_OFFLINE}

ENTRYPOINT ["./entrypoint.sh"]
