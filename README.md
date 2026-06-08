# docker-llm-guard

Custom prompt-scanning API built on the official LLM Guard API image.

Scanner configuration is sent with each prompt request. The container does not bake a runtime `scanners.json`; `config/scanners.json` is a build-time model preload manifest and repository example for shaping request payloads.

## Build

```sh
docker build -t docker-llm-guard .
```

To pin or swap the upstream image:

```sh
docker build \
  --build-arg LLM_GUARD_API_IMAGE=laiyer/llm-guard-api:latest \
  -t docker-llm-guard .
```

By default, the build warms model caches using the scanner types in `config/scanners.json`. That file is not used by the running API to decide what to scan; runtime scanner configuration still comes from request bodies.

For a faster development build that skips cache warmup:

```sh
docker build \
  --build-arg PRELOAD_MODELS=false \
  -t docker-llm-guard .
```

Runtime model downloads are still enabled by default because scanner configs are request-scoped. The container may contact Hugging Face if an incoming scanner config needs a model that was not warmed during the build, if the image was built with `PRELOAD_MODELS=false`, or if the baked cache was not copied into the final image. Set `RUN_OFFLINE=true` only when the image or runtime cache already contains every model required by incoming scanner configs.

## Run

```sh
docker run -d \
  -p 8000:8000 \
  -e AUTH_TOKEN='my-token' \
  docker-llm-guard
```

## Docker Compose

Copy `.env.example` to `.env`, set `AUTH_TOKEN`, then run:

```sh
docker compose up --build
```

The API listens on `http://localhost:8000` by default. Local Phoenix runs on `http://localhost:6006`.

Do not commit `.env`; it can contain API keys and auth tokens.

## Tracing

The custom FastAPI app exports OpenTelemetry traces when `TRACING_EXPORTER=otel_http`. Compose defaults to the local Phoenix sidecar:

```sh
TRACING_EXPORTER=otel_http
TRACING_OTEL_ENDPOINT=http://phoenix:6006/v1/traces
OTEL_EXPORTER_OTLP_TRACES_HEADERS=x-project-name=llm-guard
```

The app emits FastAPI request spans plus scanner-level spans with scanner direction, scanner type, config fingerprint, cache hit, validity, risk score, and changed status. Prompt and output text are not added to span attributes.

To verify inbound trace context during debugging, set `TRACE_HEADER_DEBUG=true`. The app will print one JSON line per request with the received `traceparent`, the active OTEL trace/span IDs, and presence flags for `tracestate` and `baggage`. It does not print `tracestate` or `baggage` values.

For Phoenix Cloud, set these in `.env`:

```sh
TRACING_OTEL_ENDPOINT=https://app.phoenix.arize.com/s/your-space-name/v1/traces
OTEL_EXPORTER_OTLP_TRACES_HEADERS=authorization=Bearer%20your-phoenix-api-key,x-project-name=llm-guard
```

Use the Hostname from Phoenix Cloud Settings. The generic `https://app.phoenix.arize.com/v1/traces` endpoint will not route to your space. Spaces in the Authorization header must be URL-encoded as `%20`; otherwise Phoenix may return `401`.

For Arize AX, set these in `.env`:

```sh
PHOENIX_API_VERSION=arize-ax
PHOENIX_SPACE_ID=U3BhY2U6MjY2MDg6RDMwbg==
PHOENIX_API_KEY=your-arize-api-key
PHOENIX_TRACING_PROJECT_NAME=llm-guard
```

When `PHOENIX_API_VERSION=arize-ax`, the app sends OTLP/HTTP traces to `https://otlp.arize.com/v1/traces` unless `PHOENIX_TRACING_COLLECTOR_ENDPOINT` is explicitly set. It derives `OTEL_EXPORTER_OTLP_TRACES_HEADERS` with `arize-space-id` and `arize-api-key`, and routes the AX project through the `openinference.project.name` resource attribute.

## Detailed Prompt Scan API

Use `POST /scan/prompt/detailed` to scan a prompt with request-provided input scanners.
Send `prompt`, `input_scanners`, and optional `fail_fast` in the request body. Each scanner config contains `type`, optional `active`, and `params`.

The response includes the final `sanitized_prompt`, an overall `is_valid` flag, an overall `risk_score`, an active request `config_fingerprint`, and a `scanners` array. Each scanner result includes `index`, `instance_id`, `type`, `config_fingerprint`, `cache_hit`, `is_valid`, `risk_score`, `changed`, and `threshold` when available.

For `BanTopics`, each scanner result may also include `matched_topic`, `matched_score`, `matched_topics`, `effective_score`, `multi_label`, and per-topic scores.

Set `fail_fast` to `true` in the request body to stop after the first invalid scanner. The default is `false`, so each active scanner reports details.

## Detailed Output Scan API

Use `POST /scan/output/detailed` to scan model output with request-provided output scanners. Send `prompt`, `output`, `output_scanners`, and optional `fail_fast` in the request body.

The response mirrors prompt scanning but returns `sanitized_output`.

## Scanner Cache

The API rejects requests that include the same scanner `type` more than once in `input_scanners` or `output_scanners`.

All submitted scanner configs supported by the endpoint direction participate in cache membership and warmup. Only active scanner configs participate in scanning and response fingerprints. The `active` flag itself is not part of the scanner config fingerprint.

Inactive scanner configs for the other direction can be included in a request and are ignored by that endpoint. For example, an inactive output-only `Sensitive` config may be present in `input_scanners`, but it will only warm/cache when sent to the output endpoint. Marking a direction-unsupported scanner active returns `422`.

Direction-agnostic scanner types, such as `BanTopics`, `Toxicity`, `Language`, and `Gibberish`, are fingerprinted from `type` and `params` and cached once across input and output scans when those params match. If the same scanner type arrives later with different params, that direction's cache set is updated to the new fingerprint.

Direction-specific scanner types are fingerprinted from scanner direction, `type`, and `params`, so they remain cached separately.

The cache keeps exactly the scanner set from the most recent prompt scan and the scanner set from the most recent output scan. A later prompt scan replaces only the previous prompt scanner set, and a later output scan replaces only the previous output scanner set. Repeated requests with the same scanner config reuse those scanner instances and return `cache_hit: true`.

Idle scanner cache entries are evicted after `SCANNER_CACHE_TTL_SECONDS`, which defaults to `172800` seconds, or about 48 hours. A background daemon checks for idle entries periodically, and requests also trigger opportunistic eviction.

Use `GET /scan/cache` to inspect cache state:

```sh
curl -s http://localhost:8000/scan/cache \
  -H 'Authorization: Bearer my-token'
```

## Scanner Notes

Use concise zero-shot candidate labels for `BanTopics` rather than full policy sentences. Broad labels can increase false positives and should be validated against representative prompts.

Set `multi_label` to `true` in `BanTopics` params to score each topic independently. The default is `false`, which forces the classifier to choose the best-fitting label from the provided topic list.

Do not add `model_max_length` to `Anonymize`, `BanCompetitors`, or `Sensitive` in this image. Those scanners use token-classification pipelines, and the installed Transformers version rejects `max_length` during pipeline construction.
