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

The API listens on `http://localhost:8000` by default.

Do not commit `.env`; it can contain API keys and auth tokens.

## Tracing

The custom FastAPI app exports OpenTelemetry traces when `TRACING_EXPORTER=otel_http`:

```sh
TRACING_EXPORTER=otel_http
TRACING_OTEL_ENDPOINT=https://otel-collector.example.test/v1/traces
OTEL_EXPORTER_OTLP_TRACES_HEADERS=authorization=Bearer%20your-token
```

The app accepts `TRACING_OTEL_ENDPOINT` or the standard `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`. It also accepts `OTEL_EXPORTER_OTLP_ENDPOINT` as a base URL and appends `/v1/traces`. Any `OTEL_EXPORTER_OTLP_TRACES_HEADERS` value is used as-is.

OTLP tracing is disabled when no endpoint is configured, preventing the exporter from silently falling back to `http://localhost:4318/v1/traces`. Set `TRACING_EXPORTER=none` to disable tracing explicitly.

The app emits FastAPI request spans plus scanner-level spans with scanner direction, scanner type, config fingerprint, cache hit, validity, risk score, raw score when available, and changed status. Prompt and output text are not added to span attributes.

To verify inbound trace context during debugging, set `TRACE_HEADER_DEBUG=true`. The app will print one JSON line per request with the received `traceparent`, the active OTEL trace/span IDs, and presence flags for `tracestate` and `baggage`. It does not print `tracestate` or `baggage` values.

## Load Testing

Use `scripts/load_test.py` to run a no-dependency load test against the detailed scan API. It supports configurable virtual users, sequential requests per user, linear ramp-up, bearer auth, warm-up requests, progress logs, and summary latency/status/error stats.

```sh
AUTH_TOKEN=my-token python scripts/load_test.py \
  --base-url http://localhost:8000 \
  --users 25 \
  --requests-per-user 20 \
  --ramp-up-seconds 60 \
  --warmup-requests 5
```

The default payload posts to `/scan/prompt/detailed` with a lightweight `TokenLimit` input scanner. To test a realistic scanner mix, save a detailed scan request body to a JSON file and pass it with `--payload-file`:

```sh
AUTH_TOKEN=my-token python scripts/load_test.py \
  --base-url http://localhost:8000 \
  --payload-file prompt-load-payload.json \
  --users 50 \
  --requests-per-user 10 \
  --ramp-up-seconds 120 \
  --stats-json load-test-stats.json
```

With the bundled compose file, use `--base-url http://localhost:7800` unless you change the port mapping. Add `--fail-on-errors` when you want the command to exit non-zero if any measured request returns a non-2xx response or connection error.

The script prints an example `curl` request before it starts so you can inspect the exact URL, headers, and JSON body being sent. Bearer tokens are redacted in the preview; use `--no-curl` to suppress it.

To use the bundled scanner config in `config/load-test-scanners.json`, pass it with `--scanner-config-file`. The script converts `useForInput` scanners into `input_scanners` for prompt scans and `useForOutput` scanners into `output_scanners` for output scans. It also converts top-level `BanTopics.topics` entries into the API's `params.topics` format.

```sh
AUTH_TOKEN=my-token python scripts/load_test.py \
  --base-url http://localhost:8000 \
  --scanner-config-file config/load-test-scanners.json \
  --users 25 \
  --requests-per-user 20 \
  --ramp-up-seconds 60
```

For output scans, set `--endpoint output` and provide representative `--prompt` and `--output` text:

```sh
AUTH_TOKEN=my-token python scripts/load_test.py \
  --endpoint output \
  --base-url http://localhost:8000 \
  --scanner-config-file config/load-test-scanners.json \
  --prompt 'What should candidates know about company policy?' \
  --output 'Candidates can review the handbook for general company policy details.' \
  --users 25 \
  --requests-per-user 20 \
  --ramp-up-seconds 60
```

## Detailed Prompt Scan API

Use `POST /scan/prompt/detailed/stream` to scan a prompt with request-provided input scanners over SSE. Send `prompt`, `input_scanners`, and optional `fail_fast` in the request body. Each scanner config contains `type`, optional `active`, and `params`.

The endpoint streams `text/event-stream` responses. It emits `start`, `progress`, `scanner_start`, `scanner_complete`, and final `complete` events. A `progress` event with `status: "queued"` is sent before each scanner starts. Once the scanner is running, `scanner_start` and periodic `progress` events use `status: "running"`. During long scanner calls, `progress` events are emitted every 15 seconds with queue position details: `current`, `total`, `remaining`, `direction`, `instance_id`, `type`, and `cache_hit`.

The final `complete` event data includes the final `sanitized_prompt`, an overall `is_valid` flag, an overall `risk_score`, an active request `config_fingerprint`, and a `scanners` array. Each scanner result includes `index`, `instance_id`, `type`, `config_fingerprint`, `cache_hit`, `is_valid`, `risk_score`, nullable `raw_score`, `changed`, and `threshold` when available. `raw_score` is the scanner's unnormalized decision metric and does not depend on `is_valid` or `risk_score`.

The existing `POST /scan/prompt/detailed` endpoint remains available with its original JSON response for compatibility, but is deprecated in favor of the SSE endpoint.

For `BanTopics`, each scanner result may also include `matched_topic`, `matched_score`, `matched_topics`, `effective_score`, `multi_label`, and per-topic scores.

Set `fail_fast` to `true` in the request body to stop after the first invalid scanner. The default is `false`, so each active scanner reports details.

## Detailed Output Scan API

Use `POST /scan/output/detailed/stream` to scan model output with request-provided output scanners. Send `prompt`, `output`, `output_scanners`, and optional `fail_fast` in the request body.

The endpoint streams the same SSE event sequence as prompt scanning. The final `complete` event data mirrors prompt scanning but returns `sanitized_output`.

The existing `POST /scan/output/detailed` endpoint remains available with its original JSON response for compatibility, but is deprecated in favor of the SSE endpoint.

## Scanner Cache

The API rejects requests that include the same scanner `type` more than once in `input_scanners` or `output_scanners`.

All submitted scanner configs supported by the endpoint direction participate in cache membership and warmup. Only active scanner configs participate in scanning and response fingerprints. The `active` flag itself is not part of the scanner config fingerprint.

Inactive scanner configs for the other direction can be included in a request and are ignored by that endpoint. For example, an inactive output-only `Sensitive` config may be present in `input_scanners`, but it will only warm/cache when sent to the output endpoint. Marking a direction-unsupported scanner active returns `422`.

Direction-agnostic scanner types, such as `BanTopics`, `Toxicity`, `Language`, and `Gibberish`, are fingerprinted from `type` and `params` and cached once across input and output scans when those params match. If the same scanner type arrives later with different params, that direction's cache set is updated to the new fingerprint.

Direction-specific scanner types are fingerprinted from scanner direction, `type`, and `params`, so they remain cached separately.

Request `threshold` and `minimum_score` values are policy inputs and do not affect scanner fingerprints or model construction. The service uses stable, nonzero scoring thresholds so cached scanners produce complete raw decision scores; callers should apply policy thresholds to each result's `raw_score`.

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
