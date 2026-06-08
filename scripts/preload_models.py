#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import os
import sys
from pathlib import Path

from app import scanner as scanner_factory
from app.config import get_config
from llm_guard.vault import Vault


def scanner_names(scanners) -> str:
    return ", ".join(scanner.type for scanner in scanners)


def scanner_instantiation_params(scanner) -> dict:
    params = dict(scanner.params or {})
    if scanner.type == "BanTopics":
        params.pop("multi_label", None)

    return params


def validate_config(config) -> None:
    unsupported_model_max_length = {
        ("input", "Anonymize"),
        ("input", "BanCompetitors"),
        ("output", "Sensitive"),
    }

    for source, scanners in (
        ("input", config.input_scanners),
        ("output", config.output_scanners),
    ):
        for scanner in scanners:
            if (
                source,
                scanner.type,
            ) in unsupported_model_max_length and "model_max_length" in (scanner.params or {}):
                raise ValueError(
                    f"{source} scanner {scanner.type} does not support model_max_length "
                    "in this LLM Guard image"
                )


def write_huggingface_snapshot_refs() -> None:
    hf_home = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface"))
    hub_cache = hf_home / "hub"
    if not hub_cache.exists():
        print(f"Hugging Face hub cache not found: {hub_cache}")
        return

    refs_written = 0
    for model_cache in hub_cache.glob("models--*"):
        snapshots_dir = model_cache / "snapshots"
        if not snapshots_dir.is_dir():
            continue

        refs_dir = model_cache / "refs"
        refs_dir.mkdir(exist_ok=True)
        for snapshot_dir in snapshots_dir.iterdir():
            if not snapshot_dir.is_dir():
                continue

            revision = snapshot_dir.name
            ref_file = refs_dir / revision
            ref_file.write_text(revision)
            refs_written += 1

    print(f"Wrote {refs_written} Hugging Face snapshot refs")


def main() -> int:
    parser = argparse.ArgumentParser(description="Warm model caches for common scanner configs")
    parser.add_argument("--config", default="/tmp/preload_scanners.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    config = get_config(args.config)
    if config is None:
        print(f"Failed to load config: {args.config}", file=sys.stderr)
        return 1

    print(f"Configured input preload scanners: {scanner_names(config.input_scanners)}")
    print(f"Configured output preload scanners: {scanner_names(config.output_scanners)}")
    validate_config(config)

    if args.dry_run:
        return 0

    vault = Vault()

    for scanner in config.input_scanners:
        print(f"Preloading input scanner: {scanner.type}", flush=True)
        loaded_scanner = scanner_factory._get_input_scanner(
            scanner.type,
            scanner_instantiation_params(scanner),
            vault=vault,
        )
        del loaded_scanner
        gc.collect()

    for scanner in config.output_scanners:
        print(f"Preloading output scanner: {scanner.type}", flush=True)
        loaded_scanner = scanner_factory._get_output_scanner(
            scanner.type,
            scanner_instantiation_params(scanner),
            vault=vault,
        )
        del loaded_scanner
        gc.collect()

    print(f"Preloaded {len(config.input_scanners)} input scanners")
    print(f"Preloaded {len(config.output_scanners)} output scanners")
    write_huggingface_snapshot_refs()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
