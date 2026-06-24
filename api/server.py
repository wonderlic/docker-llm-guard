from __future__ import annotations

import copy
import os
from typing import Any


def log_config_without_health_checks(base_config: dict[str, Any]) -> dict[str, Any]:
    log_config = copy.deepcopy(base_config)
    log_config.setdefault("filters", {})["health_check_access"] = {
        "()": "api.health_checks.HealthCheckAccessFilter",
    }
    access_handler = log_config.setdefault("handlers", {}).setdefault("access", {})
    access_handler["filters"] = [
        *access_handler.get("filters", []),
        "health_check_access",
    ]
    return log_config


def main() -> None:
    import uvicorn
    from uvicorn.config import LOGGING_CONFIG

    uvicorn.run(
        "api.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=int(os.environ.get("APP_PORT", "8000")),
        workers=int(os.environ.get("APP_WORKERS", "1")),
        forwarded_allow_ips="*",
        proxy_headers=True,
        timeout_keep_alive=2,
        log_config=log_config_without_health_checks(LOGGING_CONFIG),
    )


if __name__ == "__main__":
    main()
