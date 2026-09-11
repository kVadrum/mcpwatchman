"""mcpwatchman JSON API (scaffold — only the health probe is live).

Run with: uvicorn mcpwatchman.api.main:app  (requires the `api` extra).
"""

from __future__ import annotations

from fastapi import FastAPI

from mcpwatchman import __version__

app = FastAPI(title="mcpwatchman API", version=__version__)


@app.get("/v1/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}
