"""auditmcp JSON API (scaffold — only the health probe is live).

Run with: uvicorn auditmcp.api.main:app  (requires the `api` extra).
"""

from __future__ import annotations

from fastapi import FastAPI

from auditmcp import __version__

app = FastAPI(title="auditmcp API", version=__version__)


@app.get("/v1/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}
