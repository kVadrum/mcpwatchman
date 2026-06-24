# Worker image for auditmcp scanners (scaffold). See ADR-002 for the tool stack.
#
# The production image also installs osv-scanner (a Go binary) and pins the base
# by SHA digest; this scaffold installs the Python worker deps only.
FROM python:3.12-slim AS base

# Scans run as a non-root user (uid 1000) per the sandboxing posture.
RUN useradd --create-home --uid 1000 scanner

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[workers]"

USER scanner
