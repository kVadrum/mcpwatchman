# Worker image for mcpwatchman scanners (scaffold). See ADR-002 for the tool stack.
#
# The production image also installs osv-scanner (a Go binary) and pins the base
# by SHA digest; this scaffold installs the Python worker deps only.
FROM python:3.12-slim AS base

# Scans run as a non-root user (uid 1000) per the sandboxing posture.
RUN useradd --create-home --uid 1000 scanner

# git is REQUIRED, not optional: `scanner/source.py` clones GitHub and GitLab
# sources, and `python:3.12-slim` does not ship it — without this every git-
# sourced scan died on a missing binary. ca-certificates so the clone can verify
# TLS. Removed from the apt lists in the same layer to keep the image small.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[workers]"

USER scanner
