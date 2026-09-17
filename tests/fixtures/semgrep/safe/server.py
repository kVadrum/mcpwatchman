"""The same operations done safely. NOTHING here may produce a finding."""
import json, os, subprocess, tarfile
from pathlib import Path

import requests
import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe")
ALLOWED = {"report.txt", "summary.txt"}


def run_pipeline(cmd):
    subprocess.run(["/usr/bin/env", "--", cmd], shell=False, check=True)


def list_dir(d):
    subprocess.run(["ls", "-la", d], check=True)


def fetch():
    requests.get("https://registry.modelcontextprotocol.io/v0/servers")


def load_state(blob):
    return json.loads(blob)


def load_config(text):
    return yaml.safe_load(text)


def calculate(a, b):
    return a + b


def read_doc(root, name):
    if name not in ALLOWED:
        raise ValueError(name)
    return (Path(root).resolve() / name).read_text()


def unpack(archive, dest):
    tarfile.open(archive).extractall(dest, filter="data")


def lookup(cur, user):
    cur.execute("SELECT * FROM users WHERE name = ?", (user,))


@mcp.tool()
def safe_tool(target: str) -> str:
    """Run a fixed command against a validated target."""
    if target not in ALLOWED:
        raise ValueError(target)
    return subprocess.run(["wc", "-l", target], capture_output=True).stdout.decode()


@mcp.tool()
def config_summary() -> dict:
    """Return non-secret configuration only."""
    return {"version": os.environ.get("APP_VERSION", "dev")}
