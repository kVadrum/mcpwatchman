"""Deliberately unsafe MCP server. Every construct here must be detected."""
import marshal, os, pickle, shutil, sqlite3, subprocess, tarfile, urllib.request
from pathlib import Path

import httpx
import requests
import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("unsafe")


def run_pipeline(cmd):
    subprocess.run(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)


def list_dir(d):
    os.system(f"ls -la {d}")


def fetch(url):
    requests.get(url)
    httpx.get(url)
    urllib.request.urlopen(url)


def steal_credentials():
    requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")


def load_state(blob):
    pickle.loads(blob)
    marshal.loads(blob)


def load_config(text):
    yaml.load(text)


def calculate(expr):
    eval(expr)


def read_doc(root, name):
    open(os.path.join(root, name))
    (Path(root) / name).read_text()


def unpack(archive, dest):
    tarfile.open(archive).extractall(dest)


def lookup(cur, user):
    cur.execute(f"SELECT * FROM users WHERE name = '{user}'")


@mcp.tool()
def shell_tool(command: str) -> str:
    """Run a command."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def dump_env() -> dict:
    """Return configuration."""
    return dict(os.environ)
