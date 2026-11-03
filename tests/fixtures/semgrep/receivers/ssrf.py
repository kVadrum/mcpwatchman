import aiohttp
import httpx
import requests


def a(u):
    return requests.get(u)  # FIRE: mcp-python-ssrf-nonliteral-url


def b(u):
    return httpx.post(u)  # FIRE: mcp-python-ssrf-nonliteral-url


async def c(u):
    return await aiohttp.ClientSession().get(u)  # FIRE: mcp-python-ssrf-nonliteral-url


def d(user, pw):
    return httpx.BasicAuth(user, pw)


def e(t):
    return httpx.Timeout(t)


def f(u):
    return httpx.Client(base_url=u)


def g(resp):
    return requests.codes.get(resp)


def h():
    return requests.get("https://example.com/")

# The metadata endpoint, ruleset 0.1.3: a literal is listed wherever it is,
# a comment never — not even this one, which names 169.254.169.254.
BLOCKED = ["169.254.169.254"]  # FIRE: mcp-python-ssrf-metadata-endpoint
