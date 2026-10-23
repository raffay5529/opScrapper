import os
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

from flask import Flask, request, jsonify, Response
from curl_cffi import requests as cffi_requests
from bs4 import BeautifulSoup

app = Flask(__name__)

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_HOSTNAMES = {
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
}

MAX_REDIRECTS = 5


@app.before_request
def check_api_key():
    # Optional protection: only active if you set API_KEY in Vercel env vars.
    api_key = os.environ.get("API_KEY")
    if not api_key or request.path == "/":
        return
    if request.headers.get("x-api-key") != api_key:
        return jsonify(error="Unauthorized"), 401


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_url(url: str):
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False, "Invalid URL."

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, "Only http and https URLs are allowed."

    if not parsed.hostname:
        return False, "URL must include a hostname."

    hostname = parsed.hostname.lower()

    if hostname in BLOCKED_HOSTNAMES:
        return False, "Local/internal hostnames are blocked."

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, "Could not resolve hostname."
    except OSError as exc:
        return False, f"DNS lookup failed: {exc}"

    for info in addr_info:
        ip_str = info[4][0]
        if not is_public_ip(ip_str):
            return False, "Private/internal IP addresses are blocked."

    return True, ""


def safe_get(url: str):
    current_url = url

    for _ in range(MAX_REDIRECTS + 1):
        ok, error = validate_url(current_url)
        if not ok:
            return None, error, 400

        try:
            resp = cffi_requests.get(
                current_url,
                impersonate="chrome",
                timeout=15,
                allow_redirects=False,
            )
        except Exception as exc:
            return None, str(exc), 502

        if resp.status_code in {301, 302, 303, 307, 308}:
            location = resp.headers.get("location")
            if not location:
                return resp, None, None

            current_url = urljoin(current_url, location)
            continue

        return resp, None, None

    return None, "Too many redirects.", 502


@app.route("/")
def home():
    return "OK"


@app.route("/scrape")
def scrape():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify(error="Pass ?url=https://example.com"), 400

    resp, error, status_code = safe_get(url)

    if resp is None:
        return jsonify(error=error), status_code

    try:
        html = resp.text
    except Exception:
        html = resp.content.decode("utf-8", errors="replace")

    soup = BeautifulSoup(html, "html.parser")

    title = soup.title.get_text(strip=True) if soup.title else None
    text = soup.get_text(" ", strip=True)[:5000]

    return jsonify(
        status=resp.status_code,
        url=url,
        title=title,
        text=text,
    )


@app.route("/raw")
def raw():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify(error="Pass ?url=https://example.com"), 400

    resp, error, status_code = safe_get(url)

    if resp is None:
        return jsonify(error=error), status_code

    content_type = resp.headers.get("content-type", "application/octet-stream")

    return Response(
        resp.content,
        status=resp.status_code,
        headers={
            "Content-Type": content_type,
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/full")
def full():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify(error="Pass ?url=https://example.com"), 400

    resp, error, status_code = safe_get(url)

    if resp is None:
        return jsonify(error=error), status_code

    soup = BeautifulSoup(resp.text, "html.parser")
    text = soup.get_text("\n", strip=True)

    print("STATUS:", resp.status_code, "URL:", url)

    return Response(text, mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)