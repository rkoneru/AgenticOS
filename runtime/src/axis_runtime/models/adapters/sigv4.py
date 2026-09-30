"""AWS Signature Version 4, implemented by hand with hmac/hashlib (no boto3)."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        name, _, value = part.partition("=")
        pairs.append((quote(name, safe="-_.~"), quote(value, safe="-_.~")))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sign_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    now: datetime,
    session_token: str | None = None,
) -> dict[str, str]:
    """Return ``headers`` plus ``x-amz-date``, ``x-amz-security-token`` (if any) and
    ``authorization``.  ``url`` path must already be percent-encoded as it will be sent; for
    non-S3 services the canonical path is encoded a second time, as AWS specifies."""
    parts = urlsplit(url)
    utc = now.astimezone(UTC)
    amz_date = utc.strftime("%Y%m%dT%H%M%SZ")
    date = utc.strftime("%Y%m%d")

    signed = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    signed["host"] = parts.netloc
    signed["x-amz-date"] = amz_date
    if session_token:
        signed["x-amz-security-token"] = session_token

    names = sorted(signed)
    canonical_headers = "".join(f"{n}:{signed[n]}\n" for n in names)
    signed_headers = ";".join(names)
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_uri = quote(parts.path or "/", safe="/-_.~")
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            _canonical_query(parts.query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        signing_key(secret_key, date, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    out = {k: v for k, v in headers.items()}
    out["x-amz-date"] = amz_date
    if session_token:
        out["x-amz-security-token"] = session_token
    out["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return out
