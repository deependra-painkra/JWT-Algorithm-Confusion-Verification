#!/usr/bin/env python3
"""
Generate JWT test tokens with various payloads and algorithms
Usage: python generate_test_tokens.py
"""

import jwt
import json
from datetime import datetime, timedelta, UTC
import base64


def load_keys():
    """Load RSA keys"""
    with open("keys/server_private.pem", "r") as f:
        private_key = f.read()

    with open("keys/server_public.pem", "r") as f:
        public_key = f.read()

    with open("keys/attacker_private.pem", "r") as f:
        attacker_key = f.read()

    return private_key, public_key, attacker_key


def pem_to_hmac_secret(pem_key):
    """
    Convert PEM key into a raw string usable as HMAC secret
    (bypasses PyJWT asymmetric key check for testing)
    """
    lines = pem_key.strip().splitlines()
    key_body = "".join(line for line in lines if "-----" not in line)
    return key_body


def now():
    """Helper for current UTC time"""
    return datetime.now(UTC)


def create_base_token(private_key, algorithm="RS256"):
    payload = {
        "sub": "user123",
        "role": "user",
        "exp": now() + timedelta(hours=1),
        "iat": now()
    }
    return jwt.encode(payload, private_key, algorithm=algorithm)


def create_expired_token(private_key):
    payload = {
        "sub": "user123",
        "role": "user",
        "exp": now() - timedelta(hours=1),
        "iat": now() - timedelta(hours=2)
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def create_admin_token(private_key):
    payload = {
        "sub": "admin123",
        "role": "admin",
        "exp": now() + timedelta(hours=1),
        "iat": now()
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def decode_token_parts(token):
    parts = token.split(".")

    def decode_part(part):
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        return base64.urlsafe_b64decode(part)

    header = json.loads(decode_part(parts[0]))
    payload = json.loads(decode_part(parts[1]))
    signature = parts[2]

    return header, payload, signature


def encode_token_parts(header, payload, signature):
    def encode_part(obj):
        if isinstance(obj, dict):
            obj = json.dumps(obj, separators=(',', ':'))
        if isinstance(obj, str):
            obj = obj.encode()
        return base64.urlsafe_b64encode(obj).decode().rstrip("=")

    return f"{encode_part(header)}.{encode_part(payload)}.{signature}"


def generate_all_tokens():
    private_key, public_key, attacker_key = load_keys()

    tokens = {}

    # -------------------------
    # Valid tokens
    # -------------------------
    tokens['valid_rs256'] = create_base_token(private_key, "RS256")
    tokens['valid_admin_rs256'] = create_admin_token(private_key)

    # Expired
    tokens['expired'] = create_expired_token(private_key)

    # -------------------------
    # HS256 tokens
    # -------------------------
    payload = {
        "sub": "user123",
        "role": "user",
        "exp": int((now() + timedelta(hours=1)).timestamp()),
        "iat": int(now().timestamp())
    }

    # SAFE version (normal usage)
    hmac_secret = "supersecretkey"

    tokens['hs256'] = jwt.encode(payload, hmac_secret, algorithm="HS256")

    # VULNERABLE simulation (public key as HMAC secret)
    hmac_pubkey_secret = pem_to_hmac_secret(public_key)

    tokens['hs256_with_pubkey'] = jwt.encode(
        payload,
        hmac_pubkey_secret,
        algorithm="HS256"
    )

    # Tampered admin token
    tampered_payload = {
        "sub": "user123",
        "role": "admin",
        "exp": int((now() + timedelta(hours=1)).timestamp()),
        "iat": int(now().timestamp())
    }

    tokens['tampered_role_admin_hs256'] = jwt.encode(
        tampered_payload,
        hmac_pubkey_secret,
        algorithm="HS256"
    )

    # -------------------------
    # Algorithm confusion / edge cases
    # -------------------------
    header_none = {"alg": "none", "typ": "JWT"}
    payload_encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=")

    header_encoded = base64.urlsafe_b64encode(
        json.dumps(header_none).encode()
    ).decode().rstrip("=")

    tokens['alg_none'] = f"{header_encoded}.{payload_encoded}."

    # Null alg
    header_null = {"alg": None, "typ": "JWT"}
    tokens['alg_null'] = (
        f"{base64.urlsafe_b64encode(json.dumps(header_null).encode()).decode().rstrip('=')}"
        f".{payload_encoded}.FAKE_SIG"
    )

    # Empty alg
    header_empty = {"alg": "", "typ": "JWT"}
    tokens['alg_empty'] = (
        f"{base64.urlsafe_b64encode(json.dumps(header_empty).encode()).decode().rstrip('=')}"
        f".{payload_encoded}.FAKE_SIG"
    )

    # -------------------------
    # Attacker key token
    # -------------------------
    tokens['rs256_attacker_key'] = jwt.encode(
        payload,
        attacker_key,
        algorithm="RS256"
    )

    # -------------------------
    # Save output
    # -------------------------
    with open("keys/test_tokens.json", "w") as f:
        json.dump(tokens, f, indent=2)

    print("✓ Test tokens generated and saved to keys/test_tokens.json")
    print(f"Generated {len(tokens)} test tokens:")
    for key in tokens:
        print(f"  - {key}")


if __name__ == "__main__":
    generate_all_tokens()