#!/usr/bin/env python3

import json
import jwt
import base64
import requests
import time
import re
import hashlib
import argparse
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    r'"users?":\s*\[',
    r'"admin"',
    r'"email":\s*"',
    r'"password":\s*"',
    r'"token":\s*"',
    r'user\d+@',
    r'\$2[aby]\$',
]


def now():
    return datetime.now(UTC)


class JWTTokenManipulator:

    def __init__(self, public_key_path: str, private_key_path: str = None):
        with open(public_key_path, 'r') as f:
            self.public_key = f.read()

        if private_key_path:
            with open(private_key_path, 'r') as f:
                self.private_key = f.read()
        else:
            self.private_key = None

    def decode_token_parts(self, token):
        parts = token.split('.')

        def decode_part(part):
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            return json.loads(base64.urlsafe_b64decode(part))

        return decode_part(parts[0]), decode_part(parts[1]), parts[2]

    def encode_token_parts(self, header, payload, signature=""):
        def encode(obj):
            if isinstance(obj, dict):
                obj = json.dumps(obj, separators=(',', ':'))
            if isinstance(obj, str):
                obj = obj.encode()
            return base64.urlsafe_b64encode(obj).decode().rstrip("=")

        return f"{encode(header)}.{encode(payload)}.{signature}"

    def create_base_payload(self):
        return {
            "sub": "user123",
            "role": "user",
            "exp": int((now() + timedelta(hours=1)).timestamp()),
            "iat": int(now().timestamp())
        }

    def strategy_alg_none(self, token):
        h, p, _ = self.decode_token_parts(token)
        h['alg'] = 'none'
        return self.encode_token_parts(h, p, "")

    def strategy_hs256_with_pubkey(self, token):
        _, p, _ = self.decode_token_parts(token)
        return jwt.encode(p, self.public_key, algorithm='HS256')

    def strategy_tamper_role(self, token):
        _, p, _ = self.decode_token_parts(token)
        p['role'] = 'admin'
        return jwt.encode(p, self.public_key, algorithm='HS256')

    def strategy_expired(self):
        p = self.create_base_payload()
        p['exp'] = int((now() - timedelta(hours=1)).timestamp())
        return jwt.encode(p, self.private_key, algorithm='RS256')

    def strategy_valid(self):
        p = self.create_base_payload()
        return jwt.encode(p, self.private_key, algorithm='RS256')


class JWTVerificationTester:

    def __init__(self, target, pub, priv):
        self.target = target
        self.manip = JWTTokenManipulator(pub, priv)
        self.results = []

    def has_sensitive(self, text):
        return any(re.search(p, text, re.I) for p in SENSITIVE_PATTERNS)

    def test(self, name, func, expected):
        try:
            token = func()

            r = requests.get(
                self.target,
                headers={"Authorization": f"Bearer {token}"},
                timeout=3
            )

            result = {
                "test": name,
                "status": r.status_code,
                "sensitive": self.has_sensitive(r.text),
                "result": "PASS" if r.status_code == expected else "FAIL",
                "time": now().isoformat()
            }

        except Exception as e:
            result = {"test": name, "error": str(e), "result": "ERROR"}

        self.results.append(result)
        return result

    def run(self):
        base = self.manip.strategy_valid()

        self.test("valid_rs256", self.manip.strategy_valid, 200)
        self.test("alg_none", lambda: self.manip.strategy_alg_none(base), 401)
        self.test("hs256_pubkey", lambda: self.manip.strategy_hs256_with_pubkey(base), 401)
        self.test("tamper_admin", lambda: self.manip.strategy_tamper_role(base), 401)
        self.test("expired", self.manip.strategy_expired, 401)

        return self.results


def generate_report(results, target):
    return json.dumps({
        "target": target,
        "results": results
    }, indent=2)


def save_evidence(report, results, output_dir="evidence"):
    Path(output_dir).mkdir(exist_ok=True)

    ts = now().strftime('%Y%m%d_%H%M%S')

    report_path = Path(output_dir) / f"jwt_verification_report_{ts}.md"
    json_path = Path(output_dir) / f"jwt_verification_results_{ts}.json"
    hash_path = Path(output_dir) / f"jwt_verification_results_{ts}.sha256"

    with open(report_path, "w") as f:
        f.write(report)

    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    with open(json_path, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()

    with open(hash_path, "w") as f:
        f.write(f"{h}  {json_path.name}\n")

    return str(report_path), str(json_path), str(hash_path), h


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)

    tester = JWTVerificationTester(
        cfg["target"],
        cfg["public_key_path"],
        cfg["private_key_path"]
    )

    results = tester.run()
    report = generate_report(results, cfg["target"])

    report_path, json_path, hash_path, file_hash = save_evidence(report, results)

    print("\n==========================================")
    print("Test Suite Complete")
    print("==========================================\n")

    print("📊 Results saved to:")
    print(f"   - {report_path}")
    print(f"   - {json_path}")
    print(f"   - {hash_path}")

    print("\n==========================================")
    print("DONE")
    print("==========================================")


if __name__ == "__main__":
    main()
