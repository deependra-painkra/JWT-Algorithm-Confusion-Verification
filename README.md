# JWT-Algorithm-Confusion-Verification
Comprehensive JWT algorithm confusion remediation verification framework with threat modeling, test design, and working implementation

# PART A: Threat Modelling - JWT Algorithm Confusion Attack

## 1. ALGORITHM CONFUSION ATTACK EXPLANATION

### What Is Algorithm Confusion?

Algorithm confusion is a vulnerability class where the JWT verification logic accepts multiple signing algorithms and can be tricked into accepting tokens signed with an unintended algorithm.

### The Core Vulnerability Mechanism

The original server code operated under this **critical assumption**:

> "The signing algorithm specified in the JWT header (`alg` claim) is trusted and determines which key material should be used for verification."

This assumption is **exploitable** because:

#### 1. **Asymmetric-to-Symmetric Downgrade**
- The server was configured to verify RS256 tokens (RSA with SHA-256), which requires the private key for signing and the public key for verification.
- However, the code also accepted HS256 tokens (HMAC with SHA-256), which uses a shared secret key.

#### 2. **Public Key as Secret**
- The attacker obtained the server's public key (which is intentionally public), and used it as the HMAC secret in HS256 algorithm.
- This works because:
  - RS256 verification: `VERIFY(token, public_key_RS256)`
  - HS256 verification: `VERIFY(token, shared_secret_HS256)`
  - If `public_key == shared_secret`, the same key material performs both operations.

#### 3. **Attack Execution**
- The attacker:
  - Took a legitimate admin API token payload (e.g., `{"sub": "user123", "role": "user"}`)
  - Modified the header to `{"alg": "HS256", "typ": "JWT"}`
  - Signed it using HMAC-SHA256 with the server's public key as the secret
  - Sent it to the server, which incorrectly trusted the `alg` header and verified using HS256 logic

### Why This Worked

The vulnerable code likely followed this pattern:

```python
# VULNERABLE CODE PATTERN
import jwt

public_key = load_public_key_pem()  # Intentionally public

def verify_token(token):
    decoded = jwt.decode(
        token,
        public_key,  # Single key for all algorithms
        algorithms=["RS256", "HS256"]  # BUG: Accept both
    )
    return decoded
```
### The Critical Flaw
When the library sees `"alg": "HS256"` in the header, it treats `public_key` as an HMAC secret instead of as an RSA public key. The attacker can now forge valid tokens without the private key.

**Named Attack Vectors**
* **Key Confusion Vector:** Conflating key purposes (public key ↔ shared secret)
* **Algorithm Override Vector:** Trusting untrusted `alg` header without strict enforcement
* **Downgrade Attack:** Forcing a move from stronger (RSA) to weaker (HMAC) schemes
* **HMAC Forgery:** Creating valid HMAC signatures without knowledge of the private key
* **Signature Algorithm Substitution:** Replacing intended algorithm with attacker-controlled variant

**Original Vulnerability Root Cause**
The server made three critical mistakes:
1.  **Trusted the `alg` Header:** The JWT header is user-controlled and should not determine algorithm behavior.
2.  **Multi-Algorithm Support:** Accepting both `RS256` and `HS256` without explicit key binding to the algorithm.
3.  **No Algorithm Validation:** Failing to verify that the token's algorithm matches the expected algorithm.

---

### 2. Client's Claimed Fix Analysis

**Client Claim**
> "Fixed by enforcing strict RS256 algorithm validation on all incoming tokens"

**What This Should Mean**
The client should have implemented a structure like this:

```python
# FIXED CODE PATTERN
def verify_token(token):
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"]  # ONLY RS256
    )
    return decoded
```

**Why This Mitigates (But Doesn't Fully Guarantee)**
* ✅ Prevents `HS256` forgery (algorithm must match)
* ✅ Prevents `alg: none` attacks (not in allowed list)
* ✅ Prevents algorithm downgrade
* ⚠️ **But:** Depends on correct implementation, library version, and configuration.

**Critical Dependencies for Effective Fix**
The fix is only effective if all of these are true:
* **Hardcoded Algorithm List:** `algorithms=["RS256"]` is hardcoded, not loaded from a dynamic config.
* **No Fallback Paths:** Zero try-except blocks that silently accept tokens on verification failure.
* **Single Verification Path:** All token verification routes through the fixed function.
* **Library Version:** JWT library version is patched for algorithm confusion (e.g., PyJWT ≥ 2.0).
* **No Cache Bypass:** Tokens are not cached or pre-verified, bypassing the strict check.

**Remaining Risk Surface**
Even with "enforce RS256 only," the fix can fail if:
* **Multi-Code-Path Vulnerability:** `HS256` verification code exists in other functions not yet updated.
* **Exception Handling Bypass:** `RS256` verification fails, exception is caught, and `HS256` is silently accepted as a fallback.
* **Configuration Override:** Allowed algorithms list is loaded from environment/config that defaults to `["RS256", "HS256"]`.
* **Library-Level Bug:** Using vulnerable legacy versions (e.g., PyJWT ≤ 1.5.2, jsonwebtoken ≤ 8.3.0, golang-jwt with known bypasses).
* **KID-Based Confusion:** The `kid` header selects a symmetric key when it should select the RSA public key.
* **Caching Layer:** Tokens are cached with a TTL; the attacker crafts a token matching a cached entry.
* **Header Manipulation:** WAF, proxy, or middleware strips the algorithm validation header before reaching the server.
* **Case Sensitivity:** The library treats `alg: rs256` (lowercase) differently from `alg: RS256` (uppercase).

---

### 3. Attack Prerequisites & Assumptions

**What Attacker Needed**
* **Public Key:** Obtainable from `/.well-known/jwks.json`, certificate files, or public repositories (like GitHub).
* **Algorithm Acceptance:** Knowledge that the server accepted both `RS256` and `HS256`.
* **Payload Access:** Either a legitimate token to extract the payload or knowledge of the target payload structure.
* **HMAC Signing Capability:** Ability to sign tokens with any secret on the attacker's local machine.

**What Server Assumed (Incorrectly)**
* That the `alg` header is inherently security-critical and should be trusted to dictate verification logic.
* That using the same key for multiple algorithms is safe.
* That validating the signature mathematically proves the token is authentic (ignoring algorithm mismatches).
* That because a token is successfully signed, it must be legitimate.
* That all verification code paths are uniformly updated when patching the primary vulnerability.

### Attack Flow Diagram

![Attack Flow Daigram](https://github.com/deependra-painkra/JWT-Algorithm-Confusion-Verification/blob/05f0307c642c694e6a13679a92353707e3535501/images/jwt_algorithm_confusion_attack.svg)

---
### 4. Residual Risk Assessment

After "enforce RS256," verify:

**Layer 1: Code-Level Verification**
* Search codebase for all `jwt.decode()` calls.
* Confirm `algorithms=["RS256"]` in ALL calls.
* Confirm `algorithms` is NOT parameterized from an untrusted source.
* Confirm no catch-and-fallback logic.

**Layer 2: Library Verification**
* Confirm PyJWT >= 2.0 (or equivalent security patch).
* Confirm no known CVEs in the JWT library version.
* Run `pip check` or `cargo audit` for dependencies.

**Layer 3: Configuration Verification**
* Confirm allowed algorithms are NOT in config files.
* Confirm NO environment variables override the algorithm list.
* Confirm NO cache that bypasses verification.

**Layer 4: Integration Verification**
* Send `HS256` token → expect `401`
* Send `RS256` token with `HS256` signature → expect `401`
* Send valid `RS256` token → expect `200` (Success)
* Send `RS256` but lowercase `alg: rs256` → expect rejection or `200` (depending on the specific library fix).
---

# PART B: Minimum Viable Test Suite Design

## Complete Test Case Table

| Test ID | Category | Token Modification | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Algorithm None Attack | Set `alg: none`, remove signature | `200 OK` + Admin data returned | `401 Unauthorized` | If response is `401` and no admin data leaked |
| **TC-02** | HS256 with Public Key (Original Exploit) | Change `alg: HS256`, sign with public key as secret, keep admin payload | `200 OK` + Admin user list returned | `401 Unauthorized` | If response is `401` and no sensitive data exposed |
| **TC-03** | Algorithm Header Removal | Delete `alg` field entirely from header | `200 OK` (assumes default) | `401` or `400 Bad Request` | If request is rejected or error returned |
| **TC-04** | KID Header Injection | Inject `kid: ../../../etc/passwd` or wildcard `kid: *` | May bypass key lookup | `401` or key not found error | If request rejected and no path traversal occurs |
| **TC-05** | Expired Token Acceptance | Set `exp: 1609459200` (2021-01-01) | `200 OK` (no validation) | `401 Unauthorized` | If response is `401` with "token expired" message |
| **TC-06** | Tampered Payload - Role Escalation | Change `role: user` to `role: admin` in payload, re-sign with HS256+pubkey | `200 OK` with admin access | `401 Unauthorized` | If response is `401` and no privilege escalation occurs |
| **TC-07** | Blank/Null Algorithm | Set `alg: ""` or `alg: null` | `200 OK` (treats as none) | `401` or `400 Bad Request` | If request is rejected |
| **TC-08** | RS256 with Mismatched Key | Sign with different RSA private key, send RS256 token | `200 OK` (wrong key validation) | `401 Unauthorized` | If response is `401` (signature mismatch) |
| **TC-09** | RS256 Enforcement Validation | Use valid RS256 token with correct key, legitimate user role | `200 OK` with user data | `200 OK` with user data (no privilege escalation) | If response is `200` AND payload role matches token (no escalation) |
| **TC-10** | PyJWT Library CVE Bypass | Use known PyJWT version bypass (e.g., algorithm case sensitivity) | `200 OK` | `401 Unauthorized` | If response is `401` (library patched) |
| **TC-11** | Case Sensitivity Attack | Set `alg: rs256` (lowercase) instead of `RS256` | May succeed in case-insensitive libraries | `401 Unauthorized` | If response is `401` (case-sensitive validation) |
| **TC-12** | Multiple Algorithm Values | Set `alg: ["RS256", "HS256"]` (JSON array) | May accept first or any | `401 Unauthorized` | If request is rejected |

---

## Test Execution Strategy

### Phase 1: Preparation
1. Generate RSA keypair for server (`server_public.pem`, `server_private.pem`).
2. Generate RSA keypair for attacker (`attacker_private.pem`).
3. Load public key into test harness.
4. Create base token (valid `RS256` token).

### Phase 2: Test Execution
For each test case:
1. **Generate modified token** using the strategy.
2. **Prepare HTTP request** with token in `Authorization` header.
3. **Send request** to target endpoint.
4. **Capture response**: status code, body, headers, response time.
5. **Analyze response**: sensitive data patterns, timing anomalies.
6. **Verdict**: PASS/FAIL based on expected vs. actual response.

### Phase 3: Analysis
* Count passes vs. failures.
* Identify sensitive data leaks.
* Identify timing anomalies (>3 seconds).
* Determine overall verdict: `REMEDIATION_SUCCESS` or `REMEDIATION_FAILED`.

---

## Sensitive Data Patterns

The verification script will flag a response as "CONTAINS SENSITIVE DATA" if it matches:

```regex
"users?":\s*\[           # JSON user array
"admin"                  # Admin keyword
"email":\s*"             # Email field
"password":\s*"          # Password field
"token":\s*"             # Token field
user\d+@                 # User email pattern
\$2[aby]\$               # bcrypt hash pattern
```

---

## Expected Outcomes

### If Remediation is SUCCESSFUL
✅ **All 12 tests PASS:**
* **TC-01 through TC-08:** All return `401 Unauthorized` (malicious tokens rejected).
* **TC-09:** Returns `200 OK` (valid token accepted).
* **TC-10, TC-11, TC-12:** All return `401 Unauthorized` (variants rejected).
* Zero sensitive data leaks detected.
* Response times remain normal (< 3 seconds).

### If Remediation is FAILED
❌ **At least 1 test FAILS:**
* One or more of TC-01 through TC-08, TC-10, TC-11, TC-12 return `200 OK`.
* **OR** sensitive data appears in the response body.
* **OR** response time is > 3 seconds.
* *Conclusion:* Indicates the vulnerability is not fully fixed and the attack surface remains open.

---

## Implementation Notes
* Tests run sequentially with a **0.5s delay** between requests to respect rate limiting.
* **Timeout per request:** 3 seconds.
* Any timeout automatically triggers a **FAIL** for that specific test case.
* A comprehensive JSON report is generated containing a timestamp and SHA-256 hash for integrity tracking.
* A Markdown report is generated for human review.
* All artifacts and logs are saved to the `evidence/` directory.

---

# PART C: AI-Assisted Workflow & Critical Critique

## 1. AI PROMPTS USED

### Prompt 1: Bypass Mechanisms
You are a JWT security expert. Given that a server claims to have fixed an algorithm confusion vulnerability by "enforcing strict RS256 algorithm validation," list 5 distinct ways this fix could still be incomplete or bypassed. For each, explain the bypass mechanism in one sentence, and categorize it (token header manipulation, key confusion, library-level bugs, fallback paths, caching behavior, or other).

The original vulnerability: Server accepted HS256-signed tokens using the server's public key as the HMAC secret.

Focus on real-world implementation gaps, not theoretical attacks.


### Prompt 2: Confidence Criteria
What are 3 measurable, testable conditions that, if all true, would let you declare a JWT algorithm confusion fix successful with high confidence? For each condition, specify how you would verify it programmatically or through testing.


### Prompt 3: Secret Rotation Impact
A client says they rotate JWT secrets every 24 hours to improve security after a JWT algorithm confusion vulnerability. Evaluate: Does secret rotation strengthen the fix for algorithm confusion, or is it irrelevant? Provide a security engineer's analysis with reasoning.


---

## 2. AI RAW OUTPUT (UNEDITED)

### Response to Prompt 1: 5 Bypass Mechanisms

> **AI Response:**
> 
> 1. **Fallback to HS256 in Exception Handler**: If the code uses a try-except 
>    block and silently falls back to accepting HS256 tokens when RS256 
>    verification fails, the fix is bypassed. Mechanism: Attacker sends HS256 
>    token; RS256 verification fails; exception handler accepts it anyway.
> 
> 2. **Parameterized Algorithm List at Runtime**: If the allowed algorithms are 
>    loaded from a configuration file or environment variable that defaults to 
>    `["RS256", "HS256"]`, and the fix only changed code but not config, RS256 
>    enforcement is overridden. Mechanism: Misconfiguration overrides hardcoded 
>    fix.
> 
> 3. **Library Version Vulnerability**: Older versions of PyJWT, jsonwebtoken 
>    (Node), or golang-jwt have known bugs where the `alg` header is not 
>    properly enforced even if specified in the decode call. Mechanism: 
>    Vulnerable library version accepts tokens outside the whitelist despite 
>    code-level enforcement.
> 
> 4. **Case Sensitivity Bypass**: Some JWT libraries treat algorithm names as 
>    case-insensitive; an attacker sends `alg: rs256` (lowercase) instead of 
>    `RS256`. If the library's case-insensitive matching is used but the 
>    whitelist is case-sensitive, the attack succeeds. Mechanism: Algorithm 
>    name case mismatch between whitelist and library parsing.
> 
> 5. **KID (Key ID) Header-Based Key Confusion**: If the code uses the `kid` 
>    header to select which key to use (e.g., from a JWKS endpoint), an 
>    attacker can inject a malicious `kid` pointing to a different key (or no 
>    key, defaulting to symmetric). Mechanism: HMAC secret or a wrong key is 
>    selected based on untrusted `kid` value.

### Response to Prompt 2: 3 Measurable Success Conditions

> **AI Response:**
> 
> 1. **Algorithm Whitelist Enforcement**: Test 100+ permutations of invalid 
>    `alg` values (HS256, none, HS512, alg: null, alg: "", alg: ["RS256", 
>    "HS256"], etc.). All must result in 401 rejection. Verify by sending each 
>    variant and confirming status code is 401 and response contains no 
>    sensitive data.
> 
> 2. **Signature Validation with Correct Algorithm**: Send a legitimate RS256 
>    token (signed with the correct private key, with a non-expired, 
>    privileged-user payload). Should return 200. Then modify the payload, 
>    re-sign with a different private key, and send. Must return 401. This 
>    proves the signature is validated against the algorithm-specific key.
> 
> 3. **No Fallback or Bypass Paths**: Perform code analysis and/or runtime 
>    testing to confirm: (a) Zero try-except blocks silently catch token 
>    verification errors, (b) The algorithms whitelist is hardcoded or from a 
>    trusted config, (c) All token verification in the codebase routes through 
>    the fixed function, (d) No middleware or caching layer bypasses the 
>    verification.

### Response to Prompt 3: Secret Rotation & Algorithm Confusion

> **AI Response:**
> 
> **Analysis**: Secret rotation is **largely irrelevant** to algorithm confusion 
> fixes.
> 
> **Reasoning**:
> - Algorithm confusion is an **algorithm-level vulnerability**, not a 
>   key-strength vulnerability.
> - Rotating the HMAC secret does not help if the server still accepts HS256 
>   tokens signed with the public key as the secret.
> - However, if the fix is improperly implemented and the "enforcement" relies 
>   on checking key age or secret validity, then rotation might incidentally 
>   help. But this would be a defense-in-depth measure, not a primary fix.
> 
> **When rotation could help**:
> - If the client meant "we now use only RS256 private key rotation" (rotating 
>   the RSA keypair), then yes, this strengthens security by limiting key 
>   exposure.
> - But the problem statement says "JWT secrets," which typically refers to 
>   symmetric keys or generic secrets. For RS256, you'd say "rotate the RSA 
>   keypair."
> 
> **Conclusion**: Secret rotation for HS256 is a separate, good practice but 
> does NOT fix algorithm confusion. The real fix is algorithm enforcement.

---

## 3. CRITICAL CRITIQUE OF AI OUTPUT

### What AI Got Right

1. **Bypass #1 (Fallback to HS256)**: Highly realistic and common in real code. Try-except-accept patterns are a classic vulnerability.

2. **Bypass #3 (Library Vulnerability)**: Correctly identifies that library versions matter.
   - **Specific Issues**: PyJWT ≤ 1.5.2 (CVE-2017-11424), jsonwebtoken < 8.4.2, golang-jwt < 3.1.0

3. **Bypass #4 (Case Sensitivity)**: Real issue in case-insensitive libraries.


4. **Success Condition #1 (Algorithm Whitelist)**: Testing many `alg` variants is sound.

5. **Success Condition #2 (Signature Validation)**: Good test design (positive + negative case).


6. **Secret Rotation Analysis**: Correctly identifies it as irrelevant to algorithm confusion.


### Key Deficiencies in the Initial Analysis

#### 1. Lack of Actionable Verification
Failed to provide specific `grep` commands to find configuration overrides or concrete Python scripts (like using the `ast` module) to audit `jwt.decode` calls.

#### 2. Incomplete Attack Vectors
Did not explain that `kid` header injection requires attacker control over the keystore, and used vague terms instead of citing specific CVEs for vulnerable JWT libraries.

#### 3. Ignored Infrastructure & Transport Risks
Overlooked external bypasses, such as proxies/WAFs stripping authorization headers, caching layers (like Redis) skipping verification on a cache hit, and the necessity of TLS/HTTPS to prevent MITM attacks.

## 4. IMPROVED & CORRECTED VERSION
### Algorithm Confusion Fix Hierarchy (Correct Security Posture)

**MUST HAVE (Blocking Issues):**
* Enforce `RS256` only (not `HS256`)
* Reject `alg: none`
* Reject unsigned tokens
* No fallback paths

**SHOULD HAVE (Defense in Depth):**
* Keep JWT library updated
* Rotate RSA keypairs every 1-2 years
* Use short expiration times (15 min - 1 hour)
* Validate `exp` claim always
* Log all failed verification attempts

**NICE TO HAVE (Additional Security):**
* Implement token binding (RFC 8471)
* Use mutual TLS for token transport
* Implement JWT refresh token pattern



## 5. CORRECTED VERSION FOR IMPLEMENTATION

Below is the integrated output that should be used in your test suite:

### Test Coverage Mapping

```python

BYPASS_MECHANISMS = {
    'TC-01': {
        'name': 'alg_none attack',
        'bypass_mechanism': 'Fallback exception handler or alg: none acceptance',
        'detection': 'TC-01 fails (returns 200)',
    },
    'TC-02': {
        'name': 'HS256 with public key',
        'bypass_mechanism': 'Configuration override or library version bug',
        'detection': 'TC-02 fails (returns 200 + sensitive data)',
    },
    'TC-03': {
        'name': 'alg header removal',
        'bypass_mechanism': 'Default algorithm assumption',
        'detection': 'TC-03 fails (returns 200)',
    },
    'TC-04': {
        'name': 'KID injection',
        'bypass_mechanism': 'Untrusted key selection via KID header',
        'detection': 'TC-04 fails (key lookup succeeds for malicious KID)',
    },
    'TC-05': {
        'name': 'Expired token',
        'bypass_mechanism': 'Missing or bypassed expiration validation',
        'detection': 'TC-05 fails (returns 200 with expired token)',
    },
    'TC-06': {
        'name': 'Role escalation (HS256)',
        'bypass_mechanism': 'HS256 acceptance + missing payload validation',
        'detection': 'TC-06 fails (returns 200 with role=admin)',
    },
    'TC-07': {
        'name': 'Blank algorithm',
        'bypass_mechanism': 'Default algorithm assumption or alg: none fallback',
        'detection': 'TC-07 fails (returns 200)',
    },
    'TC-08': {
        'name': 'RS256 mismatched key',
        'bypass_mechanism': 'Signature validation with wrong key (library bug)',
        'detection': 'TC-08 fails (returns 200 with forged signature)',
    },
    'TC-09': {
        'name': 'Valid RS256 (should pass)',
        'bypass_mechanism': 'None (this is a positive test)',
        'detection': 'TC-09 fails (returns non-200)',
    },
    'TC-10': {
        'name': 'PyJWT library CVE',
        'bypass_mechanism': 'Known CVE in PyJWT version (CVE-2017-11424 for ≤1.5.2)',
        'detection': 'TC-10 fails (library version vulnerable)',
    },
    'TC-11': {
        'name': 'Case sensitivity',
        'bypass_mechanism': 'Case-insensitive library behavior vs. case-sensitive whitelist',
        'detection': 'TC-11 fails (returns 200 with lowercase alg)',
    },
    'TC-12': {
        'name': 'Multiple algorithms',
        'bypass_mechanism': 'Array handling in JWT header parsing',
        'detection': 'TC-12 fails (returns 200 with alg array)',
    },
}

SUCCESS_CONDITIONS = {
    'condition_1_algorithm_whitelist': {
        'description': 'All invalid alg variants return 401',
        'test_cases': ['TC-01', 'TC-03', 'TC-07', 'TC-11', 'TC-12'],
        'verification': 'All listed TCs pass',
    },
    'condition_2_signature_validity': {
        'description': 'Valid RS256 accepted, forged tokens rejected',
        'test_cases': ['TC-09', 'TC-08'],
        'verification': 'TC-09 returns 200, TC-08 returns 401',
    },
    'condition_3_no_bypass_paths': {
        'description': 'No exception handlers, config overrides, or caching bypasses',
        'test_cases': ['All TCs', 'Code review', 'Config audit'],
        'verification': 'Zero findings in static/dynamic analysis',
    },
}

SECRET_ROTATION_VERDICT = {
    'question': 'Does 24-hour secret rotation strengthen the algorithm confusion fix?',
    'answer': 'NO - It is irrelevant to algorithm confusion',
    'reasoning': [
        'Algorithm confusion depends on algorithm choice, not secret strength',
        'Public key is publicly known and cannot be "rotated" for protection',
        'Rotation would only help if combined with proper algorithm enforcement',
        'The real fix is rejecting HS256, not rotating the public key',
    ],
    'recommendation': 'Ask client: Do you reject HS256? If no, rotation is pointless.',
}

```



---

# PART D: Implementation Sprint & Execution

## Summary

This section documents the implementation of the JWT Algorithm Confusion Verification Suite, including the prompt engineering process, AI output assessment, and production-hardened code improvements.

### Files Implemented

| File | Purpose | Lines |
|------|---------|-------|
| `scripts/generate_test_keys.py` | RSA keypair generation | 75 |
| `scripts/generate_test_tokens.py` | Test token creation | 145 |
| `scripts/verify_jwt.py` | Main verification harness | 520 |
| `challenge2_config.json` | Configuration | 30 |
| `scripts/run_all_tests.sh` | Orchestration | 45 |



---

## Key Implementation Details

### 1. Token Generation Strategy

The test token generator creates tokens with specific properties for each attack vector:

| Token Type | Algorithm | Secret/Key | Payload | Purpose |
|------------|-----------|------------|---------|---------|
| `valid_rs256` | RS256 | server_private | user role, non-expired | Positive test (should succeed) |
| `hs256_with_pubkey` | HS256 | server_public | user role, non-expired | Original exploit (should fail) |
| `alg_none` | none | (empty) | user role, non-expired | Algorithm bypass (should fail) |
| `expired` | RS256 | server_private | user role, EXPIRED | Expiration bypass (should fail) |
| `tampered_admin` | HS256 | server_public | admin role, non-expired | Privilege escalation (should fail) |
| `attacker_key` | RS256 | attacker_private | user role, non-expired | Signature forgery (should fail) |

### 2. Request/Response Analysis

Each test request captures:

```python
{
    'test_id': 'TC-01',
    'strategy': 'alg_none',
    'status_code': 401,  # HTTP status
    'response_time': 0.28,  # seconds
    'has_sensitive_data': False,  # Pattern match
    'result': 'PASS',  # or 'FAIL'
    'timestamp': '2026-03-18T10:42:00Z'
}

```
### 3. Sensitive Data Detection

Uses regex patterns to identify data leaks:

```python
SENSITIVE_PATTERNS = [
    r'"users?":\s*\[',      # user array
    r'"admin"',              # admin keyword
    r'"email":\s*"',         # email field
    r'"password":\s*"',      # password field
    r'"token":\s*"',         # token field
    r'user\d+@',             # email pattern
    r'\$2[aby]\$',           # bcrypt hash
]
```


### 4. Evidence Collection

All test runs generate timestamped evidence:

```code
evidence/
├── jwt_verification_report_*.md      # Human-readable report
├── jwt_verification_results_*.json   # Structured data
└── jwt_verification_results_*.sha256 # Integrity hash

```
SHA-256 hash ensures report integrity for audit trails.


# Execution Guide

## Quick Start


### 1. Install dependencies
```bash
pip install -r requirements.txt
```
### 2. Run full test suite
```bash
bash scripts/run_all_tests.sh
```
### 3. Review results
```bash
cat evidence/jwt_verification_report_*.md
```

## Manual Execution (Step-by-Step)
### 1. Generate keys
```python
python3 scripts/generate_test_keys.py
```
Output: keys/server_public.pem, keys/server_private.pem, keys/attacker_private.pem

### 2. Generate tokens
```python
python3 scripts/generate_test_tokens.py
```
Output: keys/test_tokens.json (contains all variants)

### 3. Run verification
```python
python3 scripts/verify_jwt.py --config challenge2_config.json
```
Output: Report to stdout + evidence files

### 4. Verify with custom endpoint
```python
python3 scripts/verify_jwt.py \
    --config challenge2_config.json \
    --token "eyJhbGciOiJSUzI1NiJ9..."
```
