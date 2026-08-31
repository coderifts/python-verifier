#!/usr/bin/env python3
"""CodeRifts chain-receipt verifier -- Python 3.10+, depends only on `cryptography`.

Verify the receipt yourself — offline, no live CodeRifts API call needed.
The reference format is frozen in ./RECEIPT_FORMAT.md.

Usage:
  python3 verify.py <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
                    [--envelope <file>] [--audience <a>] [--environment <e>]
  python3 verify.py --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]

Key discovery: with no --key/--keys, keys are fetched from
  https://app.coderifts.com/.well-known/coderifts-keys.json  (override with --fetch <url>).
The fetch-and-resolve path accepts BOTH the registry array (active + retired)
and the legacy single-key body from /api/v1/attestation/public-key.
--keys resolves each receipt's key by kid from a registry
  ({keys: [{kid, public_key_pem, status, valid_from, retired_at}]}); accepts a URL or file.

Output: JSON { valid, status, reason?, payload?, chain? } to stdout — byte-identical to verify.js.
Exit codes: 0 valid, 1 invalid, 2 usage error.

Verification order: structure -> json -> kid -> signature -> delimiter guard -> envelope binding
-> taxonomy status. Statuses (12): VERIFIED_CURRENT, VERIFIED_EXPIRED, VERIFIED_WRONG_AUDIENCE,
VERIFIED_WRONG_ENVIRONMENT, VERIFIED_SUPERSEDED, VERIFIED_SCOPE_MISMATCH, UNKNOWN_KEY,
RETIRED_KEY_VALID_AT_ISSUE, INVALID_SIGNATURE, MALFORMED, UNSUPPORTED_VERSION, REGISTRY_UNREACHABLE.
"""

import base64
import hashlib
import json
import math
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_FETCH_URL = "https://app.coderifts.com/.well-known/coderifts-keys.json"
SIGNING_PREFIX = "crchain.v1"
MAX_SUPPORTED_V = 4
SIGNED_FIELDS = ["kid", "fp", "prev", "caller", "ts", "reg", "ir", "expires_at", "bh"]
# ID104 — verification expiry leeway (ms). exp + leeway < now → VERIFIED_EXPIRED.
CLOCK_SKEW_LEEWAY_MS = 30_000


def expiry_leeway_ms(context=None):
    """0s grace only when context DECLARES destructive AND production.

    This surface has envelope.environment / --environment; no destructive /
    operation_class field — never guess from operation labels.
    """
    return CLOCK_SKEW_LEEWAY_MS


def _is_finite_number(value):
    """Match JS Number.isFinite: real int/float only, not bool, not coerced strings."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def is_expired_at(expires_at_ms, now_ms, context=None):
    if not _is_finite_number(expires_at_ms) or not _is_finite_number(now_ms):
        return False
    return (float(expires_at_ms) + expiry_leeway_ms(context)) < float(now_ms)
USAGE = (
    "usage: python3 verify.py <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n"
    "                  [--envelope <file>] [--audience <a>] [--environment <e>]\n"
    "       python3 verify.py --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n"
)


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def sha256hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(value):
    """RFC 8785 (JCS) canonical JSON for our data domain — byte-identical to verify.js canonicalJson
    and the issuer's src/canonical-json.js (ASCII keys, JSON scalars, sorted keys, no whitespace)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("canonical_json: non-finite number")
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(value[k]) for k in keys) + "}"
    raise TypeError("canonical_json: unsupported type")


def reconstruct_signed_input(payload):
    """Byte-identical to verify.js reconstructSignedInput.

    v1: base ; v2: base|reg ; v3: base|reg|ir ; v4: base|reg|ir|expires_at|bh
    (field order matches the CodeRifts issuer, chain-attestation.js signingInputV4).
    """
    base = "{p}|{kid}|{fp}|{prev}|{caller}|{ts}".format(
        p=SIGNING_PREFIX,
        kid=payload["kid"],
        fp=payload["fp"],
        prev=payload["prev"],
        caller=payload["caller"],
        ts=payload["ts"],
    )
    if payload.get("v") == 4:
        return base + "|" + str(payload["reg"]) + "|" + str(payload["ir"]) + "|" + str(payload["expires_at"]) + "|" + str(payload["bh"])
    if payload.get("v") == 3:
        return base + "|" + str(payload["reg"]) + "|" + str(payload["ir"])
    if payload.get("v") == 2:
        return base + "|" + str(payload["reg"])
    return base


def resolve_entry(ctx, payload):
    """Resolve the key entry for a payload; None => unknown_kid. Returns {public_key, status, retired_at}."""
    kid = payload.get("kid")
    if ctx.get("keyring") is not None:
        entry = ctx["keyring"].get(kid)
        if entry is None:
            return None
        if ctx.get("expected_kid") is not None and kid != ctx["expected_kid"]:
            return None
        return entry
    if ctx.get("expected_kid") is not None and kid != ctx["expected_kid"]:
        return None
    return {"public_key": ctx["public_key"], "status": None, "retired_at": None, "revoked_at": None, "compromised_at": None}


def _parse_iso(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def derive_status(payload, entry, opts):
    """The 12-status taxonomy verdict for a signature-valid receipt (mirrors verify.js deriveStatus)."""
    v = payload.get("v")
    if isinstance(v, int) and v > MAX_SUPPORTED_V:
        return "UNSUPPORTED_VERSION"
    # FAIL CLOSED ON A STATUS WE DO NOT UNDERSTAND — mirrors verify.js deriveStatus.
    #
    # MEASURED 2026-08-26: status "revoked" returned valid/VERIFIED_CURRENT here. The status was
    # read for "retired" and otherwise ignored, so an operator marking a stolen key revoked would
    # have believed they had acted while this verifier kept accepting it. The app kernel and the
    # attest/toolset verifiers already reject an unknown status; these two did not.
    #
    # This is only the DIRECTION of the unknown case, not revocation: the rule (compromised_at,
    # REVOKED_KEY / REVOKED_KEY_UNDECIDABLE) is a separate change across eight verifiers.
    if entry.get("status") not in ("active", "retired", "revoked", None):
        return "UNKNOWN_KEY_STATUS"
    # 1079 B — OPTIONAL timestamps, additive. Absent both fields → continue as before.
    # Signing time is payload.ts (receipts have no iat). revoked_at kills history;
    # retired_at only rejects ts >= retired_at.
    revoked_at = entry.get("revoked_at")
    if isinstance(revoked_at, str) and revoked_at:
        return "KEY_REVOKED"
    retired_at = entry.get("retired_at")
    if isinstance(retired_at, str) and retired_at and payload.get("ts"):
        issued = _parse_iso(payload.get("ts"))
        retired = _parse_iso(retired_at)
        if issued is not None and retired is not None and issued >= retired:
            return "KEY_RETIRED_AFTER_SIGNING"
    # REVOKED — RECEIPT_FORMAT.md 7.1 (normative); mirrors verify.js deriveStatus exactly.
    # Both outcomes are valid:false. UNDECIDABLE is not a softer valid.
    if entry.get("status") == "revoked":
        at = entry.get("compromised_at")
        if not isinstance(at, str) or not at:
            return "REVOKED_KEY_UNDECIDABLE"
        boundary = _parse_iso(at)
        issued = _parse_iso(payload.get("ts"))
        if boundary is None or issued is None:
            return "REVOKED_KEY_UNDECIDABLE"
        return "REVOKED_KEY" if issued >= boundary else "REVOKED_KEY_UNDECIDABLE"
    if entry.get("status") == "retired":
        issued = _parse_iso(payload.get("ts"))
        retired = _parse_iso(entry.get("retired_at"))
        if retired is not None and issued is not None and issued < retired:
            return "RETIRED_KEY_VALID_AT_ISSUE"
        return "INVALID_SIGNATURE"
    now = opts["now"] if opts.get("now") is not None else (datetime.now(timezone.utc).timestamp() * 1000)
    if v == 4 and isinstance(payload.get("expires_at"), str):
        exp = _parse_iso(payload["expires_at"])
        context = opts.get("envelope") or {"environment": opts.get("expected_environment")}
        if exp is not None and is_expired_at(exp, now, context):
            return "VERIFIED_EXPIRED"
    env = opts.get("envelope")
    if env:
        if opts.get("expected_audience") is not None and env.get("audience") is not None and env["audience"] != opts["expected_audience"]:
            return "VERIFIED_WRONG_AUDIENCE"
        if opts.get("expected_environment") is not None and env.get("environment") is not None and env["environment"] != opts["expected_environment"]:
            return "VERIFIED_WRONG_ENVIRONMENT"
    return "VERIFIED_CURRENT"


def verify_receipt(token, ctx=None, opts=None):
    from .arity import split3
    c, o = split3("verify_receipt", ctx, opts)
    return _verify_receipt(token, c, o)


def _verify_receipt(token, ctx, opts=None):
    """Return an ordered dict {valid, status, reason?, payload?} matching verify.js key-for-key."""
    opts = opts or {}
    # 1. structure
    if not isinstance(token, str) or len(token) == 0:
        return {"valid": False, "status": "MALFORMED", "reason": "malformed_structure"}
    segments = token.split(".")
    if len(segments) != 2 or any(len(s) == 0 for s in segments):
        return {"valid": False, "status": "MALFORMED", "reason": "malformed_structure"}

    # 2. json
    try:
        payload = json.loads(b64url_decode(segments[0]).decode("utf-8"))
    except Exception:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"valid": False, "status": "MALFORMED", "reason": "bad_json"}

    # 3. kid
    entry = resolve_entry(ctx, payload)
    if entry is None:
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "unknown_kid", "payload": payload}

    # 4. signature (raw Ed25519 over the reconstructed UTF-8 bytes)
    message = reconstruct_signed_input(payload).encode("utf-8")
    try:
        sig = b64url_decode(segments[1])
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}
    try:
        entry["public_key"].verify(sig, message)
    except InvalidSignature:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_mismatch", "payload": payload}
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}

    # 5. anti-downgrade delimiter guard
    for k in SIGNED_FIELDS:
        if isinstance(payload.get(k), str) and "|" in payload[k]:
            return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "delimiter_in_field", "payload": payload}

    # 6. envelope binding (v4)
    if opts.get("envelope") and payload.get("v") == 4:
        rest = dict(opts["envelope"])
        rest.pop("receipt", None)
        rest.pop("decision_body_hash", None)
        recomputed = "sha256:" + sha256hex(canonical_json(rest))
        if recomputed != payload.get("bh"):
            return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "body_hash_mismatch", "payload": payload}

    # 7. taxonomy status
    status = derive_status(payload, entry, opts)
    if status == "KEY_REVOKED":
        return {"valid": False, "status": status, "reason": "KEY_REVOKED", "payload": payload}
    if status == "KEY_RETIRED_AFTER_SIGNING":
        return {"valid": False, "status": status, "reason": "KEY_RETIRED_AFTER_SIGNING", "payload": payload}
    if status == "INVALID_SIGNATURE":
        return {"valid": False, "status": status, "reason": "retired_key_after_issue", "payload": payload}
    valid = status in ("VERIFIED_CURRENT", "RETIRED_KEY_VALID_AT_ISSUE")
    return {"valid": valid, "status": status, "payload": payload}


def verify_chain(tokens, ctx=None, opts=None):
    from .arity import split3
    c, o = split3("verify_chain", ctx, opts)
    return _verify_chain(tokens, c, o)


def _verify_chain(tokens, ctx, opts=None):
    links = []
    all_valid = True
    first = None

    for i, token in enumerate(tokens):
        res = _verify_receipt(token, ctx, opts)
        link = {"index": i, "signature_valid": res["valid"]}
        if not res["valid"] and "reason" in res:
            link["reason"] = res["reason"]
        prev = res.get("payload", {}).get("prev") if res.get("payload") else None
        if res.get("payload"):
            link["prev"] = prev

        if i == 0:
            first = "genesis" if prev == "null" else "continuation"
            link["role"] = first
            link["prev_ok"] = True if prev == "null" else None
        else:
            expected = "sha256:" + sha256hex(tokens[i - 1])
            link["expected_prev"] = expected
            link["prev_ok"] = prev == expected
            if not link["prev_ok"]:
                all_valid = False

        if not res["valid"]:
            all_valid = False
        links.append(link)

    return {"valid": all_valid, "chain": {"length": len(tokens), "first": first, "links": links}}


def key_from_pem(pem_text):
    key = load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def keyring_from_document(doc, source):
    """Build a kid -> entry map from a registry document. None when keys[] is missing/empty
    so the caller can try the legacy single-key body."""
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not keys:
        return None
    keyring = {}
    for k in keys:
        if not k or not k.get("kid") or not k.get("public_key_pem"):
            raise ValueError("registry entry missing kid/public_key_pem in " + source)
        keyring[k["kid"]] = {
            "public_key": key_from_pem(k["public_key_pem"]),
            "status": k.get("status"),
            "retired_at": k.get("retired_at"),
            "revoked_at": k.get("revoked_at"),
            # Carried through for the revoked rule (RECEIPT_FORMAT 7.1). Dropping it makes the
            # rule inert: every revoked key would return UNDECIDABLE regardless of ts.
            "compromised_at": k.get("compromised_at"),
        }
    return keyring


def fetch_key_document(url):
    """Fetch a key document. Accepts BOTH shapes: registry {keys:[...]} and
    legacy {kid, public_key_pem}. Registry includes a keyring so retired kids resolve."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (explicit --fetch/default only)
        info = json.loads(resp.read().decode("utf-8"))
    keyring = keyring_from_document(info, url)
    if keyring:
        active_kid = None
        active_entry = None
        for kid, entry in keyring.items():
            if entry.get("status") == "active":
                active_kid, active_entry = kid, entry
                break
        if active_entry is None:
            active_kid = next(iter(keyring))
            active_entry = keyring[active_kid]
        return {"public_key": active_entry["public_key"], "kid": active_kid, "keyring": keyring}
    if not info or not info.get("public_key_pem"):
        raise ValueError("no public_key_pem at " + url)
    return {"public_key": key_from_pem(info["public_key_pem"]), "kid": info.get("kid")}


def fetch_key_info(url):
    """Legacy tuple (public_key, kid) of the active/single key — grant verifier unpacks this."""
    info = fetch_key_document(url)
    return info["public_key"], info.get("kid")


def load_keyring(source):
    """Build a {kid: {public_key, status, retired_at}} map from a CodeRifts key registry
    ({keys: [{kid, public_key_pem, status, valid_from, retired_at}]}). Active + retired both load."""
    if source.lower().startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (explicit --keys only)
            text = resp.read().decode("utf-8")
    else:
        with open(source, "r", encoding="utf-8") as fh:
            text = fh.read()
    doc = json.loads(text)
    keyring = keyring_from_document(doc, source)
    if not keyring:
        raise ValueError("no keys[] in registry " + source)
    return keyring


def fail(msg):
    sys.stderr.write(msg + "\n" + USAGE)
    sys.exit(2)


def parse_args(argv):
    opts = {"receipt": None, "chain_file": None, "key_file": None, "keys_source": None,
            "kid": None, "fetch_url": None, "envelope_file": None, "audience": None,
            "environment": None, "help": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--chain":
            i += 1
            opts["chain_file"] = argv[i] if i < len(argv) else None
        elif a == "--key":
            i += 1
            opts["key_file"] = argv[i] if i < len(argv) else None
        elif a == "--keys":
            i += 1
            opts["keys_source"] = argv[i] if i < len(argv) else None
        elif a == "--kid":
            i += 1
            opts["kid"] = argv[i] if i < len(argv) else None
        elif a == "--fetch":
            i += 1
            opts["fetch_url"] = argv[i] if i < len(argv) else None
        elif a == "--envelope":
            i += 1
            opts["envelope_file"] = argv[i] if i < len(argv) else None
        elif a == "--audience":
            i += 1
            opts["audience"] = argv[i] if i < len(argv) else None
        elif a == "--environment":
            i += 1
            opts["environment"] = argv[i] if i < len(argv) else None
        elif a in ("-h", "--help"):
            opts["help"] = True
        elif a.startswith("--"):
            raise ValueError("unknown flag: " + a)
        elif opts["receipt"] is None:
            opts["receipt"] = a
        else:
            raise ValueError("unexpected argument: " + a)
        i += 1
    if opts["key_file"] and opts["keys_source"]:
        raise ValueError("--key and --keys are mutually exclusive")
    return opts


def main():
    try:
        opts = parse_args(sys.argv[1:])
    except ValueError as e:
        fail(str(e))
    if opts["help"]:
        sys.stdout.write(USAGE)
        sys.exit(2)
    if not opts["chain_file"] and not opts["receipt"]:
        fail("no receipt provided")

    # Resolve the verification key(s) + expected kid.
    try:
        if opts["keys_source"]:
            ctx = {"keyring": load_keyring(opts["keys_source"]), "expected_kid": opts["kid"]}
        elif opts["key_file"]:
            with open(opts["key_file"], "r", encoding="utf-8") as fh:
                public_key = key_from_pem(fh.read())
            ctx = {"public_key": public_key, "expected_kid": opts["kid"]}
        else:
            info = fetch_key_document(opts["fetch_url"] or DEFAULT_FETCH_URL)
            if info.get("keyring"):
                ctx = {"keyring": info["keyring"], "expected_kid": opts["kid"]}
            else:
                ctx = {"public_key": info["public_key"], "expected_kid": opts["kid"] or info.get("kid")}
    except Exception as e:
        fail("could not load public key: " + str(e))

    envelope = None
    if opts["envelope_file"]:
        try:
            with open(opts["envelope_file"], "r", encoding="utf-8") as fh:
                envelope = json.loads(fh.read())
        except Exception as e:
            fail("could not read --envelope: " + str(e))
    verify_opts = {"envelope": envelope, "expected_audience": opts["audience"], "expected_environment": opts["environment"]}

    if opts["chain_file"]:
        with open(opts["chain_file"], "r", encoding="utf-8") as fh:
            tokens = [ln.strip() for ln in fh.read().split("\n") if ln.strip()]
        if not tokens:
            fail("chain file is empty")
        result = verify_chain(tokens, ctx, verify_opts)
    else:
        result = _verify_receipt(opts["receipt"], ctx, verify_opts)

    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
