"""DSSE / in-toto envelope unwrapping for CodeRifts artifacts.

Mirrors ``receipt-verifier/to-dsse.js`` ``fromDSSE``. The format is specified in
``RECEIPT_FORMAT.md`` section 9, which is the source of truth for both
implementations; the constants below are byte-exact to it.

WHAT THIS DOES
    It unwraps. ``from_dsse`` returns the compact token that was wrapped, byte
    for byte, and ``verify_receipt`` then decides.

WHAT IT DOES NOT DO
    It does not verify. No signature is checked while reading an envelope. An
    envelope wrapping a receipt with a bad signature unwraps cleanly and then
    FAILS verification, exactly as that compact token would have -- the
    signature is over the compact bytes. A DSSE envelope in hand is a container,
    not a verdict.

WHY THE PAYLOAD SEGMENT IS PRESERVED
    ``predicate.compact.encoded_payload`` carries the ORIGINAL base64url
    segment, not a re-serialisation of ``predicate.fields``. A signature is over
    bytes, and re-encoding JSON is not byte-stable -- key order and whitespace
    are free -- so a rebuilt payload would fail to verify for a reason that has
    nothing to do with authenticity. Section 9.4.
"""

from __future__ import annotations

import base64
import binascii
import json

#: Section 9.1. Byte-exact with to-dsse.js; a divergence here breaks
#: interoperability silently, so tests pin both against the spec.
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://coderifts.com/attestations/agent-action-authorization/v1"

#: The compact forms an envelope may carry (section 9.3).
FORM_RECEIPT = "crchain.v1"
FORM_ATTESTATION = "cr.exec.attest.v1"


class DsseError(Exception):
    """Named refusal. ``code`` is one of MALFORMED / UNSUPPORTED / PREDICATE_MISMATCH."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (binascii.Error, ValueError) as exc:
        raise DsseError(f"payload segment is not base64url: {exc}", "MALFORMED") from exc


def _decode_payload(encoded: str) -> dict:
    try:
        obj = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except DsseError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise DsseError(f"payload segment is not base64url JSON: {exc}", "MALFORMED") from exc
    if not isinstance(obj, dict):
        raise DsseError("payload is not a JSON object", "MALFORMED")
    return obj


def _sort_deep(value):
    """Stable key order for the consistency comparison. Lists keep their order."""
    if isinstance(value, list):
        return [_sort_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: _sort_deep(value[k]) for k in sorted(value)}
    return value


def looks_like_dsse(candidate) -> bool:
    """Is this a DSSE envelope rather than a compact token?

    Keyed on ``payloadType``, which is the envelope's own discriminator -- not on
    "does it look like JSON". A compact receipt is ``<b64url>.<b64url>`` and a
    compact attestation is pipe-delimited; neither can be mistaken for a mapping
    carrying an in-toto payloadType.
    """
    if isinstance(candidate, dict):
        return candidate.get("payloadType") == PAYLOAD_TYPE
    if isinstance(candidate, (str, bytes)):
        text = candidate.decode("utf-8", "replace") if isinstance(candidate, bytes) else candidate
        if not text.lstrip().startswith("{"):
            return False
        try:
            parsed = json.loads(text)
        except ValueError:
            return False
        return isinstance(parsed, dict) and parsed.get("payloadType") == PAYLOAD_TYPE
    return False


def from_dsse(envelope) -> str:
    """Reassemble the compact token from a DSSE envelope.

    Refuses rather than guesses. Every refusal below is a case where returning a
    token anyway would hand the caller bytes that do not correspond to the
    envelope they read.

    :raises DsseError: MALFORMED | UNSUPPORTED | PREDICATE_MISMATCH
    """
    if isinstance(envelope, (str, bytes)):
        text = envelope.decode("utf-8", "replace") if isinstance(envelope, bytes) else envelope
        try:
            envelope = json.loads(text)
        except ValueError as exc:
            raise DsseError(f"from_dsse: envelope is not JSON: {exc}", "MALFORMED") from exc
    if not isinstance(envelope, dict):
        raise DsseError("from_dsse: envelope must be an object", "MALFORMED")

    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise DsseError(
            f"from_dsse: unsupported payloadType {json.dumps(envelope.get('payloadType'))}",
            "UNSUPPORTED",
        )

    raw = envelope.get("payload")
    try:
        statement = json.loads(base64.b64decode(str(raw), validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DsseError(f"from_dsse: payload is not base64 JSON: {exc}", "MALFORMED") from exc
    if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
        got = statement.get("predicateType") if isinstance(statement, dict) else None
        raise DsseError(f"from_dsse: unsupported predicateType {json.dumps(got)}", "UNSUPPORTED")

    predicate = statement.get("predicate") or {}
    compact = predicate.get("compact") or {}
    signatures = envelope.get("signatures")
    signatures = signatures if isinstance(signatures, list) else []
    if len(signatures) != 1 or not isinstance(signatures[0], dict) or not signatures[0].get("sig"):
        raise DsseError("from_dsse: exactly one signature with a sig is required", "MALFORMED")

    encoded = compact.get("encoded_payload")
    if not isinstance(encoded, str) or not encoded:
        raise DsseError("from_dsse: predicate.compact.encoded_payload missing", "MALFORMED")

    # The predicate carries the payload twice -- preserved bytes and decoded
    # fields. If they disagree, the readable half describes something the signed
    # half does not contain, and a reader without a CodeRifts verifier would
    # believe the readable half. Refuse instead (section 9.7).
    decoded = _decode_payload(encoded)
    if _sort_deep(decoded) != _sort_deep(predicate.get("fields") or {}):
        raise DsseError(
            "from_dsse: predicate.fields does not match predicate.compact.encoded_payload -- "
            "the readable half of this envelope disagrees with the signed half",
            "PREDICATE_MISMATCH",
        )

    sig = signatures[0]["sig"]
    form = compact.get("form")
    if form == FORM_ATTESTATION:
        if not compact.get("tag") or not compact.get("kid"):
            raise DsseError(
                "from_dsse: attestation form needs compact.tag and compact.kid", "MALFORMED"
            )
        return "|".join([compact["tag"], compact["kid"], encoded, sig])
    if form == FORM_RECEIPT:
        return f"{encoded}.{sig}"
    raise DsseError(f"from_dsse: unknown compact form {json.dumps(form)}", "UNSUPPORTED")


def unwrap(candidate) -> str:
    """Accept either form and return the compact token.

    A caller that does not know which form it received can hand it here. A
    compact token passes through untouched; an envelope is unwrapped.
    """
    if looks_like_dsse(candidate):
        return from_dsse(candidate)
    if isinstance(candidate, str) and candidate:
        return candidate
    raise DsseError("unwrap: neither a compact token nor a DSSE envelope", "MALFORMED")
