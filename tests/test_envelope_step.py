"""Cross-language parity for the envelope-bound ``next_agent_step``.

The property: a decision's next step is readable only when the envelope binding verifies. Swap the
step after signing and the envelope no longer hashes to ``bh``; the receipt fails, and a consumer
must not surface the step it just failed to verify.

MEASURED: this verifier reads the envelope only to RECOMPUTE its hash (``_verify.py:257-264``). It
does not read ``next_agent_step`` or any other envelope field semantically. So the parity claim here
is precise and narrow: Python and JavaScript agree on the VERDICT, and the read-gate is a consumer
rule that this test states in one place and drives from the vectors.

Vectors come from the sibling ``receipt-verifier`` checkout, minted by its generator. Absent
checkout -> skip LOUDLY: a silent skip would make a green run mean "the two agree" when it meant
"only one was asked".
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from coderifts_verifier import keyring_from_document, verify_receipt  # noqa: E402

VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "receipt-verifier"
    / "test"
    / "envelope-step-vectors.json"
)

pytestmark = pytest.mark.skipif(
    not VECTORS_PATH.exists(),
    reason=f"sibling receipt-verifier checkout not found at {VECTORS_PATH}",
)

VECTORS = json.loads(VECTORS_PATH.read_text()) if VECTORS_PATH.exists() else {"vectors": []}
BY_NAME = {v["name"]: v for v in VECTORS.get("vectors", [])}


def _keyring():
    return keyring_from_document(
        {
            "keys": [
                {
                    "kid": VECTORS["kid"],
                    "public_key_pem": VECTORS["public_key_pem"],
                    "status": "active",
                }
            ]
        },
        str(VECTORS_PATH),
    )


def read_step(vector):
    """The consumer rule: verify first, read the step only from an envelope that verified."""
    r = verify_receipt(
        vector["token"],
        {"ctx": {"keyring": _keyring()}, "envelope": vector["envelope"]},
    )
    if not r["valid"]:
        return r, None, True
    return r, (vector["envelope"] or {}).get("next_agent_step"), False


class TestCrossLanguage:
    @pytest.mark.parametrize("name", sorted(BY_NAME))
    def test_python_verdict_matches_the_javascript_verdict(self, name):
        v = BY_NAME[name]
        r = verify_receipt(
            v["token"], {"ctx": {"keyring": _keyring()}, "envelope": v["envelope"]}
        )
        assert r["valid"] == v["js"]["valid"], f"{name}: valid"
        assert r["status"] == v["js"]["status"], f"{name}: status"
        if "reason" in v["js"]:
            assert r.get("reason") == v["js"]["reason"], f"{name}: reason"

    def test_the_tampered_envelope_fails_on_the_binding_specifically(self):
        # Not merely "invalid" -- invalid for the RIGHT reason. A signature failure and a binding
        # failure are different findings, and only the second is what this family tests.
        v = BY_NAME["ENVSTEP-BLOCK-TAMPERED"]
        r, step, refused = read_step(v)
        assert r["valid"] is False
        assert r["reason"] == "body_hash_mismatch"
        assert refused is True
        assert step is None

    def test_the_withheld_step_is_present_in_the_envelope(self):
        # Otherwise the test above could pass on an envelope that simply carried no step.
        v = BY_NAME["ENVSTEP-BLOCK-TAMPERED"]
        assert v["envelope"]["next_agent_step"]["action"] == "re_preflight"

    def test_the_bound_step_is_readable_and_byte_equal(self):
        v = BY_NAME["ENVSTEP-BLOCK-BOUND"]
        r, step, refused = read_step(v)
        assert r["valid"] is True
        assert refused is False
        assert step == v["expected_step"]

    def test_the_allow_class_verifies_and_carries_no_step(self):
        r, step, refused = read_step(BY_NAME["ENVSTEP-ALLOW-NULL"])
        assert r["valid"] is True
        assert refused is False
        assert step is None

    def test_this_verifier_does_not_read_the_step_itself(self):
        # The narrow parity claim, made executable: the verifier's result carries the signed
        # payload and no envelope field. Anything a consumer knows about the step, it read from
        # the envelope after the verdict -- not from the verifier.
        v = BY_NAME["ENVSTEP-BLOCK-BOUND"]
        r = verify_receipt(v["token"], {"ctx": {"keyring": _keyring()}, "envelope": v["envelope"]})
        assert "next_agent_step" not in r
        assert "next_agent_step" not in r.get("payload", {})
