"""Offline verification and DSSE unwrapping in Python.

The load-bearing tests are the CROSS-LANGUAGE ones: the vectors in
``xlang-vectors.json`` were produced and verified by the JavaScript verifier,
and this asserts Python reaches the SAME verdict on the same bytes. A Python
verifier that agreed with itself but not with the reference would be worse than
none -- two implementations disagreeing about whether a receipt is valid is the
failure a multi-language verifier exists to avoid.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from coderifts_verifier import (  # noqa: E402
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    DsseError,
    from_dsse,
    keyring_from_document,
    looks_like_dsse,
    reconstruct_signed_input,
    unwrap,
    verify_receipt,
)

VECTORS = json.loads((pathlib.Path(__file__).parent / "xlang-vectors.json").read_text())
# MEASURED: keyring_from_document(doc, source) takes a source label too -- it
# names where the registry came from, for the error text.
KEYRING = keyring_from_document(
    {"keys": [{"kid": VECTORS["kid"], "public_key_pem": VECTORS["public_key_pem"],
               "status": "active"}]},
    "tests/xlang-vectors.json",
)
BY_NAME = {v["name"]: v for v in VECTORS["vectors"]}


def verdict(token):
    r = verify_receipt(token, {"keyring": KEYRING})
    return {"valid": r["valid"], "status": r["status"]}


# ── CROSS-LANGUAGE ───────────────────────────────────────────────────────────
class TestCrossLanguage:
    @pytest.mark.parametrize("name", sorted(BY_NAME))
    def test_python_verdict_matches_the_javascript_verdict(self, name):
        v = BY_NAME[name]
        assert verdict(v["token"]) == v["js"], (
            f"{name}: Python and JavaScript disagree about this receipt"
        )

    def test_the_vectors_cover_a_pass_and_two_distinct_failures(self):
        # A cross-language check that only ever compared passes would agree
        # trivially. The failure MODES have to match too.
        statuses = {v["js"]["status"] for v in VECTORS["vectors"]}
        assert "VERIFIED_CURRENT" in statuses
        assert "INVALID_SIGNATURE" in statuses
        assert "UNKNOWN_KEY" in statuses

    def test_the_signed_bytes_are_reconstructed_identically(self):
        # verify.js:89 states this string must be byte-identical across the two
        # implementations. It is the whole basis of cross-language agreement.
        token = BY_NAME["VALID"]["token"]
        payload = json.loads(
            base64.urlsafe_b64decode(token.split(".")[0] + "==").decode("utf-8")
        )
        signed = reconstruct_signed_input(payload)
        assert signed.startswith("crchain.v1|")
        assert signed == "|".join(
            ["crchain.v1", payload["kid"], payload["fp"], payload["prev"],
             payload["caller"], payload["ts"]]
        )


# ── DSSE ─────────────────────────────────────────────────────────────────────
class TestDsse:
    def test_the_constants_are_byte_exact_to_the_spec(self):
        # RECEIPT_FORMAT.md section 9.1. A divergence breaks interoperability
        # silently: an envelope produced by the JS export would be refused here.
        assert PAYLOAD_TYPE == "application/vnd.in-toto+json"
        assert STATEMENT_TYPE == "https://in-toto.io/Statement/v1"
        assert PREDICATE_TYPE == (
            "https://coderifts.com/attestations/agent-action-authorization/v1"
        )

    def test_a_javascript_produced_envelope_unwraps_to_the_exact_token(self):
        envelope = VECTORS["dsse"]["valid"]
        assert from_dsse(envelope) == BY_NAME["VALID"]["token"]

    def test_the_unwrapped_token_verifies_identically_to_the_compact_one(self):
        direct = verdict(BY_NAME["VALID"]["token"])
        via_dsse = verdict(from_dsse(VECTORS["dsse"]["valid"]))
        assert via_dsse == direct
        assert via_dsse == BY_NAME["VALID"]["js"]

    def test_UNWRAPPING_IS_NOT_VERIFICATION(self):
        """A bad-signature receipt unwraps cleanly and then fails."""
        envelope = VECTORS["dsse"]["bad_signature"]
        token = from_dsse(envelope)          # succeeds -- nothing is checked here
        assert token == BY_NAME["BAD_SIGNATURE"]["token"]
        assert verdict(token) == BY_NAME["BAD_SIGNATURE"]["js"]
        assert verdict(token)["valid"] is False

    def test_an_envelope_accepts_a_dict_or_its_json_text(self):
        envelope = VECTORS["dsse"]["valid"]
        assert from_dsse(envelope) == from_dsse(json.dumps(envelope))

    def test_unwrap_passes_a_compact_token_through(self):
        token = BY_NAME["VALID"]["token"]
        assert unwrap(token) == token
        assert unwrap(VECTORS["dsse"]["valid"]) == token

    def test_looks_like_dsse_keys_on_payload_type_not_on_json_shape(self):
        assert looks_like_dsse(BY_NAME["VALID"]["token"]) is False
        assert looks_like_dsse('{"payloadType":"application/json"}') is False
        assert looks_like_dsse({"payloadType": "application/json"}) is False
        assert looks_like_dsse(VECTORS["dsse"]["valid"]) is True


# ── REFUSALS ─────────────────────────────────────────────────────────────────
class TestRefusals:
    @staticmethod
    def _statement(envelope):
        return json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))

    @staticmethod
    def _reencode(envelope, statement):
        out = dict(envelope)
        out["payload"] = base64.b64encode(
            json.dumps(statement).encode("utf-8")
        ).decode("ascii")
        return out

    def test_a_rewritten_decoded_field_is_refused(self):
        envelope = json.loads(json.dumps(VECTORS["dsse"]["valid"]))
        st = self._statement(envelope)
        st["predicate"]["fields"]["caller"] = "attacker"
        with pytest.raises(DsseError) as exc:
            from_dsse(self._reencode(envelope, st))
        assert exc.value.code == "PREDICATE_MISMATCH"

    def test_a_rewritten_payload_segment_unwraps_but_fails_verification(self):
        # The honest split: unwrapping is not verification, so the signature
        # refuses. `caller` is a SIGNED field (verify.js reconstruct order).
        envelope = json.loads(json.dumps(VECTORS["dsse"]["valid"]))
        st = self._statement(envelope)
        forged = dict(st["predicate"]["fields"], caller="attacker")
        encoded = base64.urlsafe_b64encode(
            json.dumps(forged).encode("utf-8")
        ).decode("ascii").rstrip("=")
        st["predicate"]["compact"]["encoded_payload"] = encoded
        st["predicate"]["fields"] = forged          # keep the two halves consistent

        token = from_dsse(self._reencode(envelope, st))
        assert token != BY_NAME["VALID"]["token"]
        assert verify_receipt(token, {"keyring": KEYRING})["valid"] is False

    def test_a_foreign_payload_type_or_predicate_type_is_refused(self):
        envelope = json.loads(json.dumps(VECTORS["dsse"]["valid"]))
        bad_type = dict(envelope, payloadType="application/json")
        with pytest.raises(DsseError) as exc:
            from_dsse(bad_type)
        assert exc.value.code == "UNSUPPORTED"

        st = self._statement(envelope)
        st["predicateType"] = "https://slsa.dev/provenance/v1"
        with pytest.raises(DsseError) as exc:
            from_dsse(self._reencode(envelope, st))
        assert exc.value.code == "UNSUPPORTED"

    @pytest.mark.parametrize(
        "signatures", [[], [{"keyid": "k"}], [{"sig": ""}], [{"sig": "a"}, {"sig": "b"}]]
    )
    def test_zero_two_or_signatureless_entries_are_refused(self, signatures):
        envelope = dict(VECTORS["dsse"]["valid"], signatures=signatures)
        with pytest.raises(DsseError) as exc:
            from_dsse(envelope)
        assert exc.value.code == "MALFORMED"

    @pytest.mark.parametrize("bad", [None, 42, [], "", "not-json", b"\x00\x01"])
    def test_a_non_envelope_is_refused_with_a_named_error(self, bad):
        with pytest.raises(DsseError):
            from_dsse(bad)

    def test_an_unknown_compact_form_is_refused(self):
        envelope = json.loads(json.dumps(VECTORS["dsse"]["valid"]))
        st = self._statement(envelope)
        st["predicate"]["compact"]["form"] = "cr.something.else.v9"
        with pytest.raises(DsseError) as exc:
            from_dsse(self._reencode(envelope, st))
        assert exc.value.code == "UNSUPPORTED"


# ── OFFLINE ──────────────────────────────────────────────────────────────────
class TestOffline:
    def test_verification_makes_no_network_call(self, monkeypatch):
        # Behavioural, not a source scan: _verify.py carries KEY-LOADING helpers
        # that do fetch a registry over HTTP. The verify path never calls them,
        # because the keyring is passed in -- so grepping the file would report
        # a network call that verification never makes.
        import urllib.request

        def explode(*_args, **_kwargs):
            raise AssertionError("the verify path made a network call")

        monkeypatch.setattr(urllib.request, "urlopen", explode)
        assert verdict(BY_NAME["VALID"]["token"])["valid"] is True
        assert from_dsse(VECTORS["dsse"]["valid"]) == BY_NAME["VALID"]["token"]
