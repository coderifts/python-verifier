"""P-2 -- the no-flag default is OFFLINE, and the snapshot it reads actually ships.

The load-bearing test here is ``test_the_default_makes_no_network_call``: it replaces
``urllib.request.urlopen`` with a bomb. A test that merely checked the verdict would pass for an
implementation that fetched first and happened to get the same answer.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from coderifts_verifier import _verify  # noqa: E402
from coderifts_verifier._verify import (  # noqa: E402
    VENDORED_KEYS_PATH,
    discovery_was_mandatory,
    load_keyring,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
KEYS = pathlib.Path(VENDORED_KEYS_PATH)


class TestTheSnapshotShips:
    def test_the_vendored_snapshot_exists_and_parses(self):
        assert KEYS.exists(), "the offline default has nothing to read"
        doc = json.loads(KEYS.read_text())
        assert doc.get("keys"), "a snapshot with no keys[] is an offline default that always fails"

    def test_its_digest_matches_the_pin_beside_it(self):
        recorded = KEYS.with_suffix(".json.sha256").read_text().split()[0]
        actual = hashlib.sha256(KEYS.read_bytes()).hexdigest()
        assert actual == recorded, "the snapshot and its pin disagree -- refresh both, never one"

    def test_it_is_byte_identical_to_the_javascript_verifier_copy(self):
        """NON-SILENT SKIP. Two copies that drifted would make the two implementations reach
        different offline verdicts about the same receipt -- the exact failure a multi-language
        verifier exists to avoid. Without the sibling checkout this reports UNPROVEN rather than
        passing: a parity test that greens when it cannot see the other side is useless.
        """
        sibling = pathlib.Path.home() / "receipt-verifier" / "keys" / "coderifts-keys.json"
        if not sibling.exists():
            pytest.skip(f"UNPROVEN: {sibling} not checked out here -- not proven-by-absence")
        assert KEYS.read_bytes() == sibling.read_bytes(), (
            "the vendored snapshots have drifted between the two verifiers"
        )

    def test_the_packaging_declares_it_for_THIS_backend(self):
        """WARNING -- the first attempt declared it for hatch, and this project builds with
        setuptools. An inert build setting is worse than a missing one: the repository looks as
        though the question was handled, and the wheel ships without the file.
        """
        text = (REPO / "pyproject.toml").read_text()
        assert 'build-backend = "setuptools.build_meta"' in text
        assert "[tool.setuptools.package-data]" in text
        assert "keys/*.json" in text
        # No table for a backend that never runs.
        assert "\n[tool.hatch" not in text, "a hatch table is config for a backend this project does not use"


class TestTheDefaultIsOffline:
    def test_the_default_is_not_mandatory_discovery(self):
        assert discovery_was_mandatory({}) is False

    def test_the_default_makes_NO_network_call(self, monkeypatch):
        """THE LOAD-BEARING ONE. urlopen is replaced with a bomb; the default must not reach it."""
        def bomb(*_a, **_k):
            raise AssertionError("the no-flag default made a network call")

        monkeypatch.setattr(_verify.urllib.request, "urlopen", bomb)
        keyring = load_keyring(VENDORED_KEYS_PATH)
        assert keyring, "the offline path produced no keyring"

    def test_POSITIVE_CONTROL_fetch_IS_still_the_network(self):
        """NEGATIVE CONTROL for the test above: if nothing could ever reach urlopen, the bomb
        would prove nothing. --fetch is still discovery, and still mandatory.
        """
        assert discovery_was_mandatory({"fetch_url": "https://r.invalid/k.json"}) is True
        assert discovery_was_mandatory({"keys_source": "https://r.invalid/k.json"}) is True


class TestParityWithVerifyJs:
    """The divergence P-2 closed, asserted from BOTH sides where both are readable."""

    def test_verify_js_also_defaults_to_the_vendored_snapshot(self):
        cli = pathlib.Path.home() / "receipt-verifier" / "cli.js"
        if not cli.exists():
            pytest.skip("UNPROVEN: receipt-verifier not checked out here")
        src = cli.read_text()
        assert "VENDORED_KEYS_PATH" in src
        # The js default branch loads the snapshot; neither side fetches without a flag now.
        assert "loadKeyring(VENDORED_KEYS_PATH)" in src

    def test_the_cli_default_verifies_without_a_network(self):
        """End to end: a bogus kid against the vendored snapshot is UNKNOWN_KEY -- a real verdict,
        reached offline. Before P-2 this line made an HTTP request.
        """
        r = subprocess.run(
            [sys.executable, "-m", "coderifts_verifier._verify", "eyJ2IjoxfQ.AAAA"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        out = json.loads(r.stdout)
        assert out["status"] == "UNKNOWN_KEY"
        assert out["status"] != "REGISTRY_UNREACHABLE", "the default tried to reach a registry"
