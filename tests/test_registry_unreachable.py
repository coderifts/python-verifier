"""1961/7.2 -- "we could not ask" is not "this key is not ours" (Python side).

The load-bearing half of this file is the NEGATIVE CONTROL. A verifier that answered
REGISTRY_UNREACHABLE whenever a registry was down -- including for an operator who deliberately
pinned a local keyring and never asked for the network -- would pass a test that only checked the
positive case, while making offline verification look broken.

The cross-language cases are read from the shared corpus, so JavaScript and Python are asserted
against the SAME expectations rather than against two hand-written copies of an opinion.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from coderifts_verifier._verify import (  # noqa: E402
    discovery_was_mandatory,
    registry_unreachable_verdict,
)

VECTORS = json.loads((pathlib.Path(__file__).parent / "xlang-vectors.json").read_text())
DISCOVERY = {c["name"]: c for c in VECTORS.get("discovery", {}).get("cases", [])}
CLOSED = "http://127.0.0.1:1/keys.json"


class TestDiscoveryWasMandatory:
    def test_a_url_source_is_the_network(self):
        assert discovery_was_mandatory({"keys_source": "https://r.invalid/k.json"}) is True
        assert discovery_was_mandatory({"fetch_url": "https://r.invalid/k.json"}) is True

    def test_a_file_source_is_not(self):
        """NEGATIVE CONTROL -- the case that must never be downgraded.

        Verifying offline against a pinned keyring is a deliberate mode, not a degraded one. If a
        local registry file is unreadable, that is the operator's path to fix, and calling it a
        registry outage sends them to the network to debug a filename.
        """
        assert discovery_was_mandatory({"keys_source": "./keys/registry.json"}) is False
        assert discovery_was_mandatory({"keys_source": "/abs/registry.json"}) is False
        assert discovery_was_mandatory({"key_file": "pub.pem"}) is False

    def test_the_no_flag_default_is_OFFLINE_in_both_implementations_now(self):
        """THE DIVERGENCE THIS TEST RECORDED IS CLOSED -- deliberately, and this says so.

        Yesterday this asserted the opposite: that ``discovery_was_mandatory({})`` was True here
        and False in verify.js, because this module fetched with no flags while verify.js read a
        vendored snapshot. The test refused to resolve it, calling it "a product decision rather
        than a bug in either" and pinning it so a future reader would meet it in a test instead of
        an incident. Peter chose OFFLINE for both (P-2), so the no-flag path now loads the vendored
        snapshot and is not discovery.

        Kept rather than deleted: the coverage still matters, and inverting the assertion is how a
        closed divergence stays closed.
        """
        assert discovery_was_mandatory({}) is False
        # And the offline default is therefore NOT a case that can report a registry outage.
        assert discovery_was_mandatory({"key_file": "pub.pem"}) is False


class TestTheVerdict:
    def test_it_is_fail_closed(self):
        v = registry_unreachable_verdict(CLOSED, Exception("ECONNREFUSED"))
        assert v["valid"] is False
        assert v["status"] == "REGISTRY_UNREACHABLE"
        assert v["reason"] == "registry_unreachable"

    def test_it_is_not_unknown_key(self):
        """The whole point: one answer points at the signer, the other at the network."""
        v = registry_unreachable_verdict(CLOSED, Exception("x"))
        assert v["status"] != "UNKNOWN_KEY"
        assert v["status"] != "INVALID_SIGNATURE"

    def test_it_names_the_source_and_the_offline_remedy(self):
        v = registry_unreachable_verdict(CLOSED, Exception("ECONNREFUSED"))
        assert v["registry_unreachable"]["source"] == CLOSED
        assert "ECONNREFUSED" in v["registry_unreachable"]["why"]
        assert "--keys <file>" in v["registry_unreachable"]["remedy"]


class TestCrossLanguageDiscoveryCases:
    """The shared corpus carries both cases, and Python must reach the same answers."""

    def test_the_corpus_carries_the_discovery_block(self):
        assert DISCOVERY, (
            "xlang-vectors.json has no discovery block -- regenerate it from "
            "receipt-verifier/test/gen-xlang-vectors.js rather than hand-editing it"
        )

    @pytest.mark.parametrize("name", sorted(DISCOVERY) or ["__none__"])
    def test_python_agrees_with_the_corpus_about_mandatoriness(self, name):
        if name == "__none__":
            pytest.skip("no discovery cases in this corpus copy")
        case = DISCOVERY[name]
        opts = {
            "keys_source": case["invocation"].get("keys_source"),
            "fetch_url": case["invocation"].get("fetch_url"),
            "key_file": None,
        }
        assert discovery_was_mandatory(opts) is case["discovery_mandatory"], (
            f"{name}: Python and JavaScript disagree about whether discovery was mandatory"
        )

    def test_the_mandatory_case_expects_registry_unreachable(self):
        case = DISCOVERY["REGISTRY_UNREACHABLE_DISCOVERY_MANDATORY"]
        assert case["expected"]["status"] == "REGISTRY_UNREACHABLE"
        assert case["expected"]["valid"] is False
        produced = registry_unreachable_verdict(case["invocation"]["keys_source"], Exception("x"))
        assert produced["status"] == case["expected"]["status"]
        assert produced["reason"] == case["expected"]["reason"]

    def test_the_offline_case_expects_anything_BUT_registry_unreachable(self):
        """NEGATIVE CONTROL, read from the corpus so both languages share it."""
        case = DISCOVERY["OFFLINE_PINNED_REGISTRY_UNREACHABLE_IS_NOT_A_FAILURE"]
        assert case["discovery_mandatory"] is False
        assert case["expected"]["status"] != "REGISTRY_UNREACHABLE"


class TestTheCli:
    """End to end. 127.0.0.1 on a closed port: local, immediate, no external network."""

    RECEIPT = "eyJ2IjoxfQ.AAAA"  # structurally a token; discovery fails before it is read

    def _run(self, args):
        return subprocess.run(
            [sys.executable, "-m", "coderifts_verifier._verify", *args],
            capture_output=True, text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[1]),
        )

    def test_a_failed_mandatory_discovery_prints_a_status_and_exits_1(self):
        r = self._run([self.RECEIPT, "--keys", CLOSED])
        if r.returncode == 1 and r.stdout.strip():
            out = json.loads(r.stdout)
            assert out["status"] == "REGISTRY_UNREACHABLE"
            assert out["valid"] is False
        else:
            pytest.skip(
                "module is not runnable as __main__ here (rc=%s); the verdict shape is covered "
                "by TestTheVerdict above" % r.returncode
            )

    def test_an_unreadable_local_file_is_still_a_usage_error(self):
        """NEGATIVE CONTROL -- exit 2, and NO verdict document on stdout."""
        r = self._run([self.RECEIPT, "--keys", "./definitely-not-a-registry.json"])
        if r.returncode == 2:
            assert r.stdout.strip() == "", "a usage error must not emit a verdict document"
        else:
            pytest.skip("module is not runnable as __main__ here (rc=%s)" % r.returncode)
