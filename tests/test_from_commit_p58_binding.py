"""P58 (2026-10-05) -- ``--from-commit <sha>`` binds the receipt to THAT commit (Python side).

MEASURED (CC-2 T15 item 8, T18): a sidecar copied from an old commit beside a force-pushed SHA verified
VERIFIED_CURRENT, exit 0, in both verifiers. ``receipt-verifier`` (JS) fixed it in 3e5ef59; this file
holds the Python verifier to the same rules and the same codes (``commit_binding.py`` there,
``_commit_binding.py`` here):

  - the receipt for the commit it names verifies, with commit_binding BOUND (head, and content when
    --contract names the file);
  - the same sidecar copied to another commit fails RECEIPT_COMMIT_MISMATCH, naming both;
  - editing the envelope's head to match is caught by the signature (body hash);
  - a receipt whose artifact_digest the commit's files do not produce fails CONTENT_MISMATCH;
  - a sidecar without an envelope fails RECEIPT_NOT_BOUND_TO_COMMIT;
  - an abbreviated head in the envelope binds by prefix;
  - a trailer without an envelope keeps its verdict and says on stderr what it cannot check.

``TestParityWithJs`` runs the same fixtures through ``node ~/receipt-verifier/cli.js``: the two must
agree on the status and the exit code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from coderifts_verifier._from_commit import SIDECAR_DIR, TRAILER_KEY  # noqa: E402
from coderifts_verifier._verify import canonical_json, reconstruct_signed_input  # noqa: E402

JS_CLI = pathlib.Path.home() / "receipt-verifier" / "cli.js"
KID = "p58-test-k1"
PRIVATE = Ed25519PrivateKey.generate()
PUBLIC_PEM = PRIVATE.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
US = "\x1f"

V1 = "openapi: 3.0.3\npaths:\n  /users: {}\n"
V2 = "openapi: 3.0.3\npaths:\n  /users: {}\n  /orders: {}\n"
V3 = "openapi: 3.0.3\npaths:\n  /orders: {}\n"  # the force-pushed content: /users removed


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def artifact_digest(arts):
    """The app's artifact_digest (src/change-set.js), for (before, after) pairs in order."""
    return "sha256:" + sha256hex(US.join(sha256hex(b) + sha256hex(a) for b, a in arts))


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint(envelope):
    """A v4 receipt over ``envelope``, signed with the test key (the same shape as the JS test)."""
    bh = "sha256:" + sha256hex(canonical_json(dict(envelope)))
    now = time.time()
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".000Z"  # noqa: E731
    payload = {
        "v": 4, "kid": KID, "fp": "sha256:" + sha256hex("fp"), "prev": "null", "caller": "anon",
        "ts": iso(now), "reg": sha256hex("reg"), "ir": "sha256:" + sha256hex("ir"),
        "expires_at": iso(now + 3600), "bh": bh,
    }
    sig = PRIVATE.sign(reconstruct_signed_input(payload).encode("utf-8"))
    return b64url(json.dumps(payload, separators=(",", ":")).encode()) + "." + b64url(sig)


class Repo:
    def __init__(self, path):
        self.dir = path
        self.g("init", "-q", ".")
        self.g("config", "user.email", "t@t")
        self.g("config", "user.name", "t")
        self.keys = str(path / "keys.json")
        (path / "keys.json").write_text(json.dumps({"keys": [{
            "kid": KID, "public_key_pem": PUBLIC_PEM, "status": "active", "valid_from": None, "retired_at": None,
        }]}))
        # keys.json must not be part of the commits' trees
        (path / ".git" / "info" / "exclude").write_text("keys.json\n")

    def g(self, *args):
        return subprocess.run(["git", *args], cwd=self.dir, capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, spec, message="m"):
        (self.dir / "openapi.yaml").write_text(spec)
        self.g("add", "-A")
        self.g("commit", "-q", "-m", message)
        return self.g("rev-parse", "HEAD")

    def sidecar(self, sha, doc):
        d = self.dir / SIDECAR_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / (sha + ".json")).write_text(json.dumps(doc))


def run_py(args, cwd):
    env = {k: v for k, v in os.environ.items() if k != "CODERIFTS_API_KEY"}
    env["PYTHONPATH"] = str(REPO)
    res = subprocess.run([sys.executable, "-m", "coderifts_verifier._verify", *args],
                         cwd=str(cwd), capture_output=True, text=True, env=env)
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        doc = None
    return res.returncode, doc, res.stderr


def run_js(args, cwd):
    node = shutil.which("node")
    if not node or not JS_CLI.exists():
        pytest.skip("UNPROVEN: node or receipt-verifier/cli.js unavailable here")
    env = {k: v for k, v in os.environ.items() if k != "CODERIFTS_API_KEY"}
    res = subprocess.run([node, str(JS_CLI), *args], cwd=str(cwd), capture_output=True, text=True, env=env)
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        doc = None
    return res.returncode, doc, res.stderr


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path)


def scenario(r):
    """base -> head, a receipt minted for head, its sidecar beside head."""
    base = r.commit(V1, "base")
    head = r.commit(V2, "add /orders")
    envelope = {"decision": "ALLOW", "execution_action": "CONTINUE", "base": base, "head": head,
                "artifact_digest": artifact_digest([(V1, V2)])}
    doc = {"sha": head, "receipt": mint(envelope), "envelope": envelope}
    r.sidecar(head, doc)
    return base, head, envelope, doc


def force_pushed(r, base, doc, envelope=None):
    r.g("reset", "-q", "--hard", base)
    forced = r.commit(V3, "add /orders (amended: /users removed)")
    r.sidecar(forced, dict(doc, sha=forced, **({"envelope": envelope} if envelope else {})))
    return forced


def content_mismatch(r):
    base = r.commit(V1, "base")
    head = r.commit(V3, "remove /users")
    envelope = {"decision": "ALLOW", "base": base, "head": head, "artifact_digest": artifact_digest([(V1, V2)])}
    r.sidecar(head, {"sha": head, "receipt": mint(envelope), "envelope": envelope})
    return head


def abbreviated(r):
    base = r.commit(V1, "base")
    head = r.commit(V2, "add")
    envelope = {"decision": "ALLOW", "base": base, "head": head[:12], "artifact_digest": artifact_digest([(V1, V2)])}
    r.sidecar(head, {"sha": head, "receipt": mint(envelope), "envelope": envelope})
    return head


def trailer_only(r):
    r.commit(V1, "base")
    token = mint({"decision": "ALLOW"})
    (r.dir / "openapi.yaml").write_text(V2)
    r.g("add", "-A")
    r.g("commit", "-q", "-m", "add\n\n%s: %s" % (TRAILER_KEY, token))
    return r.g("rev-parse", "HEAD")


class TestP58Binding:
    def test_the_receipt_for_the_commit_it_names_verifies_and_is_bound(self, repo):
        _, head, _, _ = scenario(repo)
        code, out, err = run_py(["--from-commit", head, "--keys", repo.keys, "--contract", "openapi.yaml"], repo.dir)
        assert code == 0, (out, err)
        assert out["status"] == "VERIFIED_CURRENT"
        assert out["commit_binding"] == {"status": "BOUND", "head": "match", "content": "match"}

    def test_THE_T15_FORCE_PUSH_a_copied_sidecar_fails_RECEIPT_COMMIT_MISMATCH_naming_both(self, repo):
        base, head, _, doc = scenario(repo)
        forced = force_pushed(repo, base, doc)
        code, out, err = run_py(["--from-commit", forced, "--keys", repo.keys], repo.dir)
        assert code == 1, (out, err)
        assert out["valid"] is False
        assert out["status"] == "RECEIPT_COMMIT_MISMATCH"
        assert head in out["reason"] and forced in out["reason"], out["reason"]
        assert out["signature_status"] == "VERIFIED_CURRENT", "the signature itself is fine; the binding is not"
        assert out["commit_binding"] == {"status": "FAILED", "head": "mismatch", "content": "not_checked"}

    def test_editing_the_envelope_head_is_caught_by_the_signature(self, repo):
        base, _, envelope, doc = scenario(repo)
        repo.g("reset", "-q", "--hard", base)
        forced = repo.commit(V3, "amended")
        repo.sidecar(forced, {"sha": forced, "receipt": doc["receipt"], "envelope": dict(envelope, head=forced)})
        code, out, _ = run_py(["--from-commit", forced, "--keys", repo.keys], repo.dir)
        assert code == 1
        assert out["status"] == "INVALID_SIGNATURE"
        assert out["reason"] == "body_hash_mismatch"

    def test_files_that_do_not_hash_to_artifact_digest_fail_CONTENT_MISMATCH(self, repo):
        head = content_mismatch(repo)
        code, out, err = run_py(["--from-commit", head, "--keys", repo.keys, "--contract", "openapi.yaml"], repo.dir)
        assert code == 1, (out, err)
        assert out["status"] == "CONTENT_MISMATCH"
        assert "openapi.yaml" in out["reason"]
        # without --contract the content is not checked, and the output says so
        code, out, _ = run_py(["--from-commit", head, "--keys", repo.keys], repo.dir)
        assert code == 0
        assert out["commit_binding"]["content"] == "not_checked"

    def test_a_sidecar_without_an_envelope_is_RECEIPT_NOT_BOUND_TO_COMMIT(self, repo):
        _, head, _, doc = scenario(repo)
        repo.sidecar(head, {"sha": head, "receipt": doc["receipt"]})
        code, out, err = run_py(["--from-commit", head, "--keys", repo.keys], repo.dir)
        assert code == 1, (out, err)
        assert out["status"] == "RECEIPT_NOT_BOUND_TO_COMMIT"

    def test_an_abbreviated_envelope_head_binds_by_prefix(self, repo):
        head = abbreviated(repo)
        code, out, err = run_py(["--from-commit", head, "--keys", repo.keys], repo.dir)
        assert code == 0, (out, err)
        assert out["commit_binding"]["head"] == "match"

    def test_a_trailer_without_an_envelope_keeps_its_verdict_and_says_so(self, repo):
        head = trailer_only(repo)
        code, out, err = run_py(["--from-commit", head, "--keys", repo.keys], repo.dir)
        assert code == 0, (out, err)
        assert out["status"] == "VERIFIED_CURRENT"
        assert "commit_binding" not in out
        assert "commit binding: the trailer carries no envelope" in err

    def test_contract_needs_from_commit_and_is_a_usage_error_otherwise(self, repo):
        code, out, err = run_py(["sometoken", "--contract", "openapi.yaml"], repo.dir)
        assert code == 2 and out is None
        assert "--contract needs --from-commit" in err


def _same(py, js):
    """The two verdicts agree on everything a caller branches on."""
    (pc, po, _), (jc, jo, _) = py, js
    assert pc == jc, (po, jo)
    assert po["valid"] == jo["valid"] and po["status"] == jo["status"], (po, jo)
    assert po.get("signature_status") == jo.get("signature_status")
    assert po.get("commit_binding") == jo.get("commit_binding"), (po, jo)
    assert po.get("reason") == jo.get("reason"), (po, jo)


class TestParityWithJs:
    """The same fixtures through both CLIs: the same status, binding and exit code."""

    def test_bound_with_content(self, repo):
        _, head, _, _ = scenario(repo)
        args = ["--from-commit", head, "--keys", repo.keys, "--contract", "openapi.yaml"]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))

    def test_force_push_copy(self, repo):
        base, _, _, doc = scenario(repo)
        forced = force_pushed(repo, base, doc)
        args = ["--from-commit", forced, "--keys", repo.keys]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))

    def test_content_mismatch(self, repo):
        head = content_mismatch(repo)
        args = ["--from-commit", head, "--keys", repo.keys, "--contract", "openapi.yaml"]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))

    def test_sidecar_without_envelope(self, repo):
        _, head, _, doc = scenario(repo)
        repo.sidecar(head, {"sha": head, "receipt": doc["receipt"]})
        args = ["--from-commit", head, "--keys", repo.keys]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))

    def test_abbreviated_head(self, repo):
        head = abbreviated(repo)
        args = ["--from-commit", head, "--keys", repo.keys]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))

    def test_trailer_only(self, repo):
        head = trailer_only(repo)
        args = ["--from-commit", head, "--keys", repo.keys]
        _same(run_py(args, repo.dir), run_js(args, repo.dir))
