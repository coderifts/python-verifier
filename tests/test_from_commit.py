"""1961 TAG 1 -- `--from-commit` in Python, and cross-language agreement with verify.js.

The load-bearing test is ``test_a_disagreement_is_refused``: preferring the trailer is the right
precedence and looks correct in every ordinary case, and is precisely wrong in the one case that
matters. And ``TestCrossLanguage`` is what makes this a convention rather than two features: both
CLIs must resolve the SAME commit to the SAME token, by the same rules.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from coderifts_verifier._from_commit import (  # noqa: E402
    SIDECAR_DIR,
    TRAILER_KEY,
    receipt_for_commit,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
JS = pathlib.Path.home() / "receipt-verifier"
TOKEN = (JS / "test" / "fixtures-receipt.txt").read_text().strip() if (JS / "test" / "fixtures-receipt.txt").exists() else None
KEYS = JS / "test" / "fixtures-keys.json"


@pytest.fixture
def git_repo(tmp_path):
    def g(*args, cwd=tmp_path):
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    g("init", "-q", ".")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")

    def commit(message, name="f"):
        (tmp_path / name).write_text("x")
        g("add", "-A")
        g("commit", "-q", "-m", message)
        return g("rev-parse", "HEAD").stdout.strip()

    def sidecar(sha, doc):
        d = tmp_path / SIDECAR_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / (sha + ".json")).write_text(doc if isinstance(doc, str) else json.dumps(doc))

    return type("R", (), {"dir": tmp_path, "commit": staticmethod(commit), "sidecar": staticmethod(sidecar)})


pytestmark = pytest.mark.skipif(TOKEN is None, reason="UNPROVEN: receipt-verifier fixtures not checked out here")


class TestTheCarriers:
    def test_the_trailer_carries_it(self, git_repo):
        sha = git_repo.commit("subject\n\n%s: %s" % (TRAILER_KEY, TOKEN))
        found = receipt_for_commit(sha, cwd=str(git_repo.dir))
        assert found["token"] == TOKEN, "the token did not survive the trailer round trip"
        assert found["carrier"] == "trailer"

    def test_the_sidecar_carries_the_envelope_a_trailer_cannot(self, git_repo):
        sha = git_repo.commit("no trailer")
        git_repo.sidecar(sha, {"receipt": TOKEN, "envelope": {"decision": "ALLOW"}})
        found = receipt_for_commit(sha, cwd=str(git_repo.dir))
        assert found["carrier"] == "sidecar"
        assert found["envelope"] == {"decision": "ALLOW"}

    def test_an_abbreviated_sha_resolves_through_git(self, git_repo):
        sha = git_repo.commit("x")
        git_repo.sidecar(sha, {"receipt": TOKEN})
        assert receipt_for_commit(sha[:8], cwd=str(git_repo.dir))["sha"] == sha


class TestPrecedence:
    def test_both_agreeing_is_carrier_both(self, git_repo):
        sha = git_repo.commit("s\n\n%s: %s" % (TRAILER_KEY, TOKEN))
        git_repo.sidecar(sha, {"receipt": TOKEN, "envelope": {"e": 1}})
        found = receipt_for_commit(sha, cwd=str(git_repo.dir))
        assert found["carrier"] == "both"
        assert found["envelope"] == {"e": 1}

    def test_a_disagreement_is_refused(self, git_repo):
        """THE LOAD-BEARING ONE. A disagreement is the signature of somebody editing the mutable
        half; letting the trailer win would hide exactly that."""
        sha = git_repo.commit("s\n\n%s: %s" % (TRAILER_KEY, TOKEN))
        git_repo.sidecar(sha, {"receipt": TOKEN.split(".")[0] + ".AAAA"})
        with pytest.raises(ValueError, match="receipt conflict"):
            receipt_for_commit(sha, cwd=str(git_repo.dir))

    def test_a_malformed_sidecar_is_not_no_sidecar(self, git_repo):
        sha = git_repo.commit("x")
        git_repo.sidecar(sha, "{not json")
        with pytest.raises(ValueError, match="not valid JSON"):
            receipt_for_commit(sha, cwd=str(git_repo.dir))


class TestAbsence:
    def test_nothing_attached_says_what_that_does_NOT_mean(self, git_repo):
        """NEGATIVE CONTROL. A missing trailer means no receipt was ATTACHED, which is not the
        same as no receipt existing."""
        sha = git_repo.commit("a perfectly ordinary commit")
        with pytest.raises(ValueError, match="it does not mean none exists"):
            receipt_for_commit(sha, cwd=str(git_repo.dir))


class TestCrossLanguage:
    """Both CLIs must resolve the same commit to the same token. Otherwise it is two features."""

    def _run_py(self, args, cwd):
        env = {"PYTHONPATH": str(REPO), "PATH": subprocess.os.environ.get("PATH", "")}
        return subprocess.run(
            [sys.executable, "-m", "coderifts_verifier._verify", *args],
            cwd=str(cwd), capture_output=True, text=True, env=env,
        )

    def _run_js(self, args, cwd):
        node = shutil.which("node")
        if not node or not (JS / "cli.js").exists():
            pytest.skip("UNPROVEN: node or receipt-verifier/cli.js unavailable here")
        return subprocess.run([node, str(JS / "cli.js"), *args], cwd=str(cwd),
                              capture_output=True, text=True)

    def test_both_CLIs_reach_the_same_verdict_from_the_same_trailer(self, git_repo):
        sha = git_repo.commit("s\n\n%s: %s" % (TRAILER_KEY, TOKEN))
        args = ["--from-commit", sha, "--keys", str(KEYS)]
        py = self._run_py(args, git_repo.dir)
        js = self._run_js(args, git_repo.dir)
        assert json.loads(py.stdout) == json.loads(js.stdout), (
            "Python and JavaScript disagree about a receipt read from the same commit"
        )
        assert py.returncode == js.returncode

    def test_both_CLIs_reach_the_same_verdict_from_the_same_sidecar(self, git_repo):
        sha = git_repo.commit("no trailer")
        git_repo.sidecar(sha, {"receipt": TOKEN})
        args = ["--from-commit", sha, "--keys", str(KEYS)]
        py = self._run_py(args, git_repo.dir)
        js = self._run_js(args, git_repo.dir)
        assert json.loads(py.stdout) == json.loads(js.stdout)

    def test_POSITIVE_CONTROL_the_carrier_changes_nothing(self, git_repo):
        """The verdict from a commit must equal the verdict from a pasted token."""
        sha = git_repo.commit("s\n\n%s: %s" % (TRAILER_KEY, TOKEN))
        a = self._run_py(["--from-commit", sha, "--keys", str(KEYS)], git_repo.dir)
        b = self._run_py([TOKEN, "--keys", str(KEYS)], git_repo.dir)
        assert json.loads(a.stdout) == json.loads(b.stdout)

    def test_both_CLIs_treat_an_absent_receipt_as_a_USAGE_error(self, git_repo):
        git_repo.commit("bare")
        args = ["--from-commit", "HEAD"]
        py = self._run_py(args, git_repo.dir)
        js = self._run_js(args, git_repo.dir)
        assert py.returncode == 2 and js.returncode == 2
        assert py.stdout.strip() == "" and js.stdout.strip() == ""
