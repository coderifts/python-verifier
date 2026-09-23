"""1961 TAG 1 -- finding the receipt that belongs to a commit (Python side).

Byte-for-byte the same convention as ``receipt-verifier/receipt-from-commit.js``: the
``CodeRifts-Receipt`` git trailer, or ``.coderifts/receipts/<full-sha>.json``. See
``receipt-verifier/docs/receipt-commit-binding.md`` for why both exist and why the trailer wins.

WARNING -- THE CARRIER PROVES NOTHING. Whichever one delivers the token, the token is then
verified exactly as if it had been pasted on the command line. A forged sidecar yields
INVALID_SIGNATURE, not a false pass. The sidecar is a POINTER; the signature is the authority.
"""

import json
import os
import pathlib
import subprocess

TRAILER_KEY = "CodeRifts-Receipt"
SIDECAR_DIR = os.path.join(".coderifts", "receipts")


def _git(args, cwd):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()


def resolve_sha(ref, cwd):
    """Abbreviations collide, and a verifier resolving one itself would be guessing which commit
    the operator meant. Git knows; ask it."""
    return _git(["rev-parse", ref + "^{commit}"], cwd)


def receipt_from_trailer(sha, cwd):
    raw = _git(["log", "-1", "--format=%%(trailers:key=%s,valueonly)" % TRAILER_KEY, sha], cwd)
    if not raw:
        return None
    # Unfold: git wraps long trailer values, and a receipt token is long. A token has no
    # whitespace in it, so joining the trimmed lines is lossless.
    token = "".join(line.strip() for line in raw.splitlines())
    return token or None


def receipt_from_sidecar(sha, cwd):
    """A MALFORMED SIDECAR IS NOT "NO SIDECAR".

    Treating it as absent would let a corrupted pointer fall through to the trailer, or to
    "nothing found" -- both of which read as an innocent absence rather than the broken file it is.
    """
    path = pathlib.Path(cwd) / SIDECAR_DIR / (sha + ".json")
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text())
    except Exception as e:
        raise ValueError("sidecar %s is not valid JSON: %s" % (path, e))
    token = (doc or {}).get("receipt") or (doc or {}).get("token")
    if not token:
        raise ValueError('sidecar %s has no "receipt" field' % path)
    return {"token": str(token), "envelope": (doc or {}).get("envelope"), "file": str(path)}


def receipt_for_commit(ref, cwd=None):
    """Returns {sha, token, envelope, carrier}. Raises on anything that is not a clean find.

    WARNING -- TRAILER WINS, BUT A DISAGREEMENT IS REFUSED RATHER THAN RESOLVED. The trailer is
    inside the commit object and the sidecar is a file anyone can edit, so where both exist the
    immutable one is authoritative. When they DISAGREE, silently preferring the trailer would hide
    precisely the tampering the precedence rule exists to make visible.
    """
    cwd = cwd or os.getcwd()
    try:
        sha = resolve_sha(ref, cwd)
    except subprocess.CalledProcessError as e:
        raise ValueError("cannot resolve %s in %s: %s" % (ref, cwd, (e.stderr or "").splitlines()[:1]))

    trailer = receipt_from_trailer(sha, cwd)
    sidecar = receipt_from_sidecar(sha, cwd)

    if trailer and sidecar:
        if trailer != sidecar["token"]:
            raise ValueError(
                "receipt conflict for %s: the commit trailer and %s carry DIFFERENT receipts. "
                "The trailer is covered by the commit SHA and the sidecar is not, so they should "
                "never disagree -- resolve it deliberately rather than letting one win silently."
                % (sha, sidecar["file"])
            )
        return {"sha": sha, "token": trailer, "envelope": sidecar["envelope"], "carrier": "both"}
    if trailer:
        return {"sha": sha, "token": trailer, "envelope": None, "carrier": "trailer"}
    if sidecar:
        return {"sha": sha, "token": sidecar["token"], "envelope": sidecar["envelope"], "carrier": "sidecar"}

    raise ValueError(
        "no receipt attached to %s: no %s trailer and no %s/%s.json. That means no receipt was "
        "ATTACHED -- it does not mean none exists." % (sha, TRAILER_KEY, SIDECAR_DIR, sha)
    )
