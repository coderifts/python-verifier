"""P58 (2026-10-05) -- is the receipt found for a commit actually ABOUT that commit? (Python side.)

The same rules, codes and wording as ``receipt-verifier/commit-binding.js`` (3e5ef59). MEASURED (CC-2
T15, T18): ``--from-commit <sha>`` found a sidecar by the SHA, verified the signature and the envelope's
body hash, and stopped there; a sidecar copied from an old commit beside a force-pushed one verified
VERIFIED_CURRENT in both verifiers.

WHAT CAN BE CHECKED, AND WHY ONLY THROUGH THE ENVELOPE. The receipt token signs no commit (kid, fp,
prev, caller, ts, reg, ir, expires_at, bh). The commit lives in the ENVELOPE (``head``, ``base``,
``artifact_digest``), and v4's ``bh`` signs the envelope -- so once the signature check has passed with
the envelope supplied, its ``head`` and ``artifact_digest`` are signed facts:

  head      envelope.head must name the commit asked about: the full SHA, or -- when the envelope carries
            an abbreviation of 7 to 39 hex characters -- a prefix of it. Otherwise
            RECEIPT_COMMIT_MISMATCH, naming both.
  content   only with --contract <path> (repeatable): each file is read at ``base`` and at the commit
            (git show), the app's artifact_digest is recomputed -- sha256 over each artifact's
            sha256(before) || sha256(after), joined with U+001F -- and compared. With several files every
            order is tried (at most 6). Otherwise CONTENT_MISMATCH. Without --contract: not_checked.

LIMITS, said rather than hidden: a sidecar WITHOUT an envelope, or an envelope without ``head``, names no
commit -> RECEIPT_NOT_BOUND_TO_COMMIT; a TRAILER without an envelope keeps its verdict (``--amend`` keeps
the trailer while the files change) and the CLI says so on stderr.
"""

import hashlib
import itertools
import re
import subprocess

US = "\x1f"
MAX_CONTRACT_FILES = 6
_ABBREV = re.compile(r"^[0-9a-f]{7,39}$")


def _sha256hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _show_at(rev, path, cwd):
    """The file at ``rev``; '' when absent there (the app hashes an absent side as '')."""
    res = subprocess.run(["git", "show", "%s:%s" % (rev, path)], cwd=cwd, capture_output=True)
    if res.returncode != 0:
        return ""
    return res.stdout.decode("utf-8")


def head_matches(head, sha):
    """The commit an envelope names matches ``sha`` (full, or an abbreviation of 7-39 hex characters)."""
    h = str(head or "").lower()
    s = str(sha).lower()
    if len(h) == 40:
        return h == s
    return bool(_ABBREV.match(h)) and s.startswith(h)


def check_commit_binding(sha, carrier, envelope, cwd, contracts=()):
    """Returns {status: BOUND|FAILED|UNCHECKED, code?, reason?, head, content, note?}.

    Raises ValueError for more than MAX_CONTRACT_FILES contracts (a usage error, as in the JS CLI).
    """
    contracts = list(contracts or [])
    # `is None`, not falsiness: an empty envelope {} is an envelope without head (as in JS, where {} is truthy).
    if envelope is None:
        if carrier == "sidecar":
            return {"status": "FAILED", "code": "RECEIPT_NOT_BOUND_TO_COMMIT", "head": "absent", "content": "not_checked",
                    "reason": "the sidecar for %s carries no envelope, so nothing in it names that commit; "
                              "a receipt copied there from any other commit would look the same" % sha}
        return {"status": "UNCHECKED", "head": "not_checked", "content": "not_checked",
                "note": "commit binding: the trailer carries no envelope, so the receipt names no commit and no content "
                        "to check; an amended commit keeps the trailer while its files change. Attach the envelope in a "
                        "sidecar to bind it."}
    if not envelope.get("head"):
        return {"status": "FAILED", "code": "RECEIPT_NOT_BOUND_TO_COMMIT", "head": "absent", "content": "not_checked",
                "reason": "the envelope names no commit (no head), so it cannot be bound to %s" % sha}
    if not head_matches(envelope["head"], sha):
        return {"status": "FAILED", "code": "RECEIPT_COMMIT_MISMATCH", "head": "mismatch", "content": "not_checked",
                "reason": "the receipt is for commit %s, and it was asked about %s" % (envelope["head"], sha)}
    if not contracts:
        return {"status": "BOUND", "head": "match", "content": "not_checked",
                "note": "commit binding: the head matches; the content was not checked "
                        "(name the contract file with --contract <path>)"}
    if not envelope.get("artifact_digest") or not envelope.get("base"):
        missing = "base" if envelope.get("artifact_digest") else "artifact_digest"
        return {"status": "FAILED", "code": "CONTENT_MISMATCH", "head": "match", "content": "unverifiable",
                "reason": "the envelope carries no %s, so %s cannot be checked against it" % (missing, ", ".join(contracts))}
    if len(contracts) > MAX_CONTRACT_FILES:
        raise ValueError("--contract: at most %d files (the artifact order is tried exhaustively)" % MAX_CONTRACT_FILES)
    arts = [(_show_at(envelope["base"], f, cwd), _show_at(sha, f, cwd)) for f in contracts]
    expected = envelope["artifact_digest"]
    match = any(
        "sha256:" + _sha256hex(US.join(_sha256hex(b) + _sha256hex(a) for b, a in order)) == expected
        for order in itertools.permutations(arts)
    )
    if not match:
        return {"status": "FAILED", "code": "CONTENT_MISMATCH", "head": "match", "content": "mismatch",
                "reason": "%s at %s…%s do not hash to the receipt's artifact_digest %s"
                          % (", ".join(contracts), envelope["base"][:12], sha[:12], expected)}
    return {"status": "BOUND", "head": "match", "content": "match"}
