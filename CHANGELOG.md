# Changelog

Versions here are the PyPI package `coderifts-verifier`. Entries land before the release that
carries them; a heading with no tag has not been published.

## 0.2.0 — 2026-10-18

### A receipt verified beside an envelope must be v4 — in the library, not only the CLI

**Fixed.** `verify_receipt()` now refuses a v1–v3 receipt whenever an envelope is supplied (`{}` included):
`valid: false`, `status: RECEIPT_VERSION_UNSUPPORTED`, `signature_status` carrying the bare verdict — the
same shape and reason text as receipt-verifier 1.1.4's `verifyReceipt`. Before, only the CLI applied the
rule; a library caller verifying a v2 receipt beside a forged ALLOW envelope got `VERIFIED_CURRENT`.
A bare token stays a signature check; `verify_chain` is unchanged.

### The receipt verdict carries `does_not_prove`

**Added.** The single-receipt CLI verdict ends with `does_not_prove`: the four published sentences
(receipt-verifier README and the app's `receipt` limits), byte-identical to the JS 1.1.4 CLI output.


### `--from-commit` binds the receipt to the commit asked about (P58)

**Fixed.** A sidecar receipt copied beside another commit (the T15 force-push) verified
`VERIFIED_CURRENT`: the signature and the envelope's body hash were checked, but nothing compared the
envelope with the commit. Now, after a valid signature:

- the envelope's `head` must name the commit (full SHA, or a 7–39 hex abbreviation as its prefix),
  else `RECEIPT_COMMIT_MISMATCH`, naming both;
- `--contract <path>` (repeatable, at most 6, only with `--from-commit`) recomputes `artifact_digest`
  from the files at the envelope's `base` and at the commit, else `CONTENT_MISMATCH`;
- a sidecar without an envelope, or an envelope without `head`, is `RECEIPT_NOT_BOUND_TO_COMMIT`;
- a trailer-only receipt keeps its verdict, and stderr says it binds nothing checkable.

On a failure: `valid: false`, `status` = the code, `signature_status` = what the signature alone said,
`commit_binding: {status, head, content}`, exit 1. The same rules, codes and fields as
`receipt-verifier` (`commit-binding.js`, 3e5ef59); `tests/test_from_commit_p58_binding.py` runs the
same fixtures through both CLIs.

### The no-flag default is now OFFLINE (P-2)

**Changed.** Running the verifier with no `--key` / `--keys` / `--fetch` now verifies against a
**vendored key snapshot** shipped with the package (`coderifts_verifier/keys/coderifts-keys.json`)
and makes **no network call**. Previously it fetched
`https://app.coderifts.com/.well-known/coderifts-keys.json`.

**Why.** `verify.js` with no flags has always read a vendored snapshot, so "no flags" meant two
different things in two implementations of the same format: one phoned home, the other did not.
A verifier's first promise is "you can check this yourself, without us", and a default that
fetches makes the quiet case — verifying on a laptop with no network, or inside a sealed build —
the one that needs a flag. Fetching is still one flag away (`--fetch <url>`, `--keys <url>`), and
it is the case that deserves to be explicit.

**Who is affected.** Anyone relying on the old implicit fetch to pick up a rotated key without
passing a flag. The remedy is one flag: `--fetch` (or `--keys <url>`) restores the previous
behaviour exactly. The snapshot's digest is pinned beside it and the refresh step is documented in
`coderifts_verifier/keys/README.md` — it must be refreshed in **both** verifier repositories
together, and `tests/test_vendored_keys.py` asserts byte equality against the sibling checkout
when one is present.

**Packaging.** The snapshot is declared as setuptools `package-data` so it ships in the wheel —
verified by building one, not by reading the config. (A first attempt declared it under
`[tool.hatch…]`, which this project does not use; an inert build setting is worse than a missing
one, because the repository looks as though the question was handled.)

**`discovery_was_mandatory({})` is now `False`.** The no-flag path is not discovery, so a failed
read on it is a local file problem (usage error) rather than `REGISTRY_UNREACHABLE`.

Version unchanged; the next minor carries this.

### `REGISTRY_UNREACHABLE` is now reachable from the CLI (1961/7.2)

**Added, additive.** A MANDATORY key discovery that fails — `--fetch <url>`, `--keys <url>`, or
the no-flag default (see the divergence note below) — now emits a structured verdict on stdout and
exits `1`:

```json
{ "valid": false, "status": "REGISTRY_UNREACHABLE", "reason": "registry_unreachable",
  "registry_unreachable": { "source": "…", "why": "…", "remedy": "…" } }
```

Previously that path went through `fail()`: free text on stderr and exit `2`, the same shape as a
mistyped flag. The verdict document shape is byte-identical to `cli.js`
`registryUnreachableVerdict` — two implementations must not describe the same outage differently.

**Nothing is loosened.** Both the old and the new answer are `valid: False`. What changes is where
an operator is sent: to their own network, or to the signer. The status has been normative in
`RECEIPT_FORMAT.md` §7.1 the whole time.

**Older verifiers treat it as unknown → fail-closed.** An unrecognised status is not valid:
`status_to_valid` names its accepting statuses explicitly rather than denying a blacklist.

**⚠ A measured divergence from `verify.js`, recorded rather than smoothed over.** With no flags at
all, `verify.js` reads a *vendored snapshot* (offline) while this module *fetches*
`DEFAULT_FETCH_URL`. So the no-flag default is mandatory discovery here and is not there. Making
the two agree is a product decision about what "no flags" should mean, not something a status
helper may decide on its own. `tests/test_registry_unreachable.py` pins the difference so a future
reader meets it in a test rather than in an incident.

**The offline path is deliberately untouched.** An unreadable local `--key` / `--keys <file>`
remains a usage error (exit `2`). The cross-language corpus carries that negative control as
`OFFLINE_PINNED_REGISTRY_UNREACHABLE_IS_NOT_A_FAILURE`.

**`tests/xlang-vectors.json` regenerated** from `receipt-verifier/test/gen-xlang-vectors.js` so it
carries the new top-level `discovery` block. The generator signs with an ephemeral key, so every
token in the file changes on each regeneration — the cross-language checks are structural for that
reason, and the eleven existing vectors keep their ids, key states and expected verdicts.
