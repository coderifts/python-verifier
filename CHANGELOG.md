# Changelog

Versions here are the PyPI package `coderifts-verifier`. Entries land before the release that
carries them; a heading with no tag has not been published.

## Unreleased — next minor

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
