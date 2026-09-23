# Vendored CodeRifts key snapshot (Python verifier)

⚠ **This is a COPY of `receipt-verifier/keys/coderifts-keys.json`, and the two must be refreshed
together.** Byte equality between the two repositories is what lets the JavaScript and Python
verifiers reach the same offline verdict; a copy that drifted would make the two implementations
disagree about a receipt, which is the failure a multi-language verifier exists to avoid.
`tests/test_vendored_keys.py` asserts the digest, and asserts equality against the sibling
checkout when one is present (loudly UNPROVEN when it is not).

`coderifts-keys.json.sha256` must match this file. The CLI default — no `--key` / `--keys` /
`--fetch` — verifies against this snapshot **offline**, the same as `verify.js`.

A CA pins roots locally; this file is that pin. Fetching the live registry is opt-in
(`--fetch <url>` or `--keys <url>`), and fetching does **not** rewrite this snapshot.

Refresh the pin (operator / release step, not verify-time) — **in both repositories**:

```
curl -fsS https://app.coderifts.com/.well-known/coderifts-keys.json -o coderifts_verifier/keys/coderifts-keys.json
shasum -a 256 coderifts_verifier/keys/coderifts-keys.json | awk '{print $1"  coderifts-keys.json"}' > coderifts_verifier/keys/coderifts-keys.json.sha256
```
