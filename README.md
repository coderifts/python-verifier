# coderifts-verifier (Python)

Verify a CodeRifts chain receipt — or a DSSE / in-toto envelope carrying one —
offline, in Python, without calling CodeRifts.

```python
from coderifts_verifier import unwrap, verify_receipt, keyring_from_document

keyring = keyring_from_document(registry_json, "my-registry.json")
token = unwrap(whatever_arrived)              # compact token, or DSSE -> compact
result = verify_receipt(token, {"keyring": keyring})

if result["valid"]:
    ...
else:
    handle(result["status"])                  # INVALID_SIGNATURE, UNKNOWN_KEY, ...
```

Ed25519 via `cryptography`. No network on the verify path.

## This is not the CodeRifts SDK

Two different packages, on purpose:

| | `coderifts` (SDK) | `coderifts-verifier` (this) |
| --- | --- | --- |
| does | calls the API to get a decision | verifies evidence you already hold |
| crypto | none — deliberately | Ed25519 |
| network | yes, that is the point | none on the verify path |

A dependency on `cryptography` is correct here: this package checks signatures.
The SDK stays crypto-free.

## Unwrapping is not verification

`unwrap` and `from_dsse` check **no signature**. An envelope wrapping a receipt
with a bad signature unwraps cleanly and then fails `verify_receipt`, exactly as
that compact token would have — the signature is over the compact bytes.

The DSSE envelope proves **exactly what the compact receipt proves**. A standard
container does not strengthen a claim.

```python
token = from_dsse(envelope)                   # succeeds — nothing checked yet
verify_receipt(token, {"keyring": keyring})   # this is the verdict
```

## Cross-language agreement

The signed-bytes reconstruction is byte-identical to the JavaScript verifier —
`verify.js` says so in its own source, and `tests/xlang-vectors.json` holds
receipts produced and verified by that implementation. The test suite asserts
Python reaches the **same verdict on the same bytes**, for a passing receipt and
for two distinct failure modes.

Two implementations disagreeing about whether a receipt is valid is the failure
a multi-language verifier exists to avoid, so the agreement is pinned rather than
assumed.

The verification core (`coderifts_verifier/_verify.py`) is **vendored** from the
reference verifier, not reimplemented. The only edit is the import path for the
vendored `arity` helper; the file is otherwise byte-identical, so there is one
definition of what a valid receipt is rather than two that can drift.

## Refusals are named

`from_dsse` raises `DsseError` with a `code`:

| code | when |
| --- | --- |
| `MALFORMED` | not an envelope; unreadable payload; zero, two, or signature-less entries; missing `encoded_payload` |
| `UNSUPPORTED` | a `payloadType`, `predicateType`, or compact `form` this version does not implement |
| `PREDICATE_MISMATCH` | the decoded `predicate.fields` disagree with the preserved payload segment |

That last one matters: the predicate carries the payload twice, once as bytes and
once decoded for a reader. If they disagree, the readable half describes
something the signed half does not contain — refuse rather than hand back bytes
that do not match the envelope someone read.

## What a valid verdict proves

* a holder of a key in **the keyring you supplied** signed this receipt;
* the receipt's signed fields are unmodified;
* per `status`: whether it is current, or was issued while a now-retired key was
  still valid.

## What it does NOT prove

* **That anything happened.** A receipt is a signed statement about a decision,
  not an observation of an effect.
* **That the key is uncompromised.** Everything reduces to "a holder of this key
  signed this". Custody is yours.
* **That the receipt is the right one for what you are about to do.** Scope
  matching — does this receipt cover THIS operation on THIS target — is the
  caller's check, against the decision envelope. This verifies the receipt.
* **That a human saw anything.**

## Format

`RECEIPT_FORMAT.md` in the reference verifier is the specification; section 9
covers the DSSE / in-toto export. The constants here are byte-exact to it and
pinned by a test.

## Tests

```bash
python3 -m pytest tests/ -q
```

## License

Apache-2.0
