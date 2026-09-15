Security

coderifts-verifier checks a CodeRifts chain receipt — or a DSSE / in-toto envelope carrying one — offline, in Python, without calling CodeRifts. This file states what that does and does not protect, where the boundary sits, and how to report a problem.

This package verifies evidence you already hold. It is not the CodeRifts SDK and it is not the runtime guard.

The same discipline applies here as in the product: every proof CodeRifts emits carries a does_not_prove field generated from what was actually measured. This file is the repository form of that field.

Reporting a vulnerability

Email hello@coderifts.com. Please include what you did, what happened, and what you expected. Do not open a public issue for a suspected vulnerability.

We aim to acknowledge within three working days. We are a small team; there is no bug bounty.

What this package does
Verifies a chain receipt you already hold, locally: no network on the verify path, no key download, no CodeRifts server. The verifier refuses to fetch a key it was not given.
Unwraps a DSSE or in-toto envelope to the compact token. Unwrapping is not verification.

Known containment gaps

These are measured limits, not hypotheticals.

This is not a sandbox. This package does not isolate, contain, or restrict what a process on your machine can do. It checks a signature over bytes you already hold.

Unwrapping is not verification. unwrap and from_dsse check no signature. An envelope wrapping a receipt with a bad signature unwraps cleanly and then fails verify_receipt. A standard container does not strengthen a claim.

A verified receipt is not permission to mutate. The signature layer and the authorization layer are separate. A receipt proves what was decided; it does not by itself entitle a caller to perform the operation. Scope matching — does this receipt cover this operation on this target — is the caller's check against the decision envelope.

A stolen signing key still signs. Cryptographic verification proves that a key signed a payload. It does not prove the key was held by the party you expect. Key custody is outside this system's control; rotation and registry state are the operator's responsibility.

The environment is asserted by the host. Values the host reports about its own environment are taken as asserted, not verified. A valid signature over those bytes is not a measurement of the environment.

Supported versions

Security fixes are applied to the current published release of each package. Older versions are not patched. Published versions, their commits and their integrity digests are listed in the public release provenance records.

Verifying what we ship

Every published release is pinned in a frozen release set, and the acceptance run that measures it uses only public artifacts: the packages from the registry, the signed tags, and the public provenance records. You can run it yourself — you do not need to take our word for any claim in this file.
