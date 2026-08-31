"""CodeRifts offline verifier for Python.

Verify a CodeRifts chain receipt, or a DSSE / in-toto envelope carrying one,
without calling CodeRifts. Offline Ed25519 against a keyring you pin.

    from coderifts_verifier import unwrap, verify_receipt

    token = unwrap(whatever_arrived)        # compact token, or DSSE -> compact
    result = verify_receipt(token, {"keyring": my_keyring})
    if result["valid"]:
        ...

UNWRAPPING IS NOT VERIFICATION. ``unwrap`` / ``from_dsse`` check no signature: a
DSSE envelope wrapping a bad receipt unwraps cleanly and then fails
``verify_receipt``, exactly as that compact token would have. The DSSE proves
exactly what the compact receipt proves -- a standard container does not
strengthen a claim.

The verification core (``_verify.py``) is VENDORED from the reference JS/Python
verifier rather than reimplemented, so there is one definition of what a valid
receipt is. Its signed-bytes reconstruction is byte-identical to ``verify.js``;
the cross-language tests pin that against shared vectors.
"""

from ._verify import (  # noqa: F401
    canonical_json,
    derive_status,
    keyring_from_document,
    reconstruct_signed_input,
    verify_chain,
    verify_receipt,
)
from .dsse import (  # noqa: F401
    FORM_ATTESTATION,
    FORM_RECEIPT,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    DsseError,
    from_dsse,
    looks_like_dsse,
    unwrap,
)

__all__ = [
    "verify_receipt",
    "verify_chain",
    "from_dsse",
    "unwrap",
    "looks_like_dsse",
    "DsseError",
    "keyring_from_document",
    "canonical_json",
    "derive_status",
    "reconstruct_signed_input",
    "PAYLOAD_TYPE",
    "STATEMENT_TYPE",
    "PREDICATE_TYPE",
    "FORM_RECEIPT",
    "FORM_ATTESTATION",
]
__version__ = "0.1.0"
