"""trooth-verify: check a Trooth witness statement yourself.

    from trooth_verify import verify_statement, verify_bundle

The rules are docs/VERIFY.md in github.com/troothllc/trooth-cli; this package
runs that repository's test vectors. Licensed under the Apache License 2.0.
"""

from .jcs import CanonicalizationError, canonicalize, is_canonical
from .tlog import LOG_ORIGIN, check_receipt, open_checkpoint, verify_consistency, verify_inclusion
from .verify import (
    ASSURANCE,
    JCS_LABEL,
    REASONS,
    VERIFICATION_BUNDLE_V1,
    WITNESS_STATEMENT_V1,
    WITNESS_STATEMENT_V2,
    WITNESS_STATEMENT_V3,
    BundleError,
    canonical_manifest,
    count_problems,
    key_state,
    key_trust,
    sha256_digest,
    statement_id,
    verify_bundle,
    verify_correction,
    verify_statement,
)

__version__ = "0.2.0"

__all__ = [
    "ASSURANCE", "JCS_LABEL", "REASONS", "VERIFICATION_BUNDLE_V1", "WITNESS_STATEMENT_V1",
    "WITNESS_STATEMENT_V2", "WITNESS_STATEMENT_V3", "BundleError", "CanonicalizationError",
    "canonical_manifest", "canonicalize", "count_problems", "is_canonical", "key_state", "key_trust",
    "sha256_digest", "statement_id", "verify_bundle", "verify_statement", "__version__",
    "LOG_ORIGIN", "check_receipt", "open_checkpoint", "verify_consistency", "verify_inclusion", "verify_correction",
]
