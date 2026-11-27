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

# CA-D-005: the version installed, from the package metadata, so it never drifts from pyproject.toml.
try:
    from importlib.metadata import version as _dist_version, PackageNotFoundError as _NotFound
    try:
        __version__ = _dist_version("trooth-verify")
    except _NotFound:
        __version__ = "0.4.1"
except ImportError:  # pragma: no cover
    __version__ = "0.4.1"

__all__ = [
    "ASSURANCE", "JCS_LABEL", "REASONS", "VERIFICATION_BUNDLE_V1", "WITNESS_STATEMENT_V1",
    "WITNESS_STATEMENT_V2", "WITNESS_STATEMENT_V3", "BundleError", "CanonicalizationError",
    "canonical_manifest", "canonicalize", "count_problems", "is_canonical", "key_state", "key_trust",
    "sha256_digest", "statement_id", "verify_bundle", "verify_statement", "__version__",
    "LOG_ORIGIN", "check_receipt", "open_checkpoint", "verify_consistency", "verify_inclusion", "verify_correction",
]
