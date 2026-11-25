"""fdie-patch-verifier: firmware security and release-diff verification.

Safely inspects firmware archives and manifests, detects hardcoded secrets and
unchecked (encrypted/corrupt/unsupported) regions, classifies CVEs as confirmed
vulnerable vs likely backported-patched, and persists every run into SQLite for
release-over-release diffing — served through a FastAPI REST API and a localhost
dashboard.
"""

__version__ = "0.1.0"
