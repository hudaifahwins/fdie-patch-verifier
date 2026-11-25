#!/usr/bin/env python3
"""Generate the strictly synthetic fixtures used by the test suite and demo.

All content is fabricated placeholder data — zero real or proprietary material.

Fixtures
--------
r1_baseline.tar.gz
    Vulnerable baseline firmware (exit code 1):
    * ``etc/openssl_version`` = OpenSSL 1.0.2u  -> CVE-2016-6304 / 6303
      confirmed vulnerable (no backport markers)
    * ``etc/server.key.pem``            -> PEM private key secret hit
    * ``etc/httpd.conf``                -> default `admin:admin` credential
    * ``opt/myapp/token.cfg``           -> hardcoded API token
    * ``nvram.enc``                     -> encrypted blob (unchecked region)
r2_fixed.tar.gz
    Fixed release (exit code 0): same upstream OpenSSL version but backport
    patch markers present -> LIKELY_BACKPORT_PATCHED; secrets removed; nvram
    now plain text -> zero unchecked regions.
r2_regressed.json
    Manifest declaring a new exposure (CVE-2018-0739) and a new blind spot
    (encrypted ``syscfg.bin``) -> exit code 1.
malformed.json
    Structurally invalid manifest (wrong field types) -> exit code 2.
"""
from __future__ import annotations

import io
import json
import random
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RNG = random.Random(20240101)

DUMMY_LIBSSL = b"\x00" * 2048 + b"OpenSSL shared library placeholder (synthetic)\n"


def write_tar_gz(name: str, entries: list[tuple[str, bytes]]):
    with tarfile.open(ROOT / name, "w:gz") as tf:
        for path, data in entries:
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))


def make_r1_baseline() -> None:
    entropy_blob = RNG.randbytes(512)  # seeded pseudo-random, encrypted-looking
    entries = [
        ("usr/lib/libssl.so.1.0.2", DUMMY_LIBSSL),
        ("etc/openssl_version", b"OpenSSL 1.0.2u 20 Sep 2016\n"),
        (
            "etc/server.key.pem",
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA...synthetic-private-key-material...\n"
            b"-----END RSA PRIVATE KEY-----\n",
        ),
        ("etc/httpd.conf", b"# factory default administrative credential\nadmin:admin\n"),
        (
            "opt/myapp/token.cfg",
            b'api_token="kQx9vT2mN4pR7sW1uY8zA3cE6fH0jL5oB"\n',
        ),
        ("nvram.enc", b"AES-256-CBC salt:\xff\x00" + entropy_blob),
    ]
    write_tar_gz("r1_baseline.tar.gz", entries)


def make_r2_fixed() -> None:
    entries = [
        ("usr/lib/libssl.so.1.0.2", DUMMY_LIBSSL),
        ("etc/openssl_version", b"OpenSSL 1.0.2u 20 Sep 2016\n"),
        (
            "usr/lib/patches/CVE-2016-6304-backport.patch",
            b"BACKPORT: CVE-2016-6304\n"
            b"CAP OCSP response memory growth when processing a flood of status requests\n"
            b"BACKPORT: CVE-2016-6303\n"
            b"Fix integer overflow in MDC2_Update\n",
        ),
        ("nvram", json.dumps({"factory_defaults": True}, indent=2).encode() + b"\n"),
    ]
    write_tar_gz("r2_fixed.tar.gz", entries)


def make_r2_regressed() -> None:
    manifest = {
        "release_id": "r2_regressed",
        "device": "acme smart-gateway",
        "firmware_version": "2.0.1",
        "packages": [
            {"name": "openssl", "version": "1.0.2u", "license": "OpenSSL"}
        ],
        "vulnerabilities": [
            {
                "cve": "CVE-2018-0739",
                "package": "openssl",
                "installed_version": "1.0.2u",
                "fixed_version": "1.0.2q",
                "backported": False,
                "severity": "HIGH",
                "evidence": "no backport patch marker present in release tree",
            }
        ],
        "unchecked_regions": [
            {
                "kind": "encrypted",
                "path": "syscfg.bin",
                "reason": "AES-256-CBC encrypted configuration blob; no key available",
            }
        ],
    }
    (ROOT / "r2_regressed.json").write_text(json.dumps(manifest, indent=2) + "\n")


def make_malformed() -> None:
    (ROOT / "malformed.json").write_text(
        json.dumps(
            {
                "release_id": "broken",
                "vulnerabilities": "not-a-list",
                "unchecked_regions": [{"kind": "encrypted"}],
            }
        )
    )


def main() -> None:
    make_r1_baseline()
    make_r2_fixed()
    make_r2_regressed()
    make_malformed()
    print(f"generated fixtures in {ROOT}")


if __name__ == "__main__":
    main()
