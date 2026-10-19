#!/usr/bin/env python3
"""Sign report.json: python3 tools/sign_report.py report.json   (writes report.json.sig)

The key is the `REPORT_SIGNING_KEY` environment variable: the raw 32-byte Ed25519 seed, base64.
This is the *report* key. It is not the library key, which lives in the owner's login Keychain and
which no workflow ever holds. Flotilla accepts this key's signature on reports only.

`report.json.sig` is the same format as `library.json.sig`: the 64-byte Ed25519 signature of the
file's exact bytes, base64, no newline. The key is never printed or written; the public half is.
"""
import base64
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def private_key(encoded):
    try:
        seed = base64.b64decode(encoded.strip(), validate=True)
    except ValueError:
        seed = b""
    if len(seed) != 32:
        raise ValueError("REPORT_SIGNING_KEY is not a base64 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_text(key):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(data, key):
    return base64.b64encode(key.sign(data)).decode()


def verify(data, signature, public_key_text):
    """True if `signature` (base64) is valid for `data` under the base64 public key."""
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_text, validate=True))
        key.verify(base64.b64decode(signature.strip(), validate=True), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: sign_report.py report.json", file=sys.stderr)
        return 2
    try:
        key = private_key(os.environ.get("REPORT_SIGNING_KEY", ""))
    except ValueError as error:
        print("error:", error, file=sys.stderr)
        return 1
    with open(argv[0], "rb") as handle:
        data = handle.read()
    signature = sign(data, key)
    if not verify(data, signature, public_text(key)):  # a signing that doesn't verify must not be published
        print("error: the signature did not verify", file=sys.stderr)
        return 1
    with open(argv[0] + ".sig", "w") as handle:
        handle.write(signature)
    print("signed %s with report key %s" % (argv[0], public_text(key)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
