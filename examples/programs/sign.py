#!/usr/bin/env python3
"""Sign standard input with a key cakeys verified: `sign.py <object>`; the DER signature on stdout.

The program names a cakeys object, never a URI. `cakeys check` verifies the key against
keys.lock (CAKEYS_CONFIG) and prints its URI with the module and the PIN by reference; the
program opens that URI with its own PKCS#11 library (python-pkcs11) and signs. A failed check
is the program's failure, with cakeys' exit code: the key is not used.
"""

import subprocess
import sys
from urllib.parse import unquote, unquote_to_bytes

import pkcs11
from pkcs11.util.ec import encode_ecdsa_signature


def verified_uri(obj: str) -> str:
    """The key's URI, once `cakeys check` has verified it."""
    run = subprocess.run(
        ["cakeys", "check", obj, "--uri-module", "--uri-pin", "source"],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        sys.exit(run.returncode)
    return run.stdout.strip()


def parse(uri: str) -> tuple[dict[str, bytes], dict[str, str]]:
    """RFC 7512: path attributes as bytes (`id` is binary), query attributes as text."""
    path, _, query = uri.removeprefix("pkcs11:").partition("?")
    attrs = dict(a.split("=", 1) for a in path.split(";") if a)
    params = dict(q.split("=", 1) for q in query.split("&") if q)
    return {k: unquote_to_bytes(v) for k, v in attrs.items()}, {k: unquote(v) for k, v in params.items()}


def pin(source: str) -> str:
    """The PIN `pin-source` names: a file (`file:` or a bare path); cakeys writes no other."""
    with open(source.removeprefix("file:"), encoding="utf-8") as f:
        return f.readline().rstrip("\n")


def main() -> None:
    attrs, params = parse(verified_uri(sys.argv[1]))
    token = pkcs11.lib(params["module-path"]).get_token(token_label=attrs["token"].decode())
    with token.open(user_pin=pin(params["pin-source"])) as session:
        key = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, id=attrs["id"])
        signature = key.sign(sys.stdin.buffer.read(), mechanism=pkcs11.Mechanism.ECDSA_SHA256)
    sys.stdout.buffer.write(encode_ecdsa_signature(signature))


if __name__ == "__main__":
    main()
