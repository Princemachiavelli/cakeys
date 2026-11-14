#!/usr/bin/env python3
"""SoftHSMv2 #628: the CKA_VALUE_LEN of an unwrapped AES key.

    SOFTHSM2_CONF=<conf> repro.py <libsofthsm2.so> <token label> <user pin>

Wraps a fresh AES-256 key under AES key wrap, AES key wrap with padding and RSA-OAEP, unwraps
each, and compares CKA_VALUE_LEN and the length of CKA_VALUE with the original. Prints one
line per mechanism; exits 1 when any unwrapped key's CKA_VALUE_LEN is not 32.
"""

import sys

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

module, label, pin = sys.argv[1:4]
session = pkcs11.lib(module).get_token(token_label=label).open(user_pin=pin, rw=True)

secret = session.generate_key(KeyType.AES, 256, template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False})
aes_wrapper = session.generate_key(
    KeyType.AES, 256, template={Attribute.WRAP: True, Attribute.UNWRAP: True, Attribute.TOKEN: False}
)
rsa_public, rsa_private = session.generate_keypair(KeyType.RSA, 2048)

cases = [
    ("CKM_AES_KEY_WRAP", aes_wrapper, aes_wrapper, Mechanism.AES_KEY_WRAP),
    ("CKM_AES_KEY_WRAP_PAD", aes_wrapper, aes_wrapper, Mechanism.AES_KEY_WRAP_PAD),
    ("CKM_RSA_PKCS_OAEP", rsa_public, rsa_private, Mechanism.RSA_PKCS_OAEP),
]
failed = False
for name, wrapper, unwrapper, mechanism in cases:
    wrapped = wrapper.wrap_key(secret, mechanism=mechanism)
    key = unwrapper.unwrap_key(
        ObjectClass.SECRET_KEY,
        KeyType.AES,
        wrapped,
        mechanism=mechanism,
        template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
    )
    value_len = key[Attribute.VALUE_LEN]
    value = key[Attribute.VALUE]
    ok = value_len == 32 and len(value) == 32 and value == secret[Attribute.VALUE]
    failed = failed or not ok
    print(f"{name}: CKA_VALUE_LEN={value_len} len(CKA_VALUE)={len(value)} {'ok' if ok else 'WRONG'}")
    key.destroy()

sys.exit(1 if failed else 0)
