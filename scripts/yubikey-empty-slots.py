#!/usr/bin/env python3
"""Empty the YubiKey's test slots (docs/DEVELOPMENT.md, "Hardware rules"): the key and the
certificate of each slot named, retired slots 90-95 only, so the YubiKey suites generate again
rather than adopt an earlier run's key (review yubikey.rs F2: ykcs11 cannot erase a PIV key).

    yubikey-empty-slots.py <management key file> <slot>...      e.g. ... mgm.txt 90 91 92 93

The management key file holds the key in hex, as `CAKEYS_TEST_YUBIKEY_MGM` does; it is read here
and never printed. It authenticates with the management key alone: a wrong one costs no PIN try,
and the PIN is never asked for, so a failure stops the run with every PIN try left. The
user's own slots must be the same after as before, or this fails.

Needs yubikit (yubikey-manager's library): `nix run .#coverage-full` brings it.
"""

import sys

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ykman.device import list_all_devices
from yubikit.core import BadResponseError
from yubikit.core.smartcard import ApduError, SmartCardConnection
from yubikit.piv import SLOT, PivSession

# The tests' slots; nothing else is ever emptied.
TEST_SLOTS = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95}
# The slots whose keys the user depends on: compared before and after.
KEPT_SLOTS = (0x82, 0x83, 0x84)


def fail(why: str) -> None:
    print(f"yubikey-empty-slots: {why}", file=sys.stderr)
    sys.exit(1)


def public(piv: PivSession, slot: int) -> bytes | None:
    """The slot's public key (SPKI DER), or None when it holds no key."""
    try:
        return piv.get_slot_metadata(SLOT(slot)).public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    except ApduError:
        return None


def has_certificate(piv: PivSession, slot: int) -> bool:
    try:
        piv.get_certificate(SLOT(slot))
        return True
    except (ApduError, BadResponseError, ValueError):
        return False


def main() -> None:
    if len(sys.argv) < 3:
        fail("usage: yubikey-empty-slots.py <management key file> <slot>...")
    try:
        slots = [int(s, 16) for s in sys.argv[2:]]
    except ValueError:
        fail(f"slots are hex, as PIV names them (90-95): {sys.argv[2:]}")
    outside = [f"{s:x}" for s in slots if s not in TEST_SLOTS]
    if outside:
        fail(f"only the test slots 90-95 are emptied, not {', '.join(outside)}")
    with open(sys.argv[1]) as f:
        text = f.read().strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        fail(f"{sys.argv[1]} is not a management key in hex")
    del text
    devices = list_all_devices()
    if len(devices) != 1:
        fail(f"{len(devices)} YubiKeys attached: attach exactly one")
    device, _ = devices[0]
    with device.open_connection(SmartCardConnection) as conn:
        piv = PivSession(conn)
        kept = {s: public(piv, s) for s in KEPT_SLOTS}
        try:
            piv.authenticate(key)
        except (ApduError, BadResponseError):
            fail("the management key was refused (no PIN was tried); nothing changed")
        finally:
            del key
        for slot in slots:
            done = []
            if public(piv, slot) is not None:
                piv.delete_key(SLOT(slot))
                done.append("key")
            if has_certificate(piv, slot):
                piv.delete_certificate(SLOT(slot))
                done.append("certificate")
            print(f"slot {slot:x}: " + (" and ".join(done) + " deleted" if done else "already empty"))
        for slot in slots:
            if public(piv, slot) is not None:
                fail(f"slot {slot:x} still holds a key")
        changed = [f"{s:x}" for s in KEPT_SLOTS if public(piv, s) != kept[s]]
        if changed:
            fail(f"THE USER'S SLOTS CHANGED: {', '.join(changed)}")
        tries = piv.get_pin_attempts()
        print(f"slots {', '.join(f'{s:x}' for s in KEPT_SLOTS)} unchanged; PIN tries left: {tries}")


if __name__ == "__main__":
    main()
