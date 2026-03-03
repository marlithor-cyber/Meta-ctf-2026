#!/usr/bin/env python3

from pathlib import Path


BIN_PATH = Path("/home/shadowbyte/Downloads/meta_ctf/reverse/chall1/license_to_rev")
LICENSE_PATH = Path("/home/shadowbyte/Downloads/meta_ctf/reverse/chall1/extracted/license.txt")
ENC_OFFSET = 0x21E0
ENC_LEN = 0x23


def main() -> None:
    binary = BIN_PATH.read_bytes()
    license_bytes = LICENSE_PATH.read_bytes()
    encrypted = binary[ENC_OFFSET:ENC_OFFSET + ENC_LEN]
    plaintext = bytes(a ^ b for a, b in zip(encrypted, license_bytes))
    print(plaintext.decode("ascii"))


if __name__ == "__main__":
    main()
