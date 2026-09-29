#!/usr/bin/env python3
"""Provision local:v1 secrets for the Superposition production key provider.

Requires cryptography. Plaintext is read from stdin and never passed as an
argument or printed. Keep the 32-byte key file outside Git and container images.
"""

import argparse
import base64
import os
import pathlib
import stat
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def read_key(path: pathlib.Path) -> bytes:
    if not path.is_absolute():
        raise ValueError("key path must be absolute")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o277:
        raise ValueError("key must be a regular read-only file with no group/other permissions")
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return key


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    init = subcommands.add_parser("init-key")
    init.add_argument("key_file", type=pathlib.Path)
    encrypt = subcommands.add_parser("encrypt")
    encrypt.add_argument("key_file", type=pathlib.Path)
    encrypt.add_argument("name", help="exact environment variable name")
    args = parser.parse_args()

    if args.command == "init-key":
        if not args.key_file.is_absolute():
            parser.error("key path must be absolute")
        fd = os.open(args.key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400)
        try:
            os.write(fd, os.urandom(32))
        finally:
            os.close(fd)
        return

    if not args.name or not args.name.isascii():
        parser.error("name must be nonempty ASCII")
    key = read_key(args.key_file)
    plaintext = sys.stdin.buffer.read()
    if not plaintext:
        parser.error("stdin is empty")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, args.name.encode("ascii"))
    print("local:v1:" + base64.b64encode(nonce + ciphertext).decode("ascii"))


if __name__ == "__main__":
    main()
