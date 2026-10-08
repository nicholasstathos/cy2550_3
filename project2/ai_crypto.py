"""
AES-256-GCM file encryption with a password-derived key.

Requires: pip install cryptography

File format:
    MAGIC (4) | SALT (16) | NONCE (12) | CIPHERTEXT (...) | TAG (16)

The header (magic + salt + nonce) is bound to the ciphertext as
associated data, so tampering with any part of the file is detected.
"""

import os
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

MAGIC = b"AGC1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
CHUNK_SIZE = 64 * 1024


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    """Encrypt in_path with AES-256-GCM and write the result to out_path."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)  # must never repeat for the same key
    key = _derive_key(password, salt)
    header = MAGIC + salt + nonce

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(header)
        while chunk := fin.read(CHUNK_SIZE):
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    """
    Decrypt a file produced by encrypt_file.

    Plaintext is written to a temp file and only moved to out_path after
    the authentication tag verifies, so unauthenticated data is never
    left behind on failure. Raises ValueError on a wrong password or
    tampered/corrupt file.
    """
    file_size = os.path.getsize(in_path)
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if file_size < header_len + TAG_LEN:
        raise ValueError("File too short to be valid ciphertext")

    with open(in_path, "rb") as fin:
        header = fin.read(header_len)
        if header[: len(MAGIC)] != MAGIC:
            raise ValueError("Unrecognized file format")
        salt = header[len(MAGIC) : len(MAGIC) + SALT_LEN]
        nonce = header[len(MAGIC) + SALT_LEN :]

        fin.seek(file_size - TAG_LEN)
        tag = fin.read(TAG_LEN)
        fin.seek(header_len)

        key = _derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(header)

        out_dir = os.path.dirname(os.path.abspath(out_path))
        fd, tmp_path = tempfile.mkstemp(dir=out_dir)
        try:
            with os.fdopen(fd, "wb") as ftmp:
                remaining = file_size - header_len - TAG_LEN
                while remaining > 0:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    remaining -= len(chunk)
                    ftmp.write(decryptor.update(chunk))
                decryptor.finalize_with_tag(tag)
            os.replace(tmp_path, out_path)
        except InvalidTag:
            os.remove(tmp_path)
            raise ValueError("Wrong password or file has been tampered with")
        except BaseException:
            os.remove(tmp_path)
            raise


if __name__ == "__main__":
    import getpass
    import sys

    if len(sys.argv) != 4 or sys.argv[1] not in ("enc", "dec"):
        print(f"Usage: {sys.argv[0]} enc|dec <input> <output>")
        sys.exit(1)

    mode, src, dst = sys.argv[1:]
    pw = getpass.getpass("Password: ")
    if mode == "enc":
        encrypt_file(src, dst, pw)
    else:
        decrypt_file(src, dst, pw)
    print("Done.")
