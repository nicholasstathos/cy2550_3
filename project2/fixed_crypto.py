"""
AES-256-GCM file encryption with a password-derived key, Ed25519 sender
signatures, password validation, and context binding against replay and
substitution.

Requires: pip install cryptography

File format:
    MAGIC (4) | SALT (16) | NONCE (12) | TIMESTAMP (8) | CIPHERTEXT (...) | TAG (16) | SIGNATURE (64)

The header (magic + salt + nonce + timestamp) and a caller-supplied
context string are bound to the ciphertext as associated data, so
tampering with any part of the file, or decrypting it under the wrong
context, is detected. The sender signs the context, header, ciphertext
and tag with an Ed25519 key, so the receiver can verify who produced
the file.
"""

import os
import struct
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC = b"AGC2"
SALT_LEN = 16
NONCE_LEN = 12
TIMESTAMP_LEN = 8
TAG_LEN = 16
SIG_LEN = 64
CHUNK_SIZE = 64 * 1024

MIN_PASSWORD_LEN = 12
MIN_DISTINCT_CHARS = 4


def _validate_password(password: str) -> None:
    """Reject empty, short, whitespace-only, or highly repetitive passwords."""
    if not password or not password.strip():
        raise ValueError("Password must not be empty or whitespace only")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters")
    if len(set(password)) < MIN_DISTINCT_CHARS:
        raise ValueError(
            f"Password must contain at least {MIN_DISTINCT_CHARS} distinct characters"
        )


def _encode_context(context: str) -> bytes:
    """Length-prefix the context so it can't be confused with adjacent data."""
    data = context.encode("utf-8")
    return struct.pack(">I", len(data)) + data


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(
    in_path: str,
    out_path: str,
    password: str,
    context: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    """
    Encrypt in_path with AES-256-GCM, sign it, and write the result to out_path.

    context identifies what this file is meant to be (e.g. "report.pdf v3"
    or "alice->bob/report.pdf"). The receiver must supply the same context
    to decrypt, so one valid file can't be substituted for another.
    """
    _validate_password(password)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)  # must never repeat for the same key
    key = _derive_key(password, salt)
    timestamp = int(time.time())
    header = MAGIC + salt + nonce + struct.pack(">Q", timestamp)
    encoded_context = _encode_context(context)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header + encoded_context)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(encoded_context)
    digest.update(header)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(header)
        while chunk := fin.read(CHUNK_SIZE):
            ct = encryptor.update(chunk)
            fout.write(ct)
            digest.update(ct)
        final = encryptor.finalize()
        fout.write(final)
        digest.update(final)
        fout.write(encryptor.tag)
        digest.update(encryptor.tag)
        fout.write(signing_key.sign(digest.finalize()))


def decrypt_file(
    in_path: str,
    out_path: str,
    password: str,
    context: str,
    sender_public_key: Ed25519PublicKey,
    not_before: int | None = None,
) -> int:
    """
    Decrypt a file produced by encrypt_file and return its signed timestamp.

    Plaintext is written to a temp file and only moved to out_path after
    the authentication tag and the sender's signature both verify, so
    unauthenticated data is never left behind on failure.

    context must match the value used at encryption. not_before (Unix
    seconds) rejects files signed earlier than that time; to block
    replays, store the timestamp returned for the last accepted file and
    pass it (plus one) as not_before next time.

    Raises ValueError on a wrong password, wrong context, wrong sender,
    an outdated file, or a tampered/corrupt file.
    """
    file_size = os.path.getsize(in_path)
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN + TIMESTAMP_LEN
    if file_size < header_len + TAG_LEN + SIG_LEN:
        raise ValueError("File too short to be valid ciphertext")

    encoded_context = _encode_context(context)

    with open(in_path, "rb") as fin:
        header = fin.read(header_len)
        if header[: len(MAGIC)] != MAGIC:
            raise ValueError("Unrecognized file format")
        salt = header[len(MAGIC) : len(MAGIC) + SALT_LEN]
        nonce = header[len(MAGIC) + SALT_LEN : len(MAGIC) + SALT_LEN + NONCE_LEN]
        (timestamp,) = struct.unpack(">Q", header[len(MAGIC) + SALT_LEN + NONCE_LEN :])

        fin.seek(file_size - SIG_LEN - TAG_LEN)
        tag = fin.read(TAG_LEN)
        signature = fin.read(SIG_LEN)
        fin.seek(header_len)

        key = _derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(header + encoded_context)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(encoded_context)
        digest.update(header)

        out_dir = os.path.dirname(os.path.abspath(out_path))
        fd, tmp_path = tempfile.mkstemp(dir=out_dir)
        try:
            with os.fdopen(fd, "wb") as ftmp:
                remaining = file_size - header_len - TAG_LEN - SIG_LEN
                while remaining > 0:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    remaining -= len(chunk)
                    digest.update(chunk)
                    ftmp.write(decryptor.update(chunk))
                decryptor.finalize_with_tag(tag)
            digest.update(tag)
            sender_public_key.verify(signature, digest.finalize())
            if not_before is not None and timestamp < not_before:
                raise ValueError("File is older than allowed (possible replay)")
            os.replace(tmp_path, out_path)
        except InvalidTag:
            os.remove(tmp_path)
            raise ValueError("Wrong password, wrong context, or file has been tampered with")
        except InvalidSignature:
            os.remove(tmp_path)
            raise ValueError("Signature invalid: file was not signed by the expected sender")
        except BaseException:
            os.remove(tmp_path)
            raise

    return timestamp


if __name__ == "__main__":
    import getpass
    import sys

    if len(sys.argv) != 6 or sys.argv[1] not in ("enc", "dec"):
        print(f"Usage: {sys.argv[0]} enc <input> <output> <context> <sender_private_key.pem>")
        print(f"       {sys.argv[0]} dec <input> <output> <context> <sender_public_key.pem>")
        sys.exit(1)

    mode, src, dst, ctx, key_path = sys.argv[1:]
    with open(key_path, "rb") as f:
        key_data = f.read()

    pw = getpass.getpass("Password: ")
    if mode == "enc":
        priv = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("Signing key must be an Ed25519 private key")
        encrypt_file(src, dst, pw, ctx, priv)
    else:
        pub = serialization.load_pem_public_key(key_data)
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("Sender key must be an Ed25519 public key")
        decrypt_file(src, dst, pw, ctx, pub)
    print("Done.")
