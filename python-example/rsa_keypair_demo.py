"""Test the RSA key pair stored in ../keys."""

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = ROOT / "keys" / "private_key.pem"
PUBLIC_KEY_PATH = ROOT / "keys" / "public_key.pem"


def load_keys():
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    return private_key, public_key


def main() -> None:
    private_key, public_key = load_keys()
    message = b"RSA key pair test message"

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("Signature verification: PASS")

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    if plaintext != message:
        raise RuntimeError("Decrypted message does not match the original")
    print("Encryption/decryption: PASS")


if __name__ == "__main__":
    main()
