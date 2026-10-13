# Public Key Playground

A small playground for experimenting with public-key cryptography.

## Repository structure

```text
.
├── keys/
│   ├── private_key.pem
│   └── public_key.pem
└── python-example/
    ├── requirements.txt
    └── rsa_keypair_demo.py
```

## RSA key pair

The `keys/` directory contains a 4096-bit RSA key pair in PEM format:

- `private_key.pem`: RSA private key
- `public_key.pem`: RSA public key

These keys are intended for local experimentation only. Do not use them in
production or share the private key.

## Python example

The Python example uses the `cryptography` package to demonstrate:

- Signing with the private key and verifying with the public key
- Encrypting with the public key and decrypting with the private key

Install the dependency and run the example from the project root:

```bash
python3 -m pip install -r python-example/requirements.txt
python3 python-example/rsa_keypair_demo.py
```

Expected output:

```text
Signature verification: PASS
Encryption/decryption: PASS
```
