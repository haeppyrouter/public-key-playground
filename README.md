# Public Key Playground

A small playground for experimenting with public-key cryptography.

## Repository structure

```text
.
├── keys/
│   ├── private_key.pem
│   └── public_key.pem
├── python-example/
    ├── requirements.txt
    └── rsa_keypair_demo.py
├── cpp-example/
    ├── CMakeLists.txt
    └── rsa_keypair_demo.cpp
├── javascript-example/
    ├── package.json
    └── rsa_keypair_demo.js
├── java-example/
    └── RsaKeypairDemo.java
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

## C++ example

The C++ example uses OpenSSL's EVP API and performs the same signing,
verification, encryption, and decryption checks.

Build and run it from the project root:

```bash
cmake -S cpp-example -B cpp-example/build
cmake --build cpp-example/build
./cpp-example/build/rsa_keypair_demo
```

OpenSSL development files and CMake are required.

## JavaScript example

The JavaScript example uses Node.js's built-in `crypto` module to perform
RSA signing, verification, encryption, and decryption without external npm
dependencies.

Run it from the project root:

```bash
node javascript-example/rsa_keypair_demo.js
```

Or run it through the npm script:

```bash
npm --prefix javascript-example start
```

## Java example

The Java example uses the standard JCA/JCE APIs to load the PEM keys and
perform RSA signing, verification, encryption, and decryption without
external dependencies.

Compile and run it from the project root:

```bash
javac java-example/RsaKeypairDemo.java
java -cp java-example RsaKeypairDemo
```
