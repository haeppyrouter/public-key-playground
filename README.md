# Public Key Playground

A small playground for experimenting with public-key cryptography.

## Repository structure

```text
.
├── keys/
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
└── c-example/
    ├── CMakeLists.txt
    └── rsa_keypair_demo.c
```

## RSA key pair

The `keys/` directory contains a 4096-bit RSA key pair in PEM format:

- `public_key.pem`: RSA public key

The key pair is intended for local experimentation only.

## Python example

The Python example uses the `cryptography` package to demonstrate:

- Signing and verification
- Encryption and decryption

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

## C example

The C example uses OpenSSL's EVP API to perform RSA signing, verification,
encryption, and decryption with the same key pair.

Build and run it from the project root:

```bash
cmake -S c-example -B c-example/build
cmake --build c-example/build
./c-example/build/rsa_keypair_demo
```

OpenSSL development files and CMake are required.
