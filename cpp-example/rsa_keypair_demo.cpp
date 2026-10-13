#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

[[noreturn]] void throw_openssl_error(const std::string& message) {
    unsigned long error = ERR_get_error();
    char buffer[256] = {};
    ERR_error_string_n(error, buffer, sizeof(buffer));
    throw std::runtime_error(message + ": " + buffer);
}

EvpPkeyPtr load_private_key(const std::string& path) {
    std::unique_ptr<FILE, decltype(&fclose)> file(std::fopen(path.c_str(), "rb"), fclose);
    if (!file) {
        throw std::runtime_error("Unable to open private key: " + path);
    }

    EVP_PKEY* key = PEM_read_PrivateKey(file.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw_openssl_error("Unable to read private key");
    }
    return EvpPkeyPtr(key, EVP_PKEY_free);
}

EvpPkeyPtr load_public_key(const std::string& path) {
    std::unique_ptr<FILE, decltype(&fclose)> file(std::fopen(path.c_str(), "rb"), fclose);
    if (!file) {
        throw std::runtime_error("Unable to open public key: " + path);
    }

    EVP_PKEY* key = PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw_openssl_error("Unable to read public key");
    }
    return EvpPkeyPtr(key, EVP_PKEY_free);
}

std::vector<unsigned char> sign(EVP_PKEY* private_key, const std::string& message) {
    EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) {
        throw_openssl_error("Unable to create signing context");
    }

    if (EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, private_key) <= 0 ||
        EVP_DigestSignUpdate(context.get(), message.data(), message.size()) <= 0) {
        throw_openssl_error("Unable to initialize signature");
    }

    size_t signature_size = 0;
    if (EVP_DigestSignFinal(context.get(), nullptr, &signature_size) <= 0) {
        throw_openssl_error("Unable to determine signature size");
    }

    std::vector<unsigned char> signature(signature_size);
    if (EVP_DigestSignFinal(context.get(), signature.data(), &signature_size) <= 0) {
        throw_openssl_error("Unable to create signature");
    }
    signature.resize(signature_size);
    return signature;
}

bool verify(EVP_PKEY* public_key, const std::string& message,
            const std::vector<unsigned char>& signature) {
    EvpMdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) {
        throw_openssl_error("Unable to create verification context");
    }

    if (EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, public_key) <= 0 ||
        EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) <= 0) {
        throw_openssl_error("Unable to initialize verification");
    }

    return EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size()) == 1;
}

std::vector<unsigned char> encrypt(EVP_PKEY* public_key, const std::string& message) {
    EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!raw_context) {
        throw_openssl_error("Unable to create encryption context");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context,
                                                                         EVP_PKEY_CTX_free);

    if (EVP_PKEY_encrypt_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha256()) <= 0) {
        throw_openssl_error("Unable to initialize encryption");
    }

    size_t ciphertext_size = 0;
    if (EVP_PKEY_encrypt(context.get(), nullptr, &ciphertext_size,
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size()) <= 0) {
        throw_openssl_error("Unable to determine ciphertext size");
    }

    std::vector<unsigned char> ciphertext(ciphertext_size);
    if (EVP_PKEY_encrypt(context.get(), ciphertext.data(), &ciphertext_size,
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size()) <= 0) {
        throw_openssl_error("Unable to encrypt message");
    }
    ciphertext.resize(ciphertext_size);
    return ciphertext;
}

std::string decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
    EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!raw_context) {
        throw_openssl_error("Unable to create decryption context");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context,
                                                                         EVP_PKEY_CTX_free);

    if (EVP_PKEY_decrypt_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha256()) <= 0) {
        throw_openssl_error("Unable to initialize decryption");
    }

    size_t plaintext_size = 0;
    if (EVP_PKEY_decrypt(context.get(), nullptr, &plaintext_size, ciphertext.data(),
                         ciphertext.size()) <= 0) {
        throw_openssl_error("Unable to determine plaintext size");
    }

    std::vector<unsigned char> plaintext(plaintext_size);
    if (EVP_PKEY_decrypt(context.get(), plaintext.data(), &plaintext_size, ciphertext.data(),
                         ciphertext.size()) <= 0) {
        throw_openssl_error("Unable to decrypt message");
    }
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_size);
}

int main(int argc, char* argv[]) {
    try {
        const std::string key_directory = argc > 1 ? argv[1] : "keys";
        const std::string message = "RSA key pair test message";

        auto private_key = load_private_key(key_directory + "/private_key.pem");
        auto public_key = load_public_key(key_directory + "/public_key.pem");

        const auto signature = sign(private_key.get(), message);
        if (!verify(public_key.get(), message, signature)) {
            throw std::runtime_error("Signature verification failed");
        }
        std::cout << "Signature verification: PASS\n";

        const auto ciphertext = encrypt(public_key.get(), message);
        if (decrypt(private_key.get(), ciphertext) != message) {
            throw std::runtime_error("Decrypted message does not match the original");
        }
        std::cout << "Encryption/decryption: PASS\n";
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
