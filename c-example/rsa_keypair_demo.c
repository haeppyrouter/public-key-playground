#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_openssl_error(const char *message) {
    fprintf(stderr, "%s: ", message);
    ERR_print_errors_fp(stderr);
}

static EVP_PKEY *load_private_key(const char *path) {
    FILE *file = fopen(path, "rb");
    EVP_PKEY *key;

    if (file == NULL) {
        perror(path);
        return NULL;
    }
    key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (key == NULL) {
        print_openssl_error("Unable to read private key");
    }
    return key;
}

static EVP_PKEY *load_public_key(const char *path) {
    FILE *file = fopen(path, "rb");
    EVP_PKEY *key;

    if (file == NULL) {
        perror(path);
        return NULL;
    }
    key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (key == NULL) {
        print_openssl_error("Unable to read public key");
    }
    return key;
}

static int sign_message(EVP_PKEY *private_key, const unsigned char *message,
                        size_t message_length, unsigned char **signature,
                        size_t *signature_length) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int result = 0;

    if (context == NULL || EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL,
                                               private_key) <= 0 ||
        EVP_DigestSignUpdate(context, message, message_length) <= 0 ||
        EVP_DigestSignFinal(context, NULL, signature_length) <= 0) {
        print_openssl_error("Unable to initialize signature");
        goto cleanup;
    }

    *signature = malloc(*signature_length);
    if (*signature == NULL || EVP_DigestSignFinal(context, *signature,
                                                   signature_length) <= 0) {
        print_openssl_error("Unable to create signature");
        free(*signature);
        *signature = NULL;
        goto cleanup;
    }
    result = 1;

cleanup:
    EVP_MD_CTX_free(context);
    return result;
}

static int verify_signature(EVP_PKEY *public_key, const unsigned char *message,
                            size_t message_length, const unsigned char *signature,
                            size_t signature_length) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int result = 0;

    if (context == NULL || EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL,
                                                 public_key) <= 0 ||
        EVP_DigestVerifyUpdate(context, message, message_length) <= 0) {
        print_openssl_error("Unable to initialize verification");
        goto cleanup;
    }

    result = EVP_DigestVerifyFinal(context, signature, signature_length) == 1;

cleanup:
    EVP_MD_CTX_free(context);
    return result;
}

static int crypt_message(EVP_PKEY *key, int encrypt, const unsigned char *input,
                         size_t input_length, unsigned char **output,
                         size_t *output_length) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(key, NULL);
    int result = 0;

    if (context == NULL ||
        (encrypt ? EVP_PKEY_encrypt_init(context) : EVP_PKEY_decrypt_init(context)) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) <= 0) {
        print_openssl_error("Unable to initialize encryption/decryption");
        goto cleanup;
    }

    if ((encrypt ? EVP_PKEY_encrypt(context, NULL, output_length, input, input_length)
                 : EVP_PKEY_decrypt(context, NULL, output_length, input, input_length)) <= 0) {
        print_openssl_error("Unable to determine output size");
        goto cleanup;
    }

    *output = malloc(*output_length);
    if (*output == NULL ||
        (encrypt ? EVP_PKEY_encrypt(context, *output, output_length, input, input_length)
                 : EVP_PKEY_decrypt(context, *output, output_length, input, input_length)) <= 0) {
        print_openssl_error("Unable to process message");
        free(*output);
        *output = NULL;
        goto cleanup;
    }
    result = 1;

cleanup:
    EVP_PKEY_CTX_free(context);
    return result;
}

int main(int argc, char **argv) {
    const char *key_directory = argc > 1 ? argv[1] : "keys";
    const unsigned char message[] = "RSA key pair test message";
    char private_key_path[1024];
    char public_key_path[1024];
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char *signature = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    size_t signature_length = 0;
    size_t ciphertext_length = 0;
    size_t plaintext_length = 0;
    int exit_code = EXIT_FAILURE;

    if (snprintf(private_key_path, sizeof(private_key_path), "%s/private_key.pem",
                 key_directory) >= (int)sizeof(private_key_path) ||
        snprintf(public_key_path, sizeof(public_key_path), "%s/public_key.pem",
                 key_directory) >= (int)sizeof(public_key_path)) {
        fprintf(stderr, "Key path is too long\n");
        return EXIT_FAILURE;
    }

    private_key = load_private_key(private_key_path);
    public_key = load_public_key(public_key_path);
    if (private_key == NULL || public_key == NULL ||
        !sign_message(private_key, message, sizeof(message) - 1, &signature,
                      &signature_length) ||
        !verify_signature(public_key, message, sizeof(message) - 1, signature,
                          signature_length)) {
        fprintf(stderr, "Signature verification failed\n");
        goto cleanup;
    }
    printf("Signature verification: PASS\n");

    if (!crypt_message(public_key, 1, message, sizeof(message) - 1, &ciphertext,
                       &ciphertext_length) ||
        !crypt_message(private_key, 0, ciphertext, ciphertext_length, &plaintext,
                       &plaintext_length) ||
        plaintext_length != sizeof(message) - 1 ||
        memcmp(plaintext, message, plaintext_length) != 0) {
        fprintf(stderr, "Encryption/decryption failed\n");
        goto cleanup;
    }
    printf("Encryption/decryption: PASS\n");
    exit_code = EXIT_SUCCESS;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    free(signature);
    free(ciphertext);
    free(plaintext);
    return exit_code;
}
