/**
 * @file ESP32SimpleCrypto.cpp
 * @brief Implementation of the ESP32SimpleCrypto class for cryptographic operations.
 */

#include "ESP32SimpleCrypto.h"

ESP32SimpleCrypto::ESP32SimpleCrypto()
{
    aes_ctx = nullptr;
    sha_ctx = nullptr;
    entropy_ctx = nullptr;
    ctr_drbg_ctx = nullptr;
    aes_key = nullptr;
    aes_key_len = 0;
    public_key_ctx = nullptr;
    private_key_ctx = nullptr;
}

ESP32SimpleCrypto::~ESP32SimpleCrypto()
{
    freeResources();
}

void ESP32SimpleCrypto::freeResources()
{
    if (aes_ctx)
    {
        mbedtls_aes_free(aes_ctx);
        delete aes_ctx;
        aes_ctx = nullptr;
    }
    if (sha_ctx)
    {
        mbedtls_sha256_free(sha_ctx);
        delete sha_ctx;
        sha_ctx = nullptr;
    }
    if (entropy_ctx)
    {
        mbedtls_entropy_free(entropy_ctx);
        delete entropy_ctx;
        entropy_ctx = nullptr;
    }
    if (ctr_drbg_ctx)
    {
        mbedtls_ctr_drbg_free(ctr_drbg_ctx);
        delete ctr_drbg_ctx;
        ctr_drbg_ctx = nullptr;
    }
    if (public_key_ctx)
    {
        mbedtls_pk_free(public_key_ctx);
        delete public_key_ctx;
        public_key_ctx = nullptr;
    }
    if (private_key_ctx)
    {
        mbedtls_pk_free(private_key_ctx);
        delete private_key_ctx;
        private_key_ctx = nullptr;
    }
    if (aes_key)
    {
        delete[] aes_key;
        aes_key = nullptr;
    }
}

int8_t ESP32SimpleCrypto::initDrbgContext()
{
    if (!entropy_ctx || !ctr_drbg_ctx)
    {
        entropy_ctx = new mbedtls_entropy_context();
        ctr_drbg_ctx = new mbedtls_ctr_drbg_context();
        mbedtls_entropy_init(entropy_ctx);
        mbedtls_ctr_drbg_init(ctr_drbg_ctx);
        const char *personalization = "-ESP32SimpleCrypto-";
        return mbedtls_ctr_drbg_seed(ctr_drbg_ctx, mbedtls_entropy_func, entropy_ctx,
                                     (const unsigned char *)personalization, strlen(personalization));
    }
    return 0;
}

int8_t ESP32SimpleCrypto::generateRandomBytes(unsigned char *output, size_t output_len)
{
    initDrbgContext(); // Ensure the DRBG context is initialized
    return mbedtls_ctr_drbg_random(ctr_drbg_ctx, output, output_len);
}

int8_t ESP32SimpleCrypto::aesInit(const String key)
{
    if (aes_ctx)
    {
        return -1; // Already initialized
    }

    aes_ctx = new mbedtls_aes_context();
    mbedtls_aes_init(aes_ctx);

    uint8_t provided_key_length = key.length();
    if (provided_key_length > 0)
    {
        return aesSetKey(key); // Set the key if provided
    }
    else
    {
        return aesGenerateKey(); // Default to 128 bits (16 bytes) if no key is provided
    }
}

int8_t ESP32SimpleCrypto::aesGenerateKey(uint8_t key_len_bytes)
{
    if (!aes_ctx)
    {
        return -1; // AES context not initialized
    }

    if (aes_key)
    {
        delete[] aes_key; // Free existing key if it exists
    }

    aes_key = new unsigned char[key_len_bytes]; // Allocate memory for AES key
    if (!aes_key)
    {
        return -2; // Memory allocation failed
    }

    if (generateRandomBytes(aes_key, key_len_bytes) != 0)
    {
        delete[] aes_key;
        aes_key = nullptr;
        return -3; // Failed to generate random key
    }

    aes_key_len = key_len_bytes;                                      // Set key length
    return mbedtls_aes_setkey_enc(aes_ctx, aes_key, aes_key_len * 8); // Set AES key for encryption
}

int8_t ESP32SimpleCrypto::aesGetKey(String &key)
{
    if (!aes_key || aes_key_len == 0)
    {
        return -1; // AES key not initialized
    }
    key = String((const char *)aes_key, aes_key_len); // Convert AES key to String
    return 0;                                         // Success
}

int8_t ESP32SimpleCrypto::aesSetKey(const String key)
{
    if (!aes_ctx)
    {
        return -1; // AES context not initialized
    }

    if (aes_key)
    {
        delete[] aes_key; // Free existing key if it exists
    }

    uint8_t provided_key_length = key.length();
    if (provided_key_length == 16 || provided_key_length == 24 || provided_key_length == 32)
    {
        aes_key_len = provided_key_length; // Set the key length based on the provided key
        aes_key = new unsigned char[aes_key_len];
        memcpy(aes_key, key.c_str(), aes_key_len);                        // Copy the provided key into aes_key
        return mbedtls_aes_setkey_enc(aes_ctx, aes_key, aes_key_len * 8); // Set AES key for encryption
    }
    else
    {
        return -2; // Invalid key length
    }
}

int8_t ESP32SimpleCrypto::aesEncryptCbc(const String input, AESCryptedData &output)
{
    if (!aes_ctx || !aes_key)
    {
        return -1; // AES context or key not initialized
    }

    size_t input_len = input.length();
    size_t padded_len = ((input_len + 15) / 16) * 16; // Pad to multiple of 16 bytes
    unsigned char *input_data = new unsigned char[padded_len];
    memset(input_data, 0, padded_len);            // Initialize with zeros
    memcpy(input_data, input.c_str(), input_len); // Copy input data

    output.data = new unsigned char[padded_len]; // Allocate memory for encrypted data
    output.length = padded_len;

    unsigned char aes_iv[16]; // Initialization vector for AES CBC mode
    if (generateRandomBytes(aes_iv, 16) != 0)
    {
        delete[] input_data;
        delete[] output.data;
        return -3; // Failed to generate random IV
    }

    if (mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len, aes_iv, input_data, output.data) != 0)
    {
        delete[] input_data;
        delete[] output.data;
        return -2; // Encryption failed
    }

    delete[] input_data;           // Free temporary input data
    memcpy(output.iv, aes_iv, 16); // Copy IV to output
    return 0;                      // Success
}

int8_t ESP32SimpleCrypto::aesDecryptCbc(const AESCryptedData &input, String &output)
{
    if (!aes_ctx || !aes_key || input.length == 0 || !input.data)
    {
        return -1; // AES context, key, or input data not initialized
    }

    unsigned char *decrypted_data = new unsigned char[input.length]; // Allocate memory for decrypted data
    unsigned char iv_copy[16];
    memcpy(iv_copy, input.iv, 16); // Make a local copy of the IV

    if (mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_DECRYPT, input.length, iv_copy, input.data, decrypted_data) != 0)
    {
        delete[] decrypted_data;
        return -2; // Decryption failed
    }

    output = String((const char *)decrypted_data, input.length); // Convert decrypted data to String
    delete[] decrypted_data;                                     // Free decrypted data memory
    return 0;                                                    // Success
}

int8_t ESP32SimpleCrypto::sha256Init()
{
    if (!sha_ctx)
    {
        sha_ctx = new mbedtls_sha256_context();
        mbedtls_sha256_init(sha_ctx);
    }
    return 0; // Success
}

// String ESP32SimpleCrypto::sha256Hash(const String input) {
int8_t ESP32SimpleCrypto::sha256Hash(const String input, String &hash)
{
    sha256Init(); // Ensure SHA-256 context is initialized
    unsigned char hash_buf[32];                                                           // SHA-256 produces a 32-byte hash
    mbedtls_sha256_starts(sha_ctx, 0);                                                    // Start SHA-256 context
    mbedtls_sha256_update(sha_ctx, (const unsigned char *)input.c_str(), input.length()); // Update with input data
    mbedtls_sha256_finish(sha_ctx, hash_buf);                                             // Finish hashing

    hash = String((const char *)hash_buf, 32); // Convert hash to String
    return 0;                                  // Success
}

bool ESP32SimpleCrypto::sha256Verify(const String input, const String hash)
{   
    sha256Init(); // Ensure SHA-256 context is initialized
    if (hash.length() != 32)
    {
        return false; // Invalid hash length
    }

    String computed_hash;
    if (sha256Hash(input, computed_hash) != 0)
    {
        return false; // Hashing failed
    }
    return (computed_hash == hash); // Compare computed hash with provided hash
}

int8_t ESP32SimpleCrypto::rsaInit(const String private_key_pem, const String public_key_pem)
{
    if (public_key_ctx || private_key_ctx)
    {
        return -1; // RSA context already initialized
    }

    public_key_ctx = new mbedtls_pk_context();
    private_key_ctx = new mbedtls_pk_context();
    mbedtls_pk_init(public_key_ctx);
    mbedtls_pk_init(private_key_ctx);

    rsaSetPublicKeyPem(public_key_pem);   // Set public key if provided
    rsaSetPrivateKeyPem(private_key_pem); // Set private key if provided

    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaSetPublicKeyPem(const String public_key_pem)
{
    if (!public_key_ctx)
    {
        return -1; // RSA public key context not initialized
    }

    int ret = mbedtls_pk_parse_public_key(public_key_ctx, (const unsigned char *)public_key_pem.c_str(), public_key_pem.length() + 1);
    if (ret != 0)
    {
        return -2; // Failed to parse public key
    }
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaSetPrivateKeyPem(const String private_key_pem)
{
    if (!private_key_ctx)
    {
        return -1; // RSA private key context not initialized
    }

    int ret = mbedtls_pk_parse_key(private_key_ctx, (const unsigned char *)private_key_pem.c_str(), private_key_pem.length() + 1, nullptr, 0);
    if (ret != 0)
    {
        return -2; // Failed to parse private key
    }
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaGetPublicKeyPem(String &public_key_pem)
{
    if (!public_key_ctx)
    {
        return -1; // RSA public key context not initialized
    }

    size_t len = mbedtls_pk_get_len(public_key_ctx);
    unsigned char *buf = new unsigned char[len];
    if (mbedtls_pk_write_pubkey_pem(public_key_ctx, buf, len) != 0)
    {
        delete[] buf;
        return -2; // Failed to write public key to PEM format
    }
    public_key_pem = String((const char *)buf);
    delete[] buf;
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaGetPrivateKeyPem(String &private_key_pem)
{
    if (!private_key_ctx)
    {
        return -1; // RSA private key context not initialized
    }

    size_t len = mbedtls_pk_get_len(private_key_ctx);
    unsigned char *buf = new unsigned char[len];
    if (mbedtls_pk_write_key_pem(private_key_ctx, buf, len) != 0)
    {
        delete[] buf;
        return -2; // Failed to write private key to PEM format
    }
    private_key_pem = String((const char *)buf);
    delete[] buf;
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaPublicEncrypt(const String input, String &ciphertext)
{
    if (!public_key_ctx)
    {
        return -1; // RSA public key context not initialized
    }

    size_t output_len = mbedtls_pk_get_len(public_key_ctx);
    if (input.length() > output_len - 11)
    {
        return -2; // Input too long for RSA encryption
    }

    initDrbgContext(); // Ensure the DRBG context is initialized

    unsigned char *buf = new unsigned char[output_len];
    int ret = mbedtls_pk_encrypt(public_key_ctx, (const unsigned char *)input.c_str(),
                                 input.length(), buf, &output_len, output_len,
                                 mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (ret != 0)
    {
        delete[] buf;
        return -3; // RSA encryption failed
    }

    ciphertext = String((const char *)buf, output_len);
    delete[] buf;
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaPrivateDecrypt(const String ciphertext, String &output)
{
    if (!private_key_ctx)
    {
        return -1; // RSA private key context not initialized
    }

    initDrbgContext(); // Ensure the DRBG context is initialized

    size_t output_len = mbedtls_pk_get_len(private_key_ctx);
    unsigned char *buf = new unsigned char[output_len];

    int ret = mbedtls_pk_decrypt(private_key_ctx, (const unsigned char *)ciphertext.c_str(),
                                 ciphertext.length(), buf, &output_len, output_len,
                                 mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (ret != 0)
    {
        delete[] buf;
        return -2; // RSA decryption failed
    }

    output = String((const char *)buf, output_len);
    delete[] buf;
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaSign(const String input, String &signature)
{
    if (!private_key_ctx)
    {
        return -1; // RSA private key context not initialized
    }

    String hash_str;
    if (sha256Hash(input, hash_str) != 0)
    {
        return -2; // Hashing failed
    }

    size_t sig_len = mbedtls_pk_get_len(private_key_ctx);
    unsigned char *sig_buf = new unsigned char[sig_len];

    int ret = mbedtls_pk_sign(private_key_ctx, MBEDTLS_MD_SHA256,
                              (const unsigned char *)hash_str.c_str(), hash_str.length(),
                              sig_buf, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (ret != 0)
    {
        delete[] sig_buf;
        return -3; // RSA signing failed
    }

    signature = String((const char *)sig_buf, sig_len);
    delete[] sig_buf;
    return 0; // Success
}

int8_t ESP32SimpleCrypto::rsaVerify(const String input, const String signature)
{
    if (!public_key_ctx)
    {
        return -1; // RSA public key context not initialized
    }

    String hash_str;
    if (sha256Hash(input, hash_str) != 0)
    {
        return -2; // Hashing failed
    }

    int ret = mbedtls_pk_verify(public_key_ctx, MBEDTLS_MD_SHA256,
                                (const unsigned char *)hash_str.c_str(), hash_str.length(),
                                (const unsigned char *)signature.c_str(), signature.length());
    return (ret == 0) ? 0 : -3; // Return 0 for success, otherwise error code
}

int8_t ESP32SimpleCrypto::rsaGenerateKeypairPem(size_t key_size)
{
    if (public_key_ctx || private_key_ctx)
    {
        return -1; // RSA context already initialized
    }

    public_key_ctx = new mbedtls_pk_context();
    private_key_ctx = new mbedtls_pk_context();
    mbedtls_pk_init(public_key_ctx);
    mbedtls_pk_init(private_key_ctx);

    int ret = mbedtls_pk_setup(public_key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        return -2; // Failed to setup public key context
    }

    ret = mbedtls_pk_setup(private_key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        return -3; // Failed to setup private key context
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*private_key_ctx), mbedtls_ctr_drbg_random, &ctr_drbg_ctx, key_size, 65537);
    if (ret != 0)
    {
        return -4; // Key generation failed
    }

    return 0; // Success
}
