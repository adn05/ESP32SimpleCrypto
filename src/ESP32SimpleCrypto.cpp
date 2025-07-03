/**
 * @file ESP32SimpleCrypto.cpp
 * @brief Implementation of the ESP32SimpleCrypto class for cryptographic
 * operations.
 */

#include "ESP32SimpleCrypto.h"

ESP32SimpleCrypto::ESP32SimpleCrypto() {
  aes_ctx = nullptr;
  sha_ctx = nullptr;
  entropy_ctx = nullptr;
  ctr_drbg_ctx = nullptr;
  aes_key = nullptr;
  aes_key_len = 0;
  public_key_ctx = nullptr;
  private_key_ctx = nullptr;
}

ESP32SimpleCrypto::~ESP32SimpleCrypto() { freeResources(); }

void ESP32SimpleCrypto::freeResources() {
  if (aes_ctx) {
    mbedtls_aes_free(aes_ctx);
    delete aes_ctx;
    aes_ctx = nullptr;
  }
  if (sha_ctx) {
    mbedtls_sha256_free(sha_ctx);
    delete sha_ctx;
    sha_ctx = nullptr;
  }
  if (entropy_ctx) {
    mbedtls_entropy_free(entropy_ctx);
    delete entropy_ctx;
    entropy_ctx = nullptr;
  }
  if (ctr_drbg_ctx) {
    mbedtls_ctr_drbg_free(ctr_drbg_ctx);
    delete ctr_drbg_ctx;
    ctr_drbg_ctx = nullptr;
  }
  if (public_key_ctx) {
    mbedtls_pk_free(public_key_ctx);
    delete public_key_ctx;
    public_key_ctx = nullptr;
  }
  if (private_key_ctx) {
    mbedtls_pk_free(private_key_ctx);
    delete private_key_ctx;
    private_key_ctx = nullptr;
  }
  if (aes_key) {
    delete[] aes_key;
    aes_key = nullptr;
  }
}

String ESP32SimpleCrypto::getErrorString(int error_code) {
  char error_buf[100];
  if (error_code == 0) return String("No error");
  if (error_code == -1) return String("ESP32SimpleCrypto context not initialized");

  mbedtls_strerror(error_code, error_buf, sizeof(error_buf));
  return String(error_buf);
}

int8_t ESP32SimpleCrypto::initDrbgContext() {
  if (!entropy_ctx || !ctr_drbg_ctx) {
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

int8_t ESP32SimpleCrypto::generateRandomBytes(unsigned char *output, size_t output_len) {
  initDrbgContext();  // Ensure the DRBG context is initialized
  return mbedtls_ctr_drbg_random(ctr_drbg_ctx, output, output_len);
}

int8_t ESP32SimpleCrypto::aesInit(const String key) {
  if (aes_ctx) {
    return -1;  // Already initialized
  }

  aes_ctx = new mbedtls_aes_context();
  mbedtls_aes_init(aes_ctx);

  uint8_t provided_key_length = key.length();
  if (provided_key_length > 0) {
    return aesSetKey(key);  // Set the key if provided
  } else {
    return aesGenerateKey();  // Default to 128 bits (16 bytes) if no key is
                              // provided
  }
}

int8_t ESP32SimpleCrypto::aesGenerateKey(uint8_t key_len_bytes) {
  if (!aes_ctx) {
    return -1;  // AES context not initialized
  }

  if (aes_key) {
    delete[] aes_key;  // Free existing key if it exists
  }

  aes_key = new unsigned char[key_len_bytes];  // Allocate memory for AES key
  if (!aes_key) {
    return -2;  // Memory allocation failed
  }

  if (generateRandomBytes(aes_key, key_len_bytes) != 0) {
    delete[] aes_key;
    aes_key = nullptr;
    return -3;  // Failed to generate random key
  }

  aes_key_len = key_len_bytes;  // Set key length
  return mbedtls_aes_setkey_enc(aes_ctx, aes_key,
                                aes_key_len * 8);  // Set AES key for encryption
}

int8_t ESP32SimpleCrypto::aesGetKey(String &key) {
  if (!aes_key || aes_key_len == 0) {
    return -1;  // AES key not initialized
  }
  key = String((const char *)aes_key, aes_key_len);  // Convert AES key to String
  return 0;                                          // Success
}

int8_t ESP32SimpleCrypto::aesSetKey(const String key) {
  if (!aes_ctx) {
    return -1;  // AES context not initialized
  }

  if (aes_key) {
    delete[] aes_key;  // Free existing key if it exists
  }

  uint8_t provided_key_length = key.length();
  if (provided_key_length == 16 || provided_key_length == 24 || provided_key_length == 32) {
    aes_key_len = provided_key_length;  // Set the key length based on the provided key
    aes_key = new unsigned char[aes_key_len];
    memcpy(aes_key, key.c_str(),
           aes_key_len);                                               // Copy the provided key into aes_key
    return mbedtls_aes_setkey_enc(aes_ctx, aes_key, aes_key_len * 8);  // Set AES key for encryption
  } else {
    return -2;  // Invalid key length
  }
}

int8_t ESP32SimpleCrypto::aesEncryptCbc(const String input, AESCryptedData *output) {
  if (!aes_ctx || !aes_key) {
    return -1;  // AES context or key not initialized
  }

  size_t input_len = input.length();
  size_t padded_len = ((input_len + 15) / 16) * 16;  // Pad to multiple of 16 bytes
  unsigned char *input_data = new unsigned char[padded_len];
  memset(input_data, 0, padded_len);             // Initialize with zeros
  memcpy(input_data, input.c_str(), input_len);  // Copy input data

  output->data = new unsigned char[padded_len];  // Allocate memory for encrypted data
  output->length = input_len;                    // Store original input length
  // output->length = padded_len; // Store padded length for consistency

  unsigned char aes_iv[16];  // Initialization vector for AES CBC mode
  // If output->iv is not null, copy the IV from output->iv
  if (output->iv == nullptr) {
    output->iv = new unsigned char[16];  // Allocate memory for IV in output structure
    if (generateRandomBytes(aes_iv, 16) != 0) {
      delete[] input_data;
      delete[] output->data;
      return -3;  // Failed to generate random IV
    }
    memcpy(output->iv, aes_iv,
           16);  // Copy the generated IV into output structure
  } else {
    memcpy(aes_iv, output->iv, 16);  // Copy the existing IV into aes_iv
  }

  if (mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len, aes_iv, input_data, output->data) != 0) {
    delete[] input_data;
    delete[] output->data;
    return -2;  // Encryption failed
  }

  delete[] input_data;  // Free temporary input data
  return 0;             // Success
}

int8_t ESP32SimpleCrypto::aesDecryptCbc(const AESCryptedData *input, String &output) {
  if (!aes_ctx || !aes_key || input->length == 0 || !input->data) {
    return -1;  // AES context, key, or input data not initialized
  }

  size_t padded_len = ((input->length + 15) / 16) * 16;           // Pad to multiple of 16 bytes
  unsigned char *decrypted_data = new unsigned char[padded_len];  // Allocate memory for decrypted data
  unsigned char iv_copy[16];
  memcpy(iv_copy, input->iv, 16);  // Make a local copy of the IV

  if (mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_DECRYPT, padded_len, iv_copy, input->data, decrypted_data) != 0) {
    delete[] decrypted_data;
    return -2;  // Decryption failed
  }

  output = String((const char *)decrypted_data,
                  input->length);  // Convert decrypted data to String
  delete[] decrypted_data;         // Free decrypted data memory
  return 0;                        // Success
}

int8_t ESP32SimpleCrypto::sha256Init() {
  if (!sha_ctx) {
    sha_ctx = new mbedtls_sha256_context();
    mbedtls_sha256_init(sha_ctx);
  }
  return 0;  // Success
}

// String ESP32SimpleCrypto::sha256Hash(const String input) {
int8_t ESP32SimpleCrypto::sha256Hash(const String input, String &hash) {
  sha256Init();                       // Ensure SHA-256 context is initialized
  unsigned char hash_buf[32];         // SHA-256 produces a 32-byte hash
  mbedtls_sha256_starts(sha_ctx, 0);  // Start SHA-256 context
  mbedtls_sha256_update(sha_ctx, (const unsigned char *)input.c_str(),
                        input.length());     // Update with input data
  mbedtls_sha256_finish(sha_ctx, hash_buf);  // Finish hashing

  hash = String((const char *)hash_buf, 32);  // Convert hash to String
  return 0;                                   // Success
}

bool ESP32SimpleCrypto::sha256Verify(const String input, const String hash) {
  sha256Init();  // Ensure SHA-256 context is initialized
  if (hash.length() != 32) {
    return false;  // Invalid hash length
  }

  String computed_hash;
  if (sha256Hash(input, computed_hash) != 0) {
    return false;  // Hashing failed
  }
  return (computed_hash == hash);  // Compare computed hash with provided hash
}

int8_t ESP32SimpleCrypto::rsaInit(const String private_key_pem, const String public_key_pem) {
  if (public_key_ctx || private_key_ctx) {
    return -1;  // RSA context already initialized
  }

  int ret = 0;

  ret = initDrbgContext();
  if (ret != 0) return ret;  // Failed to initialize DRBG context

  // public_key_ctx = new mbedtls_pk_context();
  // private_key_ctx = new mbedtls_pk_context();
  // mbedtls_pk_init(public_key_ctx);
  // mbedtls_pk_init(private_key_ctx);

  bool generate_keys = true;  // Flag to indicate if keys should be generated
  if (public_key_pem.length() > 0) {
    ret = rsaSetPublicKeyPem(public_key_pem);
    if (ret != 0) {
      return ret;  // Failed to set public key
    }
    generate_keys = false;  // Public key provided, no need to generate
  }
  if (private_key_pem.length() > 0) {
    ret = rsaSetPrivateKeyPem(private_key_pem);
    if (ret != 0) return ret;  // Failed to set private key
    generate_keys = false;     // Private key provided, no need to generate
  }

  if (generate_keys) {
    return rsaGenerateKeypairPem();  // Default key size is 1024 bits
  }
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaSetPublicKeyPem(const String public_key_pem) {
  if (public_key_ctx) {
    mbedtls_pk_free(public_key_ctx);  // Free existing public key context if it exists
    delete public_key_ctx;
    public_key_ctx = nullptr;  // Reset pointer
  }
  public_key_ctx = new mbedtls_pk_context();
  mbedtls_pk_init(public_key_ctx);
  return mbedtls_pk_parse_public_key(public_key_ctx, (const unsigned char *)public_key_pem.c_str(),
                                     public_key_pem.length() + 1);
}

int8_t ESP32SimpleCrypto::rsaSetPrivateKeyPem(const String private_key_pem) {
  if (private_key_ctx) {
    mbedtls_pk_free(private_key_ctx);  // Free existing private key context if it exists
    mbedtls_pk_free(public_key_ctx);   // Free public key context if it exists
    delete private_key_ctx;
    delete public_key_ctx;
    private_key_ctx = nullptr;  // Reset pointer
    public_key_ctx = nullptr;
  }
  private_key_ctx = new mbedtls_pk_context();
  public_key_ctx = new mbedtls_pk_context();
  mbedtls_pk_init(private_key_ctx);
  mbedtls_pk_init(public_key_ctx);

  int ret = mbedtls_pk_parse_key(private_key_ctx, (const unsigned char *)private_key_pem.c_str(),
                                 private_key_pem.length() + 1, nullptr, 0);
  if (ret != 0) return ret;  // Failed to parse private key

  // Set the public key context from the private key context
  ret = mbedtls_pk_setup(public_key_ctx, mbedtls_pk_info_from_type(mbedtls_pk_get_type(private_key_ctx)));
  if (ret != 0) return ret;  // Failed to set up public key context
  ret = mbedtls_rsa_copy(mbedtls_pk_rsa(*public_key_ctx), mbedtls_pk_rsa(*private_key_ctx));
  if (ret != 0) return ret;  // Failed to copy private key to public key context

  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaGetPublicKeyPem(String &public_key_pem) {
  if (!public_key_ctx) {
    return -1;  // RSA public key context not initialized
  }
  int ret;

  size_t len = mbedtls_pk_get_len(public_key_ctx);
  if (len == 0) {
    len = mbedtls_pk_get_len(private_key_ctx);  // Use private key length if
                                                // public key length is not set
    if (len == 0) {
      len = 2048;  // Default length if not set, can be adjusted
    } else {
      len *= 2;  // Adjust length for PEM format, as PEM is base64 encoded and
                 // adds padding
    }
  } else {
    len *= 4;  // Adjust length for PEM format, as PEM is base64 encoded and
               // adds padding
  }

  unsigned char *buf = new unsigned char[len];
  ret = mbedtls_pk_write_pubkey_pem(public_key_ctx, buf, len);
  if (ret != 0) {
    delete[] buf;
    return ret;  // Failed to write public key PEM
  }

  public_key_pem = String((const char *)buf);
  delete[] buf;
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaGetPrivateKeyPem(String &private_key_pem) {
  if (!private_key_ctx) {
    return -1;  // RSA private key context not initialized
  }
  int ret;

  size_t len = mbedtls_pk_get_len(private_key_ctx);
  if (len == 0) {
    len = 2048;  // Default length if not set, can be adjusted
  } else {
    len *= 8;  // Adjust length for PEM format, as PEM is base64 encoded and
               // adds padding
  }

  unsigned char *buf = new unsigned char[len];
  ret = mbedtls_pk_write_key_pem(private_key_ctx, buf, len);
  if (ret != 0) {
    delete[] buf;
    return ret;
  }

  private_key_pem = String((const char *)buf);
  delete[] buf;
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaPublicEncrypt(const String input, String &base64_ciphertext) {
  if (!public_key_ctx) {
    return -1;  // RSA public key context not initialized
  }

  size_t output_len = mbedtls_pk_get_len(public_key_ctx);
  if (input.length() > output_len - 11) {
    return -2;  // Input too long for RSA encryption
  }

  unsigned char *buf = new unsigned char[output_len];
  //   int ret = mbedtls_pk_encrypt(public_key_ctx, (const unsigned char *)input.c_str(), input.length(), buf,
  //   &output_len, output_len, mbedtls_ctr_drbg_random, ctr_drbg_ctx);
  int ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(mbedtls_pk_rsa(*public_key_ctx), mbedtls_ctr_drbg_random, ctr_drbg_ctx,
                                                MBEDTLS_RSA_PUBLIC, input.length(),
                                                (const unsigned char *)input.c_str(), buf);
  if (ret != 0) {
    delete[] buf;
    return ret;  // RSA encryption failed
  }

  // Convert encrypted data to base64

  unsigned char *base64_buf = new unsigned char[output_len * 2];  // Allocate buffer for base64
  size_t base64_len;
  ret = mbedtls_base64_encode(base64_buf, output_len * 2, &base64_len, buf, output_len);
  if (ret != 0) {
    delete[] buf;
    delete[] base64_buf;
    return ret;  // Base64 encoding failed
  }

  base64_ciphertext = String((const char *)base64_buf, base64_len);
  delete[] buf;
  delete[] base64_buf;
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaPrivateDecrypt(const String base64_ciphertext, String &output) {
  if (!private_key_ctx) {
    return -1;  // RSA private key context not initialized
  }

  size_t output_len = mbedtls_pk_get_len(private_key_ctx);
  unsigned char *buf = new unsigned char[output_len];

  // Decode base64 ciphertext
  size_t decoded_len;
  size_t ciphertext_len = base64_ciphertext.length() * 3 / 4 + 1;  // Estimate size for base64 decoding

  unsigned char *ciphertext = new unsigned char[ciphertext_len];
  int ret = mbedtls_base64_decode(ciphertext, ciphertext_len, &decoded_len,
                                  (const unsigned char *)base64_ciphertext.c_str(), base64_ciphertext.length());
  if (ret != 0) {
    delete[] buf;
    return ret;  // Base64 decoding failed
  }

  //   ret = mbedtls_pk_decrypt(private_key_ctx, (const unsigned char *)ciphertext, decoded_len, buf, &output_len,
  //                            output_len, mbedtls_ctr_drbg_random, ctr_drbg_ctx);
  ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(mbedtls_pk_rsa(*private_key_ctx), mbedtls_ctr_drbg_random, ctr_drbg_ctx,
                                            MBEDTLS_RSA_PRIVATE, &output_len, ciphertext, buf, output_len);

  if (ret != 0) {
    delete[] buf;
    return ret;  // RSA decryption failed
  }

  output = String((const char *)buf, output_len);
  delete[] buf;
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaSign(const String input, String &signature) {
  if (!private_key_ctx) {
    return -1;  // RSA private key context not initialized
  }

  int ret;
  String hash_str;
  ret = sha256Hash(input, hash_str);
  if (ret != 0) {
    return ret;  // Hashing failed
  }

  size_t sig_len = mbedtls_pk_get_len(private_key_ctx);
  unsigned char *sig_buf = new unsigned char[sig_len];

  ret = mbedtls_pk_sign(private_key_ctx, MBEDTLS_MD_SHA256, (const unsigned char *)hash_str.c_str(), hash_str.length(),
                        sig_buf, &sig_len, mbedtls_ctr_drbg_random, ctr_drbg_ctx);
  if (ret != 0) {
    delete[] sig_buf;
    return ret;  // RSA signing failed
  }

  signature = String((const char *)sig_buf, sig_len);
  delete[] sig_buf;
  return 0;  // Success
}

int8_t ESP32SimpleCrypto::rsaVerify(const String input, const String signature) {
  if (!public_key_ctx) {
    return -1;  // RSA public key context not initialized
  }
  int ret;
  String hash_str;
  ret = sha256Hash(input, hash_str);
  if (ret != 0) {
    return ret;  // Hashing failed
  }

  return mbedtls_pk_verify(public_key_ctx, MBEDTLS_MD_SHA256, (const unsigned char *)hash_str.c_str(),
                           hash_str.length(), (const unsigned char *)signature.c_str(), signature.length());
}

int8_t ESP32SimpleCrypto::rsaGenerateKeypairPem(size_t key_size) {
  if (public_key_ctx || private_key_ctx) {
    // if rsa contexts are already initialized, reset them
    mbedtls_pk_free(public_key_ctx);
    mbedtls_pk_free(private_key_ctx);
    delete public_key_ctx;
    delete private_key_ctx;
    public_key_ctx = nullptr;
    private_key_ctx = nullptr;
  }
  public_key_ctx = new mbedtls_pk_context();
  private_key_ctx = new mbedtls_pk_context();
  mbedtls_pk_init(public_key_ctx);
  mbedtls_pk_init(private_key_ctx);

  int ret;
  ret = mbedtls_pk_setup(private_key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) return ret;  // Failed to setup private key context

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*private_key_ctx), mbedtls_ctr_drbg_random, ctr_drbg_ctx, key_size, 65537);
  if (ret != 0) return ret;  // Failed to generate RSA key pair

  // Set the public key context from the private key context
  ret = mbedtls_pk_setup(public_key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) return ret;  // Failed to setup public key context
  ret = mbedtls_rsa_copy(mbedtls_pk_rsa(*public_key_ctx), mbedtls_pk_rsa(*private_key_ctx));
  if (ret != 0) return ret;  // Failed to copy RSA key from private to public context

  return 0;  // Success
}

String ESP32SimpleCrypto::bytesToHex(const unsigned char *data, size_t length) {
  String hexStr;
  for (size_t i = 0; i < length; ++i) {
    hexStr += (data[i] < 0x10 ? " 0" : " ");  // Add leading zero for single digit hex
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

unsigned char *ESP32SimpleCrypto::hexToBytes(const String hexStr, size_t *length) {
  // Remove 0x prefix if present and spaces
  String cleanHexStr = hexStr;
  cleanHexStr.replace("0x", "");
  cleanHexStr.replace(" ", "");
  cleanHexStr.replace("\n", "");
  cleanHexStr.replace("\r", "");
  cleanHexStr.replace("\t", "");
  cleanHexStr.toUpperCase();  // Convert to uppercase for consistency

  *length = cleanHexStr.length() / 2;  // Each byte is represented by two hex characters
  unsigned char *bytes = new unsigned char[*length];
  for (size_t i = 0; i < *length; ++i) {
    String byteStr = cleanHexStr.substring(i * 2, i * 2 + 2);
    bytes[i] = (unsigned char)strtol(byteStr.c_str(), nullptr, 16);
  }
  return bytes;
}

String ESP32SimpleCrypto::stringToHex(const String input) {
  return bytesToHex((const unsigned char *)input.c_str(), input.length());
}