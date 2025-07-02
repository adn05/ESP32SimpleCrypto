#ifndef ESP32SimpleCrypto_h
#define ESP32SimpleCrypto_h

#include <Arduino.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

struct AESCryptedData
{
  unsigned char *data;  // Pointer to the encrypted data
  size_t length;        // Length of the encrypted data
  unsigned char *iv;    // Pointer to the IV (Initialization Vector)
  // Note: The IV should be 16 bytes for AES CBC mode
};

class ESP32SimpleCrypto
{
private:
  mbedtls_aes_context *aes_ctx;
  mbedtls_sha256_context *sha_ctx;
  unsigned char *aes_key;
  uint8_t aes_key_len;

  mbedtls_entropy_context *entropy_ctx;
  mbedtls_ctr_drbg_context *ctr_drbg_ctx;
  mbedtls_pk_context *public_key_ctx;
  mbedtls_pk_context *private_key_ctx;

  int8_t generateRandomBytes(unsigned char *output, size_t output_len);
  int8_t initDrbgContext();
  int8_t sha256Init();

public:
  ESP32SimpleCrypto();
  ~ESP32SimpleCrypto();
  int8_t aesInit(const String key = "");
  // String aesEncryptCbc(const String input, const String iv = "");
  // String aesDecryptCbc(const String input, const String iv = "");
  int8_t aesEncryptCbc(const String input, AESCryptedData *crypted_data);
  int8_t aesDecryptCbc(const AESCryptedData *crypted_data, String &output);
  int8_t aesGenerateKey(const uint8_t key_len_bytes = 16); // Default is 128 bits (16 bytes)
  int8_t aesGetKey(String &key);
  int8_t aesSetKey(const String key);

  int8_t sha256Hash(const String input, String &hash);
  bool sha256Verify(const String input, const String hash);

  int8_t rsaInit(const String private_key_pem = "", const String public_key_pem = "");
  int8_t rsaPublicEncrypt(const String input, String &ciphertext);
  int8_t rsaPrivateDecrypt(const String ciphertext, String &output);
  int8_t rsaSign(const String input, String &signature);
  int8_t rsaVerify(const String input, const String signature);
  int8_t rsaGenerateKeypairPem(size_t key_size = 1024);
  int8_t rsaGetPublicKeyPem(String &public_key_pem);
  int8_t rsaGetPrivateKeyPem(String &private_key_pem);
  int8_t rsaSetPublicKeyPem(const String public_key_pem);
  int8_t rsaSetPrivateKeyPem(const String private_key_pem);

  void freeResources();

  static String bytesToHex(const unsigned char *data, size_t length);
  static unsigned char *hexToBytes(const String hexStr, size_t *length);
  static String stringToHex(const String *input);
};

#endif