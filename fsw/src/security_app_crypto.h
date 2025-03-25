#ifndef SECURITY_APP_CRYPTO_H
#define SECURITY_APP_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int32_t SECURITY_APP_InitCrypto(void);

int32_t SECURITY_APP_Encrypt(const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *iv, uint8_t *ciphertext, size_t *ciphertext_len);

int32_t SECURITY_APP_Decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *iv, uint8_t *plaintext, 
                            size_t *plaintext_len, uint32_t orig_len);

#endif /* SECURITY_APP_CRYPTO_H */