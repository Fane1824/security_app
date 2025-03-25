#include "security_app_crypto.h"
#include <string.h>
#include <gcrypt.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32  // AES-256 key size in bytes

/* Hardcoded encryption key (32 bytes for AES-256) */
static const unsigned char hardcoded_key[AES_KEY_SIZE] = {
    0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 
    0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x6e,
    0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 
    0x4b, 0x65, 0x79, 0x32, 0x30, 0x32, 0x35, 0x21
};

int32_t SECURITY_APP_InitCrypto(void)
{
    /* Initialize libgcrypt */
    if (!gcry_check_version(GCRYPT_VERSION)) {
        return -1;
    }
    
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    return 0;
}

int32_t SECURITY_APP_Encrypt(const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *iv, uint8_t *ciphertext, size_t *ciphertext_len)
{
    gcry_cipher_hd_t cipher_handle;
    gcry_error_t err;
    
    /* Parameter check */
    if (plaintext == NULL || iv == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return -1;
    }
    
    /* Create cipher handle */
    err = gcry_cipher_open(&cipher_handle, GCRY_CIPHER_AES256, 
                          GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        return -2;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher_handle, hardcoded_key, AES_KEY_SIZE);
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -3;
    }
    
    /* Generate random IV */
    gcry_randomize(iv, AES_BLOCK_SIZE, GCRY_STRONG_RANDOM);
    
    /* Set IV */
    err = gcry_cipher_setiv(cipher_handle, iv, AES_BLOCK_SIZE);
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -4;
    }
    
    /* Calculate padded length (multiple of block size) */
    size_t padded_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    
    /* Create a buffer for padded plaintext */
    uint8_t *padded_plaintext = malloc(padded_len);
    if (padded_plaintext == NULL) {
        gcry_cipher_close(cipher_handle);
        return -5;
    }
    
    /* Copy plaintext and add padding (zeros) */
    memcpy(padded_plaintext, plaintext, plaintext_len);
    memset(padded_plaintext + plaintext_len, 0, padded_len - plaintext_len);
    
    /* Encrypt */
    err = gcry_cipher_encrypt(cipher_handle, ciphertext, padded_len, 
                             padded_plaintext, padded_len);
    
    /* Free padded plaintext buffer */
    free(padded_plaintext);
    
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -6;
    }
    
    /* Output the ciphertext length */
    *ciphertext_len = padded_len;
    
    /* Clean up */
    gcry_cipher_close(cipher_handle);
    
    return 0;
}

int32_t SECURITY_APP_Decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *iv, uint8_t *plaintext, 
                            size_t *plaintext_len, uint32_t orig_len)
{
    gcry_cipher_hd_t cipher_handle;
    gcry_error_t err;
    
    /* Parameter check */
    if (ciphertext == NULL || iv == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }
    
    /* Check that ciphertext length is a multiple of the block size */
    if (ciphertext_len % AES_BLOCK_SIZE != 0) {
        return -2;
    }
    
    /* Create cipher handle */
    err = gcry_cipher_open(&cipher_handle, GCRY_CIPHER_AES256, 
                          GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        return -3;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher_handle, hardcoded_key, AES_KEY_SIZE);
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -4;
    }
    
    /* Set IV */
    err = gcry_cipher_setiv(cipher_handle, iv, AES_BLOCK_SIZE);
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -5;
    }
    
    /* Decrypt */
    err = gcry_cipher_decrypt(cipher_handle, plaintext, ciphertext_len, 
                             ciphertext, ciphertext_len);
    if (err) {
        gcry_cipher_close(cipher_handle);
        return -6;
    }
    
    /* Clean up */
    gcry_cipher_close(cipher_handle);
    
    /* Set the original plaintext length */
    *plaintext_len = orig_len;
    
    return 0;
}