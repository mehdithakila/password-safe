#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>  
#include <sodium.h>

#define PV_KEY_BYTES      crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define PV_NONCE_BYTES    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define PV_MAC_BYTES      crypto_aead_xchacha20poly1305_ietf_ABYTES
#define PV_SALT_BYTES     crypto_pwhash_SALTBYTES

// verifier qu'on peut utiliser la bibliotheque libsodium 
int pv_crypto_init(void);


void pv_generate_salt(unsigned char *salt);


int pv_derive_master_key(unsigned char *key,
                         const char *password,
                         const unsigned char *salt);


 int pv_encrypt_entry(const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char *key,
                     unsigned char *ciphertext, unsigned char *nonce);


int pv_decrypt_entry(const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char *key,
                     const unsigned char *nonce,
                     unsigned char *plaintext_out);


void pv_secure_memzero(void *buf, size_t len);

#endif // CRYPTO_H
