#include <stddef.h>  
#include"crypto.h"
#include<string.h>
// verifier qu'on peut utiliser la bibliotheque libsodium 
int pv_crypto_init(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "[Erreur] Impossible d’initialiser libsodium.\n");
        return -1;
    }
    return 0;
}   
void pv_generate_salt(unsigned char *salt)
{
    randombytes_buf(salt,crypto_pwhash_SALTBYTES);

}
// transformer un mot de passe donner par l'utilisateur et un salt en une cle de maitresse binaire
//de taille fixe, a l'aide d'une kdf resistante au brute-force
int pv_derive_master_key(unsigned char *key,
                         const char *password,
                         const unsigned char *salt)

    {
        if (key == NULL || password == NULL || salt == NULL)
        {
            return -1;
        }
        size_t pwlen = strnlen(password, (size_t)crypto_pwhash_PASSWD_MAX + 1);
        if (pwlen ==0 || pwlen > (size_t)crypto_pwhash_PASSWD_MAX) {
            return -1;
        } 
        int rc = crypto_pwhash(
            key,
            PV_KEY_BYTES,
            password,
            pwlen,
            salt,
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_ARGON2ID13
        );

        return rc == 0 ? 0 : -1;
        
    }
    int pv_encrypt_entry(const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char *key,
                     unsigned char *ciphertext, unsigned char *nonce)
    {
        if (!plaintext || !key || !ciphertext || !nonce) {
            return -1;
        }
        if (plaintext_len == 0) {
            return -1; 
        }

        
        randombytes_buf(nonce, PV_NONCE_BYTES);

        unsigned long long ciphertext_len = 0;
        int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            plaintext, (unsigned long long)plaintext_len,
            NULL, 0,                  
            NULL,                     
            nonce,                    
            key                      
        );

        if (rc != 0) {
            return -1;
        }

    
        return (int)ciphertext_len;
    }
    int pv_decrypt_entry(const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char *key,
                     const unsigned char *nonce,
                     unsigned char *plaintext_out)
{
    if (!ciphertext || !key || !nonce || !plaintext_out) {
        return -1;
    }
    if (ciphertext_len < PV_MAC_BYTES) { 
        return -1;
    }

    unsigned long long plaintext_len = 0;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext_out, &plaintext_len,
        NULL,                       
        ciphertext, ciphertext_len, 
        NULL, 0,                    
        nonce,                      
        key                         
    );

    if (rc != 0) {
        
        return -1;
    }

    return (int)plaintext_len; 
}

void pv_secure_memzero(void *buf, size_t len)
{
    if (!buf || len == 0) return;
    sodium_memzero(buf, len);
}


    