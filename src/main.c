#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int all_zero(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) if (buf[i] != 0) return 0;
    return 1;
}

int main(void) {
    // 1) init libsodium
    if (pv_crypto_init() != 0) {
        fprintf(stderr, "[FAIL] pv_crypto_init\n");
        return 1;
    }
    printf("[OK] pv_crypto_init\n");

    // 2) generate salt
    unsigned char salt[PV_SALT_BYTES];
    pv_generate_salt(salt);
    printf("[OK] pv_generate_salt\n");
    print_hex("salt", salt, PV_SALT_BYTES); // TEST UNIQUEMENT

    // 3) derive master key (Argon2id)
    const char *password = "TestPassword#2025"; // TEST UNIQUEMENT
    unsigned char key[PV_KEY_BYTES];

    if (pv_derive_master_key(key, password, salt) != 0) {
        fprintf(stderr, "[FAIL] pv_derive_master_key\n");
        return 1;
    }
    printf("[OK] pv_derive_master_key\n");
    print_hex("derived key", key, PV_KEY_BYTES); // TEST UNIQUEMENT

    // 3bis) tests déterminisme / unicité salt
    unsigned char key2[PV_KEY_BYTES];
    if (pv_derive_master_key(key2, password, salt) != 0) {
        fprintf(stderr, "[FAIL] pv_derive_master_key (repeat)\n");
        return 1;
    }
    if (memcmp(key, key2, PV_KEY_BYTES) == 0) {
        printf("[OK] deterministic: same (password,salt) -> same key\n");
    } else {
        printf("[FAIL] deterministic property broken\n");
        return 1;
    }

    unsigned char salt2[PV_SALT_BYTES];
    pv_generate_salt(salt2);
    unsigned char key3[PV_KEY_BYTES];
    if (pv_derive_master_key(key3, password, salt2) != 0) {
        fprintf(stderr, "[FAIL] pv_derive_master_key with salt2\n");
        return 1;
    }
    if (memcmp(key, key3, PV_KEY_BYTES) != 0) {
        printf("[OK] different salt -> different key\n");
    } else {
        printf("[FAIL] salt change did not change key\n");
        return 1;
    }

    // 4) test password vide (doit échouer)
    const char *empty = "";
    if (pv_derive_master_key(key3, empty, salt) != 0) {
        printf("[OK] empty password rejected\n");
    } else {
        printf("[FAIL] empty password accepted\n");
        return 1;
    }

    // ============================================================
    // Nouveaux tests: encrypt / decrypt / secure_memzero
    // ============================================================

    // 5) Encrypt → Decrypt (chemin heureux)
    const unsigned char plaintext[] = "login=alice;password=Secret123!";
    unsigned char nonce[PV_NONCE_BYTES];
    unsigned char ciphertext[sizeof(plaintext) + PV_MAC_BYTES]; // AEAD ajoute 16 octets
    int clen = pv_encrypt_entry(plaintext, sizeof(plaintext) - 1, // sans le '\0'
                                key,
                                ciphertext, nonce);
    if (clen <= 0) {
        fprintf(stderr, "[FAIL] pv_encrypt_entry\n");
        return 1;
    }
    printf("[OK] pv_encrypt_entry (len=%d)\n", clen);

    unsigned char decrypted[sizeof(plaintext)];
    int plen = pv_decrypt_entry(ciphertext, (size_t)clen,
                                key, nonce,
                                decrypted);
    if (plen <= 0) {
        fprintf(stderr, "[FAIL] pv_decrypt_entry (happy path)\n");
        return 1;
    }
    // rendre la chaîne affichable
    decrypted[plen] = '\0';

    if (memcmp(plaintext, decrypted, (size_t)plen) == 0) {
        printf("[OK] decrypt -> plaintext matches\n");
    } else {
        printf("[FAIL] decrypt mismatch\n");
        printf("expected: %s\n", plaintext);
        printf("got     : %s\n", decrypted);
        return 1;
    }

    // 6) Échec attendu si on modifie 1 octet du ciphertext
    unsigned char tampered_ct[sizeof(ciphertext)];
    memcpy(tampered_ct, ciphertext, (size_t)clen);
    tampered_ct[0] ^= 0x01; // flip 1 bit
    int plen_bad = pv_decrypt_entry(tampered_ct, (size_t)clen,
                                    key, nonce,
                                    decrypted);
    if (plen_bad < 0) {
        printf("[OK] decrypt fails when ciphertext is tampered\n");
    } else {
        printf("[FAIL] decrypt should fail on tampered ciphertext\n");
        return 1;
    }

    // 7) Échec attendu si on modifie 1 octet du nonce
    unsigned char tampered_nonce[PV_NONCE_BYTES];
    memcpy(tampered_nonce, nonce, PV_NONCE_BYTES);
    tampered_nonce[0] ^= 0x02;
    plen_bad = pv_decrypt_entry(ciphertext, (size_t)clen,
                                key, tampered_nonce,
                                decrypted);
    if (plen_bad < 0) {
        printf("[OK] decrypt fails when nonce is tampered\n");
    } else {
        printf("[FAIL] decrypt should fail on tampered nonce\n");
        return 1;
    }

    // 8) Échec attendu si ciphertext trop court (moins que le MAC)
    unsigned char tiny_ct[PV_MAC_BYTES - 1];
    memset(tiny_ct, 0, sizeof tiny_ct);
    plen_bad = pv_decrypt_entry(tiny_ct, sizeof tiny_ct,
                                key, nonce,
                                decrypted);
    if (plen_bad < 0) {
        printf("[OK] decrypt fails when ciphertext_len < MAC\n");
    } else {
        printf("[FAIL] decrypt should fail on too-short ciphertext\n");
        return 1;
    }

    // 9) Test pv_secure_memzero : la clé doit devenir 0x00 partout
    unsigned char key_to_wipe[PV_KEY_BYTES];
    memcpy(key_to_wipe, key, PV_KEY_BYTES); // part d'une valeur non-nulle
    pv_secure_memzero(key_to_wipe, PV_KEY_BYTES);
    if (all_zero(key_to_wipe, PV_KEY_BYTES)) {
        printf("[OK] pv_secure_memzero wiped the buffer\n");
    } else {
        printf("[FAIL] pv_secure_memzero did not wipe fully\n");
        return 1;
    }

    printf("\nTous les tests (crypto + encrypt/decrypt + memzero) sont PASS ✅\n");
    return 0;
}
