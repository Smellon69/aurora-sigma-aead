#include "Aurora.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    /* Prepare a 32‐byte base key */
    uint8_t base_key[32];
    for (int i = 0; i < 32; i++) {
        base_key[i] = (uint8_t)i;
    }

    /* Init AEAD context in quantum‐resistant mode */
    AuroraSigma as;
    aurora_sigma_init_qr(&as, base_key);

    /* Define plaintext and (optional) AAD */
    const char* msg = "Hello, world!";
    size_t      msg_len = strlen(msg);

    const uint8_t* aad = NULL;  // no associated data
    size_t         aad_len = 0;

    /* Encrypt */
    uint8_t  enc[msg_len + 36];     // nonce(12)+salt(8)+ct+tag(16)
    size_t   enc_len;
    if (!aurora_sigma_encrypt(
        &as,
        base_key,
        (const uint8_t*)msg, msg_len,
        aad, aad_len,
        enc, &enc_len
    )) {
        printf("Encrypt failed.\n");
        return 1;
    }

    /* Decrypt */
    uint8_t  dec[msg_len];
    size_t   dec_len;
    if (!aurora_sigma_decrypt(
        &as,
        base_key,
        enc, enc_len,
        aad, aad_len,
        dec, &dec_len
    )) {
        printf("Decrypt failed.\n");
        return 1;
    }

    /* Print out */
    printf("Decrypted: %.*s\n", (int)dec_len, dec);
    return 0;
}
