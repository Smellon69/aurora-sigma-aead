#include "Aurora.h"
#include <stdio.h>

int main() {
    uint8_t key[32];
    int i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;

    AuroraSigma as;
    aurora_sigma_init(&as, key);

    const char* msg = "Hello, world!";
    size_t msg_len = 13;

    // Allocate message buffer
    // max size needed = plaintext_len + 36
    uint8_t enc[13 + 36];
    size_t enc_len;

    if (!aurora_sigma_encrypt(&as, key, (const uint8_t*)msg, msg_len, enc, &enc_len)) {
        printf("Encrypt failed.\n");
        return 1;
    }

    uint8_t dec[13]; // same size as original plaintext
    size_t dec_len;

    if (!aurora_sigma_decrypt(&as, key, enc, enc_len, dec, &dec_len)) {
        printf("Decrypt failed.\n");
        return 1;
    }

    printf("Decrypted: ");
    for (i = 0; i < (int)dec_len; i++) putchar(dec[i]);
    putchar('\n');

    return 0;
}
