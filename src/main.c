#include "aes.h"
#include "aes_key_expansion.h"
#include "aes_constants.h"
#include <stdio.h>

int main() {
    uint8_t aes_key[4*Nk];

    puts("Enter AES Key (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256) in hexadecimal format:");
    for (size_t i = 0; i < 4*Nk; i++) {
        uint8_t byte;
        scanf("%2x", &byte);
        aes_key[i] = (uint8_t)byte;
    }

    puts("AES Key:");
    for (size_t i = 0; i < 4*Nk; i++)
        printf("%02x ", aes_key[i]);

    puts("");
    uint32_t w[Nb * (Nr + 1)];
    KeyExpansion(aes_key, w);

    puts("Round Keys:");
    for (size_t i = 0; i < Nb * (Nr + 1); i++) {
        printf("%08x ", w[i]);
        if ((i + 1) % Nb == 0)
            printf("\n");
    }

    uint8_t in[4*Nb];

    puts("Enter input data (16 bytes) in hexadecimal format:");
    for (size_t i = 0; i < 4*Nb; i++) {
        uint8_t byte;
        scanf("%2x", &byte);
        in[i] = byte;
    }

    puts("Input data:");
    for (size_t i = 0; i < 4*Nb; i++)
        printf("%02x ", in[i]);
    puts("");

    uint8_t out[4*Nb];

    Cipher(in, out, w);
    puts("Ciphertext:");
    for (size_t i = 0; i < 4*Nb; i++)
        printf("%02x ", out[i]);
    puts("");

    EqInvCipher(out, out, w);

    puts("Decrypted data:");
    for (size_t i = 0; i < 4*Nb; i++)
        printf("%02x ", out[i]);
    puts("");

    return 0;
}