#include "aes.h"
#include "aes_key_expansion.h"
#include "aes_constants.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_COUNT 10000

static uint32_t rng_state = 0x12345678u;

static uint8_t rand_byte(void)
{
    rng_state = rng_state * 1664525u + 1013904223u;
    return (uint8_t)(rng_state >> 24);
}

static void fill_random(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        data[i] = rand_byte();
}

static void run_single_test(size_t test_id)
{
    uint8_t key[4 * Nk];
    uint8_t plain[4 * Nb];
    uint8_t cipher[4 * Nb];
    uint8_t dec_inv[4 * Nb];
    uint8_t dec_eq[4 * Nb];

    uint32_t w[Nb * (Nr + 1)];

    fill_random(key, sizeof(key));
    fill_random(plain, sizeof(plain));

    KeyExpansion(key, w);

    Cipher(plain, cipher, w);

    memcpy(dec_inv, cipher, sizeof(cipher));
    memcpy(dec_eq, cipher, sizeof(cipher));

    InvCipher(dec_inv, dec_inv, w);
    EqInvCipher(dec_eq, dec_eq, w);

    if (memcmp(dec_inv, plain, sizeof(plain)) != 0)
    {
        printf("InvCipher failed. Test: %zu, Nk=%d, Nr=%d\n", test_id, Nk, Nr);
        assert(0);
    }
    else
    {
        printf("Test %zu passed. Nk=%d, Nr=%d\n", test_id, Nk, Nr);
        printf("plain: ");
        for (size_t i = 0; i < sizeof(plain); i++)
            printf("%02x ", plain[i]);
        printf("\nEqInvCipher: ");
        for (size_t i = 0; i < sizeof(dec_eq); i++)
            printf("%02x ", dec_eq[i]);
        printf("\nInvCipher: ");
        for (size_t i = 0; i < sizeof(dec_inv); i++)
            printf("%02x ", dec_inv[i]);
        puts("");
    }

    if (memcmp(dec_eq, plain, sizeof(plain)) != 0)
    {
        printf("EqInvCipher failed. Test: %zu, Nk=%d, Nr=%d\n", test_id, Nk, Nr);
        assert(0);
    }
    else
    {
        printf("Test %zu passed. Nk=%d, Nr=%d\n", test_id, Nk, Nr);
        printf("plain: ");
        for (size_t i = 0; i < sizeof(plain); i++)
            printf("%02x ", plain[i]);
        printf("\nEqInvCipher: ");
        for (size_t i = 0; i < sizeof(dec_eq); i++)
            printf("%02x ", dec_eq[i]);
        printf("\nInvCipher: ");
        for (size_t i = 0; i < sizeof(dec_inv); i++)
            printf("%02x ", dec_inv[i]);
        puts("");
    }
}

int main(void)
{
    for (size_t i = 0; i < TEST_COUNT; i++)
        run_single_test(i);

    printf("AES tests passed: Nk=%d, Nr=%d, tests=%d\n", Nk, Nr, TEST_COUNT);

    return 0;
}