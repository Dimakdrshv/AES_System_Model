#include "aes_key_expansion.h"
#include "aes_constants.h"

/* @brief
 * Round constants used by the AES Key Expansion procedure.
 * AES_RCON[0] is not used because round constants start from index 1.
 */
static const uint32_t AES_RCON[] = {
    0x00000000, // AES_RCON[0] is not used
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
};

extern const uint8_t AES_SBOX[16][16];

/* @brief
 * Performs a cyclic left shift of a 32-bit word by one byte.
 *
 * Example:
 * [b0, b1, b2, b3] -> [b1, b2, b3, b0]
 */
static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

/* @brief
 * Applies the AES S-box substitution to each byte of a 32-bit word.
 */
static uint32_t SubWord(uint32_t word) {
    uint8_t b0 = AES_SBOX[(word >> 24) & 0xFF >> 4][(word >> 24) & 0x0F];
    uint8_t b1 = AES_SBOX[(word >> 16) & 0xFF >> 4][(word >> 16) & 0x0F];
    uint8_t b2 = AES_SBOX[(word >> 8) & 0xFF >> 4][(word >> 8) & 0x0F];
    uint8_t b3 = AES_SBOX[word & 0xFF >> 4][word & 0x0F];
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
}

void KeyExpansion(uint8_t key[4*Nk], uint32_t w[Nb * (Nr + 1)]) {
    uint32_t temp;

    size_t i = 0;

    // Copy the original cipher key into the first Nk words.
    while (i < Nk) {
        w[i] = ((uint32_t)key[4 * i] << 24) |
               ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) |
               ((uint32_t)key[4 * i + 3]);
        i++;
    }

    // Generate the remaining words of the expanded key.
    i = Nk;
    while (i < Nb * (Nr + 1)) {
        temp = w[i-1];

        // Apply the key schedule core every Nk words.
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ AES_RCON[i / Nk];
        }

        // Additional SubWord step for AES-256.
        else if (Nk > 6 && i % Nk == 4) {
            temp = SubWord(temp);
        }
        
        w[i] = w[i - Nk] ^ temp;
        i++;
    }
}