#include "aes_math.h"

/* Galois Field (GF(2^8)) constants */
#define GF_REDUCING_POLYNOMIAL 0x1B /* Irreducible polynomial for AES: x^8 + x^4 + x^3 + x + 1 */
#define GF_MSB_MASK 0x80 /* Most significant bit mask */

/* Addition Field */
#define BITS_IN_BYTE 8

uint8_t galois_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (size_t i = 0; i < BITS_IN_BYTE; i++) {
        if (b & 0b1) {
            result ^= a; // Addition in GF(2^8) is just XOR
        }

        uint8_t high_bit = a & GF_MSB_MASK; // Check if the most significant bit is set
        a <<= 1; // Multiply a by x (shift left)

        if (high_bit) {
            a ^= GF_REDUCING_POLYNOMIAL; // If the high bit was set, reduce modulo the irreducible polynomial
        }

        b >>= 1; // Move to the next bit of b
    }
    return result;
}