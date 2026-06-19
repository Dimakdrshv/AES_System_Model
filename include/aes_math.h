/* AES Math Functions */

#pragma once

#include <stdint.h>

/**
 * @brief Performs multiplication in the Galois Field GF(2^8).
 * @param a The first operand.
 * @param b The second operand.
 * @return The result of (a * b) in GF(2^8).
 */
uint8_t galois_mul(uint8_t a, uint8_t b);