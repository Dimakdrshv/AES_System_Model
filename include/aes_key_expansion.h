/* key expansion functions for AES */

#pragma once

#include <stdint.h>

/**
 * @brief Expands the original AES cipher key into round key words.
 *
 * This function generates an array of 32-bit words used by the
 * AddRoundKey transformation during AES encryption and decryption.
 *
 * The number of generated words is defined as Nb * (Nr + 1).
 * The first Nk words are taken directly from the original cipher key,
 * while the remaining words are generated using RotWord(), SubWord()
 * and Rcon constants.
 *
 * @param key Original cipher key. Its size is 4 * Nk bytes.
 * @param w   Output array of expanded key words.
 *            Its size is Nb * (Nr + 1) 32-bit words.
 */
void KeyExpansion(uint8_t* key, uint32_t* w);