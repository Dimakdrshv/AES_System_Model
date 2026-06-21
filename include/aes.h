/* AES cipher and inverse cipher functions */

#pragma once

#include <stdint.h>

/**
 * @brief Encrypts one 128-bit input block using AES.
 *
 * @param in  Input plaintext block, 16 bytes.
 * @param out Output ciphertext block, 16 bytes.
 * @param w   Expanded key word array of Nb * (Nr + 1) words.
 */
void Cipher(uint8_t* in, uint8_t* out, uint32_t* w);

/**
 * @brief Decrypts one 128-bit input block using the Equivalent Inverse Cipher.
 *
 * @param in  Input ciphertext block, 16 bytes.
 * @param out Output plaintext block, 16 bytes.
 * @param w   Expanded key word array of Nb * (Nr + 1) words.
 */
void EqInvCipher(uint8_t* in, uint8_t* out, uint32_t* w);

/**
 * @brief Decrypts one 128-bit input block using the AES Inverse Cipher.
 *
 * @param in  Input ciphertext block, 16 bytes.
 * @param out Output plaintext block, 16 bytes.
 * @param w   Expanded key word array of Nb * (Nr + 1) words.
 */
void InvCipher(uint8_t* in, uint8_t* out, uint32_t* w);
