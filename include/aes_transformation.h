/* AES Transformation */

#pragma once

#include <stdint.h>

/**
 * @brief Applies the AES S-box substitution to each byte of the State matrix.
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void SubBytes(uint8_t state[4][4]);

/**
 * @brief Applies the inverse AES S-box substitution to each byte of the State matrix.
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void InvSubBytes(uint8_t state[4][4]);

/**
 * @brief Cyclically shifts the rows of the State matrix to the left.
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void ShiftRows(uint8_t state[4][4]);

/**
 * @brief Cyclically shifts the rows of the State matrix to the right.
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void InvShiftRows(uint8_t state[4][4]);

/**
 * @brief Mixes each column of the State matrix in GF(2^8).
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void MixColumns(uint8_t state[4][4]);

/**
 * @brief Applies the inverse MixColumns transformation to each State column.
 *
 * @param state AES State matrix, always 4x4 bytes.
 */
void InvMixColumns(uint8_t state[4][4]);

/**
 * @brief Applies InvMixColumns transformation to expanded key words.
 *
 * Used for preparing the modified round keys required by EqInvCipher().
 *
 * @param w  Input expanded key word array.
 * @param dw Output modified expanded key word array.
 */
void InvMixWord(uint32_t* w, uint32_t* dw);

/**
 * @brief Adds the selected round key to the State matrix using XOR.
 *
 * @param state AES State matrix, always 4x4 bytes.
 * @param w     Expanded key word array of Nb * (Nr + 1) words.
 * @param round Round number whose key is applied.
 */
void AddRoundKey(uint8_t state[4][4], uint32_t* w, uint8_t round);

/**
 * @brief Inverse AddRoundKey transformation.
 *
 * This function is identical to AddRoundKey(), since XOR is its own inverse.
 *
 * @param state AES State matrix, always 4x4 bytes.
 * @param w     Expanded key word array of Nb * (Nr + 1) words.
 * @param round Round number whose key is applied.
 */
void InvAddRoundKey(uint8_t state[4][4], uint32_t* w, uint8_t round);