#include "aes_transformation.h"
#include "aes_constants.h"
#include "aes_math.h"

/* AES S-box lookup table */
const uint8_t AES_SBOX[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

const uint8_t AES_INV_SBOX[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

void SubBytes(uint8_t state[4][4]) {
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            uint8_t row = (state[i][j] >> 4u) & 0x0F; // Get the upper 4 bits for the row
            uint8_t col = state[i][j] & 0x0F;        // Get the lower 4 bits for the column
            state[i][j] = AES_SBOX[row][col];
        }   
    }
}

void InvSubBytes(uint8_t state[4][4]) {
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            uint8_t row = (state[i][j] >> 4u) & 0x0F; // Get the upper 4 bits for the row
            uint8_t col = state[i][j] & 0x0F;        // Get the lower 4 bits for the column
            state[i][j] = AES_INV_SBOX[row][col];
        }   
    }
}

void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    
    // Row 0: No shift

    // Row 1: Shift left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Shift left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift left by 3 (or right by 1)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    
    // Row 0: No shift

    // Row 1: Shift right by 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Row 2: Shift right by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift right by 3 (or left by 1)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void MixColumns(uint8_t state[4][4]) {

    /* The MixColumns transformation mixes the columns of the state matrix. Each column is treated as a polynomial and multiplied by a fixed polynomial. The transformation can be represented as follows:
    *
    * | s'[0][c] |   | 02 03 01 01 |   | s[0][c] |
    * | s'[1][c] | = | 01 02 03 01 | * | s[1][c] |
    * | s'[2][c] |   | 01 01 02 03 |   | s[2][c] |
    * | s'[3][c] |   | 03 01 01 02 |   | s[3][c] |
    *
    * where c is the column index (0 to 3) and s[i][c] is the byte in row i and column c of the state matrix.
    */
    
    // zero column
    uint8_t temp[4] = {state[0][0], state[1][0], state[2][0], state[3][0]};

    state[0][0] = galois_mul(0x02, temp[0]) ^ galois_mul(0x03, temp[1]) ^ temp[2] ^ temp[3];
    state[1][0] = temp[0] ^ galois_mul(0x02, temp[1]) ^ galois_mul(0x03, temp[2]) ^ temp[3];
    state[2][0] = temp[0] ^ temp[1] ^ galois_mul(0x02, temp[2]) ^ galois_mul(0x03, temp[3]);
    state[3][0] = galois_mul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galois_mul(0x02, temp[3]);

    // first column
    temp[0] = state[0][1]; temp[1] = state[1][1]; temp[2] = state[2][1]; temp[3] = state[3][1];

    state[0][1] = galois_mul(0x02, temp[0]) ^ galois_mul(0x03, temp[1]) ^ temp[2] ^ temp[3];
    state[1][1] = temp[0] ^ galois_mul(0x02, temp[1]) ^ galois_mul(0x03, temp[2]) ^ temp[3];
    state[2][1] = temp[0] ^ temp[1] ^ galois_mul(0x02, temp[2]) ^ galois_mul(0x03, temp[3]);
    state[3][1] = galois_mul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galois_mul(0x02, temp[3]);

    // second column
    temp[0] = state[0][2]; temp[1] = state[1][2]; temp[2] = state[2][2]; temp[3] = state[3][2];

    state[0][2] = galois_mul(0x02, temp[0]) ^ galois_mul(0x03, temp[1]) ^ temp[2] ^ temp[3];
    state[1][2] = temp[0] ^ galois_mul(0x02, temp[1]) ^ galois_mul(0x03, temp[2]) ^ temp[3];
    state[2][2] = temp[0] ^ temp[1] ^ galois_mul(0x02, temp[2]) ^ galois_mul(0x03, temp[3]);
    state[3][2] = galois_mul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galois_mul(0x02, temp[3]);

    // third column
    temp[0] = state[0][3]; temp[1] = state[1][3]; temp[2] = state[2][3]; temp[3] = state[3][3];

    state[0][3] = galois_mul(0x02, temp[0]) ^ galois_mul(0x03, temp[1]) ^ temp[2] ^ temp[3];
    state[1][3] = temp[0] ^ galois_mul(0x02, temp[1]) ^ galois_mul(0x03, temp[2]) ^ temp[3];
    state[2][3] = temp[0] ^ temp[1] ^ galois_mul(0x02, temp[2]) ^ galois_mul(0x03, temp[3]);
    state[3][3] = galois_mul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ galois_mul(0x02, temp[3]);
}

void InvMixColumns(uint8_t state[4][4]) {
    /* The InvMixColumns transformation mixes the columns of the state matrix. Each column is treated as a polynomial and multiplied by a fixed polynomial. The transformation can be represented as follows:
    *
    * | s'[0][c] |   | 0e 0b 0d 09 |   | s[0][c] |
    * | s'[1][c] | = | 09 0e 0b 0d | * | s[1][c] |
    * | s'[2][c] |   | 0d 09 0e 0b |   | s[2][c] |
    * | s'[3][c] |   | 0b 0d 09 0e |   | s[3][c] |
    *
    * where c is the column index (0 to 3) and s[i][c] is the byte in row i and column c of the state matrix.
    */

    // zero column
    uint8_t temp[4] = {state[0][0], state[1][0], state[2][0], state[3][0]};

    state[0][0] = galois_mul(0x0e, temp[0]) ^ galois_mul(0x0b, temp[1]) ^ galois_mul(0x0d, temp[2]) ^ galois_mul(0x09, temp[3]);
    state[1][0] = galois_mul(0x09, temp[0]) ^ galois_mul(0x0e, temp[1]) ^ galois_mul(0x0b, temp[2]) ^ galois_mul(0x0d, temp[3]);
    state[2][0] = galois_mul(0x0d, temp[0]) ^ galois_mul(0x09, temp[1]) ^ galois_mul(0x0e, temp[2]) ^ galois_mul(0x0b, temp[3]);
    state[3][0] = galois_mul(0x0b, temp[0]) ^ galois_mul(0x0d, temp[1]) ^ galois_mul(0x09, temp[2]) ^ galois_mul(0x0e, temp[3]);

    // first column
    temp[0] = state[0][1]; temp[1] = state[1][1]; temp[2] = state[2][1]; temp[3] = state[3][1];

    state[0][1] = galois_mul(0x0e, temp[0]) ^ galois_mul(0x0b, temp[1]) ^ galois_mul(0x0d, temp[2]) ^ galois_mul(0x09, temp[3]);
    state[1][1] = galois_mul(0x09, temp[0]) ^ galois_mul(0x0e, temp[1]) ^ galois_mul(0x0b, temp[2]) ^ galois_mul(0x0d, temp[3]);
    state[2][1] = galois_mul(0x0d, temp[0]) ^ galois_mul(0x09, temp[1]) ^ galois_mul(0x0e, temp[2]) ^ galois_mul(0x0b, temp[3]);
    state[3][1] = galois_mul(0x0b, temp[0]) ^ galois_mul(0x0d, temp[1]) ^ galois_mul(0x09, temp[2]) ^ galois_mul(0x0e, temp[3]);

    // second column
    temp[0] = state[0][2]; temp[1] = state[1][2]; temp[2] = state[2][2]; temp[3] = state[3][2];

    state[0][2] = galois_mul(0x0e, temp[0]) ^ galois_mul(0x0b, temp[1]) ^ galois_mul(0x0d, temp[2]) ^ galois_mul(0x09, temp[3]);
    state[1][2] = galois_mul(0x09, temp[0]) ^ galois_mul(0x0e, temp[1]) ^ galois_mul(0x0b, temp[2]) ^ galois_mul(0x0d, temp[3]);
    state[2][2] = galois_mul(0x0d, temp[0]) ^ galois_mul(0x09, temp[1]) ^ galois_mul(0x0e, temp[2]) ^ galois_mul(0x0b, temp[3]);
    state[3][2] = galois_mul(0x0b, temp[0]) ^ galois_mul(0x0d, temp[1]) ^ galois_mul(0x09, temp[2]) ^ galois_mul(0x0e, temp[3]);

    // third column
    temp[0] = state[0][3]; temp[1] = state[1][3]; temp[2] = state[2][3]; temp[3] = state[3][3];

    state[0][3] = galois_mul(0x0e, temp[0]) ^ galois_mul(0x0b, temp[1]) ^ galois_mul(0x0d, temp[2]) ^ galois_mul(0x09, temp[3]);
    state[1][3] = galois_mul(0x09, temp[0]) ^ galois_mul(0x0e, temp[1]) ^ galois_mul(0x0b, temp[2]) ^ galois_mul(0x0d, temp[3]);
    state[2][3] = galois_mul(0x0d, temp[0]) ^ galois_mul(0x09, temp[1]) ^ galois_mul(0x0e, temp[2]) ^ galois_mul(0x0b, temp[3]);
    state[3][3] = galois_mul(0x0b, temp[0]) ^ galois_mul(0x0d, temp[1]) ^ galois_mul(0x09, temp[2]) ^ galois_mul(0x0e, temp[3]);
}

void InvMixWord(uint32_t w[Nb * (Nr + 1)], uint32_t dw[Nb * (Nr + 1)]) {
    /* The InvMixWord transformation mixes the words. Each word is treated as a polynomial and multiplied by a fixed polynomial. The transformation can be represented as follows:
    *
    * | w'[0][c] |   | 0e 0b 0d 09 |   | w[0][c] |
    * | w'[1][c] | = | 09 0e 0b 0d | * | w[1][c] |
    * | w'[2][c] |   | 0d 09 0e 0b |   | w[2][c] |
    * | w'[3][c] |   | 0b 0d 09 0e |   | w[3][c] |
    *
    * where c is the column index (0 to 3) and w[i][c] is the byte in row i and column c of the word matrix.
    */

    // For the first 4 words (the original key), we just copy them as they are not mixed
    dw[0] = w[0];
    dw[1] = w[1];
    dw[2] = w[2];
    dw[3] = w[3];

    // For the next k words, we apply the InvMixWord transformation
    for (size_t i = 4; i < Nb * (Nr + 1) - 4; i++) {
        uint8_t w_byte_1 = (uint8_t)(w[i] >> 24);
        uint8_t w_byte_2 = (uint8_t)(w[i] >> 16);
        uint8_t w_byte_3 = (uint8_t)(w[i] >> 8);
        uint8_t w_byte_4 = (uint8_t)(w[i]);

        uint8_t dw_byte_1 = galois_mul(0x0e, w_byte_1) ^ galois_mul(0x0b, w_byte_2) ^ galois_mul(0x0d, w_byte_3) ^ galois_mul(0x09, w_byte_4);
        uint8_t dw_byte_2 = galois_mul(0x09, w_byte_1) ^ galois_mul(0x0e, w_byte_2) ^ galois_mul(0x0b, w_byte_3) ^ galois_mul(0x0d, w_byte_4);
        uint8_t dw_byte_3 = galois_mul(0x0d, w_byte_1) ^ galois_mul(0x09, w_byte_2) ^ galois_mul(0x0e, w_byte_3) ^ galois_mul(0x0b, w_byte_4);
        uint8_t dw_byte_4 = galois_mul(0x0b, w_byte_1) ^ galois_mul(0x0d, w_byte_2) ^ galois_mul(0x09, w_byte_3) ^ galois_mul(0x0e, w_byte_4);

        dw[i] = ((uint32_t)dw_byte_1 << 24) | ((uint32_t)dw_byte_2 << 16) | ((uint32_t)dw_byte_3 << 8) | (uint32_t)dw_byte_4;
    }

    // For the last 4 words (the last round key), we also copy them as they are not mixed
    dw[Nb * (Nr + 1) - 4] = w[Nb * (Nr + 1) - 4];
    dw[Nb * (Nr + 1) - 3] = w[Nb * (Nr + 1) - 3];
    dw[Nb * (Nr + 1) - 2] = w[Nb * (Nr + 1) - 2];
    dw[Nb * (Nr + 1) - 1] = w[Nb * (Nr + 1) - 1];
}

void AddRoundKey(uint8_t state[4][4], uint32_t w[Nb * (Nr + 1)], uint8_t round) {
    for (size_t i = 0; i < 4; i++) {
        uint32_t roundState = ((uint32_t)state[0][i] << 24u) |
                              ((uint32_t)state[1][i] << 16u) |
                              ((uint32_t)state[2][i] << 8u)  |
                              ((uint32_t)state[3][i]);
        roundState ^= w[round * Nb + i]; // XOR with the round key word
        state[0][i] = (uint8_t)((roundState >> 24) & 0xFF);
        state[1][i] = (uint8_t)((roundState >> 16) & 0xFF);
        state[2][i] = (uint8_t)((roundState >> 8) & 0xFF);
        state[3][i] = (uint8_t)(roundState & 0xFF);
    }
}

void InvAddRoundKey(uint8_t state[4][4], uint32_t w[Nb * (Nr + 1)], uint8_t round) {
    AddRoundKey(state, w, round); // AddRoundKey is its own inverse since it's just XOR
}