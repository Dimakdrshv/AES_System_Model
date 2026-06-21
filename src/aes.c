#include "aes.h"
#include "aes_key_expansion.h"
#include "aes_transformation.h"
#include "aes_constants.h"

void Cipher(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb * (Nr + 1)]) {
    uint8_t state[4][4]; // always a 4x4 matrix

    // Convert input block to State matrix
    state[0][0] = in[0]; state[0][1] = in[4]; state[0][2] = in[8]; state[0][3] = in[12];
    state[1][0] = in[1]; state[1][1] = in[5]; state[1][2] = in[9]; state[1][3] = in[13];
    state[2][0] = in[2]; state[2][1] = in[6]; state[2][2] = in[10]; state[2][3] = in[14];
    state[3][0] = in[3]; state[3][1] = in[7]; state[3][2] = in[11]; state[3][3] = in[15];

    // Initial round
    AddRoundKey(state, w, 0);

    // Main rounds
    for (size_t round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w, round);
    }

    // Final round without MixColumns
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w, Nr);

    // Convert State matrix to output block
    out[0] = state[0][0]; out[4] = state[0][1]; out[8] = state[0][2]; out[12] = state[0][3];
    out[1] = state[1][0]; out[5] = state[1][1]; out[9] = state[1][2]; out[13] = state[1][3];
    out[2] = state[2][0]; out[6] = state[2][1]; out[10] = state[2][2]; out[14] = state[2][3];
    out[3] = state[3][0]; out[7] = state[3][1]; out[11] = state[3][2]; out[15] = state[3][3];
}

void InvCipher(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb * (Nr + 1)]) {
    uint8_t state[4][4]; // always a 4x4 matrix

    // Convert input block to State matrix
    state[0][0] = in[0]; state[0][1] = in[4]; state[0][2] = in[8]; state[0][3] = in[12];
    state[1][0] = in[1]; state[1][1] = in[5]; state[1][2] = in[9]; state[1][3] = in[13];
    state[2][0] = in[2]; state[2][1] = in[6]; state[2][2] = in[10]; state[2][3] = in[14];
    state[3][0] = in[3]; state[3][1] = in[7]; state[3][2] = in[11]; state[3][3] = in[15];

    // Initial round
    AddRoundKey(state, w, Nr);

    // Main rounds
    for (size_t round = Nr - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        InvAddRoundKey(state, w, round);
        InvMixColumns(state);
    }

    // Final round without InvMixColumns
    InvShiftRows(state);
    InvSubBytes(state);
    InvAddRoundKey(state, w, 0);

    // Convert State matrix to output block
    out[0] = state[0][0]; out[4] = state[0][1]; out[8] = state[0][2]; out[12] = state[0][3];
    out[1] = state[1][0]; out[5] = state[1][1]; out[9] = state[1][2]; out[13] = state[1][3];
    out[2] = state[2][0]; out[6] = state[2][1]; out[10] = state[2][2]; out[14] = state[2][3];
    out[3] = state[3][0]; out[7] = state[3][1]; out[11] = state[3][2]; out[15] = state[3][3];
}

void EqInvCipher(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb * (Nr + 1)]) {
    // Prepare modified round keys for Equivalent Inverse Cipher
    uint32_t dw[Nb * (Nr + 1)];
    InvMixWord(w, dw);

    uint8_t state[4][4]; // always a 4x4 matrix

    // Convert input block to State matrix
    state[0][0] = in[0]; state[0][1] = in[4]; state[0][2] = in[8]; state[0][3] = in[12];
    state[1][0] = in[1]; state[1][1] = in[5]; state[1][2] = in[9]; state[1][3] = in[13];
    state[2][0] = in[2]; state[2][1] = in[6]; state[2][2] = in[10]; state[2][3] = in[14];
    state[3][0] = in[3]; state[3][1] = in[7]; state[3][2] = in[11]; state[3][3] = in[15];

    // Initial round
    InvAddRoundKey(state, dw, Nr);

    // Main rounds
    for (size_t round = Nr - 1; round > 0; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        InvMixColumns(state);
        InvAddRoundKey(state, dw, round);
    }

    // Final round without MixColumns
    InvSubBytes(state);
    InvShiftRows(state);
    InvAddRoundKey(state, dw, 0);

    // Convert State matrix to output block
    out[0] = state[0][0]; out[4] = state[0][1]; out[8] = state[0][2]; out[12] = state[0][3];
    out[1] = state[1][0]; out[5] = state[1][1]; out[9] = state[1][2]; out[13] = state[1][3];
    out[2] = state[2][0]; out[6] = state[2][1]; out[10] = state[2][2]; out[14] = state[2][3];
    out[3] = state[3][0]; out[7] = state[3][1]; out[11] = state[3][2]; out[15] = state[3][3];
}