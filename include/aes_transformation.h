/* AES Transformation */

#pragma once

#include <stdint.h>

void SubBytes(uint8_t state[4][4] /* always a 4x4 matrix */); 
void InvSubBytes(uint8_t state[4][4] /* always a 4x4 matrix */);

void ShiftRows(uint8_t state[4][4] /* always a 4x4 matrix */);
void InvShiftRows(uint8_t state[4][4] /* always a 4x4 matrix */);

void MixColumns(uint8_t state[4][4] /* always a 4x4 matrix */);
void InvMixColumns(uint8_t state[4][4] /* always a 4x4 matrix */);
void InvMixWord(uint32_t* w, uint32_t* dw);

void AddRoundKey(uint8_t state[4][4] /* always a 4x4 matrix */, uint32_t* w /*word array [Nb*(Nr+1)]*/, uint8_t round);
void InvAddRoundKey(uint8_t state[4][4] /* always a 4x4 matrix */, uint32_t* w /*word array [Nb*(Nr+1)]*/, uint8_t round);