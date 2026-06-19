/* AES cipher and inverse cipher functions */

#pragma once

#include <stdint.h>

void Cipher(uint8_t* in, uint8_t* out, uint32_t* w);
void EqInvCipher(uint8_t* in, uint8_t* out, uint32_t* w); 