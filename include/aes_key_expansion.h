/* key expansion functions for AES */

#pragma once

#include <stdint.h>

void KeyExpansion(uint8_t* key, uint32_t* w);