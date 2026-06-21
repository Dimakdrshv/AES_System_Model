/* AES constants */

#pragma once

#define Nb 4 /* @brief Number of columns (32-bit words) comprising the State. For AES, this is always 4. */

#ifndef Nk
#define Nk 4 /* @brief Number of 32-bit words comprising the Cipher Key. For AES-128, this is 4, for AES-192, this is 6, and for AES-256, this is 8. */
#endif

#ifndef Nr
#define Nr 10 /* @brief Number of rounds. For AES-128, this is 10, for AES-192, this is 12, and for AES-256, this is 14. */
#endif