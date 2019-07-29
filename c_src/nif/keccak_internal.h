/**
 * @cond internal
 * @file keccak_internal.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Keccak internal interfaces.  Will be used by STROBE once reintegrated.
 */

/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Cryptography Research, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __DECAF_KECCAK_INTERNAL_H__
#define __DECAF_KECCAK_INTERNAL_H__ 1

#include <stdint.h>

/* Aliasing MSVC preprocessing to GNU preprocessing */
#if defined _MSC_VER
#define __attribute__(x) // Turn off attribute code
#define __attribute(x)
#define __restrict__ __restrict // Use MSVC restrict code
#endif                          // MSVC

/* The internal, non-opaque definition of the decaf_sponge struct. */
typedef union {
    uint64_t w[25];
    uint8_t b[25 * 8];
} kdomain_t[1];

typedef struct decaf_kparams_s {
    uint8_t position, flags, rate, start_round, pad, rate_pad, max_out, remaining;
} decaf_kparams_s, decaf_kparams_t[1];

typedef struct decaf_keccak_sponge_s {
    kdomain_t state;
    decaf_kparams_t params;
} decaf_keccak_sponge_s, decaf_keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1

void __attribute__((noinline)) keccakf(kdomain_t state, uint8_t start_round);

static inline void
dokeccak(decaf_keccak_sponge_t decaf_sponge)
{
    keccakf(decaf_sponge->state, decaf_sponge->params->start_round);
    decaf_sponge->params->position = 0;
}

#endif /* __DECAF_KECCAK_INTERNAL_H__ */
