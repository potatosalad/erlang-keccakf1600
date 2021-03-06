/**
 * @file decaf/spongerng.h
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Sponge-based RNGs.
 * @warning This construction isn't final.  In particular,
 * the outputs of deterministic RNGs from this mechanism might change in future versions.
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

#ifndef __DECAF_SPONGERNG_H__
#define __DECAF_SPONGERNG_H__

#include "decaf-shake.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Keccak CSPRNG structure as struct. */
typedef struct {
    decaf_keccak_sponge_t sponge; /**< Internal sponge object. */
} decaf_keccak_prng_s;

/** Keccak CSPRNG structure as one-element array */
typedef decaf_keccak_prng_s decaf_keccak_prng_t[1];

/** Initialize a sponge-based CSPRNG from a buffer. */
void DECAF_API_VIS decaf_spongerng_init_from_buffer(
    decaf_keccak_prng_t prng,       /**< [out] The PRNG object. */
    const uint8_t *__restrict__ in, /**< [in]  The initialization data. */
    size_t len,                     /**< [in]  The length of the initialization data. */
    int deterministic               /**< [in]  If zero, allow RNG to stir in nondeterministic data from RDRAND or RDTSC.*/
    ) DECAF_NONNULL;

/**
 * @brief Initialize a sponge-based CSPRNG from a file.
 * @retval DECAF_SUCCESS success.
 * @retval DECAF_FAILURE failure.
 * @note On failure, errno can be used to determine the cause.
 */
decaf_error_t DECAF_API_VIS decaf_spongerng_init_from_file(
    decaf_keccak_prng_t prng, /**< [out] The PRNG object. */
    const char *file,         /**< [in]  A name of a file containing initial data. */
    size_t len,               /**< [in]  The length of the initial data.  Must be positive. */
    int deterministic         /**< [in]  If zero, allow RNG to stir in nondeterministic data from RDRAND or RDTSC. */
    ) DECAF_NONNULL DECAF_WARN_UNUSED;

/**
 * @brief Initialize a nondeterministic sponge-based CSPRNG from /dev/urandom.
 * @retval DECAF_SUCCESS success.
 * @retval DECAF_FAILURE failure.
 * @note On failure, errno can be used to determine the cause.
 */
decaf_error_t DECAF_API_VIS decaf_spongerng_init_from_dev_urandom(decaf_keccak_prng_t prng /**< [out] sponge The sponge object. */
                                                                  ) DECAF_WARN_UNUSED;

/** Output bytes from a sponge-based CSPRNG. */
void DECAF_API_VIS decaf_spongerng_next(decaf_keccak_prng_t prng,  /**< [inout] The PRNG object. */
                                        uint8_t *__restrict__ out, /**< [out]   Output buffer. */
                                        size_t len                 /**< [in]    Number of bytes to output. */
);

/** Stir entropy data into a sponge-based CSPRNG from a buffer.  */
void DECAF_API_VIS decaf_spongerng_stir(decaf_keccak_prng_t prng,       /**< [out] The PRNG object. */
                                        const uint8_t *__restrict__ in, /**< [in]  The entropy data. */
                                        size_t len                      /**< [in]  The length of the initial data. */
                                        ) DECAF_NONNULL;

/** Securely destroy a sponge RNG object by overwriting it. */
static DECAF_INLINE void decaf_spongerng_destroy(decaf_keccak_prng_t doomed /**< [in] The object to destroy. */
);

/** @cond internal */
/***************************************/
/* Implementations of inline functions */
/***************************************/
void
decaf_spongerng_destroy(decaf_keccak_prng_t doomed)
{
    decaf_sha3_destroy(doomed->sponge);
}
/** @endcond */ /* internal */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_SPONGERNG_H__ */
