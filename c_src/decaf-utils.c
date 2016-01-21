// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet
/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2011 Stanford University.
 * Copyright (c) 2014 Cryptography Research, Inc.
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

/**
 * @file decaf_utils.c
 * @author Mike Hamburg
 * @brief Decaf utility functions.
 */

#include "decaf-common.h"

void decaf_bzero (
	void *s,
	size_t size
) {
#ifdef __STDC_LIB_EXT1__
	memset_s(s, size, 0, size);
#else
	const size_t sw = sizeof(decaf_word_t);
	volatile uint8_t *destroy = (volatile uint8_t *)s;
	for (; size && ((uintptr_t)destroy)%sw; size--, destroy++)
		*destroy = 0;
	for (; size >= sw; size -= sw, destroy += sw)
		*(volatile decaf_word_t *)destroy = 0;
	for (; size; size--, destroy++)
		*destroy = 0;
#endif
}

decaf_bool_t decaf_memeq (
	const void *data1_,
	const void *data2_,
	size_t size
) {
	const unsigned char *data1 = (const unsigned char *)data1_;
	const unsigned char *data2 = (const unsigned char *)data2_;
	unsigned char ret = 0;
	for (; size; size--, data1++, data2++) {
		ret |= *data1 ^ *data2;
	}
	return (((decaf_dword_t)ret) - 1) >> 8;
}
