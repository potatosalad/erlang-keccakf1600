// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef FIPS202_H
#define FIPS202_H

#include "keccakf1600_drv_common.h"

extern void	FIPS202_SHAKE128(const unsigned char *input, size_t inputByteLen, unsigned char *output, size_t outputByteLen);
extern void	FIPS202_SHAKE256(const unsigned char *input, size_t inputByteLen, unsigned char *output, size_t outputByteLen);
extern void	FIPS202_SHA3_224(const unsigned char *input, size_t inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_256(const unsigned char *input, size_t inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_384(const unsigned char *input, size_t inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_512(const unsigned char *input, size_t inputByteLen, unsigned char *output);

#endif
