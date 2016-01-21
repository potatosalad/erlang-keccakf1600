// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "fips202.h"
#include "shake.h"

void
FIPS202_SHAKE128(const unsigned char *input, size_t inputByteLen, unsigned char *output, size_t outputByteLen)
{
	(void) shake128_hash(output, outputByteLen, input, inputByteLen);
}

void
FIPS202_SHAKE256(const unsigned char *input, size_t inputByteLen, unsigned char *output, size_t outputByteLen)
{
	(void) shake256_hash(output, outputByteLen, input, inputByteLen);
}

void
FIPS202_SHA3_224(const unsigned char *input, size_t inputByteLen, unsigned char *output)
{
	(void) sha3_224_hash(output, 28, input, inputByteLen);
}

void
FIPS202_SHA3_256(const unsigned char *input, size_t inputByteLen, unsigned char *output)
{
	(void) sha3_256_hash(output, 32, input, inputByteLen);
}

void
FIPS202_SHA3_384(const unsigned char *input, size_t inputByteLen, unsigned char *output)
{
	(void) sha3_384_hash(output, 48, input, inputByteLen);
}

void
FIPS202_SHA3_512(const unsigned char *input, size_t inputByteLen, unsigned char *output)
{
	(void) sha3_512_hash(output, 64, input, inputByteLen);
}
