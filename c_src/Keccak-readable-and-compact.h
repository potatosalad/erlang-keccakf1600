// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef KECCAKF1600_READABLE_AND_COMPACT
#define KECCAKF1600_READABLE_AND_COMPACT

extern void	FIPS202_SHAKE128(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
extern void	FIPS202_SHAKE256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
extern void	FIPS202_SHA3_224(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
extern void	FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);

extern void	KeccakF1600_StatePermute(void *state);
extern void	Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

#endif
