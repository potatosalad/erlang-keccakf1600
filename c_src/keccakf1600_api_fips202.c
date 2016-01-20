// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_api_fips202.h"

static int	KECCAKF1600_API_INIT(fips202, shake128);
static void	KECCAKF1600_API_EXEC(fips202, shake128);
static int	KECCAKF1600_API_INIT(fips202, shake256);
static void	KECCAKF1600_API_EXEC(fips202, shake256);
static int	KECCAKF1600_API_INIT(fips202, sha3_224);
static void	KECCAKF1600_API_EXEC(fips202, sha3_224);
static int	KECCAKF1600_API_INIT(fips202, sha3_256);
static void	KECCAKF1600_API_EXEC(fips202, sha3_256);
static int	KECCAKF1600_API_INIT(fips202, sha3_384);
static void	KECCAKF1600_API_EXEC(fips202, sha3_384);
static int	KECCAKF1600_API_INIT(fips202, sha3_512);
static void	KECCAKF1600_API_EXEC(fips202, sha3_512);

keccakf1600_function_t	keccakf1600_functions_fips202[] = {
	KECCAKF1600_API_R_ARGV(fips202, shake128, 2),
	KECCAKF1600_API_R_ARGV(fips202, shake256, 2),
	KECCAKF1600_API_R_ARGV(fips202, sha3_224, 1),
	KECCAKF1600_API_R_ARGV(fips202, sha3_256, 1),
	KECCAKF1600_API_R_ARGV(fips202, sha3_384, 1),
	KECCAKF1600_API_R_ARGV(fips202, sha3_512, 1),
	{NULL}
};

/* fips202_shake128/2 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, shake128) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
	int			outputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, shake128);

static int
KECCAKF1600_API_INIT(fips202, shake128)
{
	KECCAKF1600_API_F_ARGV_T(fips202, shake128) *argv;
	int skip;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| (type != ERL_SMALL_INTEGER_EXT
				&& type != ERL_INTEGER_EXT
				&& type != ERL_SMALL_BIG_EXT
				&& type != ERL_LARGE_BIG_EXT)) {
		return -1;
	}

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, shake128))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, shake128) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, shake128)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_long(buffer, index, (long *)&(argv->outputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (argv->outputByteLen < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, shake128)
{
	KECCAKF1600_API_F_ARGV_T(fips202, shake128) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, shake128);

	unsigned char output[argv->outputByteLen];

	(void) FIPS202_SHAKE128(argv->input, argv->inputByteLen, output, argv->outputByteLen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), argv->outputByteLen,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}

/* fips202_shake256/2 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, shake256) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
	int			outputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, shake256);

static int
KECCAKF1600_API_INIT(fips202, shake256)
{
	KECCAKF1600_API_F_ARGV_T(fips202, shake256) *argv;
	int skip;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| (type != ERL_SMALL_INTEGER_EXT
				&& type != ERL_INTEGER_EXT
				&& type != ERL_SMALL_BIG_EXT
				&& type != ERL_LARGE_BIG_EXT)) {
		return -1;
	}

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, shake256))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, shake256) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, shake256)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_long(buffer, index, (long *)&(argv->outputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (argv->outputByteLen < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, shake256)
{
	KECCAKF1600_API_F_ARGV_T(fips202, shake256) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, shake256);

	unsigned char output[argv->outputByteLen];

	(void) FIPS202_SHAKE256(argv->input, argv->inputByteLen, output, argv->outputByteLen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), argv->outputByteLen,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}

/* fips202_sha3_224/1 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, sha3_224) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, sha3_224);

static int
KECCAKF1600_API_INIT(fips202, sha3_224)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_224) *argv;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_224))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, sha3_224) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_224)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, sha3_224)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_224) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, sha3_224);

	unsigned char output[28];

	(void) FIPS202_SHA3_224(argv->input, argv->inputByteLen, output);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), 28,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}

/* fips202_sha3_256/1 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, sha3_256) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, sha3_256);

static int
KECCAKF1600_API_INIT(fips202, sha3_256)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_256) *argv;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_256))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, sha3_256) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_256)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, sha3_256)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_256) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, sha3_256);

	unsigned char output[32];

	(void) FIPS202_SHA3_256(argv->input, argv->inputByteLen, output);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), 32,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}

/* fips202_sha3_384/1 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, sha3_384) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, sha3_384);

static int
KECCAKF1600_API_INIT(fips202, sha3_384)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_384) *argv;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_384))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, sha3_384) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_384)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, sha3_384)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_384) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, sha3_384);

	unsigned char output[48];

	(void) FIPS202_SHA3_384(argv->input, argv->inputByteLen, output);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), 48,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}

/* fips202_sha3_512/1 */

typedef struct KECCAKF1600_API_F_ARGV(fips202, sha3_512) {
	const unsigned char	*input;
	unsigned int		inputByteLen;
} KECCAKF1600_API_F_ARGV_T(fips202, sha3_512);

static int
KECCAKF1600_API_INIT(fips202, sha3_512)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_512) *argv;
	int type;
	int type_length;
	unsigned int inputByteLen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inputByteLen = (unsigned int)(type_length);

	x = (ErlDrvSizeT)(inputByteLen + (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_512))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(fips202, sha3_512) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(fips202, sha3_512)));
	argv->input = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->input), (long *)&(argv->inputByteLen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(fips202, sha3_512)
{
	KECCAKF1600_API_F_ARGV_T(fips202, sha3_512) *argv;
	KECCAKF1600_API_READ_ARGV(fips202, sha3_512);

	unsigned char output[64];

	(void) FIPS202_SHA3_512(argv->input, argv->inputByteLen, output);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(output), 64,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);
}
