// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_api_shake128.h"
#include "shake.h"

static void	KECCAKF1600_API_EXEC(shake128, init);
static int	KECCAKF1600_API_INIT(shake128, update);
static void	KECCAKF1600_API_EXEC(shake128, update);
static int	KECCAKF1600_API_INIT(shake128, final);
static void	KECCAKF1600_API_EXEC(shake128, final);

keccakf1600_function_t	keccakf1600_functions_shake128[] = {
	KECCAKF1600_API_R_ARG0(shake128, init),
	KECCAKF1600_API_R_ARGV(shake128, update, 2),
	KECCAKF1600_API_R_ARGV(shake128, final, 2),
	{NULL}
};

/* shake128_init/0 */

static void
KECCAKF1600_API_EXEC(shake128, init)
{
	shake128_ctx_t sponge;

	(void) shake128_init(sponge);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sponge), sizeof(sponge),
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(sponge), sizeof(sponge));
}

/* shake128_update/2 */

typedef struct KECCAKF1600_API_F_ARGV(shake128, update) {
	shake128_ctx_t	sponge;
	const uint8_t	*in;
	size_t		inlen;
} KECCAKF1600_API_F_ARGV_T(shake128, update);

static int
KECCAKF1600_API_INIT(shake128, update)
{
	KECCAKF1600_API_F_ARGV_T(shake128, update) *argv;
	int skip;
	int type;
	int type_length;
	size_t inlen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != sizeof(shake128_ctx_t)) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inlen = (size_t)(type_length);

	x = (ErlDrvSizeT)(inlen + (sizeof (KECCAKF1600_API_F_ARGV_T(shake128, update))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(shake128, update) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(shake128, update)));
	argv->in = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sponge), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(shake128, update)
{
	KECCAKF1600_API_F_ARGV_T(shake128, update) *argv;
	KECCAKF1600_API_READ_ARGV(shake128, update);

	(void) shake128_update(argv->sponge, argv->in, argv->inlen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(argv->sponge), sizeof(argv->sponge),
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(argv->sponge), sizeof(argv->sponge));
}

/* shake128_final/2 */

typedef struct KECCAKF1600_API_F_ARGV(shake128, final) {
	shake128_ctx_t	sponge;
	size_t		outlen;
} KECCAKF1600_API_F_ARGV_T(shake128, final);

static int
KECCAKF1600_API_INIT(shake128, final)
{
	KECCAKF1600_API_F_ARGV_T(shake128, final) *argv;
	int skip;
	int type;
	int type_length;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != sizeof(shake128_ctx_t)) {
		return -1;
	}

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

	x = (ErlDrvSizeT)((sizeof (KECCAKF1600_API_F_ARGV_T(shake128, final))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(shake128, final) *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sponge), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_ulong(buffer, index, (unsigned long *)&(argv->outlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(shake128, final)
{
	KECCAKF1600_API_F_ARGV_T(shake128, final) *argv;
	KECCAKF1600_API_READ_ARGV(shake128, final);

	uint8_t out[argv->outlen];

	(void) shake128_final(argv->sponge, out, argv->outlen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(argv->sponge), sizeof(argv->sponge));
	(void) decaf_bzero((void *)(out), argv->outlen);
}
