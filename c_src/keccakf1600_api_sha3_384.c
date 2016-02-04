// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_api_sha3_384.h"
#include "shake.h"

static void	KECCAKF1600_API_EXEC(sha3_384, init);
static int	KECCAKF1600_API_INIT(sha3_384, update);
static void	KECCAKF1600_API_EXEC(sha3_384, update);
static int	KECCAKF1600_API_INIT(sha3_384, final);
static void	KECCAKF1600_API_EXEC(sha3_384, final);

keccakf1600_function_t	keccakf1600_functions_sha3_384[] = {
	KECCAKF1600_API_R_ARG0(sha3_384, init),
	KECCAKF1600_API_R_ARGV(sha3_384, update, 2),
	KECCAKF1600_API_R_ARGV(sha3_384, final, 1),
	{NULL}
};

/* sha3_384_init/0 */

static void
KECCAKF1600_API_EXEC(sha3_384, init)
{
	sha3_384_ctx_t sponge;

	(void) sha3_384_init(sponge);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sponge), sizeof(sponge),
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(sponge), sizeof(sponge));
}

/* sha3_384_update/2 */

typedef struct KECCAKF1600_API_F_ARGV(sha3_384, update) {
	sha3_384_ctx_t	sponge;
	const uint8_t	*in;
	size_t		inlen;
} KECCAKF1600_API_F_ARGV_T(sha3_384, update);

static int
KECCAKF1600_API_INIT(sha3_384, update)
{
	KECCAKF1600_API_F_ARGV_T(sha3_384, update) *argv;
	int skip;
	int type;
	int type_length;
	size_t inlen;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != sizeof(sha3_384_ctx_t)) {
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

	x = (ErlDrvSizeT)(inlen + (sizeof (KECCAKF1600_API_F_ARGV_T(sha3_384, update))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(sha3_384, update) *)(p);
	p += (sizeof (KECCAKF1600_API_F_ARGV_T(sha3_384, update)));
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
KECCAKF1600_API_EXEC(sha3_384, update)
{
	KECCAKF1600_API_F_ARGV_T(sha3_384, update) *argv;
	KECCAKF1600_API_READ_ARGV(sha3_384, update);

	(void) sha3_384_update(argv->sponge, argv->in, argv->inlen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(argv->sponge), sizeof(argv->sponge),
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(argv->sponge), sizeof(argv->sponge));
}

/* sha3_384_final/1 */

typedef struct KECCAKF1600_API_F_ARGV(sha3_384, final) {
	sha3_384_ctx_t	sponge;
} KECCAKF1600_API_F_ARGV_T(sha3_384, final);

static int
KECCAKF1600_API_INIT(sha3_384, final)
{
	KECCAKF1600_API_F_ARGV_T(sha3_384, final) *argv;
	int type;
	int type_length;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != sizeof(sha3_384_ctx_t)) {
		return -1;
	}

	x = (ErlDrvSizeT)((sizeof (KECCAKF1600_API_F_ARGV_T(sha3_384, final))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (KECCAKF1600_API_F_ARGV_T(sha3_384, final) *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sponge), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
KECCAKF1600_API_EXEC(sha3_384, final)
{
	KECCAKF1600_API_F_ARGV_T(sha3_384, final) *argv;
	KECCAKF1600_API_READ_ARGV(sha3_384, final);

	size_t outlen = 48;
	uint8_t out[outlen];

	(void) sha3_384_final(argv->sponge, out, outlen);

	ErlDrvTermData spec[] = {
		KECCAKF1600_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), outlen,
		ERL_DRV_TUPLE, 2
	};

	KECCAKF1600_RESPOND(request, spec, __FILE__, __LINE__);

	(void) decaf_bzero((void *)(argv->sponge), sizeof(argv->sponge));
	(void) decaf_bzero((void *)(out), outlen);
}
