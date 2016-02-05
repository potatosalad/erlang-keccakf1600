// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef KECCAKF1600_NIF_H
#define KECCAKF1600_NIF_H

#include <sys/types.h>
#include <sys/time.h>
#include <erl_nif.h>
#include <string.h>
#include <stdio.h>

#ifndef timersub
#define	timersub(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0)					\
		{							\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while ((vvp)->tv_usec >= 1000000)
#endif

// #define MAX_PER_SLICE	1000000	// 1 MB
#define MAX_PER_SLICE	20000	// 20 KB

ERL_NIF_TERM ATOM_sha3_224;
ERL_NIF_TERM ATOM_sha3_256;
ERL_NIF_TERM ATOM_sha3_384;
ERL_NIF_TERM ATOM_sha3_512;
ERL_NIF_TERM ATOM_shake128;
ERL_NIF_TERM ATOM_shake256;

/*
 * Erlang NIF functions
 */

#define SHA3_NIF_DEF(bits)	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_sha3_##bits##_final_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

#define SHAKE_NIF_DEF(bits)	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_nif_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);	\
	static ERL_NIF_TERM	keccakf1600_shake##bits##_final_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

SHA3_NIF_DEF(224);
SHA3_NIF_DEF(256);
SHA3_NIF_DEF(384);
SHA3_NIF_DEF(512);
SHAKE_NIF_DEF(128);
SHAKE_NIF_DEF(256);

#undef SHA3_NIF_DEF
#undef SHAKE_NIF_DEF

#define SHA3_NIF_FUN(bits)	\
	{"sha3_" #bits, 1, keccakf1600_sha3_##bits##_nif_1},	\
	{"sha3_" #bits "_init", 0, keccakf1600_sha3_##bits##_init_nif_0},	\
	{"sha3_" #bits "_update", 2, keccakf1600_sha3_##bits##_update_nif_2},	\
	{"sha3_" #bits "_final", 1, keccakf1600_sha3_##bits##_final_nif_1}

#define SHAKE_NIF_FUN(bits)	\
	{"shake" #bits, 2, keccakf1600_shake##bits##_nif_2},	\
	{"shake" #bits "_init", 0, keccakf1600_shake##bits##_init_nif_0},	\
	{"shake" #bits "_update", 2, keccakf1600_shake##bits##_update_nif_2},	\
	{"shake" #bits "_final", 2, keccakf1600_shake##bits##_final_nif_2}

static ErlNifFunc	keccakf1600_nif_funcs[] = {
	SHA3_NIF_FUN(224),
	SHA3_NIF_FUN(256),
	SHA3_NIF_FUN(384),
	SHA3_NIF_FUN(512),
	SHAKE_NIF_FUN(128),
	SHAKE_NIF_FUN(256),
};

#undef SHA3_NIF_FUN
#undef SHAKE_NIF_FUN

/*
 * Erlang NIF callbacks
 */
static int		keccakf1600_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int		keccakf1600_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info);

#endif
