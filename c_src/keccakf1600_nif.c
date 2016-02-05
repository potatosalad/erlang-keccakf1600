// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_nif.h"
#include "shake.h"

/*
 * Erlang NIF functions
 */

#define SHA3_NIF(bits, bytes)	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
	\
		if (argc != 1 || !enif_inspect_binary(env, argv[0], &in)) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		if (in.size <= MAX_PER_SLICE) {	\
			ERL_NIF_TERM out;	\
			unsigned char *buf = enif_make_new_binary(env, bytes, &out);	\
	\
			(void) sha3_##bits##_hash(buf, bytes, in.data, in.size);	\
	\
			return out;	\
		}	\
	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, sizeof(sha3_##bits##_ctx_t));	\
		struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(resource);	\
		(void) sha3_##bits##_init(sponge);	\
	\
		ERL_NIF_TERM newargv[4];	\
	\
		newargv[0] = argv[0];					/* In */	\
		newargv[1] = enif_make_ulong(env, MAX_PER_SLICE);	/* MaxPerSlice */	\
		newargv[2] = enif_make_ulong(env, 0);			/* Offset */	\
		newargv[3] = enif_make_resource(env, resource);		/* Sponge */	\
	\
		(void) enif_release_resource(resource);	\
	\
		return enif_schedule_nif(env, "sha3_" #bits, 0, keccakf1600_sha3_##bits##_nif_4, 4, newargv);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
		unsigned long max_per_slice;	\
		unsigned long offset;	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource;	\
	\
		if (argc != 4 || !enif_inspect_binary(env, argv[0], &in)	\
				|| !enif_get_ulong(env, argv[1], &max_per_slice)	\
				|| !enif_get_ulong(env, argv[2], &offset)	\
				|| !enif_get_resource(env, argv[3], resource_type, &resource)) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(resource);	\
	\
		struct timeval start;	\
		struct timeval stop;	\
		struct timeval slice;	\
		unsigned long end;	\
		unsigned long i;	\
		int percent;	\
		int total = 0;	\
	\
		end = offset + max_per_slice;	\
	\
		if (end > in.size) {	\
			end = in.size;	\
		}	\
	\
		i = offset;	\
	\
		while (i < in.size) {	\
			(void) gettimeofday(&start, NULL);	\
			(void) sha3_##bits##_update(sponge, (uint8_t *)(in.data) + i, end - i);	\
			i = end;	\
			if (i == in.size) {	\
				break;	\
			}	\
			(void) gettimeofday(&stop, NULL);	\
			/* determine how much of the timeslice was used */	\
			timersub(&stop, &start, &slice);	\
			percent = (int)((slice.tv_sec*1000000+slice.tv_usec)/10);	\
			total += percent;	\
			if (percent > 100) {	\
				percent = 100;	\
			} else if (percent == 0) {	\
				percent = 1;	\
			}	\
			if (enif_consume_timeslice(env, percent)) {	\
				/* the timeslice has been used up, so adjust our max_per_slice byte count based on the processing we've done, then reschedule to run again */	\
				max_per_slice = i - offset;	\
				if (total > 100) {	\
					int m = (int)(total/100);	\
					if (m == 1) {	\
						max_per_slice -= (unsigned long)(max_per_slice*(total-100)/100);	\
					} else {	\
						max_per_slice = (unsigned long)(max_per_slice/m);	\
					}	\
				}	\
				ERL_NIF_TERM newargv[4];	\
				newargv[0] = argv[0];					/* In */	\
				newargv[1] = enif_make_ulong(env, max_per_slice);	/* MaxPerSlice */	\
				newargv[2] = enif_make_ulong(env, i);			/* Offset */	\
				newargv[3] = argv[3];					/* Sponge */	\
				return enif_schedule_nif(env, "sha3_" #bits, 0, keccakf1600_sha3_##bits##_nif_4, argc, newargv);	\
			}	\
			end += max_per_slice;	\
			if (end > in.size) {	\
				end = in.size;	\
			}	\
		}	\
	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, bytes, &out);	\
	\
		(void) sha3_##bits##_final(sponge, buf, bytes);	\
		(void) sha3_##bits##_destroy(sponge);	\
	\
		return out;	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		if (argc != 0) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, sizeof(sha3_##bits##_ctx_t), &out);	\
		struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(buf);	\
	\
		(void) sha3_##bits##_init(sponge);	\
	\
		return enif_make_tuple2(env, ATOM_sha3_##bits, out);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		int arity;	\
		const ERL_NIF_TERM *state;	\
		ErlNifBinary state_bin;	\
		ErlNifBinary in;	\
		\
		if (argc != 2 || !enif_get_tuple(env, argv[0], &arity, &state)	\
			|| arity != 2	\
			|| state[0] != ATOM_sha3_##bits	\
			|| !enif_inspect_binary(env, state[1], &state_bin)	\
			|| state_bin.size != sizeof(sha3_##bits##_ctx_t)	\
			|| !enif_inspect_binary(env, argv[1], &in)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		if (in.size <= MAX_PER_SLICE) {	\
			ERL_NIF_TERM out;	\
			unsigned char *buf = enif_make_new_binary(env, state_bin.size, &out);	\
			(void) memcpy(buf, state_bin.data, state_bin.size);	\
			struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(buf);	\
		\
			(void) sha3_##bits##_update(sponge, in.data, in.size);	\
		\
			return enif_make_tuple2(env, ATOM_sha3_##bits, out);	\
		}	\
		\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, state_bin.size);	\
		(void) memcpy(resource, state_bin.data, state_bin.size);	\
		\
		ERL_NIF_TERM newargv[4];	\
		\
		newargv[0] = argv[1];					/* In */	\
		newargv[1] = enif_make_ulong(env, MAX_PER_SLICE);	/* MaxPerSlice */	\
		newargv[2] = enif_make_ulong(env, 0);			/* Offset */	\
		newargv[3] = enif_make_resource(env, resource);		/* Sponge */	\
		\
		(void) enif_release_resource(resource);	\
		\
		return enif_schedule_nif(env, "sha3_" #bits "_update", 0, keccakf1600_sha3_##bits##_update_nif_4, 4, newargv);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
		unsigned long max_per_slice;	\
		unsigned long offset;	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource;	\
		\
		if (argc != 4 || !enif_inspect_binary(env, argv[0], &in)	\
				|| !enif_get_ulong(env, argv[1], &max_per_slice)	\
				|| !enif_get_ulong(env, argv[2], &offset)	\
				|| !enif_get_resource(env, argv[3], resource_type, &resource)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(resource);	\
		\
		struct timeval start;	\
		struct timeval stop;	\
		struct timeval slice;	\
		unsigned long end;	\
		unsigned long i;	\
		int percent;	\
		int total = 0;	\
		\
		end = offset + max_per_slice;	\
		\
		if (end > in.size) {	\
			end = in.size;	\
		}	\
		\
		i = offset;	\
		\
		while (i < in.size) {	\
			(void) gettimeofday(&start, NULL);	\
			(void) sha3_##bits##_update(sponge, (uint8_t *)(in.data) + i, end - i);	\
			i = end;	\
			if (i == in.size) {	\
				break;	\
			}	\
			(void) gettimeofday(&stop, NULL);	\
			/* determine how much of the timeslice was used */	\
			timersub(&stop, &start, &slice);	\
			percent = (int)((slice.tv_sec*1000000+slice.tv_usec)/10);	\
			total += percent;	\
			if (percent > 100) {	\
				percent = 100;	\
			} else if (percent == 0) {	\
				percent = 1;	\
			}	\
			if (enif_consume_timeslice(env, percent)) {	\
				/* the timeslice has been used up, so adjust our max_per_slice byte count based on the processing we've done, then reschedule to run again */	\
				max_per_slice = i - offset;	\
				if (total > 100) {	\
					int m = (int)(total/100);	\
					if (m == 1) {	\
						max_per_slice -= (unsigned long)(max_per_slice*(total-100)/100);	\
					} else {	\
						max_per_slice = (unsigned long)(max_per_slice/m);	\
					}	\
				}	\
				ERL_NIF_TERM newargv[4];	\
				newargv[0] = argv[0];					/* In */	\
				newargv[1] = enif_make_ulong(env, max_per_slice);	/* MaxPerSlice */	\
				newargv[2] = enif_make_ulong(env, i);			/* Offset */	\
				newargv[3] = argv[3];					/* Sponge */	\
				return enif_schedule_nif(env, "sha3_" #bits "_update", 0, keccakf1600_sha3_##bits##_update_nif_4, argc, newargv);	\
			}	\
			end += max_per_slice;	\
			if (end > in.size) {	\
				end = in.size;	\
			}	\
		}	\
		\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, sizeof(sha3_##bits##_ctx_t), &out);	\
		(void) memcpy(buf, resource, sizeof(sha3_##bits##_ctx_t));	\
		\
		return enif_make_tuple2(env, ATOM_sha3_##bits, out);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_sha3_##bits##_final_nif_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		int arity;	\
		const ERL_NIF_TERM *state;	\
		ErlNifBinary state_bin;	\
		\
		if (argc != 1 || !enif_get_tuple(env, argv[0], &arity, &state)	\
			|| arity != 2	\
			|| state[0] != ATOM_sha3_##bits	\
			|| !enif_inspect_binary(env, state[1], &state_bin)	\
			|| state_bin.size != sizeof(sha3_##bits##_ctx_t)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, state_bin.size);	\
		(void) memcpy(resource, state_bin.data, state_bin.size);	\
		struct sha3_##bits##_ctx_s *sponge = (struct sha3_##bits##_ctx_s *)(resource);	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, bytes, &out);	\
		\
		(void) sha3_##bits##_final(sponge, buf, bytes);	\
		(void) sha3_##bits##_destroy(sponge);	\
		(void) enif_release_resource(resource);	\
		\
		return out;	\
	}

#define SHAKE_NIF(bits)	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
		unsigned long outlen;	\
	\
		if (argc != 2 || !enif_inspect_binary(env, argv[0], &in)	\
				|| !enif_get_ulong(env, argv[1], &outlen)) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		if (in.size <= MAX_PER_SLICE) {	\
			ERL_NIF_TERM out;	\
			unsigned char *buf = enif_make_new_binary(env, outlen, &out);	\
	\
			(void) shake##bits##_hash(buf, outlen, in.data, in.size);	\
	\
			return out;	\
		}	\
	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, sizeof(shake##bits##_ctx_t));	\
		struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(resource);	\
		(void) shake##bits##_init(sponge);	\
	\
		ERL_NIF_TERM newargv[5];	\
	\
		newargv[0] = argv[0];					/* In */	\
		newargv[1] = argv[1];					/* Outlen */	\
		newargv[2] = enif_make_ulong(env, MAX_PER_SLICE);	/* MaxPerSlice */	\
		newargv[3] = enif_make_ulong(env, 0);			/* Offset */	\
		newargv[4] = enif_make_resource(env, resource);		/* Sponge */	\
	\
		(void) enif_release_resource(resource);	\
	\
		return enif_schedule_nif(env, "shake" #bits, 0, keccakf1600_shake##bits##_nif_5, 5, newargv);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_nif_5(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
		unsigned long outlen;	\
		unsigned long max_per_slice;	\
		unsigned long offset;	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource;	\
	\
		if (argc != 5 || !enif_inspect_binary(env, argv[0], &in)	\
				|| !enif_get_ulong(env, argv[1], &outlen)	\
				|| !enif_get_ulong(env, argv[2], &max_per_slice)	\
				|| !enif_get_ulong(env, argv[3], &offset)	\
				|| !enif_get_resource(env, argv[4], resource_type, &resource)) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(resource);	\
	\
		struct timeval start;	\
		struct timeval stop;	\
		struct timeval slice;	\
		unsigned long end;	\
		unsigned long i;	\
		int percent;	\
		int total = 0;	\
	\
		end = offset + max_per_slice;	\
	\
		if (end > in.size) {	\
			end = in.size;	\
		}	\
	\
		i = offset;	\
	\
		while (i < in.size) {	\
			(void) gettimeofday(&start, NULL);	\
			(void) shake##bits##_update(sponge, (uint8_t *)(in.data) + i, end - i);	\
			i = end;	\
			if (i == in.size) {	\
				break;	\
			}	\
			(void) gettimeofday(&stop, NULL);	\
			/* determine how much of the timeslice was used */	\
			timersub(&stop, &start, &slice);	\
			percent = (int)((slice.tv_sec*1000000+slice.tv_usec)/10);	\
			total += percent;	\
			if (percent > 100) {	\
				percent = 100;	\
			} else if (percent == 0) {	\
				percent = 1;	\
			}	\
			if (enif_consume_timeslice(env, percent)) {	\
				/* the timeslice has been used up, so adjust our max_per_slice byte count based on the processing we've done, then reschedule to run again */	\
				max_per_slice = i - offset;	\
				if (total > 100) {	\
					int m = (int)(total/100);	\
					if (m == 1) {	\
						max_per_slice -= (unsigned long)(max_per_slice*(total-100)/100);	\
					} else {	\
						max_per_slice = (unsigned long)(max_per_slice/m);	\
					}	\
				}	\
				ERL_NIF_TERM newargv[5];	\
				newargv[0] = argv[0];					/* In */	\
				newargv[1] = argv[1];					/* Outlen */	\
				newargv[2] = enif_make_ulong(env, max_per_slice);	/* MaxPerSlice */	\
				newargv[3] = enif_make_ulong(env, i);			/* Offset */	\
				newargv[4] = argv[4];					/* Sponge */	\
				return enif_schedule_nif(env, "shake" #bits, 0, keccakf1600_shake##bits##_nif_5, argc, newargv);	\
			}	\
			end += max_per_slice;	\
			if (end > in.size) {	\
				end = in.size;	\
			}	\
		}	\
	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, outlen, &out);	\
	\
		(void) shake##bits##_final(sponge, buf, outlen);	\
		(void) shake##bits##_destroy(sponge);	\
	\
		return out;	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_init_nif_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		if (argc != 0) {	\
			return enif_make_badarg(env);	\
		}	\
	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, sizeof(shake##bits##_ctx_t), &out);	\
		struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(buf);	\
	\
		(void) shake##bits##_init(sponge);	\
	\
		return enif_make_tuple2(env, ATOM_shake##bits, out);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_update_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		int arity;	\
		const ERL_NIF_TERM *state;	\
		ErlNifBinary state_bin;	\
		ErlNifBinary in;	\
		\
		if (argc != 2 || !enif_get_tuple(env, argv[0], &arity, &state)	\
			|| arity != 2	\
			|| state[0] != ATOM_shake##bits	\
			|| !enif_inspect_binary(env, state[1], &state_bin)	\
			|| state_bin.size != sizeof(shake##bits##_ctx_t)	\
			|| !enif_inspect_binary(env, argv[1], &in)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		if (in.size <= MAX_PER_SLICE) {	\
			ERL_NIF_TERM out;	\
			unsigned char *buf = enif_make_new_binary(env, state_bin.size, &out);	\
			(void) memcpy(buf, state_bin.data, state_bin.size);	\
			struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(buf);	\
		\
			(void) shake##bits##_update(sponge, in.data, in.size);	\
		\
			return enif_make_tuple2(env, ATOM_shake##bits, out);	\
		}	\
		\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, state_bin.size);	\
		(void) memcpy(resource, state_bin.data, state_bin.size);	\
		\
		ERL_NIF_TERM newargv[4];	\
		\
		newargv[0] = argv[1];					/* In */	\
		newargv[1] = enif_make_ulong(env, MAX_PER_SLICE);	/* MaxPerSlice */	\
		newargv[2] = enif_make_ulong(env, 0);			/* Offset */	\
		newargv[3] = enif_make_resource(env, resource);		/* Sponge */	\
		\
		(void) enif_release_resource(resource);	\
		\
		return enif_schedule_nif(env, "shake" #bits "_update", 0, keccakf1600_shake##bits##_update_nif_4, 4, newargv);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_update_nif_4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		ErlNifBinary in;	\
		unsigned long max_per_slice;	\
		unsigned long offset;	\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource;	\
		\
		if (argc != 4 || !enif_inspect_binary(env, argv[0], &in)	\
				|| !enif_get_ulong(env, argv[1], &max_per_slice)	\
				|| !enif_get_ulong(env, argv[2], &offset)	\
				|| !enif_get_resource(env, argv[3], resource_type, &resource)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(resource);	\
		\
		struct timeval start;	\
		struct timeval stop;	\
		struct timeval slice;	\
		unsigned long end;	\
		unsigned long i;	\
		int percent;	\
		int total = 0;	\
		\
		end = offset + max_per_slice;	\
		\
		if (end > in.size) {	\
			end = in.size;	\
		}	\
		\
		i = offset;	\
		\
		while (i < in.size) {	\
			(void) gettimeofday(&start, NULL);	\
			(void) shake##bits##_update(sponge, (uint8_t *)(in.data) + i, end - i);	\
			i = end;	\
			if (i == in.size) {	\
				break;	\
			}	\
			(void) gettimeofday(&stop, NULL);	\
			/* determine how much of the timeslice was used */	\
			timersub(&stop, &start, &slice);	\
			percent = (int)((slice.tv_sec*1000000+slice.tv_usec)/10);	\
			total += percent;	\
			if (percent > 100) {	\
				percent = 100;	\
			} else if (percent == 0) {	\
				percent = 1;	\
			}	\
			if (enif_consume_timeslice(env, percent)) {	\
				/* the timeslice has been used up, so adjust our max_per_slice byte count based on the processing we've done, then reschedule to run again */	\
				max_per_slice = i - offset;	\
				if (total > 100) {	\
					int m = (int)(total/100);	\
					if (m == 1) {	\
						max_per_slice -= (unsigned long)(max_per_slice*(total-100)/100);	\
					} else {	\
						max_per_slice = (unsigned long)(max_per_slice/m);	\
					}	\
				}	\
				ERL_NIF_TERM newargv[4];	\
				newargv[0] = argv[0];					/* In */	\
				newargv[1] = enif_make_ulong(env, max_per_slice);	/* MaxPerSlice */	\
				newargv[2] = enif_make_ulong(env, i);			/* Offset */	\
				newargv[3] = argv[3];					/* Sponge */	\
				return enif_schedule_nif(env, "shake" #bits "_update", 0, keccakf1600_shake##bits##_update_nif_4, argc, newargv);	\
			}	\
			end += max_per_slice;	\
			if (end > in.size) {	\
				end = in.size;	\
			}	\
		}	\
		\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, sizeof(shake##bits##_ctx_t), &out);	\
		(void) memcpy(buf, resource, sizeof(shake##bits##_ctx_t));	\
		\
		return enif_make_tuple2(env, ATOM_shake##bits, out);	\
	}	\
	\
	static ERL_NIF_TERM	\
	keccakf1600_shake##bits##_final_nif_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])	\
	{	\
		int arity;	\
		const ERL_NIF_TERM *state;	\
		ErlNifBinary state_bin;	\
		unsigned long outlen;	\
		\
		if (argc != 2 || !enif_get_tuple(env, argv[0], &arity, &state)	\
			|| arity != 2	\
			|| state[0] != ATOM_shake##bits	\
			|| !enif_inspect_binary(env, state[1], &state_bin)	\
			|| state_bin.size != sizeof(shake##bits##_ctx_t)	\
			|| !enif_get_ulong(env, argv[1], &outlen)) {	\
			return enif_make_badarg(env);	\
		}	\
		\
		ErlNifResourceType *resource_type = (ErlNifResourceType *)(enif_priv_data(env));	\
		void *resource = enif_alloc_resource(resource_type, state_bin.size);	\
		(void) memcpy(resource, state_bin.data, state_bin.size);	\
		struct shake##bits##_ctx_s *sponge = (struct shake##bits##_ctx_s *)(resource);	\
		ERL_NIF_TERM out;	\
		unsigned char *buf = enif_make_new_binary(env, outlen, &out);	\
		\
		(void) shake##bits##_final(sponge, buf, outlen);	\
		(void) shake##bits##_destroy(sponge);	\
		(void) enif_release_resource(resource);	\
		\
		return out;	\
	}

SHA3_NIF(224, 28);
SHA3_NIF(256, 32);
SHA3_NIF(384, 48);
SHA3_NIF(512, 64);
SHAKE_NIF(128);
SHAKE_NIF(256);

#undef SHA3_NIF
#undef SHAKE_NIF

/*
 * Erlang NIF callbacks
 */
static int
keccakf1600_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	/* Initialize common atoms */
	#define ATOM(Id, Value) { Id = enif_make_atom(env, Value); }
		ATOM(ATOM_sha3_224, "sha3_224");
		ATOM(ATOM_sha3_256, "sha3_256");
		ATOM(ATOM_sha3_384, "sha3_384");
		ATOM(ATOM_sha3_512, "sha3_512");
		ATOM(ATOM_shake128, "shake128");
		ATOM(ATOM_shake256, "shake256");
	#undef ATOM

	*priv_data = enif_open_resource_type(env, NULL, "keccakf1600_sponge", NULL, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
	return 0;
}

static int
keccakf1600_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
	*priv_data = enif_open_resource_type(env, NULL, "keccakf1600_sponge", NULL, ERL_NIF_RT_TAKEOVER, NULL);
	return 0;
}

ERL_NIF_INIT(keccakf1600, keccakf1600_nif_funcs, keccakf1600_nif_load, NULL, keccakf1600_nif_upgrade, NULL);
