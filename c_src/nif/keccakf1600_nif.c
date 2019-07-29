// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "keccakf1600_nif.h"
#include "xnif_env.h"
#include "xnif_slice.h"

#include <unistd.h>

// ErlNifMutex *keccakf1600_nif_mutex = NULL;

static ERL_NIF_TERM ATOM_badarg;
static ERL_NIF_TERM ATOM_error;
static ERL_NIF_TERM ATOM_false;
static ERL_NIF_TERM ATOM_nil;
static ERL_NIF_TERM ATOM_no_context;
static ERL_NIF_TERM ATOM_ok;
static ERL_NIF_TERM ATOM_sha3_224;
static ERL_NIF_TERM ATOM_sha3_256;
static ERL_NIF_TERM ATOM_sha3_384;
static ERL_NIF_TERM ATOM_sha3_512;
static ERL_NIF_TERM ATOM_shake128;
static ERL_NIF_TERM ATOM_shake256;
static ERL_NIF_TERM ATOM_true;
static ERL_NIF_TERM ATOM_undefined;

/* Static Functions (Declarations) */

#include "decaf-shake.h"
#include "decaf-spongerng.h"

static keccakf1600_nif_priv_data_t *keccakf1600_nif_priv_data(ErlNifEnv *env);

inline keccakf1600_nif_priv_data_t *
keccakf1600_nif_priv_data(ErlNifEnv *env)
{
    keccakf1600_nif_priv_data_t *pd = (void *)xnif_env_priv_data(env);
    if (pd == NULL) {
        return NULL;
    }
    if (pd->version != keccakf1600_nif_priv_data_version) {
        return NULL;
    }
    return pd;
}

#define DEFINE_RESOURCE_TYPE(Id, Type, Dtor)                                                                                       \
    static Type *keccakf1600_nif_alloc_##Id(ErlNifEnv *env);                                                                       \
    static int keccakf1600_nif_get_##Id(ErlNifEnv *env, ERL_NIF_TERM term, Type **ctx);                                            \
    static void keccakf1600_nif_dtor_##Id(ErlNifEnv *env, void *obj);                                                              \
                                                                                                                                   \
    inline int keccakf1600_nif_get_##Id(ErlNifEnv *env, ERL_NIF_TERM term, Type **ctx)                                             \
    {                                                                                                                              \
        keccakf1600_nif_priv_data_t *pd = keccakf1600_nif_priv_data(env);                                                          \
        if (pd == NULL) {                                                                                                          \
            return 0;                                                                                                              \
        }                                                                                                                          \
        if (pd->Id == NULL) {                                                                                                      \
            return 0;                                                                                                              \
        }                                                                                                                          \
        if (!enif_get_resource(env, term, pd->Id, (void **)ctx)) {                                                                 \
            return 0;                                                                                                              \
        }                                                                                                                          \
        return 1;                                                                                                                  \
    }                                                                                                                              \
                                                                                                                                   \
    inline Type *keccakf1600_nif_alloc_##Id(ErlNifEnv *env)                                                                        \
    {                                                                                                                              \
        Type *ctx = NULL;                                                                                                          \
        keccakf1600_nif_priv_data_t *pd = keccakf1600_nif_priv_data(env);                                                          \
        if (pd == NULL) {                                                                                                          \
            return NULL;                                                                                                           \
        }                                                                                                                          \
        if (pd->Id == NULL) {                                                                                                      \
            return NULL;                                                                                                           \
        }                                                                                                                          \
        ctx = (void *)enif_alloc_resource(pd->Id, sizeof(Type));                                                                   \
        if (ctx == NULL) {                                                                                                         \
            return NULL;                                                                                                           \
        }                                                                                                                          \
        return ctx;                                                                                                                \
    }                                                                                                                              \
                                                                                                                                   \
    static void keccakf1600_nif_dtor_##Id(ErlNifEnv *env, void *obj)                                                               \
    {                                                                                                                              \
        Type *ctx = (void *)obj;                                                                                                   \
        if (ctx == NULL) {                                                                                                         \
            return;                                                                                                                \
        }                                                                                                                          \
        XNIF_TRACE_F("keccakf1600_nif_dtor_" #Id ":%s:%d\n", __FILE__, __LINE__);                                                  \
        (void)Dtor(ctx);                                                                                                           \
        return;                                                                                                                    \
    }
DEFINE_RESOURCE_TYPE(sha3_224_ctx, struct decaf_sha3_224_ctx_s, decaf_sha3_224_destroy)
DEFINE_RESOURCE_TYPE(sha3_256_ctx, struct decaf_sha3_256_ctx_s, decaf_sha3_256_destroy)
DEFINE_RESOURCE_TYPE(sha3_384_ctx, struct decaf_sha3_384_ctx_s, decaf_sha3_384_destroy)
DEFINE_RESOURCE_TYPE(sha3_512_ctx, struct decaf_sha3_512_ctx_s, decaf_sha3_512_destroy)
DEFINE_RESOURCE_TYPE(shake128_ctx, struct decaf_shake128_ctx_s, decaf_shake128_destroy)
DEFINE_RESOURCE_TYPE(shake256_ctx, struct decaf_shake256_ctx_s, decaf_shake256_destroy)
DEFINE_RESOURCE_TYPE(spongerng_ctx, decaf_keccak_prng_s, decaf_spongerng_destroy)
#undef DEFINE_RESOURCE_TYPE

/* NIF Function Declarations */

/* decaf/shake.h */
#define SHA3_DECLARATION(bits)                                                                                                     \
    static ERL_NIF_TERM keccakf1600_nif_sha3_##bits##_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                      \
    static ERL_NIF_TERM keccakf1600_nif_sha3_##bits##_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                 \
    static ERL_NIF_TERM keccakf1600_nif_sha3_##bits##_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);               \
    static ERL_NIF_TERM keccakf1600_nif_sha3_##bits##_final_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
SHA3_DECLARATION(224)
SHA3_DECLARATION(256)
SHA3_DECLARATION(384)
SHA3_DECLARATION(512)
#undef SHA3_DECLARATION
#define SHAKE_DECLARATION(bits)                                                                                                    \
    static ERL_NIF_TERM keccakf1600_nif_shake##bits##_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                      \
    static ERL_NIF_TERM keccakf1600_nif_shake##bits##_init_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);                 \
    static ERL_NIF_TERM keccakf1600_nif_shake##bits##_update_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);               \
    static ERL_NIF_TERM keccakf1600_nif_shake##bits##_final_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
SHAKE_DECLARATION(128)
SHAKE_DECLARATION(256)
#undef SHAKE_DECLARATION
/* decaf/spongerng.h */
static ERL_NIF_TERM keccakf1600_nif_spongerng_init_from_buffer_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM keccakf1600_nif_spongerng_init_from_file_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM keccakf1600_nif_spongerng_init_from_dev_urandom_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM keccakf1600_nif_spongerng_next_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM keccakf1600_nif_spongerng_stir_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/* NIF Function Definitions */

/* decaf/shake.h */
#include "impl/sha3.c.h"
#include "impl/shake.c.h"
/* decaf/spongerng.h */
#include "impl/spongerng.c.h"

/* NIF Callbacks */

static ErlNifFunc keccakf1600_nif_funcs[] = {
/* decaf/shake.h */
// clang-format off
#define SHA3_NIF_FUNC(bits)                                                                                                        \
    {"sha3_" #bits, 2, keccakf1600_nif_sha3_##bits##_2, 0},                                                                           \
    {"sha3_" #bits "_init", 0, keccakf1600_nif_sha3_##bits##_init_0, 0},                                                              \
    {"sha3_" #bits "_update", 2, keccakf1600_nif_sha3_##bits##_update_2, 0},                                                          \
    {"sha3_" #bits "_final", 2, keccakf1600_nif_sha3_##bits##_final_2, 0}
    SHA3_NIF_FUNC(224),
    SHA3_NIF_FUNC(256),
    SHA3_NIF_FUNC(384),
    SHA3_NIF_FUNC(512),
#undef SHA3_NIF_FUNC
#define SHAKE_FUNC(bits)                                                                                                           \
    {"shake" #bits, 2, keccakf1600_nif_shake##bits##_2, 0},                                                                           \
    {"shake" #bits "_init", 0, keccakf1600_nif_shake##bits##_init_0, 0},                                                              \
    {"shake" #bits "_update", 2, keccakf1600_nif_shake##bits##_update_2, 0},                                                          \
    {"shake" #bits "_final", 2, keccakf1600_nif_shake##bits##_final_2, 0}
    SHAKE_FUNC(128),
    SHAKE_FUNC(256),
#undef SHAKE_FUNC
    // clang-format on
    /* decaf/spongerng.h */
    {"spongerng_init_from_buffer", 2, keccakf1600_nif_spongerng_init_from_buffer_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"spongerng_init_from_file", 3, keccakf1600_nif_spongerng_init_from_file_3, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"spongerng_init_from_dev_urandom", 0, keccakf1600_nif_spongerng_init_from_dev_urandom_0, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"spongerng_next", 2, keccakf1600_nif_spongerng_next_2, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"spongerng_stir", 2, keccakf1600_nif_spongerng_stir_2, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

static void keccakf1600_nif_make_atoms(ErlNifEnv *env);
static int keccakf1600_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int keccakf1600_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void keccakf1600_nif_unload(ErlNifEnv *env, void *priv_data);
static int keccakf1600_xnif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int keccakf1600_xnif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void keccakf1600_xnif_unload(ErlNifEnv *env, void *priv_data);

static void
keccakf1600_nif_make_atoms(ErlNifEnv *env)
{
#define ATOM(Id, Value)                                                                                                            \
    {                                                                                                                              \
        Id = enif_make_atom(env, Value);                                                                                           \
    }
    ATOM(ATOM_badarg, "badarg");
    ATOM(ATOM_error, "error");
    ATOM(ATOM_false, "false");
    ATOM(ATOM_nil, "nil");
    ATOM(ATOM_no_context, "no_context");
    ATOM(ATOM_ok, "ok");
    ATOM(ATOM_sha3_224, "sha3_224");
    ATOM(ATOM_sha3_256, "sha3_256");
    ATOM(ATOM_sha3_384, "sha3_384");
    ATOM(ATOM_sha3_512, "sha3_512");
    ATOM(ATOM_shake128, "shake128");
    ATOM(ATOM_shake256, "shake256");
    ATOM(ATOM_true, "true");
    ATOM(ATOM_undefined, "undefined");
#undef ATOM
}

static int
keccakf1600_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;
    xnif_env_config_t xnif_config = {(XNIF_FEATURE_SLICE), keccakf1600_xnif_load, keccakf1600_xnif_upgrade,
                                     keccakf1600_xnif_unload};
    retval = xnif_env_load(env, (xnif_env_t **)priv_data, load_info, &xnif_config);
    return retval;
}

static int
keccakf1600_nif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    int retval = 0;
    xnif_env_config_t xnif_config = {(XNIF_FEATURE_SLICE), keccakf1600_xnif_load, keccakf1600_xnif_upgrade,
                                     keccakf1600_xnif_unload};
    retval = xnif_env_upgrade(env, (xnif_env_t **)new_priv_data, (xnif_env_t **)old_priv_data, load_info, &xnif_config);
    return retval;
}

static void
keccakf1600_nif_unload(ErlNifEnv *env, void *priv_data)
{
    (void)xnif_env_unload(env, (xnif_env_t *)priv_data);
    return;
}

static int
keccakf1600_xnif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    keccakf1600_nif_priv_data_t *pd = (void *)enif_alloc(sizeof(keccakf1600_nif_priv_data_t));
    if (pd == NULL) {
        return -1;
    }
    pd->version = keccakf1600_nif_priv_data_version;
#define OPEN_RESOURCE_TYPE(Id)                                                                                                     \
    pd->Id = enif_open_resource_type(env, NULL, #Id, keccakf1600_nif_dtor_##Id, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);    \
    if (pd->Id == NULL) {                                                                                                          \
        (void)enif_free((void *)pd);                                                                                               \
        return -1;                                                                                                                 \
    }
    OPEN_RESOURCE_TYPE(sha3_224_ctx);
    OPEN_RESOURCE_TYPE(sha3_256_ctx);
    OPEN_RESOURCE_TYPE(sha3_384_ctx);
    OPEN_RESOURCE_TYPE(sha3_512_ctx);
    OPEN_RESOURCE_TYPE(shake128_ctx);
    OPEN_RESOURCE_TYPE(shake256_ctx);
    OPEN_RESOURCE_TYPE(spongerng_ctx);
#undef OPEN_RESOURCE_TYPE
    /* Initialize common atoms */
    (void)keccakf1600_nif_make_atoms(env);
    *priv_data = (void *)(pd);
    return 0;
}

static int
keccakf1600_xnif_upgrade(ErlNifEnv *env, void **new_priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    (void)old_priv_data;
    return keccakf1600_xnif_load(env, new_priv_data, load_info);
}

static void
keccakf1600_xnif_unload(ErlNifEnv *env, void *priv_data)
{
    if (priv_data != NULL) {
        (void)enif_free(priv_data);
    }
    return;
}

ERL_NIF_INIT(keccakf1600_nif, keccakf1600_nif_funcs, keccakf1600_nif_load, NULL, keccakf1600_nif_upgrade, keccakf1600_nif_unload);
