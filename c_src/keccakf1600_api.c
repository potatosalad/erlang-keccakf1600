// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_api.h"
#include "keccakf1600_api_fips202.h"

#define KECCAKF1600_NS(NAMESPACE)	{ #NAMESPACE, keccakf1600_functions_ ## NAMESPACE }

static keccakf1600_namespace_t	keccakf1600_namespaces[] = {
	KECCAKF1600_NS(fips202),
	{NULL}
};

void
init_keccakf1600_api(void)
{
	keccakf1600_namespace_t *n;
	keccakf1600_function_t *f;

	n = NULL;
	f = NULL;

	for (n = keccakf1600_namespaces; n->namespace; n++) {
		n->am_namespace = driver_mk_atom((char *)(n->namespace));
		for (f = n->functions; f->function; f++) {
			f->am_function = driver_mk_atom((char *)(f->function));
		}
	}
}

keccakf1600_function_t *
get_keccakf1600_api(const char *namespace, const char *function)
{
	keccakf1600_namespace_t *n;
	keccakf1600_function_t *f;
	ErlDrvTermData am_namespace;
	ErlDrvTermData am_function;

	n = NULL;
	f = NULL;

	// (void) erl_drv_mutex_lock(keccakf1600_mutex);
	am_namespace = driver_mk_atom((char *)namespace);
	am_function = driver_mk_atom((char *)function);
	// (void) erl_drv_mutex_unlock(keccakf1600_mutex);

	for (n = keccakf1600_namespaces; n->namespace; n++) {
		if (n->am_namespace == am_namespace) {
			for (f = n->functions; f->function; f++) {
				if (f->am_function == am_function) {
					return f;
				}
			}
			return NULL;
		}
	}

	return NULL;
}
