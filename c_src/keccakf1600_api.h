// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef KECCAKF1600_API_H
#define KECCAKF1600_API_H

#include "keccakf1600_drv_common.h"
#include "keccakf1600_request.h"

typedef struct keccakf1600_function {
	const char		*function;
	int			arity;
	int			(*init)(keccakf1600_request_t *request, char *buffer, int *index);
	void			(*exec)(keccakf1600_request_t *request);
	ErlDrvTermData		am_function;
} keccakf1600_function_t;

typedef struct keccakf1600_namespace {
	const char		*namespace;
	keccakf1600_function_t	*functions;
	ErlDrvTermData		am_namespace;
} keccakf1600_namespace_t;

extern void			init_keccakf1600_api(void);
extern keccakf1600_function_t	*get_keccakf1600_api(const char *namespace, const char *function);

#define KECCAKF1600_API_F_NS(NAMESPACE)				keccakf1600_api_ ## NAMESPACE
#define KECCAKF1600_API_F_FN(FUNCTION)				_ ## FUNCTION
#define KECCAKF1600_API_F0(A, B)				A ## B
#define KECCAKF1600_API_F1(A, B)				KECCAKF1600_API_F0(A, B)
#define KECCAKF1600_API_F2(NAMESPACE, FUNCTION)			KECCAKF1600_API_F1(KECCAKF1600_API_F_NS(NAMESPACE), KECCAKF1600_API_F_FN(FUNCTION))

#define KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION)		KECCAKF1600_API_F2(NAMESPACE, FUNCTION)
#define KECCAKF1600_API_F_INIT(NAMESPACE, FUNCTION)		KECCAKF1600_API_F1(KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION), _init)
#define KECCAKF1600_API_F_ARGV(NAMESPACE, FUNCTION)		KECCAKF1600_API_F1(KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION), _argv)
#define KECCAKF1600_API_F_ARGV_T(NAMESPACE, FUNCTION)		KECCAKF1600_API_F1(KECCAKF1600_API_F_ARGV(NAMESPACE, FUNCTION), _t)

#define KECCAKF1600_API_EXEC(NAMESPACE, FUNCTION)		KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION) (keccakf1600_request_t *request)
#define KECCAKF1600_API_INIT(NAMESPACE, FUNCTION)		KECCAKF1600_API_F_INIT(NAMESPACE, FUNCTION) (keccakf1600_request_t *request, char *buffer, int *index)

#define KECCAKF1600_API_R_ARG0(NAMESPACE, FUNCTION)		{ #FUNCTION, 0, NULL, KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION) }
#define KECCAKF1600_API_R_ARGV(NAMESPACE, FUNCTION, ARITY)	{ #FUNCTION, ARITY, KECCAKF1600_API_F_INIT(NAMESPACE, FUNCTION), KECCAKF1600_API_F_EXEC(NAMESPACE, FUNCTION) }

#define KECCAKF1600_API_INIT_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (KECCAKF1600_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(driver_alloc((ErlDrvSizeT)(sizeof (KECCAKF1600_API_F_ARGV_T(NAMESPACE, FUNCTION)))));	\
		if (argv == NULL) {	\
			return -1;	\
		}	\
	} while (0)

#define KECCAKF1600_API_READ_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (KECCAKF1600_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(request->argv);	\
	} while (0)

#define KECCAKF1600_RES_TAG(REQUEST)	ERL_DRV_EXT2TERM, (ErlDrvTermData)(REQUEST->tag.buff), REQUEST->tag.index

#define KECCAKF1600_RESPOND(REQUEST, SPEC, FILE, LINE)	\
	do {	\
		if (erl_drv_send_term(REQUEST->port->term_port, REQUEST->caller, SPEC, sizeof(SPEC) / sizeof(SPEC[0])) < 0) {	\
			TRACE_F("error sending term\n", FILE, LINE);	\
		}	\
	} while (0)

#define KECCAKF1600_PROTECT(...)	__VA_ARGS__

#endif
