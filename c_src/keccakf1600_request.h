// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef KECCAKF1600_REQUEST_H
#define KECCAKF1600_REQUEST_H

#include "keccakf1600_drv_common.h"
#include "keccakf1600_port.h"

#define KECCAKF1600_ASYNC_CALL	1

typedef struct keccakf1600_request {
	keccakf1600_port_t	*port;
	ErlDrvTermData		caller;
	void			(*command)(struct keccakf1600_request **, char *, ErlDrvSizeT);
	ei_x_buff		tag;
	ei_term			namespace;
	ei_term			function;
	int			argc;
	void			*argv;
	void			(*execute)(struct keccakf1600_request *);
	int			error;
	ei_x_buff		reply;
} keccakf1600_request_t;

extern keccakf1600_request_t	*keccakf1600_request_alloc(keccakf1600_port_t *port, ErlDrvTermData caller, unsigned int command);
extern void			keccakf1600_request_free(keccakf1600_request_t *request);

#endif