// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef KECCAKF1600_PORT_H
#define KECCAKF1600_PORT_H

#include "keccakf1600_drv_common.h"

typedef struct keccakf1600_port {
	ErlDrvPort	drv_port;
	ErlDrvTermData	term_port;
} keccakf1600_port_t;

extern keccakf1600_port_t	*keccakf1600_port_alloc(ErlDrvPort drv_port);
extern void			keccakf1600_port_free(keccakf1600_port_t *port);

#endif