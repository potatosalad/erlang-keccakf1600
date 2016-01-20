// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_port.h"

keccakf1600_port_t *
keccakf1600_port_alloc(ErlDrvPort drv_port)
{
	ErlDrvSizeT x;
	void *p;
	keccakf1600_port_t *port;

	x = (ErlDrvSizeT)((sizeof (keccakf1600_port_t)));
	p = driver_alloc(x);

	if (p == NULL) {
		return NULL;
	}

	port = (keccakf1600_port_t *)(p);
	port->drv_port = drv_port;
	port->term_port = driver_mk_port(drv_port);

	return port;
}

void
keccakf1600_port_free(keccakf1600_port_t *port)
{
	if (port == NULL) {
		return;
	}
	(void) driver_free(port);
	port = NULL;
}
