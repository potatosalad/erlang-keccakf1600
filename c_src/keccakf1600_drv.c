// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "keccakf1600_drv.h"
#include "keccakf1600_port.h"
#include "keccakf1600_request.h"
#include "keccakf1600_api.h"

#define INIT_ATOM(NAME)		keccakf1600_drv->am_ ## NAME = driver_mk_atom(#NAME)

/*
 * Erlang DRV functions
 */
static int
keccakf1600_drv_init(void)
{
	TRACE_F("keccakf1600_drv_init:%s:%d\n", __FILE__, __LINE__);

	if (keccakf1600_mutex == NULL) {
		keccakf1600_mutex = erl_drv_mutex_create("keccakf1600");
		if (keccakf1600_mutex == NULL) {
			return -1;
		}
	}

	(void) erl_drv_mutex_lock(keccakf1600_mutex);

	if (keccakf1600_drv == NULL) {
		keccakf1600_drv = (keccakf1600_drv_term_data_t *)(driver_alloc(sizeof (keccakf1600_drv_term_data_t)));
		if (keccakf1600_drv == NULL) {
			(void) erl_drv_mutex_unlock(keccakf1600_mutex);
			return -1;
		}
		INIT_ATOM(ok);
		INIT_ATOM(error);
		INIT_ATOM(false);
		INIT_ATOM(true);
		INIT_ATOM(undefined);
	}

	(void) init_keccakf1600_api();

	(void) erl_drv_mutex_unlock(keccakf1600_mutex);

	return 0;
}

static ErlDrvData
keccakf1600_drv_start(ErlDrvPort drv_port, char *command)
{
	keccakf1600_port_t *port;

	(void) command; // Unused

	TRACE_F("keccakf1600_drv_start:%s:%d\n", __FILE__, __LINE__);

	port = keccakf1600_port_alloc(drv_port);

	if (port == NULL) {
		return ERL_DRV_ERROR_GENERAL;
	}

	return (ErlDrvData)(port);
}

static void
keccakf1600_drv_stop(ErlDrvData drv_data)
{
	keccakf1600_port_t *port;

	TRACE_F("keccakf1600_drv_stop:%s:%d\n", __FILE__, __LINE__);

	port = (keccakf1600_port_t *)(drv_data);

	(void) keccakf1600_port_free(port);
}

static void
keccakf1600_drv_finish(void)
{
	TRACE_F("keccakf1600_drv_finish:%s:%d\n", __FILE__, __LINE__);
	if (keccakf1600_mutex != NULL) {
		(void) erl_drv_mutex_lock(keccakf1600_mutex);
	}
	if (keccakf1600_drv != NULL) {
		(void) driver_free(keccakf1600_drv);
		keccakf1600_drv = NULL;
	}
	if (keccakf1600_mutex != NULL) {
		(void) erl_drv_mutex_unlock(keccakf1600_mutex);
		(void) erl_drv_mutex_destroy(keccakf1600_mutex);
		keccakf1600_mutex = NULL;
	}
}

static ErlDrvSSizeT
keccakf1600_drv_call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len,
		char **rbuf, ErlDrvSizeT rlen, unsigned int *flags)
{
	keccakf1600_port_t *port;
	ErlDrvTermData caller;
	keccakf1600_request_t *request;
	ErlDrvSSizeT retval;

	(void) flags; // Unused

	TRACE_F("keccakf1600_drv_call:%s:%d\n", __FILE__, __LINE__);

	port = (keccakf1600_port_t *)(drv_data);

	if (port == NULL) {
		return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
	}

	// (void) erl_drv_mutex_lock(keccakf1600_mutex);
	caller = driver_caller(port->drv_port);
	// (void) erl_drv_mutex_unlock(keccakf1600_mutex);

	request = keccakf1600_request_alloc(port, caller, command);

	if (request == NULL) {
		KECCAKF1600_FAIL_OOM(port->drv_port);
		return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
	}

	if (request->error < 0) {
		retval = (ErlDrvSSizeT)(request->error);
		(void) keccakf1600_request_free(request);
		return retval;
	}

	(void) (request->command)(&request, buf, len);

	if (request->error < 0) {
		retval = (ErlDrvSSizeT)(request->error);
		(void) keccakf1600_request_free(request);
		return retval;
	}

	retval = (ErlDrvSSizeT)(request->reply.index);

	if (rlen < retval) {
		*rbuf = (char *)(driver_realloc((void *)(*rbuf), (ErlDrvSizeT)(retval)));
		if ((*rbuf) == NULL) {
			(void) keccakf1600_request_free(request);
			KECCAKF1600_FAIL_OOM(port->drv_port);
			return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
		}
	}

	(void) memcpy((void *)(*rbuf), (void *)(request->reply.buff), (size_t)(request->reply.index));

	(void) keccakf1600_request_free(request);

	return retval;
}

DRIVER_INIT(keccakf1600_drv)
{
	return &keccakf1600_driver_entry;
}
