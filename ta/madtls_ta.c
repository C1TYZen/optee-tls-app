#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
#include <trace.h>

#include <madtls_ta.h>

// #include <mbedtls/ssl.h>

struct sock_handle {
	TEE_iSocketHandle ctx;
	TEE_iSocket *socket;
};

// The first call in the TA
TEE_Result TA_CreateEntryPoint(void) {
	DMSG("has been called");
	return TEE_SUCCESS;
}

// The last call in the TA.
void TA_DestroyEntryPoint(void) {
	DMSG("has been called");
}

// Called when a new session is opened to the TA. In this function you will 
// normally do the global initialization for the TA.
TEE_Result TA_OpenSessionEntryPoint(
		uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
	    TEE_PARAM_TYPE_NONE,
	    TEE_PARAM_TYPE_NONE,
	    TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;
	// The DMSG() macro is non-standard, TEE Internal API doesn't
	// specify any means to logging from a TA.
	IMSG("Hello World!\n");

	return TEE_SUCCESS;
}

// Called when a session is closed, sess_ctx hold the value that was
// assigned by TA_OpenSessionEntryPoint().
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result ta_entry_tcp_open(uint32_t param_types, TEE_Param params[4])
{
	IMSG("*** OPEN");
	TEE_Result res = TEE_ERROR_GENERIC;
	struct sock_handle h = { 0 };
	TEE_tcpSocket_Setup setup = { 0 };
	uint32_t req_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x", param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[2].memref.size < sizeof(struct sock_handle)) {
		params[2].memref.size = sizeof(struct sock_handle);
		return TEE_ERROR_SHORT_BUFFER;
	}

    TEE_ipSocket_ipVersion ta_ip_version = TEE_IP_VERSION_4;
    setup.ipVersion = ta_ip_version;
	setup.server_port = params[0].value.b;
	setup.server_addr = strndup(params[1].memref.buffer, params[1].memref.size);
	if (!setup.server_addr)
		return TEE_ERROR_OUT_OF_MEMORY;

	h.socket = TEE_tcpSocket;
	IMSG("*** setup: %s %d", setup.server_addr, setup.server_port);
	res = h.socket->open(&h.ctx, &setup, &params[3].value.a);
	free(setup.server_addr);
	if (res == TEE_SUCCESS) {
		memcpy(params[2].memref.buffer, &h, sizeof(h));
		params[2].memref.size = sizeof(h);
	}
	return res;
}

static TEE_Result ta_entry_udp_open(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct sock_handle h = { };
	TEE_udpSocket_Setup setup = { };
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[2].memref.size < sizeof(struct sock_handle)) {
		params[2].memref.size = sizeof(struct sock_handle);
		return TEE_ERROR_SHORT_BUFFER;
	}

	setup.ipVersion = params[0].value.a;
	setup.server_port = params[0].value.b;
	setup.server_addr = strndup(params[1].memref.buffer,
				    params[1].memref.size);
	if (!setup.server_addr)
		return TEE_ERROR_OUT_OF_MEMORY;

	h.socket = TEE_udpSocket;
	res = h.socket->open(&h.ctx, &setup, &params[3].value.a);
	free(setup.server_addr);
	if (res == TEE_SUCCESS) {
		memcpy(params[2].memref.buffer, &h, sizeof(h));
		params[2].memref.size = sizeof(h);
	}
	return res;
}

static TEE_Result ta_entry_close(uint32_t param_types, TEE_Param params[4])
{
	struct sock_handle *h = NULL;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != sizeof(struct sock_handle))
		return TEE_ERROR_BAD_PARAMETERS;

	h = params[0].memref.buffer;
	return h->socket->close(h->ctx);
}

static TEE_Result ta_entry_send(uint32_t param_types, TEE_Param params[4])
{
	struct sock_handle *h = NULL;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_NONE);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != sizeof(*h))
		return TEE_ERROR_BAD_PARAMETERS;

	h = params[0].memref.buffer;
	params[2].value.b = params[1].memref.size;
	return h->socket->send(h->ctx, params[1].memref.buffer,
			       &params[2].value.b, params[2].value.a);
}

static TEE_Result ta_entry_recv(uint32_t param_types, TEE_Param params[4])
{
	IMSG("*** RECEIVE called");
	TEE_Result res = TEE_SUCCESS;
	struct sock_handle *h = NULL;
	uint32_t req_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE);
	uint32_t sz = 0;

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != sizeof(struct sock_handle))
		return TEE_ERROR_BAD_PARAMETERS;

	h = params[0].memref.buffer;
	sz = params[1].memref.size;
	IMSG("*** RECEIVE");
	// res = h->socket->recv(h->ctx, params[1].memref.buffer, &sz, params[2].value.a);
	res = h->socket->recv(h->ctx, params[1].memref.buffer, &sz, params[2].value.a);
	params[1].memref.size = sz;

	IMSG("*** RECEIVE finished");
	return res;
}

static TEE_Result ta_entry_error(uint32_t param_types, TEE_Param params[4])
{
	struct sock_handle *h = NULL;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != sizeof(struct sock_handle))
		return TEE_ERROR_BAD_PARAMETERS;

	h = params[0].memref.buffer;
	params[1].value.a = h->socket->error(h->ctx);
	return TEE_SUCCESS;
}

static TEE_Result ta_entry_ioctl(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	struct sock_handle *h = NULL;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	uint32_t sz = 0;

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size != sizeof(struct sock_handle))
		return TEE_ERROR_BAD_PARAMETERS;

	h = params[0].memref.buffer;
	sz = params[1].memref.size;
	res = h->socket->ioctl(h->ctx, params[2].value.a,
			       params[1].memref.buffer, &sz);
	params[1].memref.size = sz;
	return res;
}

// Called when a TA is invoked. sess_ctx hold that value that was
// assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
// comes from normal world.
TEE_Result TA_InvokeCommandEntryPoint(
	void __maybe_unused *sess_ctx,
	uint32_t cmd_id,
	uint32_t param_types,
	TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_SOCKET_CMD_TCP_OPEN:
		return ta_entry_tcp_open(param_types, params);
	case TA_SOCKET_CMD_UDP_OPEN:
		return ta_entry_udp_open(param_types, params);
	case TA_SOCKET_CMD_CLOSE:
		return ta_entry_close(param_types, params);
	case TA_SOCKET_CMD_SEND:
		return ta_entry_send(param_types, params);
	case TA_SOCKET_CMD_RECV:
		return ta_entry_recv(param_types, params);
	case TA_SOCKET_CMD_ERROR:
		return ta_entry_error(param_types, params);
	case TA_SOCKET_CMD_IOCTL:
		return ta_entry_ioctl(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
