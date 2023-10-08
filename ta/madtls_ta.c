#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <madtls_ta.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_tcpsocket.h>

// #include <mbedtls/ctr_drbg.h>
// #include <mbedtls/entropy.h>
// #include <mbedtls/net_sockets.h>
// #include <mbedtls/ssl.h>

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
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");
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

TEE_Result TA_tcp_socket(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    // TCP Socket Set Up
    TEE_ipSocket_ipVersion ta_ip_version = TEE_IP_VERSION_4;
    TEE_tcpSocket_Setup *tcp_socket_setup;
    tcp_socket_setup = TEE_Malloc(sizeof *tcp_socket_setup,
            TEE_MALLOC_FILL_ZERO);
    tcp_socket_setup->ipVersion = ta_ip_version;
    tcp_socket_setup->server_addr = TA_SERVER_IP;
    tcp_socket_setup->server_port = TA_SERVER_PORT;
    TEE_iSocketHandle *tee_socket_handle;
    // Measure time here
    tee_socket_handle = TEE_Malloc(sizeof *tee_socket_handle,
            TEE_MALLOC_FILL_ZERO);

    // Define Socket
    uint32_t error_code;
    // Measure Time
    res = (*TEE_tcpSocket->open)(tee_socket_handle, tcp_socket_setup,
            &error_code);
    // Measure Time
    res = (*TEE_tcpSocket->send)(tee_socket_handle, params[0].memref.buffer,
            params[0].memref.size, 60);
    // Fails at core/arch/arm/tee/pta_socket.c -> send
    res = (*TEE_tcpSocket->close)(tee_socket_handle);

    printf("%s\n", (char *) params[0].memref.buffer);

    return TEE_SUCCESS;
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4]) {
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("GHOT Ah value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("INCREASE YOUR ASS to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("GHOST value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease YOUR MOM value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

// Called when a TA is invoked. sess_ctx hold that value that was
// assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
// comes from normal world.
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_MY_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_MY_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
