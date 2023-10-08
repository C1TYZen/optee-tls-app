#include <err.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h> 
#include <stdlib.h>
#include <sys/socket.h> 
#include <sys/time.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <madtls_ta.h>

#define BUFFER_SIZE 1024
#define MAX         80
#define PORT        9000
#define REMOTE_IP   "10.0.2.2"

struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

struct socket_handle {
	uint64_t buf[2];
	size_t blen;
};

TEEC_Result socket_tcp_open(
	TEEC_Session *session, uint32_t ip_vers,
	const char *addr, uint16_t port,
	struct socket_handle *handle,
	uint32_t *error, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	memset(handle, 0, sizeof(*handle));

	op.params[0].value.a = ip_vers;
	op.params[0].value.b = port;
	op.params[1].tmpref.buffer = (void *)addr;
	op.params[1].tmpref.size = strlen(addr) + 1;
	op.params[2].tmpref.buffer = handle->buf;
	op.params[2].tmpref.size = sizeof(handle->buf);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_TCP_OPEN,
				&op, ret_orig);

	handle->blen = op.params[2].tmpref.size;
	*error = op.params[3].value.a;
	return res;
}

static TEEC_Result socket_udp_open(
		TEEC_Session *session, uint32_t ip_vers,
		const char *addr, uint16_t port,
		struct socket_handle *handle,
		uint32_t *error, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	memset(handle, 0, sizeof(*handle));

	op.params[0].value.a = ip_vers;
	op.params[0].value.b = port;
	op.params[1].tmpref.buffer = (void *)addr;
	op.params[1].tmpref.size = strlen(addr) + 1;
	op.params[2].tmpref.buffer = handle->buf;
	op.params[2].tmpref.size = sizeof(handle->buf);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_UDP_OPEN,
				 &op, ret_orig);

	handle->blen = op.params[2].tmpref.size;
	*error = op.params[3].value.a;
	return res;
}

static TEEC_Result socket_send(
		TEEC_Session *session,
		struct socket_handle *handle,
		const void *data, size_t *dlen,
		uint32_t timeout, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = timeout;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_INOUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_SEND, &op, ret_orig);

	*dlen = op.params[2].value.b;
	return res;
}

static TEEC_Result socket_recv(
		TEEC_Session *session,
		struct socket_handle *handle,
		void *data, size_t *dlen,
		uint32_t timeout, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = timeout;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_RECV, &op, ret_orig);

	*dlen = op.params[1].tmpref.size;
	return res;
}

static TEEC_Result socket_get_error(
		TEEC_Session *session,
		struct socket_handle *handle,
		uint32_t *proto_error, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_OUTPUT,
		TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_ERROR, &op, ret_orig);

	*proto_error = op.params[1].value.a;
	return res;
}

static TEEC_Result socket_close(
		TEEC_Session *session,
		struct socket_handle *handle, uint32_t *ret_orig)
{
	TEEC_Operation op = { };

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(session, TA_SOCKET_CMD_CLOSE, &op, ret_orig);
}

static TEEC_Result socket_ioctl(
		TEEC_Session *session,
		struct socket_handle *handle, uint32_t ioctl_cmd,
		void *data, size_t *dlen, uint32_t *ret_orig)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = { };

	op.params[0].tmpref.buffer = handle->buf;
	op.params[0].tmpref.size = handle->blen;
	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = *dlen;
	op.params[2].value.a = ioctl_cmd;

	op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_INOUT,
			TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SOCKET_CMD_IOCTL, &op, ret_orig);

	*dlen = op.params[1].tmpref.size;
	return res;
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session session;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_MY_UUID;
	uint32_t err_origin;
	char server_message[256] = "You have reached the server!";
	int server_socket;
	int client_socket;

	// Initialize a context connecting us to the TEE
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	// Clear the TEEC_Operation struct
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;

	// create the server socket
	// if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    //     perror("Socket Failed");
    //     return -1;
    // }
    // puts("Socket created");

	// // define the server address
	// struct sockaddr_in server_addr;
	// server_addr.sin_family = AF_INET;
	// server_addr.sin_port = htons(9002);
	// server_addr.sin_addr.s_addr = INADDR_ANY;
    // puts("Socket defined");

	// if((bind(server_socket, (struct sockaddr*) &server_addr, sizeof(server_addr))) < 0) {
    //     perror("Bind Failed");
    //     return -1;
    // }
    // puts("Socket binded");

	// if(listen(server_socket, 5) < 0) {
    //     perror("Listen Failed");
    //     return -1;
    // }
    // puts("Listening...");

	// if((client_socket = accept(server_socket, NULL, NULL)) < 0) {
    //     perror("Accept Failed");
    //     return -1;
    // }
    // puts("Accepted!");

	// send(client_socket, server_message, sizeof(server_message), 0);

	struct socket_handle handle = { };
	uint32_t proto_error = 9;
	if (!socket_tcp_open(
		&session, NULL, TA_SERVER_IP, TA_SERVER_PORT,
		&handle, &proto_error, &err_origin))
	{
		printf("TEE TCP Socket failure!\n");
		return 1;
	}

	close(server_socket);
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
