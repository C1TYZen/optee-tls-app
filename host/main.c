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

#define BUFFER_SIZE                                 1024
#define MAX                                         80
#define PORT                                        9998
#define REMOTE_IP                                   "10.0.2.2"
#define TCP_SERVER_MODE                             0
#define TCP_CLIENT_MODE                             1
#define TEE_TCP                                     3

struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

TEEC_Result tee_tcp_socket(struct test_ctx *ctx, char *buffer)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t ori;

    memset(&op, 0, sizeof op);
    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE);

    strcpy(buffer, "Hello World!");
    op.params[0].tmpref.buffer = buffer;
    op.params[0].tmpref.size = BUFFER_SIZE;

    res = TEEC_InvokeCommand(&ctx->sess, TA_TCP_SOCKET, &op, &ori);

    return res;
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
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
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	// Clear the TEEC_Operation struct
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;

	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_MY_CMD_INC_VALUE, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("TA incremented value to %d\n", op.params[0].value.a);

	// create the server socket
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket Failed");
        return -1;
    }
    puts("Socket created");

	// define the server address
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(9002);
	server_addr.sin_addr.s_addr = INADDR_ANY;
    puts("Socket defined");

	if((bind(server_socket, (struct sockaddr*) &server_addr, sizeof(server_addr))) < 0) {
        perror("Bind Failed");
        return -1;
    }
    puts("Socket binded");

	if(listen(server_socket, 5) < 0) {
        perror("Listen Failed");
        return -1;
    }
    puts("Listening...");

	if((client_socket = accept(server_socket, NULL, NULL)) < 0) {
        perror("Accept Failed");
        return -1;
    }
    puts("Accepted!");

	send(client_socket, server_message, sizeof(server_message), 0);

	close(server_socket);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
