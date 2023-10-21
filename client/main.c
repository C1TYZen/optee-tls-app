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

#include <tee_client_api.h>
#include <tls_ta.h>

int main(void) {
	TEEC_Result res = { 0 };
	TEEC_Context ctx = { 0 };
	TEEC_Session session = { 0 };
	TEEC_UUID uuid = TA_MY_UUID;
	uint32_t err_origin = { 0 };

	// Initialize a context connecting us to the TEE
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(
		&ctx, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
