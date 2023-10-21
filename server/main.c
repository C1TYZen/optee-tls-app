#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
	uint32_t err_origin;
	char server_message[256] = "You have reached the server!";
	int server_socket;
	int client_socket;

	// create the server socket
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket Failed");
        return -1;
    }
    // puts("Socket created");

	// define the server address
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(9000);
	server_addr.sin_addr.s_addr = INADDR_ANY;
    // puts("Socket defined");

	if((bind(server_socket, (struct sockaddr*) &server_addr, sizeof(server_addr))) < 0) {
        perror("Bind Failed");
        return -1;
    }
    // puts("Socket binded");

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

	return 0;
}
