#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc , char *argv[])
{
	int sock;
	struct sockaddr_in server;
	char server_reply[2000];
	
    char message[1000] = "hello";

	//Create socket
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_family = AF_INET;
	
    int b = 0;
    scanf("%d", &b);

    sock = socket(AF_INET , SOCK_STREAM , 0);

    if (b){
        server.sin_port = htons( 8080 );
        bind(sock , (struct sockaddr*)&server, sizeof(server) );
    } else {
        server.sin_port = htons( 1337 );
        bind(sock , (struct sockaddr*)&server, sizeof(server) );
    }
    close(sock);
	return 0;
}