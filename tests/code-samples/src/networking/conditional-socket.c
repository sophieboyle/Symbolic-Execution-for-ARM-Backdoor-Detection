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
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );

    int b = 0;
    scanf("%d", &b);

    if (b){
        sock = socket(AF_INET , SOCK_STREAM , 0);
        connect(sock , (struct sockaddr *)&server , sizeof(server));
    }

    close(sock);
	return 0;
}