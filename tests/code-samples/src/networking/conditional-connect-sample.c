#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc , char *argv[])
{
	int sock;
	struct sockaddr_in server;
	char message[1000] , server_reply[2000];
	
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );

    sock = socket(AF_INET , SOCK_STREAM , 0);

    int b = 0;
    scanf("%d", &b);

    if (b == 1){
        printf("test");
        connect(sock , (struct sockaddr *)&server , sizeof(server));
        close(sock);
    } else {
        printf("Dead");
    }

	return 0;
}