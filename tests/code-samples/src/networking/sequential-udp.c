/*
	BASED OFF OF: https://github.com/SpencerCDixon/simple-udp-server/blob/master/client.c
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>

#define SERVER "127.0.0.1"
#define BUFLEN 512
#define PORT 8888

void die(char *s){
	perror(s);
	exit(1);
}

int main(void)
{
	struct sockaddr_in si_other, si_other2;
	int s, i, slen=sizeof(si_other), slen2=sizeof(si_other2);
	char buf[BUFLEN];
	char message[BUFLEN];

	if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		die("socket");
	}

	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	
	if (inet_aton(SERVER , &si_other.sin_addr) == 0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		die("socket");
	}

	memset((char *) &si_other2, 0, sizeof(si_other2));
	si_other2.sin_family = AF_INET;
	si_other2.sin_port = htons(PORT+1);
	
	if (inet_aton(SERVER , &si_other2.sin_addr) == 0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

    printf("Enter message : ");
    fgets(message, BUFLEN, stdin);
    
    if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1){
        die("sendto()");
    }
    
    memset(buf,'\0', BUFLEN);
    if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1){
        die("recvfrom()");
    }

    if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other2, slen2)==-1){
        die("sendto()");
    }
    
    memset(buf,'\0', BUFLEN);
    if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other2, &slen2) == -1){
        die("recvfrom()");
    }

	close(s);
	return 0;
}