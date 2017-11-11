#include <nsocker/client.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define PORT 32644

int main()
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (const void *)&optval , sizeof(int));

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		if (errno == EADDRINUSE) {
			return 2;
		} else {
			perror("bind");
			return 1;
		}
	}

	if (listen(fd, 1) < 0) {
		perror("listen");
		return 1;
	}

	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	} else if (child == 0) {
		while(1)
			sleep(100);
		return 0;
	} else {
		printf("%d\n", child);
		return 0;
	}
}
