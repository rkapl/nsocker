#include <nsocker/client.h>
#include <nsocker/fd.h>
#include <nsocker/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <endian.h>
#include "errno.h"

void ns_client_init(ns_client *ns)
{
	ns->sockfd = 0;
	ns->flags = 0;
}

bool ns_client_connect(ns_client *ns, const char *path)
{
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0)
		return false;

	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	assert( strlen(path) < sizeof(sun.sun_path));
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (connect(sockfd, (struct sockaddr*)&sun, SUN_LEN(&sun))) {
		close(sockfd);
		return false;
	}

	ns->sockfd = sockfd;
	return true;
}

int ns_client_socket(ns_client *ns, int domain, int type, int protocol)
{
	ns_hdr theader;
	ns_tsocket tsocket;
	bzero(&theader, sizeof(theader));
	bzero(&tsocket, sizeof(tsocket));

	ns_hdr_set(&theader, NS_TSOCKET, sizeof(tsocket));
	tsocket.domain = htobe32(domain);
	tsocket.type = htobe32(type);
	tsocket.protocol = htobe32(protocol);

	if (!ns_send_blocking(ns->sockfd, &theader, &tsocket, NS_NULL_FD))
		return -1;

	ns_hdr rheader;
	ns_rsocket rsocket;
	int fd;
	bool eof;
	if (!ns_recv_blocking(ns->sockfd, &rheader, &rsocket, sizeof(rsocket), &fd, &eof))
		return -1;

	if (be32toh(rheader.size) != sizeof(rsocket) + sizeof(rheader)) {
		errno = EPROTO;
		return -1;
	}

	if (be32toh(rheader.cmd) != NS_RSOCKET) {
		errno = EPROTO;
		return -1;
	}

	if (be32toh(rsocket.error)) {
		errno = be32toh(rsocket.error);
		return -1;
	} else {
		return fd;
	}
}

void ns_client_free(ns_client *ns)
{
	if (ns->sockfd)
		close(ns->sockfd);
}
