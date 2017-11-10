#define _GNU_SOURCE 1
#include <nsocker/client.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

typedef int (*fn_socket)(int domain, int type, int protocol);

static fn_socket prev_socket;
static char* path;

static void init() __attribute__((constructor));
static void fini() __attribute__((destructor));

static void init()
{
	prev_socket = (fn_socket) dlsym(RTLD_NEXT, "socket");
	path = getenv("NSOCKER_SERVER");
	if (path)
		path = strdup(path);
}

static void fini()
{
	free(path);
}

int socket(int domain, int type, int protocol)
{
	if (domain == AF_UNIX) {
		return prev_socket(domain, type, protocol);
	} else {
		ns_context *c = ns_get();
		if (!c) {
			if (path) {
				if(!ns_context_push_new(path)) {
					perror("connecting to NSOCKET_SERVER");
					errno = EPROTO;
					return -1;
				}
				c = ns_get();
			} else {
				return prev_socket(domain, type, protocol);
			}
		}
		if (!c)
			abort();

		if (c->socket_client) {
			return ns_client_socket(c->socket_client, domain, type, protocol);
		} else {
			return prev_socket(domain, type, protocol);
		}
	}
}
