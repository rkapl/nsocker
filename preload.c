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
static bool default_ctx();
static void free_default_ctx(ns_context *ctx);

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

static void free_default_ctx(ns_context *ctx)
{
	free(ctx);
}

static bool default_ctx()
{
	ns_context *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		errno = ENOMEM;
		return false;
	}
	if (!ns_push(ctx)) {
		errno = ENOMEM;
		free(ctx);
		return false;
	}
	ctx->pop_cb = free_default_ctx;
	if(!ns_client_connect(&ctx->client, path)) {
		perror("connecting to NSOCKER_SERVER");
		errno = EPROTO;
		return false;
	}
	return true;
}

int socket(int domain, int type, int protocol)
{
	if (domain == AF_UNIX) {
		return prev_socket(domain, type, protocol);
	} else {
		ns_client *c = ns_get();
		if (!c) {
			if (path) {
				if(!default_ctx())
					return -1;
				c = ns_get();
			} else {
				return prev_socket(domain, type, protocol);
			}
		}
		if (!c)
			abort();
		return ns_client_socket(c, domain, type, protocol);
	}
}
