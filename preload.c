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
	ns_client_free(ctx->socket_client);
	free(ctx->socket_client);
	free(ctx);
}

static bool default_ctx()
{
	ns_context *ctx = malloc(sizeof(*ctx));
	ns_client *c = malloc(sizeof(*ctx));
	if (!ctx || !c) {
		free(c);
		free(ctx);
		errno = ENOMEM;
		return false;
	}
	ns_client_init(c);

	if(!ns_client_connect(c, path)) {
		perror("connecting to NSOCKER_SERVER");
		errno = EPROTO;
		free_default_ctx(ctx);
		return false;
	}

	if (!ns_push(ctx)) {
		errno = ENOMEM;
		free_default_ctx(ctx);
		return false;
	}
	ctx->pop_cb = free_default_ctx;
	ctx->socket_client = c;

	return true;
}

int socket(int domain, int type, int protocol)
{
	if (domain == AF_UNIX) {
		return prev_socket(domain, type, protocol);
	} else {
		ns_context *c = ns_get_context();
		if (!c) {
			if (path) {
				if(!default_ctx())
					return -1;
				c = ns_get_context();
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
