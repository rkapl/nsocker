#pragma once
#include <stdbool.h>

typedef struct {
	int sockfd;
	int flags;
	void *reserved[4];
} ns_client;

void ns_client_init(ns_client *ns);
bool ns_client_connect(ns_client *ns, const char *path);
int ns_client_socket(ns_client *ns, int domain, int type, int protocol);
void ns_client_free(ns_client *ns);

typedef struct ns_context_{
	struct ns_context_ *parent;
	int flags;
	void (*pop_cb)(struct ns_context_* ctx);
	void *user;

	ns_client *socket_client;
	void *reserved[4];
} ns_context;

void ns_context_init(ns_context *ctx);
void ns_context_free(ns_context *ctx);
ns_context *ns_push(ns_context *newctx);
void ns_pop(ns_context *current);
ns_context *ns_get(void);

/* shortcuts */
bool ns_context_push_new(const char *path);
