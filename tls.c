#include <nsocker/client.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>

static pthread_key_t tls_key;

static void key_init() __attribute__((constructor));
static void free_thread(void *v);
static void free_context(ns_context *ctx);
static void free_thread(void *v)
{
	ns_context *c = v;
	while (c) {
		ns_context *parent = c->parent;
		free_context(c);
		c = parent;
	}
}

static void key_init()
{
	if (pthread_key_create(&tls_key, free_thread))
		abort();
}

static void free_context(ns_context *ctx)
{
	if (ctx->pop_cb)
		ctx->pop_cb(ctx);
}

void ns_context_init(ns_context *ctx)
{
	ctx->flags = 0;
	ctx->socket_client = NULL;
	ctx->pop_cb = NULL;
	ctx->user = NULL;
}

void ns_context_free(ns_context *ctx)
{
}

ns_context *ns_push(ns_context *newctx)
{
	ns_context* old = pthread_getspecific(tls_key);
	if (pthread_setspecific(tls_key, newctx))
		return NULL;

	newctx->parent = old;
	return newctx;
}

void ns_pop(ns_context *current)
{
	ns_context* old = pthread_getspecific(tls_key);
	assert(old == current || current == NULL);
	ns_context* parent = old->parent;
	free_context(old);
	if (pthread_setspecific(tls_key, parent))
		abort();
}

ns_context* ns_get()
{
	ns_context* c = pthread_getspecific(tls_key);
	return c;
}
