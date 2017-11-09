#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <assert.h>
#include <nsocker/msg.h>
#include <nsocker/fd.h>
#include "fd.h"

static bool verbose;
static struct event_base* base;

#define MAX_OUT_MSG 128
#define MAX_IN_MSG 128

typedef struct {
	int sockfd;
	bool write_pending;

	struct event *evt_read;
	msg_reader reader;
	ns_hdr request;
	int recvfd;
	char recv[MAX_IN_MSG];

	msg_writer writer;
	struct event *evt_write;
	ns_hdr response;
	int sendfd;
	char send[MAX_OUT_MSG];
} connection;

static void listener_cb(struct evconnlistener* lconn, evutil_socket_t socket,
	struct sockaddr* from, int socklen, void* user);
static void conn_read(evutil_socket_t sockfd, short what, void *user);
static void conn_write(evutil_socket_t sockfd, short what, void *user);
static bool abort_connection(connection *c);
static void sigint_handler(evutil_socket_t fd, short event, void *arg);
static void write_hdr(connection *c, ns_cmd cmd, size_t body_size);
static void start_receive(connection *c);
static void start_send(connection *c);
static void usage(const char* progname);

static void usage(const char* progname)
{
	printf("Usage: %s [-v] <socket-file>\n", progname);
	printf("\n");
	printf("Run a socket server listening on a given unix socket path for requests\n");
	printf("\n");
	printf("  -v, --verbose be verbose\n");
	printf("  -h, --help    show this message\n");
}

int main(int argc, char *argv[])
{
	int longopt = 0;
	int opt;
	static struct option opts[] = {
		{"help",     no_argument,       NULL, 'h'},
		{"verbose",  no_argument,       NULL, 'v'},
		{0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hv", opts, &longopt)) != -1) {
		switch(opt){
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'v':
			verbose = true;
			break;
		case '?':
			return 1;
			break;
		default:
			abort();
		}
	}

	int remaining = argc - optind;
	if (remaining != 1) {
		fprintf(stderr, "Expected single socket file as argument\n");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);

	/* Bind socket and start listening */
	base = event_base_new();

	struct sockaddr_un sun;
	const char* path = argv[optind];
	sun.sun_family = AF_UNIX;
	if (strlen(path) + 1 >  sizeof(sun.sun_path)) {
		fprintf(stderr, "Socket path is too long\n");
		return 1;
	}
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));

	struct evconnlistener *listener = evconnlistener_new_bind(
		base, listener_cb, NULL, LEV_OPT_CLOSE_ON_FREE, -1,
		(struct sockaddr*)&sun, SUN_LEN(&sun));

	if (!listener) {
		perror("can not bind socket");
		return 1;
	}

	struct event *sigevent = evsignal_new(base, SIGINT, sigint_handler, NULL);
	if(!sigevent) {
		fprintf(stderr, "can not register signal handler\n");
		return 1;
	}
	event_add(sigevent, NULL);

	event_base_dispatch(base);

	evconnlistener_free(listener);
	evsignal_del(sigevent);
	event_base_free(base);
	unlink(path);
	return 0;
}

static void sigint_handler(evutil_socket_t fd, short event, void *arg)
{
	fprintf(stderr, "SIGINT received\n");
	event_base_loopbreak(base);
}

#define BUFFER_SIZE 128
static void listener_cb(
	struct evconnlistener* lconn, evutil_socket_t socket,
	struct sockaddr* from, int socklen, void* user)
{
	if (verbose)
		fprintf(stderr, "Received new connection\n");

	connection *c = malloc(sizeof(*c));
	if(!c) {
		fprintf(stderr, "out of memory, can not accept connection");
		return;
	}
	c->write_pending = false;
	c->sockfd = socket;
	c->evt_read = NULL;
	c->evt_write = NULL;

	evutil_make_socket_nonblocking(c->sockfd);
	c->evt_read = event_new(base, c->sockfd, EV_READ|EV_PERSIST, conn_read, c);
	if (!c->evt_read)
		abort_connection(c);
	c->evt_write = event_new(base, c->sockfd, EV_WRITE|EV_PERSIST, conn_write, c);
	if (!c->evt_write)
		abort_connection(c);

	start_receive(c);
}

static void write_hdr(connection *c, ns_cmd cmd, size_t body_size) {
	ns_hdr *r = &c->response;
	r->cmd = htobe32(cmd);
	r->id = c->request.id;
	r->size = htobe32(sizeof(*r) + body_size);
	c->write_pending= true;
}

static void start_receive(connection *c)
{
	ns_recv_start(&c->reader, c->sockfd, &c->request, c->recv, sizeof(c->recv), &c->recvfd);
	event_add(c->evt_read, NULL);
	event_del(c->evt_write);
}

static void start_send(connection *c)
{
	ns_send_start(&c->writer, c->sockfd, &c->response, c->send, c->sendfd);
	event_add(c->evt_write, NULL);
	event_del(c->evt_read);
}

static bool handle_bad(connection *c, ns_cmd cmd) {
	write_hdr(c, cmd, 0);
	return true;
}

static bool handle_socket(connection *c) {
	if (be32toh(c->request.size) != sizeof(ns_hdr) + sizeof(ns_tsocket))
		return handle_bad(c, NS_RBADSIZE);

	ns_tsocket *tsocket = (ns_tsocket*) c->recv;
	ns_rsocket *rsocket = (ns_rsocket*) c->send;
	int sockfd = socket(be32toh(tsocket->domain), be32toh(tsocket->type), be32toh(tsocket->protocol));
	bool sockfd_ok = !(sockfd < 0);
	rsocket->error = htobe32(sockfd_ok ? 0 : errno);
	if (verbose)
		fprintf(stderr, "socket(%d, %d, %d) -> fd=%d, errno=%d\n",
			be32toh(tsocket->domain), be32toh(tsocket->type), be32toh(tsocket->protocol),
			sockfd, be32toh(rsocket->error));
	write_hdr(c, NS_RSOCKET, sizeof(*rsocket));
	c->sendfd = sockfd_ok ? sockfd : NS_NULL_FD;
	return true;
}

static bool abort_connection(connection *c)
{
	if (verbose)
		perror("aborting connection");

	return false;
}

static void free_connection(connection *c)
{
	if (c->sendfd >= 0)
		close(c->sendfd);

	event_free(c->evt_read);
	event_free(c->evt_write);
	close(c->sockfd);
	free(c);
	return;
}

static void conn_read(evutil_socket_t sockfd, short what, void *user)
{
	connection *c = user;
	if (!ns_recv(&c->reader)) {
		if (c->reader.eof) {
			fprintf(stderr, "Client disconnected\n");
		} else {
			abort_connection(c);
		}
		free_connection(c);
		return;
	}

	if(c->reader.complete) {
		bool ok;
		c->sendfd = NS_NULL_FD;
		switch (be32toh(c->request.cmd)) {
			case NS_TSOCKET:
				ok = handle_socket(c);
			break;
			default:
				ok = handle_bad(c, NS_RUNKNOWN);
		}
		if (!ok) {
			free_connection(c);
			return;
		}
		if (c->write_pending)
			start_send(c);
	}
}

static void conn_write(evutil_socket_t sockfd, short what, void *user)
{
	connection *c = user;
	assert(c->write_pending);
	if(!ns_send(&c->writer)) {
		abort_connection(c);
		free_connection(c);
		return;
	}
	if (c->reader.complete) {
		close(c->sendfd);
		start_receive(c);
	}
}
