#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <assert.h>
#include <errno.h>
#include <libdaemon/daemon.h>
#include <nsocker/msg.h>
#include <nsocker/fd.h>
#include "fd.h"

static bool verbose;
static struct event_base* base;

#define MAX_OUT_MSG 128
#define MAX_IN_MSG 128

enum {D_SIGINT, D_SIGTERM, D_SIGQUIT, D_SIGHUP, D_SIGCOUNT};
static struct event* sighandlers[D_SIGCOUNT];

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
static void sighup_handler(evutil_socket_t fd, short event, void *arg);
static void write_hdr(connection *c, ns_cmd cmd, size_t body_size);
static void start_receive(connection *c);
static void start_send(connection *c);
static void daemon_perror(const char *msg);
static void usage(const char* progname);
static char* relpath(const char* path);

static void usage(const char* progname)
{
	printf("Usage: %s [options] <socket-file>\n", progname);
	printf("\n");
	printf("Run a socket server listening on a given unix socket path for requests\n");
	printf("\n");
	printf("  -v, --verbose     be verbose\n");
	printf("  -m, --mode        unix socket creation mode\n");
	printf("  -p, --pid         pid file path\n");
	printf("  -f  --foreground  do not daemonize\n");
	printf("  -h, --help        show this message\n");
}

static void daemon_perror(const char *msg)
{
	daemon_log(LOG_ERR, "%s: %s", msg, strerror(errno));
}

static char* working_directory;
static char* pid_file = NULL;
static const char* pid_file_proc(){
	return pid_file;
}

int main(int argc, char *argv[])
{
	int longopt = 0;
	int opt;

	int err = 1;
	bool mode_override = false;
	mode_t mode = 0, old_mode;
	bool pid_file_created = false;
	bool daemonize = true;
	char* socket_path = NULL;
	struct evconnlistener *listener = NULL;
	static struct option opts[] = {
		{"help",        no_argument,       NULL, 'h'},
		{"verbose",     no_argument,       NULL, 'v'},
		{"mode",        required_argument, NULL, 'm'},
		{"pid",         required_argument, NULL, 'p'},
		{"foreground",  required_argument, NULL, 'f'},
		{0, 0, 0, 0 }
	};

	working_directory = getcwd(NULL, 0);
	if (!working_directory) {
		perror("getcwd");
		return 1;
	}

	while ((opt = getopt_long(argc, argv, "hvm:p:f", opts, &longopt)) != -1) {
		switch(opt){
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			pid_file = relpath(optarg);
			if (!pid_file) {
				fprintf(stderr, "malloc failed");
				goto err_before_daemon;
			}
			break;
		case 'f':
			daemonize = false;
			break;
		case 'm':
			mode_override = true;
			if (sscanf(optarg, "%o", &mode) != 1) {
				fprintf(stderr, "invalid value provided to mode switch\n");
				exit(1);
			}
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
		goto err_before_daemon;
	}

	socket_path = relpath(argv[optind]);
	if (!socket_path) {
		fprintf(stderr, "malloc failed");
		goto err_before_daemon;
	}

	daemon_log_ident = daemon_ident_from_argv0(argv[0]);

	/* Daemonize */
	if (daemonize) {
		pid_t pid;
		if (pid_file) {
			daemon_pid_file_proc = pid_file_proc;
			if ((pid = daemon_pid_file_is_running()) >= 0) {
				daemon_log(LOG_ERR, "Daemon already running on PID %u", pid);
				return 1;
			}
		}

		/* Prepare for return value passing from the initialization procedure of the daemon process */
		if (daemon_retval_init() < 0) {
			daemon_log(LOG_ERR, "Failed to create pipe.");
			return 1;
		}

		if ((pid = daemon_fork()) < 0) {
			perror("fork");
			daemon_retval_done();
			return 1;
		} else if (pid) { /* The parent */
			/* Wait for 20 seconds for the return value passed from the daemon process */
			int ret;
			if ((ret = daemon_retval_wait(20)) < 0) {
				daemon_log(LOG_ERR, "Could not recieve return value from daemon process: %s", strerror(errno));
				return 255;
			}
			if (ret != 0) {
				fprintf(stderr, "daemon could not start, see sysglog for details or run with -f\n");
			}
			return ret;
		}

		/* Close FDs */
		if (daemon_close_all(-1) < 0) {
			daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));
			goto err;
		}

		/* Create the PID file */
		if (pid_file) {
			if (daemon_pid_file_create() < 0) {
				daemon_log(LOG_ERR, "Could not create PID file (%s).", strerror(errno));
				goto err;
			}
			pid_file_created = true;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	/* Bind socket and start listening */
	base = event_base_new();

	if (verbose)
		daemon_log(LOG_INFO, "Using socket %s", socket_path);

	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	if (strlen(socket_path) + 1 >  sizeof(sun.sun_path)) {
		daemon_log(LOG_ERR, "Socket path is too long\n");
		goto err;
	}
	strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	if (mode_override)
		old_mode = umask(~mode);
	listener = evconnlistener_new_bind(
		base, listener_cb, NULL, LEV_OPT_CLOSE_ON_FREE, -1,
		(struct sockaddr*)&sun, SUN_LEN(&sun));
	if (mode_override)
		umask(old_mode);

	if (!listener) {
		daemon_perror("can not bind socket");
		goto err;
	}

	sighandlers[D_SIGINT] = evsignal_new(base, SIGINT, sigint_handler, NULL);
	sighandlers[D_SIGQUIT] = evsignal_new(base, SIGQUIT, sigint_handler, NULL);
	sighandlers[D_SIGTERM] = evsignal_new(base, SIGTERM, sigint_handler, NULL);
	sighandlers[D_SIGHUP] = evsignal_new(base, SIGHUP, sighup_handler, NULL);
	for(int i = 0; i<D_SIGCOUNT; i++) {
		if(!sighandlers[i]) {
			daemon_log(LOG_ERR, "Failed to allocate signal handlers");
			goto err;
		}
		event_add(sighandlers[i], NULL);
	}

	daemon_retval_send(0);
	err = 0;
	daemon_log(LOG_INFO, "accepting connections");
	event_base_dispatch(base);

	err:
	daemon_log(LOG_INFO, "exiting");
	if (listener) {
		evconnlistener_free(listener);
		unlink(socket_path);
	}
	for(int i = 0; i<D_SIGCOUNT; i++)
		if (sighandlers[i])
			event_free(sighandlers[i]);
	if (base)
		event_base_free(base);
	if (pid_file_created)
		daemon_pid_file_remove();
	if (daemonize && err)
		daemon_retval_send(err);

	err_before_daemon:
	free(socket_path);
	free(pid_file);
	free(working_directory);
	return err;
}

static char* relpath(const char* path)
{
	if (*path == '/') {
		return strdup(path);
	} else {
		size_t len = strlen(path) + 1 + strlen(working_directory);
		char *buf = malloc(len);
		if (!buf)
			return NULL;
		strcpy(buf, working_directory);
		strcat(buf, "/");
		strcat(buf, path);
		return buf;
	}
}

static void sigint_handler(evutil_socket_t fd, short event, void *arg)
{
	daemon_log(LOG_INFO, "SIGINT received");
	event_base_loopbreak(base);
}

static void sighup_handler(evutil_socket_t fd, short event, void *arg)
{

}

#define BUFFER_SIZE 128
static void listener_cb(
	struct evconnlistener* lconn, evutil_socket_t socket,
	struct sockaddr* from, int socklen, void* user)
{
	if (verbose)
		daemon_log(LOG_INFO, "Received new connection\n");

	connection *c = malloc(sizeof(*c));
	if(!c) {
		daemon_log(LOG_ERR, "out of memory, can not accept connection");
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
		daemon_log(LOG_INFO, "socket(%d, %d, %d) -> fd=%d, errno=%d\n",
			be32toh(tsocket->domain), be32toh(tsocket->type), be32toh(tsocket->protocol),
			sockfd, be32toh(rsocket->error));
	write_hdr(c, NS_RSOCKET, sizeof(*rsocket));
	c->sendfd = sockfd_ok ? sockfd : NS_NULL_FD;
	return true;
}

static bool abort_connection(connection *c)
{
	if (verbose)
		daemon_perror("aborting connection");

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
			if (verbose)
				daemon_log(LOG_INFO, "Client disconnected\n");
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
		c->sendfd = NS_NULL_FD;
		start_receive(c);
	}
}
