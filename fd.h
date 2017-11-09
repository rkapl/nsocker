#pragma once
#include <stddef.h>
#include "include/nsocker/fd.h"

typedef struct {
	size_t count;
	struct iovec *ptr;
} iov_ptr;

typedef struct {
	int sockfd;
	int fd;
	ns_hdr *hdr;

	iov_ptr ioptr;
	struct iovec io[2];
	bool complete;
} msg_writer;

typedef struct {
	int sockfd;
	int *fd;
	ns_hdr *hdr;
	size_t recv_count;

	bool hdr_received;
	size_t junk_remaining;
	size_t body_buf_size;
	bool complete;
	bool eof;

	iov_ptr ioptr;
	struct iovec io[2];
} msg_reader;

void ns_send_start(msg_writer *buf, int sockfd, ns_hdr* hdr, void* body, int fd);
bool ns_send(msg_writer *fd);
void ns_recv_start(msg_reader *buf, int sockfd, ns_hdr* hdr, void* body, size_t body_size, int *fd);
bool ns_recv(msg_reader *fd);
