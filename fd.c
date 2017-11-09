#include <nsocker/fd.h>
#include "fd.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

// https://keithp.com/blogs/fd-passing/
// https://unix.stackexchange.com/questions/185011/what-happens-with-unix-stream-ancillary-data-on-partial-reads

static void init_send_ioptr(struct iovec io[], iov_ptr* ioptr, ns_hdr *hdr, void *body, size_t body_size);
static void pull_ioptr(iov_ptr* ioptr, size_t size);
static bool is_ioptr_complete(iov_ptr *ioptr);
static bool would_block(bool *is_complete);
bool recv_junk(msg_reader *buf);

enum {IOV_HDR, IOV_BODY};

void ns_hdr_set(ns_hdr *hdr, ns_cmd cmd, size_t body_size)
{
	hdr->id = htobe32(0);
	hdr->cmd = htobe32(cmd);
	hdr->size = htobe32(body_size + sizeof(*hdr));
}

static void init_send_ioptr(struct iovec io[], iov_ptr* ioptr, ns_hdr *hdr, void *body, size_t body_size)
{
	io[IOV_HDR].iov_base = hdr;
	io[IOV_HDR].iov_len = sizeof(*hdr);
	io[IOV_BODY].iov_base = body;
	io[IOV_BODY].iov_len = body_size;
	ioptr->count = 2;
	ioptr->ptr = &io[0];
}

static void pull_ioptr(iov_ptr* ioptr, size_t size)
{
	while (size > 0) {
		assert(ioptr->count != 0);
		size_t chunk = size;
		if (chunk > ioptr->ptr->iov_len)
			chunk = ioptr->ptr->iov_len;

		size -= chunk;
		ioptr->ptr->iov_len -= chunk;
		ioptr->ptr->iov_base += chunk;
		if (ioptr->ptr->iov_len == 0) {
			ioptr->ptr++;
			ioptr->count--;
		}
	}
}

static bool is_ioptr_complete(iov_ptr *ioptr)
{
	return ioptr->count == 0;
}

void ns_send_start(msg_writer *buf, int sockfd, ns_hdr* hdr, void* body, int fd)
{
	size_t size = be32toh(hdr->size);
	assert(size >= sizeof(*hdr));
	size -= sizeof(*hdr);
	buf->hdr = hdr;
	buf->sockfd = sockfd;
	buf->fd = fd;
	buf->complete = false;
	init_send_ioptr(buf->io, &buf->ioptr, hdr, body, size);
}

static bool would_block(bool *is_complete)
{
	if (errno == EWOULDBLOCK) {
		*is_complete = false;
		return true;
	} else {
		return false;
	}
}

bool ns_send(msg_writer *buf)
{
	assert(!is_ioptr_complete(&buf->ioptr));
	assert(!buf->complete);

	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = buf->ioptr.ptr;
	msg.msg_iovlen = buf->ioptr.count;
	msg.msg_flags = 0;
	if (buf->fd >= 0) {
		bzero(cbuf, sizeof(cbuf));
		msg.msg_control = cbuf;
		msg.msg_controllen = CMSG_SPACE(sizeof(int));

		cmsg = CMSG_FIRSTHDR(&msg);
		assert(cmsg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int*)CMSG_DATA(cmsg) = buf->fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	ssize_t sent = sendmsg(buf->sockfd, &msg, 0);
	if (sent < 0)
		return would_block(&buf->complete);

	pull_ioptr(&buf->ioptr, sent);
	buf->fd = NS_NULL_FD;
	buf->complete = is_ioptr_complete(&buf->ioptr);
	return true;
}

bool ns_send_blocking(int sockfd, ns_hdr* hdr, void* body, int fd)
{
	msg_writer buf;
	bool error;
	ns_send_start(&buf, sockfd, hdr, body, fd);
	do {
		error = ns_send(&buf);
	} while (!error && !buf.complete);
	return error;
}

#define JUNK_AT_TIME 0x100
static char junkbuf[JUNK_AT_TIME];
void ns_recv_start(msg_reader *buf, int sockfd, ns_hdr* hdr, void* body, size_t body_size, int *fd)
{
	buf->hdr = hdr;
	buf->sockfd = sockfd;
	buf->fd = fd;
	buf->recv_count = 0;
	buf->body_buf_size = body_size;
	buf->hdr_received = false;
	buf->junk_remaining = 0;
	buf->complete = false;
	if (fd)
		*fd = NS_NULL_FD;

	buf->ioptr.ptr = buf->io;
	buf->ioptr.count = 1;
	buf->io[IOV_HDR].iov_base = hdr;
	buf->io[IOV_HDR].iov_len = sizeof(*hdr);
	buf->io[IOV_BODY].iov_base = body;
}

bool recv_junk(msg_reader *buf)
{
	size_t junk_size = (buf->junk_remaining > JUNK_AT_TIME) ? JUNK_AT_TIME : buf->junk_remaining;
	ssize_t received = recv(buf->sockfd, junkbuf, junk_size, 0);
	if (received < 0)
		return would_block(&buf->complete);
	buf->junk_remaining -= received;
	buf->complete = buf->junk_remaining == 0;
	errno = EPROTO;
	return false;
}

bool ns_recv(msg_reader *buf)
{
	assert(!buf->complete);
	if (buf->junk_remaining)
		return recv_junk(buf);

	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];

	// to the receive, optionally accepting the fd
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = buf->ioptr.ptr;
	msg.msg_iovlen = buf->ioptr.count;
	msg.msg_flags = 0;
	if (buf->fd) {
		bzero(cbuf, sizeof(cbuf));
		msg.msg_control = cbuf;
		msg.msg_controllen = CMSG_LEN(sizeof(int));

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	ssize_t received = recvmsg(buf->sockfd, &msg, 0);
	if (received < 0)
		return would_block(&buf->complete);
	if (received == 0) {
		errno = 0;
		buf->eof = true;
		return false;
	}
	pull_ioptr(&buf->ioptr, received);

	if (buf->fd) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
			*buf->fd = *(int*)CMSG_DATA(cmsg);
			buf->fd = NULL;
		}
	}

	// have we received the header? we need to get ready for more data
	buf->recv_count += received;
	if (buf->recv_count >= sizeof(ns_hdr) && !buf->hdr_received) {
		buf->hdr_received = true;
		size_t size = be32toh(buf->hdr->size);
		if (size < sizeof(ns_hdr)) {
			errno = EPROTO;
			return false;
		}
		size -=  sizeof(ns_hdr);

		// larger than expected? start treating everything like junk
		if (size > buf->body_buf_size) {
			buf->junk_remaining = size;
			return true;
		}

		buf->io[IOV_BODY].iov_len = size;
		buf->ioptr.count++;
	}
	buf->complete = is_ioptr_complete(&buf->ioptr);
	return true;
}

bool ns_recv_blocking(int sockfd, ns_hdr* hdr, void *body, size_t body_size, int *fd, bool *eof){
	msg_reader buf;
	bool ok;
	ns_recv_start(&buf, sockfd, hdr, body, body_size, fd);
	do {
		ok = ns_recv(&buf);
	} while (ok && !buf.complete);
	*eof = buf.eof;
	return ok;
}
