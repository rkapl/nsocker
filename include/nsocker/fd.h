#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "msg.h"
#include <sys/uio.h>

#define NS_NULL_FD -1

void ns_hdr_set(ns_hdr *hdr, ns_cmd cmd, size_t body_size);
bool ns_send_blocking(int sockfd, ns_hdr* hdr, void *body, int fd);
bool ns_recv_blocking(int sockfd, ns_hdr* hdr, void *body, size_t body_size, int *fd, bool *eof);
