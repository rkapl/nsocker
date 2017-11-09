#pragma once
#include <stdint.h>

#define NS_MAX_MSG_SIZE 0xFF

typedef struct {
	uint32_t size;
	uint32_t id;
	uint32_t cmd;
} ns_hdr;

typedef enum {
	NS_TSOCKET,
	NS_RSOCKET,
	NS_RUNKNOWN,
	NS_RBADSIZE,
	NS_MALFORMED
} ns_cmd;

typedef struct {
	int32_t domain;
	int32_t type;
	int32_t protocol;
} ns_tsocket;

typedef struct {
	/* A file descriptor of the socket is attached to the packet if errno = 0 */
	int32_t error;
} ns_rsocket;
