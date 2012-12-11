/*
 * BTHost
 * Written 2012 by David Herrmann <dh.herrmann@googlemail.com>
 */

#ifndef BTH_PROTOCOL_H
#define BTH_PROTOCOL_H

#include <stdlib.h>
#include "eloop.h"

struct bth_server;

int bth_server_new(struct bth_server **out,
		   struct ev_eloop *eloop,
		   const char *addr,
		   unsigned int channel);
void bth_server_free(struct bth_server *s);

#endif /* BTH_PROTOCOL_H */
