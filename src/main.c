/*
 * BTHost
 * Written 2012 by David Herrmann <dh.herrmann@googlemail.com>
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include "eloop.h"
#include "log.h"
#include "protocol.h"

#define LOG_SUBSYSTEM "bthost"

static void sig_generic(struct ev_eloop *p, struct signalfd_siginfo *info,
			void *data)
{
	struct ev_eloop *eloop = data;

	ev_eloop_exit(eloop);
	log_info("terminating due to caught signal %d", info->ssi_signo);
}

int main(int argc, char **argv)
{
	struct ev_eloop *eloop;
	int ret;
	struct bth_server *server;
	const char *addr;

	log_set_config(&LOG_CONFIG_INFO(1, 1));
	log_print_init("moind");

	ret = ev_eloop_new(&eloop, log_llog);
	if (ret)
		goto out;

	ret = ev_eloop_register_signal_cb(eloop, SIGTERM, sig_generic, eloop);
	if (ret)
		goto out_eloop;

	ret = ev_eloop_register_signal_cb(eloop, SIGINT, sig_generic, eloop);
	if (ret)
		goto out_sigterm;

	if (argc < 2)
		addr = NULL;
	else
		addr = argv[1];

	ret = bth_server_new(&server, eloop, addr, 8);
	if (ret)
		goto out_sigint;

	ev_eloop_run(eloop, -1);

	bth_server_free(server);
out_sigint:
	ev_eloop_unregister_signal_cb(eloop, SIGINT, sig_generic, eloop);
out_sigterm:
	ev_eloop_unregister_signal_cb(eloop, SIGTERM, sig_generic, eloop);
out_eloop:
	ev_eloop_unref(eloop);
out:
	if (ret)
		log_err("failed, error %d: %s", ret, strerror(-ret));
	return -ret;
}
