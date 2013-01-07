/*
 * BTHost
 * Written 2012 by David Herrmann <dh.herrmann@googlemail.com>
 */

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "eloop.h"
#include "log.h"
#include "protocol.h"
#include "shl_array.h"
#include "shl_dlist.h"
#include "shl_ring.h"

#define LOG_SUBSYSTEM "protocol"

enum proto_id {
	PROTO_ID_ERROR = 0,
	PROTO_ID_SERVICELIST = 1,
	PROTO_ID_LIGHT = 2,
	PROTO_ID_BARTTERY = 3,
	PROTO_ID_EMERGENCY = 4,
	PROTO_ID_ROOM = 5,
	PROTO_ID_PHONE = 6,
	PROTO_ID_MAP = 7,
	PROTO_ID_QUIZ = 8,
};

struct bth_client {
	struct bth_server *server;
	struct shl_dlist list;
	int sock;
	struct ev_fd *fd;
	struct shl_ring *buf;
	struct shl_array *input;
};

struct bth_server {
	struct ev_eloop *eloop;
	int sock;
	struct ev_fd *fd;

	struct shl_dlist clients;
	char *map;
	size_t map_len;
};

static void client_free(struct bth_client *client);

static void client_write_pkg(struct bth_client *client,
			     uint8_t type,
			     uint16_t size,
			     const uint8_t *payload)
{
	uint8_t buf[3], crc;
	unsigned int i;

	crc = 0;
	buf[0] = type;
	*((uint16_t*)&buf[1]) = htole16(size);

	/* write header */
	shl_ring_write(client->buf, (void*)buf, sizeof(buf));
	for (i = 0; i < 3; ++i)
		crc ^= buf[i];

	/* write payload */
	if (size) {
		shl_ring_write(client->buf, (void*)payload, size);
		for (i = 0; i < size; ++i)
			crc ^= payload[i];
	}

	/* write checksum */
	shl_ring_write(client->buf, (void*)&crc, sizeof(crc));

	ev_fd_update(client->fd, EV_READABLE | EV_WRITEABLE);
	log_debug("client %p: queue pkg t: %d s: %d c: %d p: %s",
		  client, (int)type, (int)size, (int)crc, (char*)payload);
}

static void client_write_introduction(struct bth_client *client)
{
	uint8_t service_ids[] = {
		PROTO_ID_ERROR,
		PROTO_ID_SERVICELIST,
		PROTO_ID_PHONE,
		PROTO_ID_ROOM,
		PROTO_ID_MAP,
		PROTO_ID_QUIZ,
	};

	client_write_pkg(client, PROTO_ID_SERVICELIST, sizeof(service_ids),
			 service_ids);
}

static void client_write_phone(struct bth_client *client, const char *phone)
{
	client_write_pkg(client, PROTO_ID_PHONE, strlen(phone), (void*)phone);
}

static void client_write_room(struct bth_client *client, const char *start,
			      const char *end, const char *name)
{
	int len1 = strlen(start), len2 = strlen(end), len3 = strlen(name);
	char buf[len1 + len2 + len3];

	if (len1 != 4 || len2 != 4)
		log_warning("invalid time-length %d %d in outgoing ROOM message",
			    len1, len2);

	memcpy(buf, start, len1);
	memcpy(&buf[len1], end, len2);
	memcpy(&buf[len2], name, len3);

	client_write_pkg(client, PROTO_ID_ROOM, len1 + len2 + len3, (void*)buf);
}

static void client_write_map(struct bth_client *client)
{
	client_write_pkg(client, PROTO_ID_MAP, client->server->map_len,
			 (void*)client->server->map);
}

static void client_write_quiz(struct bth_client *client)
{
	static const char *list[] = {
		"PI ist ...;3.14159265;3.14159263;3.14159267;3.14159261;1",
		"sum(2i, i = 1 -> n) = ?;(n+1)n/2;(n+1)n;(n-1)n/2;(n-1)n;2",
		"differentiate(cos(x), x) = ?;sin(x);-sin(x);none;none;2",
		"differentiate(sin(x), x) = ?;cos(x);-cos(x);none;none;1",
		"integrate(ln(1-x), x)-c = ?;(1-x)ln(x-1)-x;"
			"(1-x)ln(1-x)-x;(x-1)ln(x-1)-x;(x-1)ln(1-x)-x;4",
		"1 - (j-1)/j = ?;1/j;1/(j+1);(j-1);j/(j+1);1",
		"Which is not e?;none;cos(-i) + i * sin(-i);"
			"integrate(e^x, x = -inf -> 1);lim(n / n!^(1/n), n -> inf);"
			"lim((1 + 1/n)^n, n -> inf);sum((i-1)^2 / i!, i = 0 -> inf);"
			"sum(1 / i!, i = 0 -> inf);~2.718281828",
		"Guess right!;here;here;here;here;3",
	};
	static size_t llen = sizeof(list) / sizeof(*list);
	unsigned int pos = rand() % llen;

	client_write_pkg(client, PROTO_ID_QUIZ, strlen(list[pos]),
			 (void*)list[pos]);
}

static void client_handle_phone(struct bth_client *client, uint16_t len,
				const uint8_t *payload)
{
	log_notice("client %p: received PHONE request", client);

	if (len != 0)
		log_warning("client %p: received PHONE request with invalid length %d",
			    client, len);

	client_write_phone(client, "07071 204 - 1300");
}

static void client_handle_room(struct bth_client *client, uint16_t len,
			       const uint8_t *payload)
{
	log_notice("client %p: received ROOM request", client);

	if (len != 0)
		log_warning("client %p: received ROOM request with invalid length %d",
			    client, len);

	client_write_room(client, "1215", "1345", "Dinner!");
}

static void client_handle_map(struct bth_client *client, uint16_t len,
			      const uint8_t *payload)
{
	log_notice("client %p: received MAP request", client);

	if (len != 0)
		log_warning("client %p: received MAP request with invalid length %d",
			    client, len);

	client_write_map(client);
}

static void client_handle_quiz(struct bth_client *client, uint16_t len,
			       const uint8_t *payload)
{
	log_notice("client %p: received QUIZ request", client);

	if (len != 0)
		log_warning("client %p: received QUIZ request with invalid length %d",
			    client, len);

	client_write_quiz(client);
}

static void client_handle(struct bth_client *client, uint8_t type, uint16_t len,
			  const uint8_t *payload, uint8_t crc)
{
	uint8_t rcrc;
	unsigned int i;

	log_notice("client %p: Received package:\n"
		   "  Type: %d\n"
		   "  Length: %d\n"
		   "  Payload: %s\n"
		   "  CRC: %x\n",
		   client, (int)type, (int)len, payload, (int)crc);

	rcrc = type ^ (len & 0x00ff) ^ (len & 0xff00);
	for (i = 0; i < len; ++i)
		rcrc ^= payload[i];

	if (rcrc != crc)
		log_warning("CRC failure: %d != %d", (int)crc, (int)rcrc);

	switch (type) {
	case PROTO_ID_PHONE:
		client_handle_phone(client, len, payload);
		break;
	case PROTO_ID_ROOM:
		client_handle_room(client, len, payload);
		break;
	case PROTO_ID_MAP:
		client_handle_map(client, len, payload);
		break;
	case PROTO_ID_QUIZ:
		client_handle_quiz(client, len, payload);
		break;
	default:
		log_warning("client %p: unknown type %d", client, (int)type);
		break;
	}
}

static void client_parse(struct bth_client *client, const char *buf, size_t s)
{
	int ret, i;
	uint8_t *data;
	size_t size;
	uint16_t length;

	for (i = 0; i < s; ++i) {
		log_notice("received byte %d", buf[i]);
		ret = shl_array_push(client->input, &buf[i]);
		if (ret) {
			log_error("client %p: cannot grow input buffer",
				  client);
			return;
		}

		data = shl_array_get_array(client->input);
		size = shl_array_get_length(client->input);
		if (size < 4)
			continue;

		length = le16toh(*(const uint16_t*)&data[1]);
		if (size < length + 4)
			continue;

		client_handle(client, data[0], length, &data[3],
			      data[3 + length]);
		shl_array_reset(client->input);
	}
}

static void client_event(struct ev_fd *fd, int mask, void *data)
{
	struct bth_client *client = data;
	const char *out;
	size_t len;
	int ret;
	char buf[4096];

	if (mask & (EV_HUP | EV_ERR)) {
		log_info("client %p: close due to HUP/ERR", client);
		client_free(client);
		return;
	}

	if (mask & (EV_WRITEABLE)) {
		out = shl_ring_peek(client->buf, &len, 0);
		if (out && len) {
			ret = write(client->sock, out, len);
			if (ret < 0) {
				log_warning("client %p: write error (%d): %m",
					    client, errno);
			} else {
				log_notice("client %p: wrote message (%d): %s",
					   client, ret, out);
				shl_ring_drop(client->buf, ret);
			}
		}

		if (shl_ring_is_empty(client->buf))
			ev_fd_update(client->fd, EV_READABLE);
	}

	if (mask & (EV_READABLE)) {
		ret = read(client->sock, buf, sizeof(buf));
		if (ret == 0) {
			log_warning("client %p: read HUP",
				    client);
		} else if (ret < 0) {
			log_warning("client %p: read error (%d): %m",
				    client, errno);
		} else {
			log_notice("client %p: received %d bytes",
				   client, ret);
			client_parse(client, buf, ret);
		}
	}
}

static void client_new(struct bth_server *s, int sock, const char *name)
{
	struct bth_client *client;
	int ret;

	client = malloc(sizeof(*client));
	if (!client)
		goto err_close;

	log_notice("client %p: new from %s", client, name);

	memset(client, 0, sizeof(*client));
	client->sock = sock;
	client->server = s;

	ret = shl_ring_new(&client->buf);
	if (ret)
		goto err_free;

	ret = shl_array_new(&client->input, sizeof(uint8_t), 512);
	if (ret)
		goto err_ring;

	ret = ev_eloop_new_fd(s->eloop, &client->fd, client->sock,
			      EV_READABLE,
			      client_event, client);
	if (ret)
		goto err_input;

	shl_dlist_link(&s->clients, &client->list);
	client_write_introduction(client);
	return;

err_input:
	shl_array_free(client->input);
err_ring:
	shl_ring_free(client->buf);
err_free:
	free(client);
err_close:
	close(sock);
}

static void client_free(struct bth_client *client)
{
	log_notice("client %p: free", client);
	shl_dlist_unlink(&client->list);
	ev_eloop_rm_fd(client->fd);
	close(client->sock);
	shl_array_free(client->input);
	shl_ring_free(client->buf);
	free(client);
}

static void server_event(struct ev_fd *fd, int mask, void *data)
{
	struct bth_server *s = data;
	struct sockaddr_rc addr;
	socklen_t len;
	char buf[18];
	int client;

	if (mask & (EV_HUP | EV_ERR)) {
		log_err("server socket closed unexpectedly");
		ev_eloop_exit(s->eloop);
		return;
	}

	len = sizeof(addr);
	client = accept4(s->sock, (struct sockaddr*)&addr, &len,
			 SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (client < 0) {
		log_err("cannot accept client (%d): %m", errno);
		return;
	}

	ba2str(&addr.rc_bdaddr, buf);
	buf[sizeof(buf) - 1] = 0;
	client_new(s, client, buf);
}

static char *read_file(const char *path, size_t *size)
{
	FILE *ffile;
	ssize_t len;
	char *buf;

	ffile = fopen(path, "rb");
	if (!ffile) {
		log_error("cannot open file %s (%d): %m", path, errno);
		return NULL;
	}

	if (fseek(ffile, 0, SEEK_END) != 0) {
		log_error("cannot seek %s (%d): %m", path, errno);
		fclose(ffile);
		return NULL;
	}

	len = ftell(ffile);
	if (len < 0) {
		log_error("cannot tell %s (%d): %m", path, errno);
		fclose(ffile);
		return NULL;
	}

	if (len < 1) {
		log_error("empty file %s (%d): %m", path, errno);
		fclose(ffile);
		return NULL;
	}

	rewind(ffile);

	buf = malloc(len + 1);
	if (!buf) {
		log_error("memory allocation failed");
		fclose(ffile);
		return NULL;
	}

	if (len != fread(buf, 1, len, ffile)) {
		log_error("cannot read %s (%d): %m", path, errno);
		free(buf);
		fclose(ffile);
		return NULL;
	}

	buf[len] = 0;
	*size = len;
	fclose(ffile);

	return buf;
}

int bth_server_new(struct bth_server **out,
		   struct ev_eloop *eloop,
		   const char *srcaddr,
		   unsigned int channel)
{
	struct bth_server *s;
	int ret;
	struct sockaddr_rc addr;

	if (!out || !eloop || channel < 0 || channel > 20)
		return -EINVAL;

	s = malloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	memset(s, 0, sizeof(*s));
	s->eloop = eloop;
	shl_dlist_init(&s->clients);

	log_info("creating RFCOMM server socket on %s:%u", srcaddr, channel);
	s->sock = socket(AF_BLUETOOTH,
			 SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			 BTPROTO_RFCOMM);
	if (s->sock < 0) {
		log_err("cannot create socket (%d): %m", errno);
		ret = -EFAULT;
		goto err_free;
	}

	memset(&addr, 0, sizeof(addr));
	if (srcaddr)
		str2ba(srcaddr, &addr.rc_bdaddr);
	else
		addr.rc_bdaddr = *BDADDR_ANY;
	addr.rc_family = AF_BLUETOOTH;
	addr.rc_channel = channel;
	ret = bind(s->sock, (struct sockaddr*)&addr, sizeof(addr));
	if (ret) {
		log_err("cannot bind socket (%d): %m", errno);
		ret = -EFAULT;
		goto err_close;
	}

	log_info("creating listener socket");
	ret = listen(s->sock, 10);
	if (ret) {
		log_err("cannot set listening mode (%d): %m", errno);
		ret = -EFAULT;
		goto err_close;
	}

	ret = ev_eloop_new_fd(s->eloop, &s->fd, s->sock, EV_READABLE,
			      server_event, s);
	if (ret)
		goto err_close;

	log_info("reading map-file 'map.png'");
	s->map = read_file("test.png", &s->map_len);
	if (!s->map) {
		log_error("cannot read map file 'map.png'");
		goto err_eloop;
	}

	ev_eloop_ref(s->eloop);
	*out = s;
	return 0;

err_eloop:
	ev_eloop_rm_fd(s->fd);
err_close:
	close(s->sock);
err_free:
	free(s);
	return ret;
}

void bth_server_free(struct bth_server *s)
{
	struct bth_client *client;

	if (!s)
		return;

	log_info("free RFCOMM server socket");
	while (s->clients.next != &s->clients) {
		client = shl_dlist_entry(s->clients.next,
					 struct bth_client,
					 list);
		client_free(client);
	}

	free(s->map);
	ev_eloop_rm_fd(s->fd);
	close(s->sock);
	ev_eloop_unref(s->eloop);
	free(s);
}
