/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "sol-log.h"
#include "sol-mainloop.h"
#include "sol-network.h"
#include "sol-util.h"

#include "sol-socket.h"
#include "sol-socket-impl.h"

#include "dtls.h"

#define DTLS_PSK_ID_LEN 16
#define DTLS_PSK_KEY_LEN 16

struct sol_socket *sol_socket_dtls_wrap_socket(struct sol_socket *to_wrap);

struct queue_item {
    struct sol_buffer buffer;
    struct sol_network_link_addr addr;
};

struct sol_socket_dtls {
    struct sol_socket base;
    struct sol_socket *wrapped;
    struct sol_timeout *retransmit_timeout;
    dtls_context_t *context;

    struct {
        bool (*cb)(void *data, struct sol_socket *s);
        const void *data;
        struct sol_vector queue;
    } read, write;
};

struct cred_item {
    char *id;
    char *psk;
};

struct creds {
    struct sol_vector items;
    char *id;
};

#include <ctype.h>
#include <stdio.h>
static void
printdump(const void *ptr, size_t len)
{
    unsigned char *p = ptr;
    size_t i;

    putchar(' ');
    putchar(' ');

    for (i = len; i < 16; i++)
        printf("   ");

    if (len < 8)
        putchar(' ');

    for (i = 0; i < len; i++) {
        if (isprint(p[i]))
            printf("\033[0;34m%c\033[0m", p[i]);
        else
            putchar('.');

        if (i == 7)
            putchar(' ');
    }

    putchar('\n');
}

static void
hexdump(const void *ptr, size_t len)
{
    static const char hexdigits[] = "0123456789abcdef";
    unsigned char *p = ptr;
    size_t i;
    size_t bytes = 0;

    printf("Hexdumping %zu bytes:\n", len);
    printf("\033[0;32m          0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\033[0m\n");
    for (i = 0; i < len; i++, bytes++) {
        switch (bytes) {
        case 0:
            printf("\033[0;32m%8lx\033[0m ", i);
            break;
        case 8:
            putchar(' ');
            break;
        case 16:
            printdump(p + i - 16, 16);
            printf("\033[0;32m%8lx\033[0m ", i);
            bytes = 0;
            break;
        }

        if (isprint(p[i]))
            printf("\033[0;34m");

        putchar(hexdigits[p[i] >> 4]);
        putchar(hexdigits[p[i] & 0xf]);

        if (isprint(p[i]))
            printf("\033[0m");

        putchar(' ');
    }

    if (bytes)
        printdump(p + i - bytes, bytes);

    printf("End of hexdump\n");
}

static int
from_sockaddr(const struct sockaddr *sockaddr, socklen_t socklen,
    struct sol_network_link_addr *addr)
{
    SOL_NULL_CHECK(sockaddr, -EINVAL);
    SOL_NULL_CHECK(addr, -EINVAL);

    addr->family = sockaddr->sa_family;

    if (sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sock4 = (struct sockaddr_in *)sockaddr;
        if (socklen < sizeof(struct sockaddr_in))
            return -EINVAL;

        addr->port = ntohs(sock4->sin_port);
        memcpy(&addr->addr.in, &sock4->sin_addr, sizeof(sock4->sin_addr));
    } else if (sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sock6 = (struct sockaddr_in6 *)sockaddr;
        if (socklen < sizeof(struct sockaddr_in6))
            return -EINVAL;

        addr->port = ntohs(sock6->sin6_port);
        memcpy(&addr->addr.in6, &sock6->sin6_addr, sizeof(sock6->sin6_addr));
    } else {
        return -EINVAL;
    }

    return 0;
}

static int
to_sockaddr(const struct sol_network_link_addr *addr, struct sockaddr *sockaddr, socklen_t *socklen)
{
    SOL_NULL_CHECK(addr, -EINVAL);
    SOL_NULL_CHECK(sockaddr, -EINVAL);
    SOL_NULL_CHECK(socklen, -EINVAL);

    if (addr->family == AF_INET) {
        struct sockaddr_in *sock4 = (struct sockaddr_in *)sockaddr;
        if (*socklen < sizeof(struct sockaddr_in))
            return -EINVAL;

        memcpy(&sock4->sin_addr, addr->addr.in, sizeof(addr->addr.in));
        sock4->sin_port = htons(addr->port);
        sock4->sin_family = AF_INET;
        *socklen = sizeof(*sock4);
    } else if (addr->family == AF_INET6) {
        struct sockaddr_in6 *sock6 = (struct sockaddr_in6 *)sockaddr;
        if (*socklen < sizeof(struct sockaddr_in6))
            return -EINVAL;

        memcpy(&sock6->sin6_addr, addr->addr.in6, sizeof(addr->addr.in6));
        sock6->sin6_port = htons(addr->port);
        sock6->sin6_family = AF_INET6;
        *socklen = sizeof(*sock6);
    } else {
        return -EINVAL;
    }

    return *socklen;
}

static bool
session_from_linkaddr(const struct sol_network_link_addr *addr,
    session_t *session)
{
    memset(session, 0, sizeof(*session));
    session->size = sizeof(session->addr);

    return to_sockaddr(addr, &session->addr.sa, &session->size) >= 0;
}

static void
sol_socket_dtls_del(struct sol_socket *socket)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    sol_socket_del(s->wrapped);
    sol_vector_clear(&s->read.queue);
    sol_vector_clear(&s->write.queue);

    dtls_free_context(s->context);

    free(s);
}

static int
sol_socket_dtls_recvmsg(struct sol_socket *socket, void *buf, size_t len, struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;
    struct queue_item *item;

    if (s->read.queue.len == 0) {
        SOL_DBG("Receive queue empty, returning 0");
        return -1;
    }

    item = sol_vector_get(&s->read.queue, 0);
    if (!item) {
        SOL_DBG("Could not get first item in queue");
        return -1;
    }

    memcpy(cliaddr, &item->addr, sizeof(*cliaddr));

    if (item->buffer.used <= len) {
        memcpy(buf, item->buffer.data, item->buffer.used);
        sol_vector_del(&s->read.queue, 0);

        return (int)item->buffer.used;
    }

    memcpy(buf, item->buffer.data, len);
    item->buffer.data = (char *)item->buffer.data + len;
    item->buffer.used -= len;

    return (int)len;
}

static int
sol_socket_dtls_sendmsg(struct sol_socket *socket, const void *buf, size_t len,
    const struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;
    struct queue_item *item;

    if (s->write.queue.len > 16) {
        SOL_WRN("Transmission queue too long");
        return -ENOMEM;
    }

    item = sol_vector_append(&s->write.queue);
    SOL_NULL_CHECK(item, -ENOMEM);

    item->addr = *cliaddr;
    sol_buffer_init_flags(&item->buffer, buf, len, SOL_BUFFER_FLAGS_FIXED_CAPACITY | SOL_BUFFER_FLAGS_NO_NUL_BYTE);

    return (int)len;
}

static int
sol_socket_dtls_join_group(struct sol_socket *socket, int ifindex, const struct sol_network_link_addr *group)
{
    /* DTLS servers are unicast only */
    return 0;
}

static int
sol_socket_dtls_bind(struct sol_socket *socket, const struct sol_network_link_addr *addr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    return sol_socket_bind(s->wrapped, addr);
}

static void
init_dtls_if_needed(void)
{
    static bool initialized = false;

    if (!initialized) {
        dtls_init();
        initialized = true;
        SOL_DBG("TinyDTLS initialized");
    }
}

/* Called whenever the wrapped socket can be read. This receives a packet
 * from that socket, and passes to TinyDTLS. When it's done decrypting
 * the payload, dtls_handle_message() will call sol_dtls_read(), which
 * in turn will call the user callback with the decrypted data. */
static bool
read_encrypted(void *data, struct sol_socket *wrapped)
{
    struct sol_socket_dtls *socket = data;
    struct sol_network_link_addr cliaddr;
    session_t session = { 0 };
    uint8_t buf[DTLS_MAX_BUF];
    int len;

    SOL_DBG("Reading encrypted data from wrapped socket");

    len = sol_socket_recvmsg(wrapped, buf, sizeof(buf), &cliaddr);
    SOL_INT_CHECK(len, < 0, false);

    SOL_DBG("Got %d encrypted bytes, passing to TinyDTLS for decryption",
        len);
    hexdump(buf, len);

    session.size = sizeof(session.addr);
    if (to_sockaddr(&cliaddr, &session.addr.sa, &session.size) < 0)
        return false;

    return dtls_handle_message(socket->context, &session, buf, len) == 0;
}

static int
call_user_read_cb(struct dtls_context_t *ctx, session_t *session, uint8_t *buf, size_t len)
{
    struct sol_socket_dtls *socket = dtls_get_app_data(ctx);

    SOL_DBG("Decrypted data@%p (len %zu), user callback@%p", buf, len,
        socket->read.cb);
    hexdump(buf, len);

    if (!socket->read.cb)
        return -EINVAL;

    if (socket->read.cb(socket->read.data, socket))
        return 0;

    return -EINVAL;
}

/* Called whenever the wrapped socket can be written to. This gets the
 * unencrypted data previously set with sol_socket_sendmsg() and cached in
 * the sol_socket_dtls struct, passes through TinyDTLS, and when it's done
 * encrypting the payload, it calls sol_socket_sendmsg() to finally pass it
 * to the wire.  */
static bool
encrypt_payload(void *data, struct sol_socket *wrapped)
{
    struct sol_socket_dtls *socket = data;
    struct queue_item *item;
    dtls_peer_t *peer;
    session_t session;
    int r;

    item = sol_vector_get(&socket->write.queue, 0);
    if (!item) {
        SOL_WRN("Write transmission queue empty");
        return false;
    }

    if (!session_from_linkaddr(&item->addr, &session)) {
        SOL_DBG("Could not create create session from link address");
        return false;
    }

    peer = dtls_get_peer(socket->context, &session);
    if (!peer) {
        SOL_DBG("Unkonwn peer, trying to establish connection");

        r = dtls_connect(socket->context, &session);
        return r >= 0;
    }
    if (peer->state != DTLS_STATE_CONNECTED) {
        SOL_DBG("Peer is known but not connected, will try again");
        return true;
    }

    r = dtls_write(socket->context, &session, item->buffer.data, item->buffer.used);
    if (r < 0) {
        SOL_WRN("Could not send data through the secure channel, will try again");
        return true;
    }

    if (r < (int)item->buffer.used)
        SOL_WRN("Could not send all of the enqueued data, will discard");
    else
        SOL_DBG("Sent everything, will remove from queue");

    sol_vector_del(&socket->write.queue, 0);

    return true;
}

static int
write_encrypted(struct dtls_context_t *ctx, session_t *session, uint8_t *buf, size_t len)
{
    struct sol_socket_dtls *socket = dtls_get_app_data(ctx);
    struct sol_network_link_addr addr;

    if (from_sockaddr(&session->addr.sa, session->size, &addr) < 0) {
        SOL_DBG("Could not get link address from session");
        return -EINVAL;
    }

    SOL_DBG("Sending encrypted payload to wrapped socket");
    hexdump(buf, len);
    return sol_socket_sendmsg(socket->wrapped, buf, len, &addr);
}

static bool
call_user_write_cb(void *data, struct sol_socket *wrapped)
{
    struct sol_socket_dtls *socket = data;

    if (!socket->write.cb) {
        SOL_DBG("No wrapped write callback");
        return false;
    }

    if (socket->write.cb(socket->write.data, socket)) {
        SOL_DBG("User func@%p returned success, encrypting payload",
            socket->write.cb);

        if (encrypt_payload(data, wrapped)) {
            SOL_DBG("Data encrypted, should have been passed to the "
                "wrapped socket");
            return true;
        } else {
            SOL_DBG("Could not encrypt payload");
        }
    }

    return false;
}

static void
retransmit_timer_disable(struct sol_socket_dtls *s)
{
    if (s->retransmit_timeout) {
        SOL_DBG("Disabling DTLS retransmit timer");

        sol_timeout_del(s->retransmit_timeout);
        s->retransmit_timeout = NULL;
    }
}

static bool
retransmit_timer_cb(void *data)
{
    struct sol_socket_dtls *socket = data;

    SOL_DBG("Retransmitting DTLS packets");
    dtls_check_retransmit(socket->context, NULL);
    socket->retransmit_timeout = NULL;

    return false;
}

static void
retransmit_timer_enable(struct sol_socket_dtls *s, clock_time_t next)
{
    SOL_DBG("Next DTLS retransmission will happen in %d seconds", next);

    if (s->retransmit_timeout) {
        sol_timeout_del(s->retransmit_timeout);
        s->retransmit_timeout = NULL;
    }

    if (next < 0 || next > 3600)
        return;

    s->retransmit_timeout = sol_timeout_add(next * 1000, retransmit_timer_cb,
        socket);
}

static void
retransmit_timer_check(struct sol_socket_dtls *s)
{
    clock_time_t next_retransmit;

    dtls_check_retransmit(s->context, &next_retransmit);
    if (next_retransmit == 0)
        retransmit_timer_disable(s);
    else
        retransmit_timer_enable(s, next_retransmit);
}

static int
handle_dtls_event(struct dtls_context_t *ctx, session_t *session,
    dtls_alert_level_t level, unsigned short code)
{
    struct sol_socket_dtls *socket = dtls_get_app_data(ctx);
    const char *msg;

    if (code == DTLS_EVENT_CONNECT)
        msg = "handshake_init";
    else if (code == DTLS_EVENT_CONNECTED)
        msg = "handshake_or_renegotiation_done";
    else if (code == DTLS_EVENT_RENEGOTIATE)
        msg = "renegotiation_started";
    else if (code == DTLS_ALERT_CLOSE_NOTIFY)
        msg = "close_notify";
    else if (code == DTLS_ALERT_UNEXPECTED_MESSAGE)
        msg = "unexpected_message";
    else if (code == DTLS_ALERT_BAD_RECORD_MAC)
        msg = "bad_record_mac";
    else if (code == DTLS_ALERT_RECORD_OVERFLOW)
        msg = "record_overflow";
    else if (code == DTLS_ALERT_DECOMPRESSION_FAILURE)
        msg = "decompression_failure";
    else if (code == DTLS_ALERT_HANDSHAKE_FAILURE)
        msg = "handshake_failure";
    else if (code == DTLS_ALERT_BAD_CERTIFICATE)
        msg = "bad_certificate";
    else if (code == DTLS_ALERT_UNSUPPORTED_CERTIFICATE)
        msg = "unsupported_certificate";
    else if (code == DTLS_ALERT_CERTIFICATE_REVOKED)
        msg = "certificate_revoked";
    else if (code == DTLS_ALERT_CERTIFICATE_EXPIRED)
        msg = "certificate_expired";
    else if (code == DTLS_ALERT_CERTIFICATE_UNKNOWN)
        msg = "certificate_unknown";
    else if (code == DTLS_ALERT_ILLEGAL_PARAMETER)
        msg = "illegal_parameter";
    else if (code == DTLS_ALERT_UNKNOWN_CA)
        msg = "unknown_ca";
    else if (code == DTLS_ALERT_ACCESS_DENIED)
        msg = "access_denied";
    else if (code == DTLS_ALERT_DECODE_ERROR)
        msg = "decode_error";
    else if (code == DTLS_ALERT_DECRYPT_ERROR)
        msg = "decrypt_error";
    else if (code == DTLS_ALERT_PROTOCOL_VERSION)
        msg = "protocol_version";
    else if (code == DTLS_ALERT_INSUFFICIENT_SECURITY)
        msg = "insufficient_security";
    else if (code == DTLS_ALERT_INTERNAL_ERROR)
        msg = "internal_error";
    else if (code == DTLS_ALERT_USER_CANCELED)
        msg = "user_canceled";
    else if (code == DTLS_ALERT_NO_RENEGOTIATION)
        msg = "no_renegotiation";
    else if (code == DTLS_ALERT_UNSUPPORTED_EXTENSION)
        msg = "unsupported_extension";
    else
        msg = "unknown_event";

    if (level == DTLS_ALERT_LEVEL_WARNING) {
        SOL_WRN("\n\nDTLS warning for socket %p: %s\n\n", socket, msg);
    } else if (level == DTLS_ALERT_LEVEL_FATAL) {
        /* FIXME: What to do here? Destroy the wrapped socket? Renegotiate? */
        SOL_ERR("\n\nDTLS fatal error for socket %p: %s\n\n", socket, msg);
    } else {
        SOL_DBG("\n\nTLS session changed for socket %p: %s\n\n", socket, msg);
        if (code == DTLS_EVENT_CONNECTED) {
            struct queue_item *item;
            uint16_t idx;

            SOL_DBG("Sending %d enqueued packets in write queue", socket->write.queue.len);
            SOL_VECTOR_FOREACH_IDX (&socket->write.queue, item, idx) {
                session_t session;

                if (!session_from_linkaddr(&item->addr, &session))
                    continue;

                (void)dtls_write(socket->context, &session, item->buffer.data, item->buffer.used);
            }
            sol_vector_clear(&socket->write.queue);
        }
    }

    retransmit_timer_check(socket);

    return 0;
}

static int
sol_socket_dtls_set_on_read(struct sol_socket *socket, bool (*cb)(void *data, struct sol_socket *s), void *data)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    s->read.cb = cb;
    s->read.data = data;

    return sol_socket_set_on_read(s->wrapped, read_encrypted, socket);
}

static int
sol_socket_dtls_set_on_write(struct sol_socket *socket, bool (*cb)(void *data, struct sol_socket *s), void *data)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    s->write.cb = cb;
    s->write.data = data;

    return sol_socket_set_on_write(s->wrapped, call_user_write_cb, socket);
}

static void
clear_memory(void *buf, size_t len)
{
    memset(buf, 0, len);

    /* Clobber memory pointed to by `buf` to prevent the optimizer from
     * eliding the memset() call.  */
    asm volatile ("" : : "g" (buf) : "memory");
}

static const char *
creds_find_psk(const struct creds *creds, const char *desc, size_t desc_len)
{
    struct cred_item *iter;
    uint16_t idx;

    SOL_DBG("Looking for PSK with ID=%.*s", (int)desc_len, desc);

    SOL_VECTOR_FOREACH_IDX (&creds->items, iter, idx) {
        if (!memcmp(desc, iter->id, desc_len)) /* timingsafe_bcmp()? */
            return iter->psk;
    }

    return NULL;
}

static bool
creds_add(struct creds *creds, const char *id, size_t id_len,
    const char *psk, size_t psk_len)
{
    struct cred_item *item;
    char *psk_stored;

    psk_stored = creds_find_psk(creds, id, id_len);
    if (psk_stored) {
        if (!memcmp(psk_stored, psk, psk_len))
            return true;

        SOL_WRN("Attempting to add PSK for ID=%.*s, it's already registered "
            " and different from the supplied key", (int)id_len, id);
        return false;
    }

    item = sol_vector_append(&creds->items);
    SOL_NULL_CHECK(item, false);

    item->id = strndup(id, id_len);
    SOL_NULL_CHECK_GOTO(item->id, no_id);

    item->psk = strndup(psk, psk_len);
    SOL_NULL_CHECK_GOTO(item->psk, no_psk);

    return true;

no_psk:
    clear_memory(item->id, strlen(id));
    free(item->id);
no_id:
    clear_memory(item, sizeof(*item));
    sol_vector_del(&creds->items, creds->items.len);

    return false;
}

static void
creds_clear(struct creds *creds)
{
    struct cred_item *iter;
    uint16_t idx;

    SOL_VECTOR_FOREACH_IDX (&creds->items, iter, idx) {
        clear_memory(iter->id, DTLS_PSK_ID_LEN);
        clear_memory(iter->psk, DTLS_PSK_KEY_LEN);

        free(iter->id);
        free(iter->psk);
    }
    sol_vector_clear(&creds->items);

    clear_memory(creds->id, strlen(creds->id));
    free(creds->id);

    clear_memory(creds, sizeof(*creds));
}

static bool
creds_init(struct creds *creds)
{
    creds->id = strdup("1111111111111111");
    if (!creds->id)
        return false;

    sol_vector_init(&creds->items, sizeof(struct cred_item));

    /* FIXME: Load this information from a secure storage area somehow. */
    if (!creds_add(creds, "1111111111111111", DTLS_PSK_ID_LEN, "AAAAAAAAAAAAAAAA", DTLS_PSK_KEY_LEN)) {
        creds_clear(creds);
        return false;
    }

    return true;
}

static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
    dtls_credentials_type_t type, const char *desc, size_t desc_len,
    char *result, size_t result_len)
{
    struct creds creds;
    const char *psk;
    int r = -1;

    SOL_NULL_CHECK(result, r);

    if (!creds_init(&creds)) {
        SOL_WRN("Could not obtain PSK credentials");
        return -1;
    }

    if (type == DTLS_PSK_HINT || type == DTLS_PSK_IDENTITY) {
        if (result_len >= DTLS_PSK_ID_LEN) {
            memcpy(result, creds.id, DTLS_PSK_ID_LEN);
            r = DTLS_PSK_ID_LEN;
        } else {
            SOL_DBG("Not enough space to write PSK");
        }
        goto out;
    }

    if (desc_len != DTLS_PSK_KEY_LEN) {
        SOL_WRN("Expecting PSK key but no space to write it");
        goto out;
    }
    if (type != DTLS_PSK_KEY) {
        SOL_WRN("Expecting request for PSK, got something else instead");
        goto out;
    }
    SOL_NULL_CHECK_GOTO(desc, out);

    psk = creds_find_psk(&creds, desc, desc_len);
    if (psk) {
        memcpy(result, psk, DTLS_PSK_KEY_LEN);
        r = DTLS_PSK_KEY_LEN;
    }

out:
    creds_clear(&creds);
    return r;
}

struct sol_socket *
sol_socket_dtls_wrap_socket(struct sol_socket *to_wrap)
{
    static const struct sol_socket_impl impl = {
        .bind = sol_socket_dtls_bind,
        .join_group = sol_socket_dtls_join_group,
        .sendmsg = sol_socket_dtls_sendmsg,
        .recvmsg = sol_socket_dtls_recvmsg,
        .set_on_write = sol_socket_dtls_set_on_write,
        .set_on_read = sol_socket_dtls_set_on_read,
        .del = sol_socket_dtls_del,
        .new = NULL,
    };
    static const dtls_handler_t dtls_handler = {
        .write = write_encrypted,
        .read = call_user_read_cb,
        .event = handle_dtls_event,
        .get_psk_info = get_psk_info
    };
    struct sol_socket_dtls *socket;

    init_dtls_if_needed();

    socket = malloc(sizeof(*socket));
    SOL_NULL_CHECK(socket, NULL);

    socket->context = dtls_new_context(socket);
    if (!socket->context) {
        SOL_WRN("Could not create DTLS context");
        free(socket);
        return NULL;
    }

    dtls_set_handler(socket->context, &dtls_handler);

    socket->read.cb = NULL;
    socket->write.cb = NULL;
    socket->retransmit_timeout = NULL;
    socket->wrapped = to_wrap;
    socket->base.impl = &impl;

    sol_vector_init(&socket->write.queue, sizeof(struct queue_item));
    sol_vector_init(&socket->read.queue, sizeof(struct queue_item));

    return &socket->base;
}
