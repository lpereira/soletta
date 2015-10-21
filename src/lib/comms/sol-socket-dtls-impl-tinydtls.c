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

struct sol_socket *sol_socket_dtls_wrap_socket(struct sol_socket *to_wrap);

struct sol_socket_dtls {
    struct sol_socket base;
    struct sol_socket *wrapped;
    struct sol_timeout *retransmit_timeout;
    dtls_context_t *context;

    struct {
        bool (*cb)(void *data, struct sol_socket *s);
        const void *data;

        struct sol_buffer buf;
        struct sol_network_link_addr addr;
    } read, write;

    bool bound;
};

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
    session->size = sizeof(session->addr.sa);

    return to_sockaddr(&addr, &session->addr.sa, &session->size) == 0;
}

static void
sol_socket_dtls_del(struct sol_socket *socket)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    sol_socket_del(s->wrapped);
    sol_buffer_fini(&s->read.buf);
    sol_buffer_fini(&s->write.buf);
    dtls_free_context(s->context);
    free(s);
}

static int
sol_socket_dtls_set_on_read(struct sol_socket *socket, bool (*cb)(void *data, struct sol_socket *s), void *data)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    s->read.cb = cb;
    s->read.data = data;

    return 0;
}

static int
sol_socket_dtls_set_on_write(struct sol_socket *socket, bool (*cb)(void *data, struct sol_socket *s), void *data)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    s->write.cb = cb;
    s->write.data = data;

    return 0;
}

static bool
connect_if_needed(const struct sol_socket_dtls *s,
    const struct sol_network_link_addr *addr)
{
    session_t session;
    int r;

    if (s->bound)
        return false;

    if (!session_from_linkaddr(addr, &session))
        return false;

    r = dtls_connect(s->context, &session);
    if (r < 0) {
        SOL_ERR("Could not establish DTLS channel for socket %p", s);
        return false;
    }

    if (r == 0)
        SOL_DBG("DTLS channel already stablished for socket %p", s);
    else
        SOL_DBG("DTLS channel being stablished for socket %p", s);

    return true;
}

static int
sol_socket_dtls_recvmsg(struct sol_socket *socket, void *buf, size_t len, struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    memcpy(cliaddr, &s->read.addr, sizeof(s->read.addr));
    memset(&s->read.addr, 0, sizeof(s->read.addr));

    memcpy(buf, s->read.buf.data, s->read.buf.used);
    sol_buffer_reset(&s->read.buf);

    return 0;
}

static int
sol_socket_dtls_sendmsg(struct sol_socket *socket, const void *buf, size_t len,
    const struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    if (!connect_if_needed(s, cliaddr)) {
        SOL_WRN("Could not establish DTLS channel");
        return -ENOTCONN;
    }

    memcpy(&s->write.addr, cliaddr, sizeof(s->write.addr));
    if (sol_buffer_set_slice(&s->write.buf, SOL_STR_SLICE_STR(buf, len)) < 0)
        return -ENOMEM;

    return 0;
}

static int
sol_socket_dtls_join_group(struct sol_socket *socket, int ifindex, const struct sol_network_link_addr *group)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;

    return sol_socket_join_group(s->wrapped, ifindex, group);
}

static int
sol_socket_dtls_bind(struct sol_socket *socket, const struct sol_network_link_addr *addr)
{
    struct sol_socket_dtls *s = (struct sol_socket_dtls *)socket;
    int r;

    r = sol_socket_bind(s->wrapped, addr);
    if (!r)
        s->bound = true;

    return r;
}

static void
init_dtls_if_needed(void)
{
    static bool initialized = false;

    if (!initialized) {
        dtls_init();
        initialized = true;
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

    len = sol_socket_recvmsg(wrapped, buf, sizeof(buf), &cliaddr);
    SOL_INT_CHECK(len, < 0, false);

    session.size = sizeof(session.addr.sa);
    if (to_sockaddr(&cliaddr, &session.addr.sa, &session.size) < 0)
        return false;

    return dtls_handle_message(socket->context, &session, buf, len) == 0;
}

static int
call_user_read_cb(struct dtls_context_t *ctx, session_t *session, uint8_t *buf, size_t len)
{
    struct sol_socket_dtls *socket = dtls_get_app_data(ctx);
    struct sol_str_slice slice;

    if (!socket->read.cb)
        return -EINVAL;

    slice = SOL_STR_SLICE_STR((const char *)buf, len);
    if (sol_buffer_set_slice(&socket->read.buf, slice) < 0)
        return -ENOMEM;

    if (from_sockaddr(&session->addr.sa, session->size, &socket->read.addr) < 0)
        return -EINVAL;

    return socket->read.cb(socket->read.data, socket) ? 0 : -EINVAL;
}

/* Called whenever the wrapped socket can be written to. This gets the
 * unencrypted data previously set with sol_socket_sendmsg() and cached in
 * the sol_socket_dtls struct, passes through TinyDTLS, and when it's done
 * encrypting the payload, it calls sol_dtls_write() to finally pass it to
 * the wire.  */
static bool
encrypt_payload(void *data, struct sol_socket *wrapped)
{
    struct sol_socket_dtls *socket = data;
    session_t session;
    int r;

    if (!session_from_linkaddr(&socket->write.addr, &session))
        return false;

    r = dtls_write(socket->context, &session, &socket->write.buf.data,
        socket->write.buf.used);

    sol_buffer_reset(&socket->write.buf);
    memset(&socket->write.addr, 0, sizeof(socket->write.addr));

    return r == 0;
}

static int
write_encrypted(struct dtls_context_t *ctx, session_t *session, uint8_t *buf, size_t len)
{
    struct sol_socket_dtls *socket = dtls_get_app_data(ctx);
    struct sol_network_link_addr addr;

    if (from_sockaddr(&session->addr.sa, session->size, &addr) < 0)
        return -EINVAL;

    if (!connect_if_needed(socket, &addr))
        return -ENOTCONN;

    return sol_socket_sendmsg(socket->wrapped, buf, len, &addr);
}

static bool
call_user_write_cb(void *data, struct sol_socket *wrapped)
{
    struct sol_socket_dtls *socket = data;

    if (socket->write.cb && socket->write.cb(data, socket))
        return encrypt_payload(data, wrapped);

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

    if (s->retransmit_timeout)
        retransmit_timer_disable(s);

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
        SOL_WRN("DTLS warning for socket %p: %s", socket, msg);
    } else if (level == DTLS_ALERT_LEVEL_FATAL) {
        SOL_ERR("DTLS fatal error for socket %p: %s", socket, msg);
    } else {
        SOL_DBG("DTLS session changed for socket %p: %s", socket, msg);
    }

    retransmit_timer_check(socket);

    return 0;
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
    static dtls_handler_t dtls_handler = {
        .write = write_encrypted,
        .read = call_user_read_cb,
        .event = handle_dtls_event
    };

    struct sol_socket_dtls *socket;

    socket = malloc(sizeof(*socket));
    SOL_NULL_CHECK(socket, NULL);

    init_dtls_if_needed();

    socket->context = dtls_new_context(socket);
    if (!socket->context)
        goto dtls_new_context_error;

    dtls_set_handler(socket->context, &dtls_handler);

    socket->retransmit_timeout = NULL;
    socket->base.impl = &impl;
    socket->wrapped = to_wrap;
    socket->bound = false;

    if (sol_socket_set_on_read(socket->wrapped, read_encrypted, socket) < 0)
        goto set_cb_error;

    if (sol_socket_set_on_write(socket->wrapped, call_user_write_cb, socket) < 0)
        goto set_cb_error;

    /* FIXME: Limit the buffer capacity? */
    sol_buffer_init(&socket->read.buf);
    sol_buffer_init(&socket->write.buf);

    return &socket->base;

set_cb_error:
    dtls_free_context(socket->context);

dtls_new_context_error:
    free(socket);
    return NULL;
}
