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

#pragma once

#include "sol-coap.h"
#include "sol-oic-client.h"
#include "sol-oic-common.h"
#include "sol-str-slice.h"

struct sol_oic_security;

enum sol_oic_security_pair_result {
    SOL_OIC_PAIR_SUCCESS,
    SOL_OIC_PAIR_ERROR_ALREADY_OWNED,
    SOL_OIC_PAIR_ERROR_PAIR_FAILURE
};

struct sol_oic_security *sol_oic_server_security_add(
    struct sol_coap_server *server, struct sol_coap_server *server_dtls);
void sol_oic_server_security_del(struct sol_oic_security *security);

struct sol_oic_security *sol_oic_client_security_add(
    struct sol_coap_server *server, struct sol_coap_server *server_dtls);
void sol_oic_client_security_del(struct sol_oic_security *security);

bool sol_oic_security_get_is_paired(const struct sol_oic_security *security,
    struct sol_str_slice device_id);
int sol_oic_security_pair_request(struct sol_oic_security *security,
    struct sol_oic_resource *resource,
    void (*paired_cb)(void *data, enum sol_oic_security_pair_result result), void *data);

bool sol_oic_set_token_and_mid(struct sol_coap_packet *pkt, int64_t *token);
