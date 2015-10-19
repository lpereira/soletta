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

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sol-coap.h"
#include "sol-json.h"
#include "sol-log.h"
#include "sol-oic-cbor.h"
#include "sol-oic-security.h"
#include "sol-oic-server.h"
#include "sol-platform.h"
#include "sol-random.h"
#include "sol-socket-dtls.h"
#include "sol-socket.h"
#include "sol-str-slice.h"
#include "sol-util-file.h"
#include "sol-util.h"
#include "sol-vector.h"

enum oxm_sel {
    OXM_JUST_WORKS,
    OXM_COUNT
};

struct doxm_data {
    /* Device Onwership Transfer Method */
    char as_json[256]; /* FIXME: should not be required for confirmable coap packets! */

    char owner_uuid[16];
    char device_uuid[16];
    enum oxm_sel oxm_sel;
    bool owned;
};

enum provisioning_mode {
    DPM_NORMAL = 0,
    DPM_RESET = 1<<0,
    DPM_TAKE_OWNER = 1<<1,
    DPM_BOOTSTRAP_SERVICE = 1<<2,
    DPM_SEC_MGMT_SERVICES = 1<<3,
    DPM_PROVISION_CREDS = 1<<4,
    DPM_PROVISION_ACLS = 1<<5
};

enum provisioning_op_mode {
    DOP_MULTIPLE = 0,
    DOP_SINGLE = 1<<0,
    DOP_SERVICE = 1<<1
};

struct pstat_data {
    /* Provisioning Strategy */
    char as_json[256]; /* FIXME: should not be required for confirmable coap packets! */

    char device_id[16]; /* duplicate? */

    enum provisioning_mode cm;
    enum provisioning_mode tm;

    enum provisioning_op_mode operation_mode;
    struct sol_vector sm;

    uint16_t commit_hash;
    bool op;
};

enum method {
    METHOD_GET,
    METHOD_PUT
};

struct transfer_method {
    const char *oxm_string;

    sol_coap_responsecode_t (*handle_doxm)(struct sol_oic_security *security,
        const struct sol_network_link_addr *cliaddr,
        enum method method, const struct sol_vector *input,
        struct sol_vector *output);
    sol_coap_responsecode_t (*handle_pstat)(struct sol_oic_security *security,
        const struct sol_network_link_addr *cliaddr,
        enum method method, const struct sol_vector *input,
        struct sol_vector *output);
    sol_coap_responsecode_t (*handle_cred)(struct sol_oic_security *security,
        const struct sol_network_link_addr *cliaddr,
        enum method method, const struct sol_vector *input,
        struct sol_vector *output);
    sol_coap_responsecode_t (*handle_svc)(struct sol_oic_security *security,
        const struct sol_network_link_addr *cliaddr,
        enum method method, const struct sol_vector *input,
        struct sol_vector *output);

    int (*pair_request)(struct sol_oic_security *security,
        const struct sol_network_link_addr *cliaddr,
        const struct sol_str_slice *device_id,
        void (*paired_cb)(void *data, enum sol_oic_security_pair_result result), void *data);
};

struct sol_oic_security {
    struct sol_coap_server *server;
    struct sol_coap_server *server_dtls;
    const struct transfer_method *transfer_method;
    struct sol_socket_dtls_credential_cb callbacks;

    struct {
        struct sol_oic_server_resource *doxm;
        struct sol_oic_server_resource *pstat;
        struct sol_oic_server_resource *cred;
        struct sol_oic_server_resource *svc;
    } resources;

    struct doxm_data doxm;

    /* This is implemented by IoTivity but it's not actually used. Why?
     * Don't ask.  */
    struct pstat_data pstat;
};

struct cred_item {
    struct {
        char *data;
        struct sol_str_slice slice;
    } id, psk;
    /* FIXME: Only symmetric pairwise keys supported at the moment */
};

struct creds {
    struct sol_vector items;
    const struct sol_oic_security *security;
};

struct security_ctx {
    bool (*cb)(const struct sol_network_link_addr *addr,
        struct sol_str_slice payload, void *data);
    void *data;
    int64_t token;
};

struct sol_socket *sol_coap_server_get_socket(const struct sol_coap_server *server);

static ssize_t
creds_get_psk(const void *data, struct sol_str_slice id,
    char *psk, size_t psk_len)
{
    const struct creds *creds = data;
    struct cred_item *iter;
    uint16_t idx;

    SOL_DBG("Looking for PSK with ID=%.*s", (int)id.len, id.data);

    SOL_VECTOR_FOREACH_IDX (&creds->items, iter, idx) {
        if (sol_str_slice_eq(id, iter->id.slice)) {
            if (iter->id.slice.len > psk_len)
                return -ENOBUFS;

            memcpy(psk, iter->psk.data, iter->id.slice.len);
            return (ssize_t)iter->psk.slice.len;
        }
    }

    return -ENOENT;
}

static ssize_t
creds_get_id(const void *data, char *id, size_t id_len)
{
    const char *machine_id = sol_platform_get_machine_id();
    size_t len = strnlen(machine_id, DTLS_PSK_ID_LEN);

    if (len > id_len)
        return -ENOBUFS;

    memcpy(id, machine_id, len);
    return (ssize_t)len;
}

static bool
creds_add(struct creds *creds, const char *id, size_t id_len,
    const char *psk, size_t psk_len)
{
    struct cred_item *item;
    char psk_stored[64];
    ssize_t r;

    r = creds_get_psk(creds, SOL_STR_SLICE_STR(id, id_len),
        psk_stored, sizeof(psk_stored));
    if (r > 0) {
        struct sol_str_slice stored = SOL_STR_SLICE_STR(psk_stored, r);
        struct sol_str_slice passed = SOL_STR_SLICE_STR(psk, psk_len);

        if (sol_str_slice_eq(stored, passed))
            return true;

        SOL_WRN("Attempting to add PSK for ID=%.*s, but it's already"
            " registered and different from the supplied key",
            (int)id_len, id);
        return false;
    } else if (r < 0 && r != -ENOENT) {
        SOL_WRN("Error while adding credentials: %s", sol_util_strerrora(-r));
        return false;
    }

    item = sol_vector_append(&creds->items);
    SOL_NULL_CHECK(item, false);

    item->id.data = strndup(id, id_len);
    SOL_NULL_CHECK_GOTO(item->id.data, no_id);

    item->psk.data = strndup(psk, psk_len);
    SOL_NULL_CHECK_GOTO(item->psk.data, no_psk);

    item->id.slice = SOL_STR_SLICE_STR(item->id.data, id_len);
    item->psk.slice = SOL_STR_SLICE_STR(item->psk.data, psk_len);

    return true;

no_psk:
    sol_util_secure_clear_memory(item->id.data, id_len);
    free(item->id.data);
no_id:
    sol_util_secure_clear_memory(item, sizeof(*item));
    sol_vector_del(&creds->items, creds->items.len - 1);

    return false;
}

static void
creds_clear(void *data)
{
    struct creds *creds = data;
    struct cred_item *iter;
    uint16_t idx;

    SOL_VECTOR_FOREACH_IDX (&creds->items, iter, idx) {
        sol_util_secure_clear_memory(iter->id.data, iter->id.slice.len);
        sol_util_secure_clear_memory(iter->psk.data, iter->psk.slice.len);

        free(iter->id.data);
        free(iter->psk.data);
    }
    sol_vector_clear(&creds->items);

    sol_util_secure_clear_memory(creds, sizeof(*creds));
    free(creds);
}

static bool
creds_add_json_token(struct creds *creds, struct sol_json_scanner *scanner,
    struct sol_json_token *token)
{
    struct sol_json_token key, value;
    enum sol_json_loop_reason reason;
    struct sol_str_slice psk = SOL_STR_SLICE_EMPTY;
    struct sol_str_slice id = SOL_STR_SLICE_EMPTY;

    SOL_JSON_SCANNER_OBJECT_LOOP (scanner, token, &key, &value, reason) {
        if (SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "id")) {
            id = sol_json_token_to_slice(&value);
        } else if (SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "psk")) {
            psk = sol_json_token_to_slice(&value);
        }
    }

    if (id.len && psk.len) {
        char id_buf_backing[16], psk_buf_backing[16];
        struct sol_buffer id_buf, psk_buf;
        bool result = false;

        sol_buffer_init_flags(&id_buf, id_buf_backing, sizeof(id_buf_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);
        sol_buffer_init_flags(&psk_buf, psk_buf_backing, sizeof(psk_buf_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);

        if (sol_buffer_append_from_base64(&id_buf, id, SOL_BASE64_MAP) < 0)
            goto finish_bufs;
        if (sol_buffer_append_from_base64(&psk_buf, psk, SOL_BASE64_MAP) < 0)
            goto finish_bufs;

        result = creds_add(creds, id_buf.data, id_buf.used,
            psk_buf.data, psk_buf.used);

finish_bufs:
        sol_buffer_fini(&psk_buf);
        sol_buffer_fini(&id_buf);

        return result;
    }

    return false;
}

static void *
creds_init(const void *data)
{
    struct creds *creds = calloc(1, sizeof(*creds));
    struct sol_json_scanner scanner;
    struct sol_json_token token;
    enum sol_json_loop_reason reason;
    char *file_data;
    size_t length;

    SOL_NULL_CHECK(creds, NULL);

    creds->security = data;
    sol_vector_init(&creds->items, sizeof(struct cred_item));

    file_data = sol_util_load_file_string("/tmp/oic-creds.json", &length);
    if (!file_data)
        return creds;

    sol_json_scanner_init(&scanner, file_data, length);
    SOL_JSON_SCANNER_ARRAY_LOOP (&scanner, &token, SOL_JSON_TYPE_OBJECT_START, reason) {
        if (!creds_add_json_token(creds, &scanner, &token)) {
            creds_clear(creds);
            creds = NULL;
            goto out;
        }
    }

    if (reason != SOL_JSON_LOOP_REASON_OK) {
        creds_clear(creds);
        creds = NULL;
    }

out:
    sol_util_secure_clear_memory(&scanner, sizeof(scanner));
    sol_util_secure_clear_memory(&token, sizeof(token));
    sol_util_secure_clear_memory(&reason, sizeof(reason));

    sol_util_secure_clear_memory(file_data, length);
    free(file_data);

    return creds;
}

static bool
creds_store(struct creds *creds)
{
    struct sol_buffer buf;
    struct cred_item *item;
    uint16_t idx;
    char contents[1024];
    int r = -1;

    sol_buffer_init_flags(&buf, contents, sizeof(contents), SOL_BUFFER_FLAGS_CLEAR_MEMORY);

    if (sol_buffer_append_char(&buf, '[') < 0)
        goto failure;

    SOL_VECTOR_FOREACH_IDX (&creds->items, item, idx) {
        char id_buf_backing[64], psk_buf_backing[64];
        struct sol_buffer id_buf, psk_buf;
        bool iter_failed = true;

        sol_buffer_init_flags(&id_buf, id_buf_backing, sizeof(id_buf_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);
        sol_buffer_init_flags(&psk_buf, psk_buf_backing, sizeof(psk_buf_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);

        if (sol_buffer_append_as_base64(&id_buf, item->id.slice, SOL_BASE64_MAP) < 0)
            goto finish_bufs;
        if (sol_buffer_append_as_base64(&psk_buf, item->psk.slice, SOL_BASE64_MAP) < 0)
            goto finish_bufs;

        if (sol_buffer_append_printf(&buf, "{\"id\":\"%.*s\",", (int)id_buf.used, (const char *)id_buf.data) < 0)
            goto finish_bufs;
        if (sol_buffer_append_printf(&buf, "\"psk\":\"%.*s\"},", (int)psk_buf.used, (const char *)psk_buf.data) < 0)
            goto finish_bufs;

        iter_failed = false;

finish_bufs:
        sol_buffer_fini(&psk_buf);
        sol_buffer_fini(&id_buf);

        if (iter_failed)
            goto failure;
    }
    if (idx) {
        /* Remove trailing ',' */
        if (sol_buffer_resize(&buf, buf.used - 1) < 0)
            goto failure;
    }

    if (sol_buffer_append_char(&buf, ']') < 0)
        goto failure;

    r = sol_util_write_file("/tmp/oic-creds.json", "%.*s", (int)buf.used,
        (const char *)buf.data);
failure:
    sol_buffer_fini(&buf);

    return r == 0;
}

static bool
decode_base64(const struct sol_str_slice input, char *output, size_t output_len)
{
    struct sol_buffer buf;
    bool success = true;

    sol_buffer_init_flags(&buf, output, output_len,
        SOL_BUFFER_FLAGS_MEMORY_NOT_OWNED | SOL_BUFFER_FLAGS_NO_NUL_BYTE);

    if (sol_buffer_append_from_base64(&buf, input, SOL_BASE64_MAP) < 0) {
        SOL_WRN("Could not decode Base 64 value");
        success = false;
    }

    sol_buffer_fini(&buf);
    return success;
}

static bool
parse_doxm_json(struct doxm_data *doxm, const char *payload, size_t len)
{
    struct sol_json_scanner scanner;
    struct sol_json_token token, key, value;
    enum sol_json_loop_reason reason;
    bool set_oxmsel = false, set_owned = false, set_deviceid = false, set_owner = false;

    sol_util_secure_clear_memory(doxm, sizeof(*doxm));

    sol_json_scanner_init(&scanner, payload, len);
    SOL_JSON_SCANNER_OBJECT_LOOP (&scanner, &token, &key, &value, reason) {
        if (!set_oxmsel && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "oxmsel")) {
            if (sol_json_token_get_int32(&value, (int32_t *)&doxm->oxm_sel) < 0) {
                SOL_WRN("Could not convert `oxmsel` field to integer");
                return false;
            }

            set_oxmsel = true;
        } else if (!set_owned && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "owned")) {
            if (sol_json_token_get_type(&value) == SOL_JSON_TYPE_TRUE) {
                doxm->owned = true;
            } else if (sol_json_token_get_type(&value) == SOL_JSON_TYPE_FALSE) {
                doxm->owned = false;
            } else {
                SOL_WRN("Invalid type for field `owned`");
                return false;
            }

            set_owned = true;
        } else if (!set_deviceid && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "deviceid") && sol_json_token_get_type(&value) == SOL_JSON_TYPE_STRING) {
            struct sol_str_slice slice = sol_json_token_to_slice(&value);

            if (!decode_base64(slice, doxm->device_uuid, sizeof(doxm->device_uuid)))
                return false;

            set_deviceid = true;
        } else if (!set_owner && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "ownr") && sol_json_token_get_type(&value) == SOL_JSON_TYPE_STRING) {
            struct sol_str_slice slice = sol_json_token_to_slice(&value);

            if (!decode_base64(slice, doxm->owner_uuid, sizeof(doxm->owner_uuid)))
                return false;

            set_owner = true;
        }
    }

    if (reason != SOL_JSON_LOOP_REASON_OK)
        return false;

    return set_oxmsel && set_owned && set_deviceid && set_owner;
}

static bool
serialize_doxm_json(const struct doxm_data *doxm, char *payload, size_t len)
{
    char device_id_backing[64], owner_id_backing[64];
    struct sol_str_slice device_id_slice = SOL_STR_SLICE_STR(doxm->device_uuid, 16);
    struct sol_str_slice owner_id_slice = SOL_STR_SLICE_STR(doxm->owner_uuid, 16);
    struct sol_buffer device_id, owner_id;
    int r = -1;

    sol_buffer_init_flags(&device_id, device_id_backing, sizeof(device_id_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);
    sol_buffer_init_flags(&owner_id, owner_id_backing, sizeof(owner_id_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);

    if (sol_buffer_append_as_base64(&device_id, device_id_slice, SOL_BASE64_MAP) < 0)
        goto fini_device_id;
    if (sol_buffer_append_as_base64(&owner_id, owner_id_slice, SOL_BASE64_MAP) < 0)
        goto fini_owner_id;

    r = snprintf(payload, len, "{\"oxmsel\":%d,"
        "\"owned\":%s,"
        "\"deviceid\":\"%.*s\","
        "\"ownr\":\"%.*s\"}",
        doxm->oxm_sel, doxm->owned ? "true" : "false",
        (int)device_id.used, (const char *)device_id.data,
        (int)owner_id.used, (const char *)owner_id.data);

fini_owner_id:
    sol_buffer_fini(&owner_id);
fini_device_id:
    sol_buffer_fini(&device_id);

    return r > 0 && r <= (int)len;
}

static bool
validate_provisioning_mode(int32_t val)
{
    if (val < 0)
        return false;

    if (val > (DPM_NORMAL | DPM_RESET | DPM_TAKE_OWNER | DPM_BOOTSTRAP_SERVICE | DPM_SEC_MGMT_SERVICES | DPM_PROVISION_CREDS | DPM_PROVISION_ACLS))
        return false;

    return true;
}

static bool
validate_provisioning_op_mode(int32_t val)
{
    if (val < 0)
        return false;

    if (val > (DOP_MULTIPLE | DOP_SINGLE | DOP_SERVICE))
        return false;

    return true;
}

static bool
parse_sm_vector(struct sol_json_scanner *scanner, struct sol_json_token *current_token,
    struct sol_vector *vector)
{
    enum sol_json_loop_reason reason;

    SOL_JSON_SCANNER_ARRAY_LOOP(scanner, current_token, SOL_JSON_TYPE_NUMBER, reason) {
        enum provisioning_op_mode *item;
        int32_t v;

        if (sol_json_token_get_int32(current_token, &v) < 0)
            return false;

        if (!validate_provisioning_op_mode(v))
            return false;

        item = sol_vector_append(vector);
        SOL_NULL_CHECK(item, false);

        *item = (enum provisioning_op_mode)v;
    }

    return reason == SOL_JSON_LOOP_REASON_OK;
}

enum pstat_fields {
    PF_ERROR = 0,
    PF_CM = 1<<0,
    PF_TM = 1<<1,
    PF_OM = 1<<2,
    PF_CH = 1<<3,
    PF_ISOP = 1<<4,
    PF_SM = 1<<5,
    PF_DEVICEID = 1<<6
};

static enum pstat_fields
parse_pstat_json(struct pstat_data *pstat, const char *payload, size_t len)
{
    struct sol_json_scanner scanner;
    struct sol_json_token token, key, value;
    enum sol_json_loop_reason reason;
    enum pstat_fields fields = 0;

    sol_util_secure_clear_memory(pstat, sizeof(*pstat));
    sol_vector_init(&pstat->sm, sizeof(enum provisioning_op_mode));

    sol_json_scanner_init(&scanner, payload, len);
    /* FIXME: find `pstat` object before parsing, this won't work */
    SOL_JSON_SCANNER_OBJECT_LOOP (&scanner, &token, &key, &value, reason) {
        if (!(fields & PF_CM) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "cm")) {
            if (sol_json_token_get_int32(&value, (int32_t *)&pstat->cm) < 0) {
                SOL_WRN("Could not convert `cm` field to integer");
                goto failure;
            }
            if (!validate_provisioning_mode(pstat->cm)) {
                SOL_WRN("Invalid value for field `cm`");
                goto failure;
            }
            fields |= PF_CM;
        } else if (!(fields & PF_TM) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "tm")) {
            if (sol_json_token_get_int32(&value, (int32_t *)&pstat->tm) < 0) {
                SOL_WRN("Could not convert `tm` field to integer");
                goto failure;
            }
            if (!validate_provisioning_mode(pstat->tm)) {
                SOL_WRN("Invalid value for field `tm`");
                goto failure;
            }
            fields |= PF_TM;
        } else if (!(fields & PF_OM) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "om")) {
            if (sol_json_token_get_int32(&value, (int32_t *)&pstat->operation_mode) < 0) {
                SOL_WRN("Could not convert `om` field to integer");
                goto failure;
            }
            if (!validate_provisioning_op_mode(pstat->operation_mode)) {
                SOL_WRN("Invalid value for field `om`");
                goto failure;
            }
            fields |= PF_OM;
        } else if (!(fields & PF_CH) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "ch")) {
            int32_t v;

            if (sol_json_token_get_int32(&value, &v) < 0) {
                SOL_WRN("Could not convert `ch` field to integer");
                goto failure;
            }

            if (v < 0 || v > UINT16_MAX) {
                SOL_WRN("Field `ch` has value out of bounds");
                goto failure;
            }

            pstat->commit_hash = (uint16_t)v;
            fields |= PF_CH;
        } else if (!(fields & PF_ISOP) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "isop")) {
            if (sol_json_token_get_type(&value) == SOL_JSON_TYPE_TRUE) {
                pstat->op = true;
            } else if (sol_json_token_get_type(&value) == SOL_JSON_TYPE_FALSE) {
                pstat->op = false;
            } else {
                SOL_WRN("Invalid type for field `isop`");
                goto failure;
            }
            fields |= PF_ISOP;
        } else if (!(fields & PF_SM) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "sm")) {
            if (sol_json_token_get_type(&value) != SOL_JSON_TYPE_ARRAY_START) {
                SOL_WRN("Field `sm` has an unexpected value");
                goto failure;
            }
            if (!parse_sm_vector(&scanner, &value, &pstat->sm)) {
                SOL_WRN("Could not parse `sm` vector");
                goto failure;
            }
            fields |= PF_SM;
        } else if (!(fields & PF_DEVICEID) && SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "deviceid")) {
            struct sol_str_slice slice = sol_json_token_to_slice(&value);
            struct sol_buffer buf;

            sol_buffer_init_flags(&buf, pstat->device_id, sizeof(pstat->device_id),
                SOL_BUFFER_FLAGS_MEMORY_NOT_OWNED | SOL_BUFFER_FLAGS_NO_NUL_BYTE);

            if (sol_buffer_append_from_base64(&buf, slice, SOL_BASE64_MAP) < 0) {
                SOL_WRN("Could not decode `deviceid` from base64");
                sol_buffer_fini(&buf);
                goto failure;
            }

            sol_buffer_fini(&buf);
            fields |= PF_DEVICEID;
        }
    }

    if (reason != SOL_JSON_LOOP_REASON_OK)
        goto failure;

    if (fields & (PF_ISOP | PF_DEVICEID | PF_CH | PF_CM | PF_OM | PF_SM))
        return fields;

failure:
    sol_vector_clear(&pstat->sm);
    return PF_ERROR;
}

static bool
serialize_pstat_json(const struct pstat_data *pstat, char *payload, size_t len)
{
    struct sol_str_slice device_id_slice = SOL_STR_SLICE_STR(pstat->device_id, 16);
    enum provisioning_op_mode *sm;
    struct sol_buffer device_id, json;
    bool success = false;
    char device_id_backing[64];
    uint16_t idx;

    sol_buffer_init_flags(&device_id, device_id_backing, sizeof(device_id_backing), SOL_BUFFER_FLAGS_CLEAR_MEMORY);
    sol_buffer_init_flags(&json, payload, len,
        SOL_BUFFER_FLAGS_MEMORY_NOT_OWNED);

    if (sol_buffer_append_as_base64(&device_id, device_id_slice, SOL_BASE64_MAP) < 0)
        goto fini_device_id;

    if (sol_buffer_append_printf(&json, "{\"pstat\":{") < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"isop\":%s,", pstat->op ? "true" : "false") < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"deviceid\":\"%.*s\",", (int)device_id.used, (const char *)device_id.data) < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"ch\":%d,", pstat->commit_hash) < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"cm\":%d,", pstat->cm) < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"tm\":%d,", pstat->tm) < 0)
        goto fini_json;
    if (sol_buffer_append_printf(&json, "\"om\":%d,", pstat->operation_mode) < 0)
        goto fini_json;

    if (sol_buffer_append_printf(&json, "\"sm\":[") < 0)
        goto fini_json;
    SOL_VECTOR_FOREACH_IDX (&pstat->sm, sm, idx) {
        if (sol_buffer_append_printf(&json, "%d,", *sm) < 0)
            goto fini_json;
    }
    if (idx) {
        /* Remove trailing ',' */
        if (sol_buffer_resize(&json, json.used - 1) < 0)
            goto fini_json;
    }

    if (sol_buffer_append_printf(&json, "]}}") < 0)
        goto fini_json;

    success = true;

fini_json:
    sol_buffer_fini(&json);
fini_device_id:
    sol_buffer_fini(&device_id);

    return success;
}

static const char *
find_repr(const struct sol_vector *input, size_t *len)
{
    struct sol_oic_repr_field *iter;
    uint16_t idx;

    SOL_VECTOR_FOREACH_IDX (input, iter, idx) {
        if (iter->type != SOL_OIC_REPR_TYPE_TEXT_STRING)
            continue;

        if (!streq(iter->key, "repr"))
            continue;

        *len = iter->v_slice.len;
        return iter->v_slice.data;
    }

    return NULL;
}

static int
security_register_owner_psk(struct sol_oic_security *security,
    const struct sol_network_link_addr *cliaddr,
    struct doxm_data *doxm)
{
    struct sol_str_slice label = sol_str_slice_from_str(security->transfer_method->oxm_string);
    struct sol_str_slice owner_id = SOL_STR_SLICE_STR(doxm->owner_uuid, sizeof(doxm->owner_uuid));
    struct sol_str_slice device_id = SOL_STR_SLICE_STR(doxm->device_uuid, sizeof(doxm->device_uuid));
    struct sol_buffer psk;
    struct sol_socket *socket_dtls;
    struct creds *creds;
    uint8_t psk_data[16];
    int r;

    socket_dtls = sol_coap_server_get_socket(security->server_dtls);
    SOL_NULL_CHECK(socket_dtls, -EINVAL);

    sol_buffer_init_flags(&psk, psk_data, sizeof(psk_data),
        SOL_BUFFER_FLAGS_NO_NUL_BYTE
        | SOL_BUFFER_FLAGS_CLEAR_MEMORY);

    r = sol_socket_dtls_prf_keyblock(socket_dtls, cliaddr, label, owner_id,
        device_id, &psk);
    if (r < 0) {
        SOL_WRN("Could not generate PSK from DTLS handshake");
        goto inval;
    }

    creds = creds_init(security);
    if (!creds) {
        SOL_WRN("Could not load credentials database");
        goto inval;
    }

    if (!creds_add(creds, doxm->owner_uuid, sizeof(doxm->owner_uuid),
        psk.data, psk.used)) {
        SOL_WRN("Could not register PSK in credentials database");
        goto inval;
    }

    r = creds_store(creds);
    creds_clear(creds);
    if (!r) {
        SOL_WRN("Could not store credentials database");
        goto inval;
    }

    security->doxm.owned = true;
    security->doxm.oxm_sel = doxm->oxm_sel;
    memcpy(security->doxm.owner_uuid, doxm->owner_uuid, 16);

    sol_buffer_fini(&psk);
    return 0;

inval:
    sol_buffer_fini(&psk);
    return -EINVAL;
}

static int
security_store_context(struct sol_oic_security *security)
{
    struct sol_buffer buf;
    char contents[1024];
    char repr[512];
    int r = -1;

    sol_buffer_init_flags(&buf, contents, sizeof(contents),
        SOL_BUFFER_FLAGS_CLEAR_MEMORY);

    if (sol_buffer_append_printf(&buf, "{\"doxm\":") < 0)
        goto failure;
    if (!serialize_doxm_json(&security->doxm, repr, sizeof(repr)))
        goto failure;
    if (sol_buffer_append_slice(&buf, sol_str_slice_from_str(repr)) < 0)
        goto failure;

    if (sol_buffer_append_printf(&buf, ",\"pstat\":") < 0)
        goto failure;
    if (!serialize_pstat_json(&security->pstat, repr, sizeof(repr)))
        goto failure;
    if (sol_buffer_append_slice(&buf, sol_str_slice_from_str(repr)) < 0)
        goto failure;

    if (sol_buffer_append_char(&buf, '}') < 0)
        goto failure;

    if (sol_util_write_file("/tmp/oic-security-context.json", "%.*s",
        (int)buf.used, (const char *)buf.data) < 0)
        goto failure;

    r = 0;

failure:
    sol_util_secure_clear_memory(repr, sizeof(repr));
    sol_buffer_fini(&buf);
    return r;
}

static int
security_load_context(struct sol_oic_security *security)
{
    struct sol_json_scanner scanner;
    struct sol_json_token token, key, value;
    enum sol_json_loop_reason reason;
    size_t length;
    char *contents = sol_util_load_file_string("/tmp/oic-security-context.json", &length);

    if (!contents) {
        sol_util_secure_clear_memory(&security->pstat, sizeof(security->pstat));
        sol_util_secure_clear_memory(&security->doxm, sizeof(security->doxm));
        return 0;
    }

    sol_json_scanner_init(&scanner, contents, length);
    SOL_JSON_SCANNER_OBJECT_LOOP (&scanner, &token, &key, &value, reason) {
        if (SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "doxm")) {
            struct sol_str_slice slice = sol_json_token_to_slice(&value);

            if (!parse_doxm_json(&security->doxm, slice.data, slice.len)) {
                reason = SOL_JSON_LOOP_REASON_INVALID;
                break;
            }
        } else if (SOL_JSON_TOKEN_STR_LITERAL_EQ(&key, "pstat")) {
            struct sol_str_slice slice = sol_json_token_to_slice(&value);

            if (!parse_pstat_json(&security->pstat, slice.data, slice.len)) {
                reason = SOL_JSON_LOOP_REASON_INVALID;
                break;
            }
        }
    }

    free(contents);

    return reason == SOL_JSON_LOOP_REASON_OK ? 0 : -EINVAL;    
}

static sol_coap_responsecode_t
handle_doxm_jw(struct sol_oic_security *security,
    const struct sol_network_link_addr *cliaddr, enum method method,
    const struct sol_vector *input, struct sol_vector *output)
{
    static const char unowned_uuid[16] = { 0 };
    int r;

    switch (method) {
    case METHOD_GET: {
        struct sol_oic_repr_field *repr;

        if (!serialize_doxm_json(&security->doxm, security->doxm.as_json, sizeof(security->doxm.as_json))) {
            SOL_WRN("Could not serialize transfer method data");
            return SOL_COAP_RSPCODE_INTERNAL_ERROR;
        }

        repr = sol_vector_append(output);
        SOL_NULL_CHECK(repr, SOL_COAP_RSPCODE_INTERNAL_ERROR);

        *repr = SOL_OIC_REPR_TEXT_STRING("repr", security->doxm.as_json,
            strlen(security->doxm.as_json));
        return SOL_COAP_RSPCODE_OK;
    }
    case METHOD_PUT: {
        const char *payload;
        size_t len;
        struct doxm_data new_doxm;

        payload = find_repr(input, &len);
        if (!payload) {
            SOL_WRN("Transfer method has no security payload");
            return SOL_COAP_RSPCODE_BAD_REQUEST;
        }

        if (!parse_doxm_json(&new_doxm, payload, len)) {
            SOL_WRN("Could not parse security payload");
            return SOL_COAP_RSPCODE_BAD_REQUEST;
        }

        if (new_doxm.oxm_sel != OXM_JUST_WORKS) {
            SOL_WRN("Ownership transfer method invalid, expecting just works "
                "(%d), got %d instead", OXM_JUST_WORKS, new_doxm.oxm_sel);
            return SOL_COAP_RSPCODE_BAD_REQUEST;
        }

        if (!security->doxm.owned && !new_doxm.owned) {
            struct sol_socket *socket;

            socket = sol_coap_server_get_socket(security->server_dtls);
            SOL_NULL_CHECK(socket, SOL_COAP_RSPCODE_INTERNAL_ERROR);

            SOL_INF("Device is unowned, enabling anonymous ECDH for initial handshake");
            sol_socket_dtls_set_anon_ecdh_enabled(socket, true);
            return SOL_COAP_RSPCODE_OK;
        }

        if (!security->doxm.owned && new_doxm.owned &&
            memcmp(new_doxm.owner_uuid, unowned_uuid, sizeof(unowned_uuid))) {

            r = security_register_owner_psk(security, cliaddr, &new_doxm);
            if (!r) {
                SOL_INF("Owner PSK has been added, storing on disk");
                r = security_store_context(security);
            }
            if (!r) {
                struct sol_socket *socket;

                socket = sol_coap_server_get_socket(security->server_dtls);
                SOL_NULL_CHECK(socket, SOL_COAP_RSPCODE_INTERNAL_ERROR);

                SOL_INF("Anonymous ECDH not needed anymore, disabling");
                sol_socket_dtls_set_anon_ecdh_enabled(socket, false);
                return SOL_COAP_RSPCODE_OK;
            }

            SOL_INF("Some error happened while trying to register owner PSK");
            return SOL_COAP_RSPCODE_UNAUTHORIZED;
        }

        /* Fallthrough */
    }
    default:
        return SOL_COAP_RSPCODE_BAD_REQUEST;
    }
}

static sol_coap_responsecode_t
handle_pstat_jw(struct sol_oic_security *security,
    const struct sol_network_link_addr *cliaddr, enum method method,
    const struct sol_vector *input, struct sol_vector *output)
{
    switch (method) {
    case METHOD_GET: {
        struct sol_oic_repr_field *repr;

        if (!serialize_pstat_json(&security->pstat, security->pstat.as_json, sizeof(security->pstat.as_json))) {
            SOL_WRN("Could not serialize provisioning strategy data");
            return SOL_COAP_RSPCODE_INTERNAL_ERROR;
        }

        repr = sol_vector_append(output);
        SOL_NULL_CHECK(repr, SOL_COAP_RSPCODE_INTERNAL_ERROR);

        *repr = SOL_OIC_REPR_TEXT_STRING("repr", security->pstat.as_json,
            strlen(security->pstat.as_json));
        return SOL_COAP_RSPCODE_OK;
    }
    case METHOD_PUT: {
        const char *payload;
        size_t len;
        struct pstat_data new_pstat;
        enum pstat_fields fields;
        uint16_t commit_hash = 0;

        payload = find_repr(input, &len);
        if (!payload) {
            SOL_WRN("Could not find provisioning strategy payload");
            return SOL_COAP_RSPCODE_BAD_REQUEST;
        }

        fields = parse_pstat_json(&new_pstat, payload, len);
        if (fields == PF_ERROR) {
            SOL_WRN("Could not parse security payload");
            return SOL_COAP_RSPCODE_BAD_REQUEST;
        }

        if (fields & PF_CH)
            commit_hash = new_pstat.commit_hash;

        if (fields & PF_TM) {
            if (new_pstat.tm == 0 && security->pstat.commit_hash == commit_hash) {
                security->pstat.op = true;
                security->pstat.cm = DPM_NORMAL;
            }
        }

        if (fields & PF_OM) {
            enum provisioning_op_mode *pom;
            uint16_t idx;

            SOL_VECTOR_FOREACH_IDX (&security->pstat.sm, pom, idx) {
                if (*pom == new_pstat.operation_mode) {
                    security->pstat.operation_mode = new_pstat.operation_mode;
                    break;
                }
            }
        }

        if (security_store_context(security) == 0)
            return SOL_COAP_RSPCODE_OK;

        SOL_WRN("Could not store security context");

        /* Fallthrough */
    }
    default:
        return SOL_COAP_RSPCODE_BAD_REQUEST;
    }
}

bool
sol_oic_set_token_and_mid(struct sol_coap_packet *pkt, int64_t *token)  
{
    static struct sol_random *random = NULL;
    int32_t mid;
   
    if (unlikely(!random)) {
        random = sol_random_new(SOL_RANDOM_DEFAULT, 0);
        SOL_NULL_CHECK(random, false);
    }

    if (!sol_random_get_int64(random, token)) {
        SOL_WRN("Could not generate CoAP token");
        return false;
    }
    if (!sol_random_get_int32(random, &mid)) {
        SOL_WRN("Could not generate CoAP message id");
        return false;
    }

    if (!sol_coap_header_set_token(pkt, (uint8_t *)token, (uint8_t)sizeof(*token))) {
        SOL_WRN("Could not set CoAP packet token");
        return false;
    }

    sol_coap_header_set_id(pkt, (int16_t)mid);

    return true;
}

static bool
security_request_cb(struct sol_coap_server *coap,
    struct sol_coap_packet *req, const struct sol_network_link_addr *addr,
    void *data)
{
    struct security_ctx *ctx = data;
    CborParser parser;
    CborValue root, array, value;
    CborError err;
    uint8_t *payload;
    uint16_t payload_len;
    int payload_type;

    if (!ctx->cb)
        return false;
    /* FIXME: check tokens */
    /*if (!sol_oic_pkt_has_cbor_content(req))
        return true;*/
    if (!sol_coap_packet_has_payload(req))
        return true;
    if (sol_coap_packet_get_payload(req, &payload, &payload_len) < 0)
        return true;

    err = cbor_parser_init(payload, payload_len, 0, &parser, &root);
    if (err != CborNoError)
        return true;

    if (!cbor_value_is_array(&root))
        return true;

    err |= cbor_value_enter_container(&root, &array);

    err |= cbor_value_get_int(&array, &payload_type);
    err |= cbor_value_advance_fixed(&array);
    if (err != CborNoError)
        return true;
    if (payload_type != SOL_OIC_PAYLOAD_SECURITY)
        return true;

    if (!cbor_value_is_map(&array))
        return true;

    err |= cbor_value_map_find_value(&array, SOL_OIC_KEY_REPRESENTATION, &value);
    if (err == CborNoError) {
        char *json;
        size_t json_len;
    
        err |= cbor_value_dup_text_string(&value, &json, &json_len, NULL);
        if (err == CborNoError) {
            bool ret = ctx->cb(addr, sol_str_slice_from_str(json), ctx->data);

            free(json);
            if (ret)
                free(ctx);

            return ret;
        }
    }

    return true;
}

static int
security_request(struct sol_coap_server *coap, sol_coap_method_t method,
    struct sol_network_link_addr addr, const char *href,
    struct sol_str_slice payload,
    bool (*cb)(const struct sol_network_link_addr *addr,
    const struct sol_str_slice repr, void *data), void *data)
{
    const uint8_t format_cbor = SOL_COAP_CONTENTTYPE_APPLICATION_CBOR;
    struct sol_coap_packet *req;
    struct sol_vector reprs = SOL_VECTOR_INIT(struct sol_oic_repr_field);
    struct sol_oic_repr_field *repr;
    CborError err;
    int64_t token;

    req = sol_coap_packet_request_new(method, SOL_COAP_TYPE_CON);
    SOL_NULL_CHECK(req, -ENOMEM);

    if (!sol_oic_set_token_and_mid(req, &token)) {
        SOL_WRN("Could not set token and mid");
        goto out;
    }

    if (sol_coap_packet_add_uri_path_option(req, href) < 0) {
        SOL_WRN("Invalid URI: %s", href);
        goto out;
    }

    sol_coap_add_option(req, SOL_COAP_OPTION_CONTENT_FORMAT, &format_cbor,
        sizeof(format_cbor));

    repr = sol_vector_append(&reprs);
    if (!repr) {
        SOL_WRN("Could not append security payload");
        goto out;
    }
    *repr = SOL_OIC_REPR_TEXT_STRING("repr", payload.data, payload.len);
    err = sol_oic_encode_cbor_repr(req, href, &reprs, SOL_OIC_PAYLOAD_SECURITY);
    sol_vector_clear(&reprs);
    if (err == CborNoError) {
        struct security_ctx *ctx = sol_util_memdup(&(struct security_ctx){
            .cb = cb,
            .data = data,
            .token = token
        }, sizeof(*ctx));

        SOL_NULL_CHECK_GOTO(ctx, out);

        return sol_coap_send_packet_with_reply(coap, req, &addr,
            security_request_cb, ctx);
    }

out:
    SOL_ERR("Could not encode CBOR representation: %s", cbor_error_string(err));
    sol_coap_packet_unref(req);

    return -EINVAL;
}

static int
pair_request_jw(struct sol_oic_security *security,
    const struct sol_network_link_addr *cliaddr,
    const struct sol_str_slice *device_id,
    void (*paired_cb)(void *data, enum sol_oic_security_pair_result result), void *data)
{
    /* FIXME: these steps are mostly the same for any of the ownership
     * transfer modes, so this should be made into a single chain of
     * callbacks, which call the specific behavior of any of the OXMs */

    /*  GET/PUT  ->  request to security->server
     *  GETS/PUTS -> request to security->dtls_server
     *
     *  PUT /oic/sec/doxm {owned: false} // request to enable anon ecdhe server-side
        if not OK, then
            call callback(pair_failure)
            return

        GET /oic/sec/pstat
        if not OK, then
            call callback(pair_failure)
            return
        
        check if operation mode is single service client driven,
        if not,
            call callback(pair_failure)
        
        PUT /oic/sec/pstat (operation mode = 0x11)
        if not ok, then
            call callback(pair failure)
            return
        
        enable dtls client-side
        connect dtls
        if not ok,
            call callback(pair failure)
            return

        PUTS /oic/sec/doxm {owned = true, owner = uuid}
        if not ok:
            call callback(pair failure)
            disable dtls client-side
            disconnect dtls
            return

        should be done now, but there's still ACL; soletta does not implement it
        yet in the server side, though. see FinalizeProvisioning() in
            ownershiptransfermanager.c for information. not much different
            from doxm and pstat (it's serialized json, should be saved to
            disk, etc). for ACLs, there will be permissions to create,
            read, update, and destroy resources, and checks will need to
            be performed inside soletta before passing to user handlers.

        disable dtls client side
        disconnect dtls
        save psk

        call callback(success)
        done!
     */
     return 0;
}

static const struct transfer_method transfer_method_just_works = {
    .oxm_string = "oic.sec.doxm.jw",
    .handle_doxm = handle_doxm_jw,
    .handle_pstat = handle_pstat_jw,
    .pair_request = pair_request_jw,
};

static sol_coap_responsecode_t
handle_get_doxm_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_doxm)
        return -ENOENT;

    return security->transfer_method->handle_doxm(security, cliaddr, METHOD_GET,
        input, output);
}

static sol_coap_responsecode_t
handle_put_doxm_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_doxm)
        return SOL_COAP_RSPCODE_NOT_IMPLEMENTED;

    return security->transfer_method->handle_doxm(security, cliaddr, METHOD_PUT,
        input, output);
}

static sol_coap_responsecode_t
handle_get_pstat_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_pstat)
        return SOL_COAP_RSPCODE_NOT_IMPLEMENTED;

    return security->transfer_method->handle_pstat(security, cliaddr,
        METHOD_GET, input, output);
}

static sol_coap_responsecode_t
handle_put_pstat_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_pstat)
        return SOL_COAP_RSPCODE_NOT_IMPLEMENTED;

    return security->transfer_method->handle_pstat(security, cliaddr,
        METHOD_PUT, input, output);
}

static sol_coap_responsecode_t
handle_put_cred_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_cred)
        return SOL_COAP_RSPCODE_NOT_IMPLEMENTED;

    return security->transfer_method->handle_cred(security, cliaddr,
        METHOD_PUT, input, output);
}

static sol_coap_responsecode_t
handle_put_svc_thunk(const struct sol_network_link_addr *cliaddr,
    const void *data, const struct sol_vector *input, struct sol_vector *output)
{
    struct sol_oic_security *security = (struct sol_oic_security *)data;

    if (!security->transfer_method->handle_svc)
        return SOL_COAP_RSPCODE_NOT_IMPLEMENTED;

    return security->transfer_method->handle_svc(security, cliaddr,
        METHOD_PUT, input, output);
}

static bool
register_server_bits(struct sol_oic_security *security)
{
    static const struct sol_oic_resource_type sec_doxm = {
        SOL_SET_API_VERSION(.api_version = SOL_OIC_RESOURCE_TYPE_API_VERSION, )
        .get.handle = handle_get_doxm_thunk,
        .put.handle = handle_put_doxm_thunk,
    };
    static const struct sol_oic_resource_type sec_pstat = {
        SOL_SET_API_VERSION(.api_version = SOL_OIC_RESOURCE_TYPE_API_VERSION, )
        .get.handle = handle_get_pstat_thunk,
        .put.handle = handle_put_pstat_thunk,
    };
    static const struct sol_oic_resource_type sec_cred = {
        SOL_SET_API_VERSION(.api_version = SOL_OIC_RESOURCE_TYPE_API_VERSION, )
        .put.handle = handle_put_cred_thunk,
    };
    static const struct sol_oic_resource_type sec_svc = {
        SOL_SET_API_VERSION(.api_version = SOL_OIC_RESOURCE_TYPE_API_VERSION, )
        .put.handle = handle_put_svc_thunk,
    };
    struct sol_oic_server_resource *doxm, *pstat, *cred, *svc;

    doxm = sol_oic_server_add_resource_full(&sec_doxm, security,
        SOL_OIC_FLAG_DISCOVERABLE | SOL_OIC_FLAG_OBSERVABLE | SOL_OIC_FLAG_SECURE,
        SOL_OIC_PAYLOAD_SECURITY, "/oic/sec/doxm");
    if (!doxm)
        return false;

    pstat = sol_oic_server_add_resource_full(&sec_pstat, security,
        0, SOL_OIC_PAYLOAD_SECURITY, "/oic/sec/pstat");
    if (!pstat)
        goto free_doxm;

    cred = sol_oic_server_add_resource_full(&sec_cred, security,
        0, SOL_OIC_PAYLOAD_SECURITY, "/oic/sec/cred");
    if (!cred)
        goto free_pstat;

    svc = sol_oic_server_add_resource_full(&sec_svc, security,
        0, SOL_OIC_PAYLOAD_SECURITY, "/oic/sec/svc");
    if (!svc)
        goto free_cred;

    security->resources.doxm = doxm;
    security->resources.pstat = pstat;
    security->resources.cred = cred;
    security->resources.svc = svc;
    return true;

free_cred:
    sol_oic_server_del_resource(svc);
free_pstat:
    sol_oic_server_del_resource(pstat);
free_doxm:
    sol_oic_server_del_resource(doxm);

    return false;
}

static void
unregister_server_bits(struct sol_oic_security *security)
{
    if (security->resources.doxm)
        sol_oic_server_del_resource(security->resources.doxm);

    if (security->resources.pstat)
        sol_oic_server_del_resource(security->resources.pstat);

    if (security->resources.cred)
        sol_oic_server_del_resource(security->resources.cred);

    if (security->resources.svc)
        sol_oic_server_del_resource(security->resources.svc);
}

static void
sol_oic_security_del_full(struct sol_oic_security *security, bool is_server)
{
    SOL_NULL_CHECK(security);

    if (is_server)
        unregister_server_bits(security);

    sol_coap_server_unref(security->server);
    sol_coap_server_unref(security->server_dtls);

    sol_util_secure_clear_memory(security, sizeof(*security));
    free(security);
}

static struct sol_oic_security *
sol_oic_security_add_full(struct sol_coap_server *server,
    struct sol_coap_server *server_dtls, bool is_server)
{
    struct sol_oic_security *security;
    struct sol_socket *socket_dtls;

    security = malloc(sizeof(*security));
    SOL_NULL_CHECK(security, NULL);

    socket_dtls = sol_coap_server_get_socket(server_dtls);
    SOL_NULL_CHECK(socket_dtls, NULL);

    security->callbacks = (struct sol_socket_dtls_credential_cb) {
        .data = security,
        .init = creds_init,
        .clear = creds_clear,
        .get_id = creds_get_id,
        .get_psk = creds_get_psk
    };
    if (sol_socket_dtls_set_credentials_callbacks(socket_dtls, &security->callbacks) < 0) {
        SOL_WRN("Passed DTLS socket is not a valid sol_socket_dtls");
        return NULL;
    }

    security->server = sol_coap_server_ref(server);
    security->server_dtls = sol_coap_server_ref(server_dtls);

    /* FIXME: More methods may be added in the future, so this might
     * have to change to a vector of supported methods. */
    security->transfer_method = &transfer_method_just_works;

    if (security_load_context(security) < 0) {
        SOL_WRN("Could not load security context");
        sol_oic_security_del_full(security, false);
        return NULL;
    }

    if (is_server) {
        if (register_server_bits(security))
            return security;

        sol_oic_security_del_full(security, false);
        return NULL;
    } 

    return security;
}

struct sol_oic_security *
sol_oic_server_security_add(struct sol_coap_server *server,
    struct sol_coap_server *server_dtls)
{
    return sol_oic_security_add_full(server, server_dtls, true);
}

void
sol_oic_server_security_del(struct sol_oic_security *security)
{
    sol_oic_security_del_full(security, true);
}

struct sol_oic_security *
sol_oic_client_security_add(struct sol_coap_server *server,
    struct sol_coap_server *server_dtls)
{
    return sol_oic_security_add_full(server, server_dtls, false);
}

void
sol_oic_client_security_del(struct sol_oic_security *security)
{
    sol_oic_security_del_full(security, false);
}

bool
sol_oic_security_get_is_paired(const struct sol_oic_security *security,
    struct sol_str_slice device_id)
{
    struct creds *creds;
    char psk[16];
    ssize_t r;

    creds = creds_init(security);
    SOL_NULL_CHECK(creds, false);

    r = creds_get_psk(creds, device_id, psk, sizeof(psk));
    creds_clear(creds);
    sol_util_secure_clear_memory(psk, sizeof(psk));

    return r > 0;
}

int
sol_oic_security_pair_request(struct sol_oic_security *security,
    struct sol_oic_resource *resource,
    void (*paired_cb)(void *data, enum sol_oic_security_pair_result result), void *data)
{
    int r;

    SOL_NULL_CHECK(security, -EINVAL);
    SOL_NULL_CHECK(security->transfer_method, -EINVAL);
    SOL_NULL_CHECK(security->transfer_method->pair_request, -EINVAL);
    SOL_NULL_CHECK(resource, -EINVAL);
    SOL_NULL_CHECK(paired_cb, -EINVAL);

    resource = sol_oic_resource_ref(resource);
    SOL_NULL_CHECK(resource, -EINVAL);

    r = security->transfer_method->pair_request(security,
        &resource->addr, &resource->device_id, paired_cb, data);
    if (r < 0)
        sol_oic_resource_unref(resource);

    return r;
}
