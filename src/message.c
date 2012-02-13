/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pdu.h"
#include "usm.h"

#include "message.h"

/******************************************************************************
 * private func prototypes
 */

struct asn1_struct* _snmp_create_message(const struct snmp_messageheader *h,
                                         struct snmp_usm_context *usm,
                                         struct asn1_struct *pdu,
                                         unsigned char pdutype,
                                         int internal);

/******************************************************************************
 * impls
 */

void snmp_message_initialize()
{
    srand(time(NULL));
}

/* initiailize message header */
struct snmp_messageheader* snmp_message_header_new()
{
    struct snmp_messageheader *header = (struct snmp_messageheader *)malloc(
        sizeof(struct snmp_messageheader));

    header->version = VERSION_SNMPv3;

    header->global_data.msgid = (unsigned int)rand();
    header->global_data.maxsize = DATA_MAX_SIZE;
    header->global_data.flags = 0;
    header->global_data.security_model = SECURITY_MODEL_USM;

    header->engine_id = NULL;
    header->engine_boots = 0;
    header->engine_time = 0;

    header->username = NULL;

    header->context_engine_id = NULL;
    header->context_name = NULL;

    return header;
}

/* decode message header from structured ASN.1 data */
struct snmp_messageheader* snmp_message_header_decode(struct
                                                      asn1_struct *message)
{
    struct asn1_node *node;
    struct asn1_struct *body, *global, *params, *paramsi, *data;
    struct snmp_messageheader *header;

    node = asn1_node_at(message, 0);
    if (!node || !(node->type == NODE_SEQUENCE))
        goto error1;

    header = snmp_message_header_new();

    body = AS_SEQUENCE(node->data);

    /* global data */
    node = asn1_node_at(body, 1);
    if (!node || node->type != NODE_SEQUENCE)
        goto error2;
    global = AS_SEQUENCE(node->data);

    /* version */
    node = asn1_node_at(body, 0);
    if (!node || node->type != NODE_INTEGER)
        goto error2;
    header->version = *AS_INTEGER(node->data);

    /* msgid */
    node = asn1_node_at(global, 0);
    if (!node || node->type != NODE_INTEGER)
        goto error2;
    header->global_data.msgid = *AS_INTEGER(node->data);

    /* maxsize */
    node = asn1_node_at(global, 1);
    if (!node || node->type != NODE_INTEGER)
        goto error2;
    header->global_data.maxsize = *AS_INTEGER(node->data);

    /* msgid */
    node = asn1_node_at(global, 2);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error2;
    header->global_data.flags = AS_OCTETSTRING(node->data)->data[0];

    /* usm */
    node = asn1_node_at(global, 3);
    if (!node || node->type != NODE_INTEGER)
        goto error2;
    header->global_data.security_model = *AS_INTEGER(node->data);

    /* data */
    node = asn1_node_at(body, 3);
    if (!node || node->type != NODE_SEQUENCE)
        goto error2;
    data = AS_SEQUENCE(node->data);

    /* context engine id */
    node = asn1_node_at(data, 0);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error2;
    header->context_engine_id = (struct snmp_engineid *)malloc(
        sizeof(struct snmp_engineid));
    memcpy(header->context_engine_id,
           AS_OCTETSTRING(node->data)->data,
           sizeof(struct snmp_engineid));

    /* context name */
    node = asn1_node_at(data, 1);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error2;
    header->context_name = asn1_data_octetstring_copy(
        AS_OCTETSTRING(node->data));

    /* params */
    node = asn1_node_at(body, 2);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error2;
    params = asn1_decode(AS_OCTETSTRING(node->data)->data,
                         AS_OCTETSTRING(node->data)->length);

    if (!params)
        goto error2;

    node = asn1_node_at(params, 0);
    if (!node || node->type != NODE_SEQUENCE)
        goto error3;
    paramsi = AS_SEQUENCE(node->data);

    /* engine id */
    node = asn1_node_at(paramsi, 0);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error3;
    header->engine_id = (struct snmp_engineid *)malloc(
        sizeof(struct snmp_engineid));
    memcpy(header->engine_id,
           AS_OCTETSTRING(node->data)->data,
           sizeof(struct snmp_engineid));

    /* boot count */
    node = asn1_node_at(paramsi, 1);
    if (!node || node->type != NODE_INTEGER)
        goto error3;
    header->engine_boots = *AS_INTEGER(node->data);

    /* boot time */
    node = asn1_node_at(paramsi, 2);
    if (!node || node->type != NODE_INTEGER)
        goto error3;
    header->engine_time = *AS_INTEGER(node->data);

    /* username */
    node = asn1_node_at(paramsi, 3);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error3;
    header->username = asn1_data_octetstring_copy(
        AS_OCTETSTRING(node->data));

    /* auth param */
    node = asn1_node_at(paramsi, 4);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error3;
    /*header->authentication_param = asn1_data_octetstring_copy(
      AS_OCTETSTRING(node->data));*/

    /* privacy param */
    node = asn1_node_at(paramsi, 5);
    if (!node || node->type != NODE_OCTETSTRING)
        goto error3;
    /*header->privacy_param = asn1_data_octetstring_copy(
      AS_OCTETSTRING(node->data));*/

    asn1_destroy(params);

    return header;

    /* fallback */
  error3:
    asn1_destroy(params);

  error2:
    snmp_message_header_del(header);

  error1:   
    fprintf(stderr, "%s: corrupted header\n", __func__);
        
    return NULL;
}

/* free header */
void snmp_message_header_del(struct snmp_messageheader *header)
{
    if (header->engine_id)
        free(header->engine_id);

    if (header->username)
        asn1_data_octetstring_del(header->username);

    if (header->context_engine_id)
        free(header->context_engine_id);

    if (header->context_name)
        asn1_data_octetstring_del(header->context_name);

    free(header);
}

/* initialize SNMPv3 frame */
struct asn1_struct* snmp_create_message(const struct snmp_messageheader *h,
                                        struct snmp_usm_context *usm,
                                        struct asn1_struct *pdu,
                                        unsigned char pdutype)
{
    struct asn1_struct *message;

    if (!pdutype & FORMAT_CONSTRUCTED) {
        fprintf(stderr,
                "%s: given pdu is not a sequence\n",
                __func__);
        return NULL;
    }

    message = _snmp_create_message(h, usm, pdu, pdutype, 0);

    return message;
}

struct asn1_struct* snmp_create_discovery()
{
    struct snmp_messageheader *header;
    struct asn1_struct *msg;

    header = snmp_message_header_new();
    header->global_data.flags = FLAGS_REPORTABLE;

    msg = snmp_create_message(header,
                              NULL,
                              snmp_create_empty_pdu(rand()),
                              NODE_GETREQUEST);

    snmp_message_header_del(header);

    return msg;
}

/******************************************************************************
 * private funcs impl.
 */

struct asn1_struct* _snmp_create_message(const struct snmp_messageheader *h,
                                         struct snmp_usm_context *usm,
                                         struct asn1_struct *pdu,
                                         unsigned char pdutype,
                                         int internal)
{
    struct asn1_struct *message, *messagei, *gdata, *context, *param, *parami;
    unsigned char *encodedparam;
    int encodelength;

    message = asn1_new();
    messagei = asn1_data_sequence_new();
    gdata = asn1_data_sequence_new();
    context = asn1_data_sequence_new();

    /* global data */
    asn1_node_append(gdata,
                     asn1_data_integer_new(h->global_data.msgid),
                     NODE_INTEGER);
    asn1_node_append(gdata,
                     asn1_data_integer_new(h->global_data.maxsize),
                     NODE_INTEGER);
    asn1_node_append(gdata,
                     asn1_data_octetstring_new(&h->global_data.flags, 1),
                     NODE_OCTETSTRING);
    asn1_node_append(gdata,
                     asn1_data_integer_new(h->global_data.security_model),
                     NODE_INTEGER);

    /* parameters */
    param = asn1_new();
    parami = asn1_data_sequence_new();

    if (h->engine_id) {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(
                             (unsigned char *)h->engine_id,
                             sizeof(struct snmp_engineid)),
                         NODE_OCTETSTRING);
    } else {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }

    asn1_node_append(parami,
                     asn1_data_integer_new(h->engine_boots),
                     NODE_INTEGER);
    asn1_node_append(parami,
                     asn1_data_integer_new(h->engine_time),
                     NODE_INTEGER);

    if (h->username) {
        asn1_node_append(parami,
                         asn1_data_octetstring_copy(h->username),
                         NODE_OCTETSTRING);
    } else {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }

    if (internal) {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(NULL, 12),
                         NODE_OCTETSTRING);
    } else if (usm && usm->auth_key) {
        struct asn1_struct *dummy =
            _snmp_create_message(h, usm, pdu, pdutype, 1);
        
        asn1_node_append(parami,
                         snmp_encode_auth(usm, dummy),
                         NODE_OCTETSTRING);

        asn1_destroy(dummy);
    } else {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }

    if (usm && usm->priv_param) {
        asn1_node_append(parami,
                         asn1_data_octetstring_copy(usm->priv_param),
                         NODE_OCTETSTRING);
    } else {
        asn1_node_append(parami,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }
    
    asn1_node_append(param,
                     parami,
                     NODE_SEQUENCE);

    encodelength = asn1_expected_encoding_length(param);
    encodedparam = (unsigned char *)malloc(
        sizeof(unsigned char) * encodelength + 1);
    asn1_encode(param, encodedparam, encodelength + 1);

    asn1_destroy(param);

    /* context data */
    if (h->context_engine_id) {
        asn1_node_append(context,
                         asn1_data_octetstring_new(
                             (unsigned char *)h->context_engine_id,
                             sizeof(struct snmp_engineid)),
                         NODE_OCTETSTRING);
    } else {
        asn1_node_append(context,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }
    
    if (h->context_name) {
        asn1_node_append(context,
                         asn1_data_octetstring_copy(h->context_name),
                         NODE_OCTETSTRING);
    } else {
        asn1_node_append(context,
                         asn1_data_octetstring_new(NULL, 0),
                         NODE_OCTETSTRING);
    }

    /* top level */
    asn1_node_append(message,
                     messagei,
                     NODE_SEQUENCE);

    asn1_node_append(context, asn1_copy(pdu), pdutype);

    /* body */
    asn1_node_append(messagei,
                     asn1_data_integer_new(h->version),
                     NODE_INTEGER);
    asn1_node_append(messagei,
                     gdata,
                     NODE_SEQUENCE);
    asn1_node_append(messagei,
                     asn1_data_octetstring_new(encodedparam, encodelength),
                     NODE_OCTETSTRING);

    if (usm && usm->priv_param) {
        asn1_node_append(messagei,
                         snmp_encrypt(usm, context),
                         NODE_OCTETSTRING);
        asn1_destroy(context);
    } else {
        asn1_node_append(messagei,
                         context,
                         NODE_SEQUENCE);
    }

    free(encodedparam);

    return message;
}

unsigned int snmp_msgid(const struct asn1_struct *msg)
{
    struct asn1_node *node;
    struct asn1_struct *toplevel, *global;

    node = asn1_node_at((struct asn1_struct *)msg, 0);
    if (!node || node->type != NODE_SEQUENCE)
        return 0;
    toplevel = AS_SEQUENCE(node->data);

    node = asn1_node_at((struct asn1_struct *)toplevel, 1);
    if (!node || node->type != NODE_SEQUENCE)
        return 0;
    global = AS_SEQUENCE(node->data);

    node = asn1_node_at((struct asn1_struct *)global, 0);
    if (!node || node->type != NODE_INTEGER)
        return 0;

    return *AS_INTEGER(node->data);
}

