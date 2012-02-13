/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "message.h"

#include "pdu.h"

struct asn1_struct* snmp_create_pdu(asn1_integer reqid,
                                    struct asn1_struct *bindings)
{
    struct asn1_struct *body = asn1_new();

    /* reqid */
    asn1_node_append(body, asn1_data_integer_new(reqid), NODE_INTEGER);

    /* error status */
    asn1_node_append(body, asn1_data_integer_new(0), NODE_INTEGER);

    /* error id */
    asn1_node_append(body, asn1_data_integer_new(0), NODE_INTEGER);

    /* variable bindings */
    asn1_node_append(body, bindings, NODE_SEQUENCE);

    return body;
}

struct asn1_struct* snmp_create_empty_pdu(asn1_integer reqid)
{
    return snmp_create_pdu(reqid, asn1_new());
}

void snmp_append_bindings(struct asn1_struct *bindings,
                          struct asn1_oid *oid,
                          void *data,
                          unsigned char type)
{
    struct asn1_struct *entry = asn1_new();

    asn1_node_append(entry, oid, NODE_OBJECTID); // oid
    asn1_node_append(entry, data, type);         // value

    asn1_node_append(bindings, entry, NODE_SEQUENCE);
}

struct asn1_struct* snmp_get_pdu_section(struct asn1_struct *msg,
                                         unsigned char *pdutype)
{
    struct asn1_node *node;
    struct asn1_struct *toplevel, *secondlevel;

    node = asn1_node_at(msg, 0);
    if (!node || node->type != NODE_SEQUENCE)
        return NULL;
    toplevel = AS_SEQUENCE(node->data);

    node = asn1_node_at(toplevel, 3);
    if (!node || node->type != NODE_SEQUENCE)
        return NULL;
    secondlevel = AS_SEQUENCE(node->data);

    node = asn1_node_at(secondlevel, 2);
    if (!node || !(node->type & FORMAT_CONSTRUCTED))
        return NULL;

    *pdutype = node->type;

    return AS_SEQUENCE(node->data);
}
