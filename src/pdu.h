/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _PDU_H_
#define _PDU_H_

#include "asn1.h"

/******************************************************************************
 * function prototypes
 */

struct asn1_struct* snmp_create_pdu(asn1_integer reqid,
                                    struct asn1_struct *bindings);
struct asn1_struct* snmp_create_empty_pdu(asn1_integer reqid);

void snmp_append_bindings(struct asn1_struct *bindings,
                          struct asn1_oid *oid,
                          void *data,
                          unsigned char type);

struct asn1_struct* snmp_get_pdu_section(struct asn1_struct *msg,
                                         unsigned char *pdutype);

#endif
