/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _NET_H_
#define _NET_H_

#include "asn1.h"

/******************************************************************************
 * constants
 */

#define SNMP_PORT 161

/******************************************************************************
 * structs
 */

struct sockaddr_in;

struct snmp_net 
{
    int clifd;
    int srvfd;

    int maxtries;
    asn1_integer reqid;
    struct asn1_struct *response;

    void *p;
};

/******************************************************************************
 * function prototypes
 */

int snmp_net_initialize(struct snmp_net *net,
                        const struct asn1_octetstring *host);

int snmp_send_message(struct snmp_net *net,
                      const struct asn1_struct *msg);

#endif
