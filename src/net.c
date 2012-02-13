/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2008 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#include "message.h"

#include "net.h"

/******************************************************************************
 * privates
 */

#define PRIVATE(net) ((struct _snmp_private *)net->p)

struct _snmp_private 
{
    struct sockaddr_in cliaddr;
};

int _snmp_resolve_name(struct snmp_net *net,
                       const struct asn1_octetstring *name);

/******************************************************************************
 * impls
 */

int snmp_net_initialize(struct snmp_net *net,
                        const struct asn1_octetstring *host)
{
    struct timeval tv;

    net->p = (struct _snmp_private *)malloc(sizeof(struct _snmp_private));

    net->maxtries = 5;
    net->reqid = 0;
    net->response = NULL;
    
    /* initialize sender socket */
    if ((net->clifd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        free(net->p);
        perror(__func__);

        return 0;
    }

    /* set destination address */
    memset(&PRIVATE(net)->cliaddr, 0, sizeof(struct sockaddr_in));
    PRIVATE(net)->cliaddr.sin_family = AF_INET;
    PRIVATE(net)->cliaddr.sin_port = htons(SNMP_PORT);
    if (!_snmp_resolve_name(net, host)) {
        free(net->p);

        return 0;
    }

    /* set timeout */
    tv.tv_sec = 1;
    setsockopt(net->clifd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

    return 1;
}

int snmp_send_message(struct snmp_net *net,
                      const struct asn1_struct *msg)
{
    struct asn1_struct *incoming;
    unsigned char *encoded, dincoming[DATA_MAX_SIZE];
    int len, readlen;
    int i;
    int arrived;

    if (net->response) {
        asn1_destroy(net->response);
        net->response = NULL;
    }

    len = asn1_expected_encoding_length(msg);
    encoded = (unsigned char *)malloc(sizeof(unsigned char) * len + 1);

    asn1_encode(msg, encoded, len);

    arrived = 0;
    /* I/O */
    for (i = 0; i < net->maxtries; ++i) {
        /* send multiple times until the response arrives.
         * there's no way to do these thinkgs automatically because UDP
         * doesn't provide check-and-redeliver in contrast with TCP. */
        sendto(net->clifd,
               encoded,
               len,
               0,
               (const struct sockaddr *)&PRIVATE(net)->cliaddr,
               sizeof(struct sockaddr_in));
    
        if ((readlen = recv(net->clifd,
                            dincoming,
                            DATA_MAX_SIZE,
                            0)) != -1 &&
            errno != EAGAIN) {
            arrived = 1;
            break;
        }   
    }

    free(encoded);

    if (!arrived) {
        fprintf(stderr, "%s: no response from the server\n", __func__);
        return 0;
    }

    /* decode incoming ASN.1 stream */
    incoming = asn1_decode(dincoming, readlen);
    if (!incoming) {
        fprintf(stderr, "%s: corrupted response\n", __func__);
        return 0;
    }

    /* check whether message id is identical */
    net->reqid = snmp_msgid(incoming);
    if (!net->reqid || snmp_msgid(msg) != net->reqid) {
        fprintf(stderr, "%s: incorrect msgid\n", __func__);
        net->reqid = 0;
        asn1_destroy(incoming);
        return 0;
    }
    
    net->response = incoming;

    return 1;
}

/******************************************************************************
 * private impls
 */

int _snmp_resolve_name(struct snmp_net *net,
                       const struct asn1_octetstring *name)
{
    /* 1. check whether this is an ip */
    if (inet_aton((const char *)name->data,
                  &PRIVATE(net)->cliaddr.sin_addr) == 0) {
        /* 2. check whether this is a domain name */
        struct hostent *hostent = gethostbyname((const char *)name->data);

        if (!hostent || *hostent->h_addr_list == NULL) {
            fprintf(stderr, "%s: could not resolve name address\n", __func__);
            return 0;
        }
        
        PRIVATE(net)->cliaddr.sin_addr.s_addr =
            ((long int *)*hostent->h_addr_list)[0];
    }

    return 1;
}
