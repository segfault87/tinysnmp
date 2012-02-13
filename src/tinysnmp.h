/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _TINYSNMP_H_
#define _TINYSNMP_H_

#include "message.h"

/******************************************************************************
 * constants
 */

#define COMMAND_GET      0
#define COMMAND_GETNEXT  1
#define COMMAND_GETBULK  2
#define COMMAND_SET      3
#define COMMAND_WALK     4
#define COMMAND_BULKWALK 5

/******************************************************************************
 * structures
 */

struct snmp_context
{
    struct snmp_engineid *engine_id;
    int engine_boot;
    int engine_time;
    
    struct snmp_engineid *context_engine_id;
    struct asn1_octetstring *context_name;

    struct asn1_octetstring *username;
    int auth_type;
    struct asn1_octetstring *auth_passphrase;

    int priv_type;
    struct asn1_octetstring *priv_passphrase;

    struct asn1_octetstring *host;

    int command;
    unsigned char pdutype;
    struct asn1_struct *bindings;

    int debug;

    int non_repeater;
    int max_repeaters;

    struct snmp_messageheader *header;
};

/******************************************************************************
 * function prototypes
 */

struct snmp_net;
struct snmp_usm_context;

void snmp_context_initialize(struct snmp_context *ctx);
void snmp_context_free(struct snmp_context *ctx);

int snmp_parse_arguments(struct snmp_context *ctx,
                         int argc,
                         char *argv[]);
void snmp_display_help(const char *progname);

int snmp_is_discovery_required(const struct snmp_context *ctx);

void snmp_initialize_header(struct snmp_context *ctx);
void snmp_update_header(struct snmp_context *ctx);

int snmp_query(struct snmp_context *ctx,
               struct snmp_net *net,
               struct snmp_usm_context *usm);
int snmp_query_walk(struct snmp_context *ctx,
                    struct snmp_net *net,
                    struct snmp_usm_context *usm);

int snmp_display_results(struct snmp_context *ctx,
                         struct asn1_struct *pdu,
                         unsigned char type);

void snmp_decrypt_if_needed(struct snmp_usm_context *usm,
                            struct asn1_struct *data);

#endif
