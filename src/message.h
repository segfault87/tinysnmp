/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include "asn1.h"

/******************************************************************************
 * constants
 */

#define FLAGS_AUTHENTICATED         0x01
#define FLAGS_ENCRYPTED             0x02
#define FLAGS_REPORTABLE            0x04

#define DATA_MAX_SIZE               65507 /* net-snmp behavior */

#define ENGINE_CONFORMANCE_RFC3411  0x80  /* SNMPv3 */

#define VERSION_SNMPv3              3

#define SECURITY_MODEL_USM          3

#define AUTH_NONE                   0
#define AUTH_MD5                    1
#define AUTH_SHA                    2

#define PRIVACY_NONE                0
#define PRIVACY_DES                 1
#define PRIVACY_AES                 2

/******************************************************************************
 * base structures
 */

struct snmp_globaldata
{
    asn1_integer msgid;
    asn1_integer maxsize;
    unsigned char flags;
    asn1_integer security_model;
};  

struct snmp_engineid
{
    unsigned char conformance;
    unsigned char enterprise_id[3];
    unsigned char format;
    unsigned char data[4];
    unsigned char creation_time[4];
};

struct snmp_messageheader
{
    asn1_integer version;
    struct snmp_globaldata global_data;
    struct snmp_engineid *engine_id;
    asn1_integer engine_boots;
    asn1_integer engine_time;

    /* authentication data */
    struct asn1_octetstring *username;

    /* context data */
    struct snmp_engineid *context_engine_id;
    struct asn1_octetstring *context_name;
};

/******************************************************************************
 * function prototypes
 */

struct snmp_usm_context;

/* global */
void snmp_message_initialize();

/* header-related */
struct snmp_messageheader* snmp_message_header_new();
struct snmp_messageheader* snmp_message_header_decode(struct
                                                      asn1_struct *message);
void snmp_message_header_del(struct snmp_messageheader *header);
void snmp_set_authentication(struct snmp_messageheader *header,
                             unsigned char *passphrase,
                             int auth_method);
void snmp_set_privacy(struct snmp_messageheader *header,
                      unsigned char *passphrase,
                      int privacy_method);

/* message manipulation */
struct asn1_struct* snmp_create_message(const struct snmp_messageheader *h,
                                        struct snmp_usm_context *usm,
                                        struct asn1_struct *pdu,
                                        unsigned char pdutype);
struct asn1_struct* snmp_create_message_encrypted(const struct
                                                  snmp_messageheader *h,
                                                  struct snmp_usm_context *usm,
                                                  struct asn1_struct *pdu,
                                                  unsigned char pdutype);
struct asn1_struct* snmp_create_discovery();

unsigned int snmp_msgid(const struct asn1_struct *msg);

#endif
