/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _USM_H_
#define _USM_H_

#include "asn1.h"

/******************************************************************************
 * constants
 */

/* hmac */
#define USM_PASSPHRASE_MIN 8
#define USM_HASH_BLOCK     64
#define USM_PP_EXPANDED    1048576

/* des */
#define USM_DES_SALT_SIZE  8
#define USM_DES_PRIVLEN    8
#define USM_DES_PRIVLEN_IV 8

/* aes */
#define USM_AES_SALT_SIZE  16
#define USM_AES_PRIVLEN    16
#define USM_AES_PRIVLEN_IV 16

/******************************************************************************
 * structures
 */

struct snmp_usm_context
{
    int auth_type;
    struct asn1_octetstring *auth_key;

    int priv_type;
    struct asn1_octetstring *priv_key;
    struct asn1_octetstring *salt;
    struct asn1_octetstring *priv_param;

    void *p;
};  

/******************************************************************************
 * function prototypes
 */

struct snmp_engineid;

void snmp_usm_context_initialize(struct snmp_usm_context *ctx);

int snmp_create_auth_key(struct snmp_usm_context *ctx,
                         int auth_method,
                         struct asn1_octetstring *pass,
                         struct snmp_engineid *engineid);
int snmp_create_priv_key(struct snmp_usm_context *ctx,
                         int priv_method,
                         struct asn1_octetstring *pass,
                         struct snmp_engineid *engineid);

struct asn1_octetstring* snmp_encode_auth(struct snmp_usm_context *ctx,
                                          struct asn1_struct *msg);
struct asn1_octetstring* snmp_encrypt(struct snmp_usm_context *ctx,
                                      struct asn1_struct *pdu);
struct asn1_struct* snmp_decrypt(struct snmp_usm_context *ctx,
                                 struct asn1_octetstring *iv,
                                 struct asn1_octetstring *cipher);

struct asn1_octetstring* snmp_salt_localize(struct snmp_usm_context *ctx,
                                            struct asn1_octetstring *salt);

#endif
