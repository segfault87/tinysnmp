/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "asn1.h"

struct FILE;

/******************************************************************************
 * function prototypes
 */

asn1_integer asn1_create_integer_from_string(const char *string,
                                              int length);
struct asn1_oid* asn1_create_oid_from_string(const char *string,
                                             int length);
struct asn1_ipaddress* asn1_create_ipaddress_from_string(const char *string,
                                                         int length);
int asn1_compare_oid(const struct asn1_oid *super,
                     const struct asn1_oid *sub);

struct asn1_octetstring* snmp_create_engine_id_from_string(const char *string,
                                                           int length);
struct asn1_octetstring* snmp_hex_to_octet(const char *hexstr,
                                           int length);

/* output */
void asn1_print(FILE *fp, const struct asn1_struct *asn1);
void asn1_print_node(FILE *fp, const struct asn1_node *node);
void asn1_print_boolean(FILE *fp, const asn1_integer *obj);
void asn1_print_integer(FILE *fp, const asn1_integer *obj);
void asn1_print_string(FILE *fp, const struct asn1_octetstring *obj);
void asn1_print_oid(FILE *fp, const struct asn1_oid *obj);
void asn1_print_timeticks(FILE *fp, const asn1_integer *obj);
void asn1_print_ip(FILE *fp, const struct asn1_ipaddress *obj);

#endif
