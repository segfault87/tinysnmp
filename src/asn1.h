/* asn1.h: A simple and ill-implemented ASN.1 (a subset of BER and its derivat-
 * ives) encoder and decoder
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#ifndef _ASN1_H_
#define _ASN1_H_

#include <stdlib.h>

/******************************************************************************
 * flags
 */

#define ASN1_INITIAL_PAYLOAD 1
#define EOC_PAYLOAD 2

#define CONFIG_LITTLE_ENDIAN

/******************************************************************************
 * type identifiers
 */

typedef unsigned long long asn1_integer;

/* type traits */
#define CLASS_UNIVERSAL    0x00
#define CLASS_APPLICATION  0x40
#define CLASS_CONTEXT      0x80
#define FORMAT_PRIMITIVE   0x00
#define FORMAT_CONSTRUCTED 0x20

/* built-in */
#define NODE_EOC         (0x00 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_BOOLEAN     (0x01 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_INTEGER     (0x02 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_OCTETSTRING (0x04 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_NULL        (0x05 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_OBJECTID    (0x06 | CLASS_UNIVERSAL | FORMAT_PRIMITIVE)
#define NODE_SEQUENCE    (0x10 | CLASS_UNIVERSAL | FORMAT_CONSTRUCTED)

/* SNMP-specific types */
#define NODE_IPADDRESS   (0x00 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_COUNTER32   (0x01 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_UNSIGNED32  (0x02 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_TIMETICKS   (0x03 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_OPAQUE      (0x04 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_NSAPADDRESS (0x05 | CLASS_APPLICATION | FORMAT_PRIMITIVE)
#define NODE_COUNTER64   (0x06 | CLASS_APPLICATION | FORMAT_PRIMITIVE)

/* SNMP PDUs */
#define NODE_GETREQUEST     (0x00 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_GETNEXTREQUEST (0x01 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_RESPONSE       (0x02 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_SETREQUEST     (0x03 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_GETBULKREQUEST (0x05 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_INFORMREQUEST  (0x06 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_TRAP           (0x04 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)
#define NODE_REPORT         (0x08 | CLASS_CONTEXT | FORMAT_CONSTRUCTED)

/* SNMP exceptions */
#define NODE_NOSUCHOBJECT   (0x00 | CLASS_CONTEXT | FORMAT_PRIMITIVE)
#define NODE_NOSUCHINSTANCE (0x01 | CLASS_CONTEXT | FORMAT_PRIMITIVE)
#define NODE_ENDOFMIBVIEW   (0x02 | CLASS_CONTEXT | FORMAT_PRIMITIVE)

/******************************************************************************
 * ASN.1 base structures
 */

struct asn1_struct;

struct asn1_node
{
    unsigned char type;
    void *data;

    struct asn1_struct *parent;
    struct asn1_node *prev;
    struct asn1_node *next;
};

struct asn1_struct
{
    int nodecount;
    
    struct asn1_node *head;
    struct asn1_node *tail;
};

/******************************************************************************
 * primitive type decls
 */

struct asn1_octetstring
{
    unsigned int length;
    unsigned char *data;
};

struct asn1_oid
{
    unsigned int length;
    int *data;
};

struct asn1_ipaddress
{
    unsigned char addr[4];
};

/******************************************************************************
 * function prototypes
 */

struct asn1_struct* asn1_new();
struct asn1_struct* asn1_copy(const struct asn1_struct *other);
struct asn1_struct* asn1_decode(const unsigned char *data,
                                int length);
int asn1_encode(const struct asn1_struct *asn1,
                unsigned char *outbuf,
                int outbuflen);
void asn1_destroy(struct asn1_struct *asn1);
int asn1_expected_encoding_length(const struct asn1_struct *asn1);

/* data sequence manipulation */
struct asn1_node* asn1_node_at(struct asn1_struct *asn1,
                               int idx);
void asn1_node_insert_before(struct asn1_node *node,
                             void *data,
                             unsigned char type);
void asn1_node_append(struct asn1_struct *asn1,
                      void *data,
                      unsigned char type);
void asn1_node_remove(struct asn1_node *node);
void asn1_node_remove_last(struct asn1_struct *asn1);

/* data initialization */
void* asn1_data_integer_new(asn1_integer integer);
void* asn1_data_octetstring_new(const unsigned char *string,
                                int length);
void* asn1_data_octetstring_copy(const struct asn1_octetstring *string);
void* asn1_data_null_new();
void* asn1_data_oid_new(const int *oid,
                        int length);
void* asn1_data_oid_copy(const struct asn1_oid *oid);
void* asn1_data_sequence_new();
void* asn1_data_ipaddress_new(const unsigned char *addrs);
void* asn1_data_ipaddress_copy(const struct asn1_ipaddress *addr);

/* data deallocation */
void asn1_data_integer_del(asn1_integer *data);
void asn1_data_octetstring_del(struct asn1_octetstring *data);
void asn1_data_oid_del(struct asn1_oid *data);
void asn1_data_sequence_del(struct asn1_struct *data);
void asn1_data_ipaddress_del(struct asn1_ipaddress *data);

/* data encoding */
int asn1_data_integer_encode(const void *data,
                             unsigned char *str,
                             int length);
int asn1_data_octetstring_encode(const void *pdata,
                                 unsigned char *str,
                                 int length);
int asn1_data_null_encode(const void *pdata,
                          unsigned char *str,
                          int length);
int asn1_data_oid_encode(const void *pdata,
                         unsigned char *str,
                         int length);
int asn1_data_sequence_encode(const void *pdata,
                              unsigned char *str,
                              int length);
int asn1_data_ipaddress_encode(const void *pdata,
                               unsigned char *str,
                               int length);

/* data decoding */
int asn1_data_integer_decode(const unsigned char *str,
                             void **out);
int asn1_data_octetstring_decode(const unsigned char *str,
                                 void **out);
int asn1_data_null_decode(const unsigned char *str,
                          void **out);
int asn1_data_oid_decode(const unsigned char *str,
                         void **out);
int asn1_data_sequence_decode(const unsigned char *str,
                              void **out);
int asn1_data_ipaddress_decode(const unsigned char *str,
                               void **out);

/* data encode length */
int asn1_data_integer_encode_length(const asn1_integer *data);
int asn1_data_octetstring_encode_length(const struct asn1_octetstring *data);
int asn1_data_null_encode_length(const void *data);
int asn1_data_oid_encode_length(const struct asn1_oid *data);
int asn1_data_sequence_encode_length(const struct asn1_struct *data);
int asn1_data_ipaddress_encode_length(const struct asn1_ipaddress *data);

/******************************************************************************
 * type casting helpers
 */

#define AS_INTEGER(p)     ((asn1_integer *)p)
#define AS_OCTETSTRING(p) ((struct asn1_octetstring *)p)
#define AS_NULL(p)        NULL
#define AS_OID(p)         ((struct asn1_oid *)p)
#define AS_SEQUENCE(p)    ((struct asn1_struct *)p)
#define AS_IPADDRESS(p)   ((struct asn1_ipaddress *)p)

#endif
