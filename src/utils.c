/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

/******************************************************************************
 * private func prototypes
 */

void _asn1_print(FILE *fp,
                      const struct asn1_struct *node,
                      int depth);
int _snmp_hex_to_dec(char c);

/******************************************************************************
 * impls
 */

asn1_integer asn1_create_integer_from_string(const char *string,
                                              int length)
{
    asn1_integer integer;
    struct asn1_octetstring *str = asn1_data_octetstring_new(
        (unsigned char *)string, length);

    integer = atoll((char *)str->data);

    asn1_data_octetstring_del(str);

    return integer;
}

struct asn1_oid* asn1_create_oid_from_string(const char *string,
                                             int length)
{
    int i;
    int digit = 0;
    int cnt = 0;
    int base, start, end;
    struct asn1_oid *oid;
    
    for (i = 0; i < length; ++i) {
        if (string[i] >= '0' && string[i] <= '9' && !digit) {
            digit = 1;
            ++cnt;
        } else if (string[i] >= '0' && string[i] <= '9') {
            // noop
        } else if (string[i] == '.' && digit) {
            digit = 0;
        } else if (string[i] == '.') {
            fprintf(stderr, "%s: invalid oid format\n", __func__);
            return NULL;
        } else {
            fprintf(stderr, "%s: invalid oid format\n", __func__);
            return NULL;
        }
    }

    oid = asn1_data_oid_new(NULL, cnt - 1);

    digit = 0;
    base = 0;
    for (i = 0; i < length; ++i) {
        if (string[i] >= '0' && string[i] <= '9' && !digit) {
            digit = 1;
            start = i;
        } else if (string[i] == '.' && digit) {
            digit = 0;
            end = i - 1;

            if (base == 0) {
                oid->data[0] = 40 * asn1_create_integer_from_string(
                    string + start, end - start + 1);
            } else if (base == 1) {
                oid->data[0] += asn1_create_integer_from_string(
                    string + start, end - start + 1);
            } else {
                oid->data[base - 1] = asn1_create_integer_from_string(
                    string + start, end - start + 1);
            }

            ++base;
        }
    }
    
    end = length - 1;
    oid->data[cnt - 2] = asn1_create_integer_from_string(
        string + start, end - start + 1);

    return oid;
}

struct asn1_ipaddress* asn1_create_ipaddress_from_string(const char *string,
                                                         int length)
{
    struct asn1_ipaddress *addr;
    int dec[4];
    
    sscanf(string, "%d.%d.%d.%d", dec, dec + 1, dec + 2, dec + 3);
    
    if (!((dec[0] >= 0 && dec[0] <= 255) &&
          (dec[1] >= 0 && dec[1] <= 255) &&
          (dec[2] >= 0 && dec[2] <= 255) &&
          (dec[3] >= 0 && dec[3] <= 255))) {
        fprintf(stderr, "%s: invalid ip address format\n", __func__);
        return NULL;
    }

    addr = asn1_data_ipaddress_new(NULL);
    addr->addr[0] = dec[0];
    addr->addr[1] = dec[1];
    addr->addr[2] = dec[2];
    addr->addr[3] = dec[3];

    return addr;
}

int asn1_compare_oid(const struct asn1_oid *super,
                     const struct asn1_oid *sub)
{
    int i;

    if (super->length > sub->length)
        return 0;

    for (i = 0; i < super->length; ++i) {
        if (super->data[i] != sub->data[i])
            return 0;
    }

    return 1;
}

struct asn1_octetstring* snmp_hex_to_octet(const char *hexstr,
                                           int length)
{
    struct asn1_octetstring *str;
    int i;
    
    if (length % 2) {
        fprintf(stderr, "%s: invalid hex string\n", __func__);
        return NULL;
    }

    for (i = 0; i < length; ++i) {
        if (_snmp_hex_to_dec(i) == -1) {
            fprintf(stderr, "%s: invalid hex string\n", __func__);
            return NULL;
        }
    }

    str = asn1_data_octetstring_new(NULL, length / 2);
    for (i = 0; i < length / 2; ++i) {
        str->data[i] =
            _snmp_hex_to_dec(hexstr[0]) * 16 +
            _snmp_hex_to_dec(hexstr[1]);
        hexstr += 2;
    }

    return str;
}

/* Print ASN.1 structure (for debugging) */
void asn1_print(FILE *fp, const struct asn1_struct *asn1)
{
    _asn1_print(fp, asn1, 0);
}

void asn1_print_node(FILE *fp,
                      const struct asn1_node *node)
{
    if (node->type & FORMAT_CONSTRUCTED) {
        switch (node->type) {
            case NODE_SEQUENCE:
                fprintf(fp, "sequence"); break;
            case NODE_GETREQUEST:
                fprintf(fp, "SNMP getRequest"); break;
            case NODE_GETNEXTREQUEST:
                fprintf(fp, "SNMP getNextRequest"); break;
            case NODE_RESPONSE:
                fprintf(fp, "SNMP response"); break;
            case NODE_SETREQUEST:
                fprintf(fp, "SNMP setRequest"); break;
            case NODE_GETBULKREQUEST:
                fprintf(fp, "SNMP getBulkRequest"); break;
            case NODE_INFORMREQUEST:
                fprintf(fp, "SNMP informRequest"); break;
            case NODE_TRAP:
                fprintf(fp, "SNMP trap"); break;
            case NODE_REPORT:
                fprintf(fp, "SNMP report"); break;
            default:
                fprintf(fp, "unrecognized sequence");
        }
        
        fprintf(fp ,": %d items", AS_SEQUENCE(node->data)->nodecount);
    } else {
        switch (node->type) {
            case NODE_EOC:
            case NODE_NULL:
                fprintf(fp, "null");
                break;
            case NODE_NOSUCHOBJECT:
                fprintf(fp, "noSuchObject");
                break;
            case NODE_NOSUCHINSTANCE:
                fprintf(fp, "noSuchInstance");
                break;
            case NODE_ENDOFMIBVIEW:
                fprintf(fp, "endOfMibView");
                break;
            case NODE_BOOLEAN:
                fprintf(fp, "boolean: ");
                asn1_print_boolean(fp, node->data);
                break;
            case NODE_INTEGER:
            case NODE_UNSIGNED32:
                fprintf(fp, "integer: ");
                asn1_print_integer(fp, node->data);
                break;
            case NODE_COUNTER32:
            case NODE_COUNTER64:
                fprintf(fp, "counter: ");
                asn1_print_integer(fp, node->data);
                break;
            case NODE_TIMETICKS:
                fprintf(fp, "timeticks: ");
                asn1_print_timeticks(fp, node->data);
                break;
            case NODE_OCTETSTRING:
                fprintf(fp, "octet string: ");
                asn1_print_string(fp, node->data);
                break;
            case NODE_OBJECTID:
                fprintf(fp, "object id: ");
                asn1_print_oid(fp, node->data);
                break;
            default:
                fprintf(fp, "unknown");
        }
    }
}

void asn1_print_boolean(FILE *fp, const asn1_integer *obj)
{
    fprintf(fp, "%s", *obj ? "true" : "false");
}

void asn1_print_integer(FILE *fp, const asn1_integer *obj)
{
    fprintf(fp, "%llu", *obj);
}

void asn1_print_string(FILE *fp, const struct asn1_octetstring *obj)
{
    int printable = 1;
    int i;
    
    if (!obj->length) {
        fprintf(fp, "null");
        return;
    }
    
    /* print it directly if this string is printable
     * too sad there's no PrintableString for SNMP */
    for (i = 0; i < obj->length; ++i) {
        if (obj->data[i] < 0x20 || obj->data[i] > 0x7e) {
            printable = 0;
            break;
        }
    }
    
    if (printable) {
        fprintf(fp, "%s (%d)", obj->data, obj->length);
    } else {
        for (i = 0; i < obj->length; ++i)
            fprintf(fp, "%02x ", obj->data[i]);
        fprintf(fp, "(%d)", obj->length);
    }
}

void asn1_print_oid(FILE *fp, const struct asn1_oid *obj)
{
    int i;
    
    fprintf(fp, "%d.%d.", obj->data[0] / 40, obj->data[0] % 40);
    for (i = 1; i < obj->length - 1; ++i)
        fprintf(fp, "%d.", obj->data[i]);
    fprintf(fp, "%d (%d)", obj->data[i], obj->length + 1);
}

void asn1_print_timeticks(FILE *fp, const asn1_integer *obj)
{
    unsigned int i = *obj;
    unsigned int days, hours, minutes, seconds;

    days = i / (100 * 60 * 60 * 24);
    i -= days * (100 * 60 * 60 * 24);
    hours = i / (100 * 60 * 60);
    i -= hours * (100 * 60 * 60);
    minutes = i / (100 * 60);
    i -= minutes * (100 * 60);
    seconds = i / 100;
    i -= seconds * 100;

    fprintf(fp, "%u:%02u:%02u:%02u.%02u",
            days,
            hours,
            minutes,
            seconds,
            i);
}

void asn1_print_ip(FILE *fp, const struct asn1_ipaddress *obj)
{
    fprintf(fp, "%d.%d.%d.%d",
            obj->addr[0],
            obj->addr[1],
            obj->addr[2],
            obj->addr[3]);
}

/******************************************************************************
 * private funcs impl.
 */

void _asn1_print(FILE *fp,
                 const struct asn1_struct *node,
                 int depth)
{
    const struct asn1_node *n = node->head->next;
    int i;

    while (n != node->tail) {
        for (i = 0; i < depth; ++i)
            fprintf(fp, "\t");
        asn1_print_node(fp, n);
        fprintf(fp, "\n");

        if (n->type & FORMAT_CONSTRUCTED)
            _asn1_print(fp, AS_SEQUENCE(n->data), depth + 1);
        
        n = n->next;
    }
}

int _snmp_hex_to_dec(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    else if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    else
        return -1;
}
