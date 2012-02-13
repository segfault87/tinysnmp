/* asn1.c: A simple and ill-implemented ASN.1 (a subset of BER and its derivat-
 * ives) encoder and decoder
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <string.h>

#include "asn1.h"

/******************************************************************************
 * private func prototypes
 */

struct asn1_node* _asn1_node_new(struct asn1_struct *asn1);
int _asn1_encode(const struct asn1_struct *asn1,
                 unsigned char *outbuf,
                 int outbuflen,
                 int prependlength);
int _asn1_node_encode_length(const struct asn1_node *node);
void _asn1_free_node_data(unsigned char type,
                          void *data);
int _asn1_integer_decode(const unsigned char *data,
                         int length);
int _asn1_integer_length(asn1_integer len);
int _asn1_vlen_length(int len);
int _asn1_vlen_encode(int number,
                      unsigned char *buf,
                      int buflen);
int _asn1_vlen_decode(const unsigned char *buf,
                      int *out);
int _asn1_oid_length(int len);
void _asn1_node_print(const struct asn1_struct *node,
                      int depth);

/******************************************************************************
 * impls
 */

/* Create an empty ASN.1 structure */
struct asn1_struct* asn1_new()
{
    struct asn1_struct *s = (struct asn1_struct *)malloc(
        sizeof(struct asn1_struct));

    s->nodecount = 0;
    s->head = _asn1_node_new(s);
    s->tail = _asn1_node_new(s);
    s->head->prev = s->head;
    s->head->next = s->tail;
    s->tail->prev = s->head;
    s->tail->next = s->tail;

    return s;
}

/* Clone an ASN.1 tree */
struct asn1_struct* asn1_copy(const struct asn1_struct *other)
{
    struct asn1_struct *asn1 = asn1_new();
    struct asn1_node *node;
    unsigned char type;
    void *data;

    node = other->head->next;
    while (node != other->tail) {
        type = node->type;

        if (type & FORMAT_CONSTRUCTED) {
            /* treat all constructed types in one way */
            data = asn1_copy(AS_SEQUENCE(node->data));
        } else {
            switch (type) {
                case NODE_EOC:
                case NODE_NULL:
                case NODE_NOSUCHOBJECT:
                case NODE_NOSUCHINSTANCE:
                case NODE_ENDOFMIBVIEW:
                    data = asn1_data_null_new();
                    break;
                case NODE_BOOLEAN:
                case NODE_INTEGER:
                case NODE_COUNTER32:
                case NODE_UNSIGNED32:
                case NODE_TIMETICKS:
                case NODE_COUNTER64:
                    data = asn1_data_integer_new(*AS_INTEGER(node->data));
                    break;
                case NODE_OCTETSTRING:
                    data = asn1_data_octetstring_copy(node->data);
                    break;
                case NODE_OBJECTID:
                    data = asn1_data_oid_copy(AS_OID(node->data));
                    break;
                case NODE_IPADDRESS:
                    data = asn1_data_ipaddress_copy(node->data);
                    break;
                default:
                    fprintf(stderr, "%s: undefined node type %02x\n",
                            __func__,
                            type);
            }
        }

        asn1_node_append(asn1, data, type);
        
        node = node->next;
    }

    return asn1;
}

/* Decode ASN.1 stream */
struct asn1_struct* asn1_decode(const unsigned char *data,
                                int length)
{
    int (*decoder)(const unsigned char *, void **);
    int offset;
    struct asn1_struct *asn1 = asn1_new();

    for (offset = 0; offset < length; ) {
        unsigned char otype;
        int len, olen;
        void *nobj;

        if (offset + 1 > length) {
            fprintf(stderr, "%s: unxepected end of stream\n", __func__);
            return asn1;
        }
        
        otype = *data++;
        ++offset;

        if (otype & FORMAT_CONSTRUCTED) {
            decoder = asn1_data_sequence_decode;
        } else {
            switch (otype) {
                case NODE_EOC:
                case NODE_NULL:
                case NODE_NOSUCHOBJECT:
                case NODE_NOSUCHINSTANCE:
                case NODE_ENDOFMIBVIEW:
                    decoder = asn1_data_null_decode;
                    break;
                case NODE_BOOLEAN:
                case NODE_INTEGER:
                case NODE_COUNTER32:
                case NODE_UNSIGNED32:
                case NODE_TIMETICKS:
                case NODE_COUNTER64:
                    decoder = asn1_data_integer_decode;
                    break;
                case NODE_OCTETSTRING:
                    decoder = asn1_data_octetstring_decode;
                    break;
                case NODE_OBJECTID:
                    decoder = asn1_data_oid_decode;
                    break;
                case NODE_IPADDRESS:
                    decoder = asn1_data_ipaddress_decode;
                    break;
                default:
                    fprintf(stderr, "%s: unrecognized type %x\n",
                            __func__,
                            otype);
            
                    olen = _asn1_vlen_decode(data, &len);
                    data += olen + len;
                    offset += olen + len;

                    continue;
            }
        }

        len = decoder(data, &nobj);
        if (len == -1) {
            asn1_destroy(asn1);
            return NULL;
        }

        asn1_node_append(asn1, nobj, otype);

        data += len;
        offset += len;
    }

    return asn1;
}

/* Encode ASN.1 */
int asn1_encode(const struct asn1_struct *asn1,
                unsigned char *outbuf,
                int outbuflen)
{
    return _asn1_encode(asn1, outbuf, outbuflen, 0);
}

/* Disallocator */
void asn1_destroy(struct asn1_struct *asn1)
{
    while (asn1->nodecount != 0)
        asn1_node_remove_last(asn1);

    free(asn1->head);
    free(asn1->tail);
}

/* Returns encode length */
int asn1_expected_encoding_length(const struct asn1_struct *asn1)
{
    int len = 0;
    const struct asn1_node *n = asn1->head->next;

    while (n != asn1->tail) {
        int clen = _asn1_node_encode_length(n);
        len += clen + _asn1_vlen_length(clen) + ASN1_INITIAL_PAYLOAD;
        n = n->next;
    }

    return len;
}

/* Returns the nth node of an ASN.1 structure */
struct asn1_node* asn1_node_at(struct asn1_struct *asn1,
                               int idx)
{
    struct asn1_node *n;
    int i;
    
    if (idx < 0 || idx >= asn1->nodecount)
        return NULL;

    n = asn1->head;
    for (i = 0; i <= idx; ++i)
        n = n->next;

    if (n == asn1->head || n == asn1->tail)
        return NULL;
    else
        return n;
}

/* Insert a new node into a specific position */
void asn1_node_insert_before(struct asn1_node *node,
                             void *data,
                             unsigned char type)
{
    struct asn1_node *n;

    if (!node) return;
    
    n = _asn1_node_new(node->parent);
    n->type = type;
    n->data = data;
    
    if (node->prev == NULL) {
        // head
        n->prev = node;
        n->next = node->next;
        node->next = n;
    } else if (node->next == NULL) {
        // tail
        n->next = node;
        n->prev = node->prev;
        node->prev = n;
    } else {
        node->prev->next = n;
        n->next = node;
        n->prev = node->prev;
        node->prev = n;
    }

    node->parent->nodecount++;
}

/* Append a new node */
void asn1_node_append(struct asn1_struct *asn1,
                      void *data,
                      unsigned char type)
{
    struct asn1_node *n = _asn1_node_new(asn1);
    n->type = type;
    n->data = data;

    n->next = asn1->tail;
    n->prev = asn1->tail->prev;
    asn1->tail->prev->next = n;
    asn1->tail->prev = n;

    asn1->nodecount++;
}

/* Remove a node */
void asn1_node_remove(struct asn1_node *node)
{
    if (node->prev == NULL || node->next == NULL)
        return; // head or tail

    node->prev->next = node->next;
    node->next->prev = node->prev;

    _asn1_free_node_data(node->type, node->data);
    free(node);

    node->parent->nodecount--;
}

/* Remove the last node */
void asn1_node_remove_last(struct asn1_struct *asn1)
{
    struct asn1_node *n;
    
    if (asn1->tail->prev == asn1->head)
        return;

    n = asn1->tail->prev;

    n->prev->next = asn1->tail;
    asn1->tail->prev = n->prev;

    _asn1_free_node_data(n->type, n->data);
    free(n);

    asn1->nodecount--;
}

/* initializer functions */

void* asn1_data_integer_new(asn1_integer integer)
{
    asn1_integer *data = (asn1_integer *)malloc(sizeof(asn1_integer));
    *data = integer;

    return data;
}

void* asn1_data_octetstring_new(const unsigned char *string,
                                int length)
{
    struct asn1_octetstring *data = (struct asn1_octetstring *)malloc(
        sizeof(struct asn1_octetstring));

    data->length = length;
    data->data = (unsigned char *)malloc(sizeof(unsigned char) * (length + 1));

    if (string) {
        memcpy(data->data, string, length);
        data->data[data->length] = 0;
    } else {
        memset(data->data, 0, sizeof(unsigned char) * (length + 1));
    }

    return data;
}

void* asn1_data_octetstring_copy(const struct asn1_octetstring *string)
{
    struct asn1_octetstring *data;

    if (!string)
        return asn1_data_octetstring_new(NULL, 0);

    data = (struct asn1_octetstring *)malloc(sizeof(struct asn1_octetstring));

    data->length = string->length;
    data->data = (unsigned char *)malloc(
        sizeof(unsigned char) * (data->length + 1));

    memcpy(data->data, string->data, data->length + 1);
    
    return data;
}

void* asn1_data_null_new()
{
    return NULL;
}

void* asn1_data_oid_new(const int *oid,
                        int length)
{
    struct asn1_oid *data = (struct asn1_oid *)malloc(sizeof(struct asn1_oid));

    data->length = length;
    data->data = (int *)malloc(sizeof(int) * length);

    if (oid)
        memcpy(data->data, oid, sizeof(int) * length);
    else
        memset(data->data, 0, sizeof(int) * length);

    return data;
}

void* asn1_data_oid_copy(const struct asn1_oid *oid)
{
    struct asn1_oid *data;

    if (!oid)
        return NULL;

    data = (struct asn1_oid *)malloc(sizeof(struct asn1_oid));
    data->length = oid->length;
    data->data = (int *)malloc(sizeof(int) * data->length);
    memcpy(data->data, oid->data, sizeof(int) * data->length);

    return data;
}

void* asn1_data_sequence_new()
{
    return asn1_new();
}

void* asn1_data_ipaddress_new(const unsigned char *addrs)
{
    struct asn1_ipaddress *addr = (struct asn1_ipaddress *)malloc(
        sizeof(struct asn1_ipaddress));

    if (!addrs)
        memset(addr->addr, 0, 4);
    else
        memcpy(addr->addr, addrs, 4);

    return addr;
}

void* asn1_data_ipaddress_copy(const struct asn1_ipaddress *addr)
{
    struct asn1_ipaddress *newaddr;

    if (!addr)
        return asn1_data_ipaddress_new(NULL);

    newaddr = (struct asn1_ipaddress *)malloc(sizeof(struct asn1_ipaddress));

    memcpy(newaddr->addr, addr->addr, 4);

    return newaddr;
}

/* dtors */

void asn1_data_integer_del(asn1_integer *data)
{
    free(data);
}

void asn1_data_octetstring_del(struct asn1_octetstring *data)
{
    free(data->data);
    free(data);
}

void asn1_data_oid_del(struct asn1_oid *data)
{
    free(data->data);
    free(data);
}

void asn1_data_sequence_del(struct asn1_struct *data)
{
    asn1_destroy(data);
}

void asn1_data_ipaddress_del(struct asn1_ipaddress *data)
{
    free(data);
}

/* encoders */

int asn1_data_integer_encode(const void *pdata,
                             unsigned char *str,
                             int length)
{
    const asn1_integer *data = pdata;
    int i;
    int len = asn1_data_integer_encode_length(data);
    int lenlen = _asn1_vlen_length(len);
    const char *octets = (const char *)data;

    if (length < len + lenlen)
        return -1;

    str += _asn1_vlen_encode(len, str, length);

#ifdef CONFIG_LITTLE_ENDIAN
    for (i = len - 1; i >= 0; --i)
#else
    for (i = 0; i < len; ++i)
#endif
        *str++ = octets[i];

    return len + lenlen;
}

int asn1_data_octetstring_encode(const void *pdata,
                                 unsigned char *str,
                                 int length)
{
    const struct asn1_octetstring *data = pdata;
    int len = asn1_data_octetstring_encode_length(data);
    int lenlen = _asn1_vlen_length(len);
    
    if (length < len + lenlen)
        return -1;

    str += _asn1_vlen_encode(len, str, length);

    memcpy(str, data->data, data->length);
    
    return len + lenlen;
}

int asn1_data_null_encode(const void *pdata,
                          unsigned char *str,
                          int length)
{
    *str = 0;
    
    return 1;
}

int asn1_data_oid_encode(const void *pdata,
                         unsigned char *str,
                         int length)
{
    const struct asn1_oid *data = pdata;
    int i, j, k;
    int *ptr;
    int len = asn1_data_oid_encode_length(data);
    int lenlen = _asn1_vlen_length(len);

    if (length < len + lenlen)
        return -1;

    str += _asn1_vlen_encode(len, str, length);

    ptr = data->data;
    for (i = 0; i < data->length; ++i) {
        int d = data->data[i];
        int l = _asn1_oid_length(d);

        for (j = l; j >= 1; --j) {
            int c, s;

            s = 1;
            for (k = 1; k < j; ++k)
                s *= 128;

            c = d / s;

            if (j == 1)
                *str++ = (unsigned char)c;
            else
                *str++ = 0x80 | (unsigned char)c;
            
            d -= c * s;
        }
        
        length -= l;
    }

    return len + lenlen;
}

int asn1_data_sequence_encode(const void *pdata,
                              unsigned char *str,
                              int length)
{
    return _asn1_encode(pdata, str, length, 1);
}

int asn1_data_ipaddress_encode(const void *pdata,
                               unsigned char *str,
                               int length)
{
    int len = asn1_data_ipaddress_encode_length(pdata);
    int lenlen = _asn1_vlen_length(len);
    const struct asn1_ipaddress *data = pdata;

    if (length < len + lenlen)
        return -1;

    str += _asn1_vlen_encode(len, str, length);
    
    memcpy(str, data->addr, 4);

    return len + lenlen;
}

/* decoders */

int asn1_data_integer_decode(const unsigned char *str,
                             void **out)
{
    int read, length;

    read = _asn1_vlen_decode(str, &length);
    
    if (length < 0 || length > sizeof(asn1_integer)) {
        fprintf(stderr, "%s: integer is out of range!\n", __func__);
        *out = NULL;
        return -1;
    }

    *out = asn1_data_integer_new(_asn1_integer_decode(str + read, length));

    return read + length;
}

int asn1_data_octetstring_decode(const unsigned char *str,
                                 void **out)
{
    int read, length;

    read = _asn1_vlen_decode(str, &length);
    
    *out = asn1_data_octetstring_new(str + read, length);

    return read + length;
}

int asn1_data_null_decode(const unsigned char *str,
                          void **out)
{
    *out = NULL;

    return 1;
}

int asn1_data_oid_decode(const unsigned char *str,
                         void **out)
{
    int read, length;
    int count;
    int i;
    struct asn1_oid *oid;
    int *ptr;
    const unsigned char *cptr;

    read = _asn1_vlen_decode(str, &length);
    
    if (length == 0)
        fprintf(stderr, "%s: oid has zero length\n", __func__);
    
    str += read;

    count = 0;
    for (i = 0; i < length; ++i) {
        if (!(str[i] & 0x80))
            ++count;
    }

    oid = asn1_data_oid_new(NULL, count);
    ptr = oid->data;
    for (i = 0; i < count; ++i) {
        int j, v;
        
        cptr = str;
        while (*cptr & 0x80)
            ++cptr;

        v = cptr - str + 1;

        *ptr = 0;
        for (j = v; j >= 1; --j) {
            int s, k;

            s = 1;
            for (k = 1; k < j; ++k)
                s *= 128;

            *ptr += (int)(*str++ & 0x7f) * s;
        }

        ++ptr;
        str = cptr + 1;
    }
    

    *out = oid;

    return read + length;
}

int asn1_data_sequence_decode(const unsigned char *str,
                              void **out)
{
    int read, length;

    read = _asn1_vlen_decode(str, &length);

    *out = asn1_decode(str + read, length);

    return read + length;
}

int asn1_data_ipaddress_decode(const unsigned char *str,
                               void **out)
{
    int read, length;
    struct asn1_ipaddress *addr;

    read = _asn1_vlen_decode(str, &length);

    str += read;

    memcpy(addr->addr, str, 4);

    return read + length;
}

/* encode length functions */

int asn1_data_integer_encode_length(const asn1_integer *data)
{
    return _asn1_integer_length(*data);
}

int asn1_data_octetstring_encode_length(const struct asn1_octetstring *data)
{
    return data->length;
}

int asn1_data_null_encode_length(const void *data)
{
    return 0;
}

int asn1_data_oid_encode_length(const struct asn1_oid *data)
{
    int i;
    int sum = 0;

    for (i = 0; i < data->length; ++i)
        sum += _asn1_oid_length(data->data[i]);
    
    return sum;
}

int asn1_data_sequence_encode_length(const struct asn1_struct *data)
{
    int length = asn1_expected_encoding_length(data);
    
    return length;
}

int asn1_data_ipaddress_encode_length(const struct asn1_ipaddress *addr)
{
    return 4;
}

struct asn1_node* _asn1_node_new(struct asn1_struct *asn1)
{
    struct asn1_node *n = (struct asn1_node *)malloc(sizeof(struct asn1_node));
    
    n->type = NODE_NULL;
    n->data = NULL;

    n->parent = asn1;
    n->prev = NULL;
    n->next = NULL;

    return n;
}

/******************************************************************************
 * private funcs impl.
 */

int _asn1_encode(const struct asn1_struct *asn1,
                 unsigned char *outbuf,
                 int outbuflen,
                 int prependlength)
{
    const struct asn1_node *node;
    int (*encoder)(const void *, unsigned char *, int);
    int len, elen;

    if (prependlength)
        elen = asn1_data_sequence_encode_length(asn1);
    else
        elen = asn1_expected_encoding_length(asn1);

    if (outbuflen < elen) {
        fprintf(stderr, "%s: outbuf is too small\n", __func__);
        return -1;
    }

    /* encode sequence length if this node is not the top-level */
    if (prependlength) {
        int plen = _asn1_vlen_encode(elen, outbuf, outbuflen);
        outbuf += plen;
        outbuflen -= plen;
    }

    node = asn1->head->next;
    while (node != asn1->tail) {
        if (node->type & FORMAT_CONSTRUCTED) {
            encoder = asn1_data_sequence_encode;
        } else {
            switch (node->type) {
                case NODE_EOC:
                case NODE_NULL:
                case NODE_NOSUCHOBJECT:
                case NODE_NOSUCHINSTANCE:
                case NODE_ENDOFMIBVIEW:
                    encoder = asn1_data_null_encode;
                    break;
                case NODE_BOOLEAN:
                case NODE_INTEGER:
                case NODE_COUNTER32:
                case NODE_UNSIGNED32:
                case NODE_TIMETICKS:
                case NODE_COUNTER64:
                    encoder = asn1_data_integer_encode;
                    break;
                case NODE_OCTETSTRING:
                    encoder = asn1_data_octetstring_encode;
                    break;
                case NODE_OBJECTID:
                    encoder = asn1_data_oid_encode;
                    break;
                default:
                    fprintf(stderr, "%s: unrecognized type %x\n",
                            __func__,
                            node->type);
                    continue;
            }
        }

        *outbuf++ = node->type;
        --outbuflen;
        
        len = encoder(node->data, outbuf, outbuflen);
        outbuf += len;
        outbuflen -= len;

        node = node->next;
    }

    if (prependlength)
        return elen + _asn1_vlen_length(elen);
    else
        return elen;
}

int _asn1_node_encode_length(const struct asn1_node *node)
{
    if (node->type & FORMAT_CONSTRUCTED)
        return asn1_data_sequence_encode_length(node->data);
    
    switch (node->type) {
        case NODE_BOOLEAN:
        case NODE_INTEGER:
        case NODE_COUNTER32:
        case NODE_UNSIGNED32:
        case NODE_TIMETICKS:
        case NODE_COUNTER64:
            return asn1_data_integer_encode_length(node->data);
        case NODE_OCTETSTRING:
            return asn1_data_octetstring_encode_length(node->data);
        case NODE_EOC:
        case NODE_NULL:
        case NODE_NOSUCHOBJECT:
        case NODE_NOSUCHINSTANCE:
        case NODE_ENDOFMIBVIEW:
            return asn1_data_null_encode_length(node->data);
        case NODE_OBJECTID:
            return asn1_data_oid_encode_length(node->data);
        case NODE_IPADDRESS:
            return asn1_data_ipaddress_encode_length(node->data);
        default:
            fprintf(stderr, "%s: undefined node type %x\n",
                    __func__,
                    node->type);
            return 0;
    }
}

void _asn1_free_node_data(unsigned char type,
                          void *data)
{
    if (!data)
        return;

    if (type & FORMAT_CONSTRUCTED) {
        asn1_data_sequence_del(data);
        return;
    }
    
    switch (type) {
        case NODE_BOOLEAN:
        case NODE_INTEGER:
        case NODE_COUNTER32:
        case NODE_UNSIGNED32:
        case NODE_TIMETICKS:
        case NODE_COUNTER64:
            asn1_data_integer_del(data);
            break;
        case NODE_OCTETSTRING:
            asn1_data_octetstring_del(data);
            break;
        case NODE_EOC:
        case NODE_NULL:
        case NODE_NOSUCHOBJECT:
        case NODE_NOSUCHINSTANCE:
        case NODE_ENDOFMIBVIEW:
            break;
        case NODE_OBJECTID:
            asn1_data_oid_del(data);
            break;
        case NODE_IPADDRESS:
            asn1_data_ipaddress_del(data);
        default:
            fprintf(stderr, "%s: undefined node type %x\n",
                    __func__,
                    type);
    }
}

int _asn1_integer_decode(const unsigned char *data,
                         int length)
{
    int i, j = 0;

    for (i = 0; i < length; ++i)
#ifdef CONFIG_LITTLE_ENDIAN
        j |= (int)data[i] << ((length - 1 - i) * 8);
#else
        j |= (int)data[i] << (i * 8);
#endif

    return j;
}   

int _asn1_integer_length(asn1_integer num)
{
    const char *octet = (const char *)&num;
    int i;
    int cnt = 0;

    for (i = sizeof(asn1_integer) - 1; i >= 0; --i) {
        if (octet[i] & 0x80) {
            if (cnt > 0)
                --cnt;
            break;
        } else if (octet[i]) {
            break;
        }
        
        ++cnt;
    }

    /* To avoid null payload */
    if (cnt == sizeof(asn1_integer))
        --cnt;

    return sizeof(asn1_integer) - cnt;
}

int _asn1_vlen_length(int num)
{
    int len = _asn1_integer_length(num);

    if (len == 1)
        return 1;
    else
        return len + 1;
}

int _asn1_vlen_encode(int number,
                      unsigned char *buf,
                      int buflen)
{
    int i;
    int len = _asn1_integer_length(number);
    int pll = _asn1_vlen_length(number);
    const char *octets = (const char *)&number;
    
    if (buflen < pll) {
        fprintf(stderr, "%s: buffer overflow\n", __func__);
        return -1;
    }

    if (len == 1) {
        *buf = (unsigned char)number;
    } else {
        *buf++ = 0x80 | (unsigned char)len;
#ifdef CONFIG_LITTLE_ENDIAN
        /* little endian to big endian conversion */
        for (i = len - 1; i >= 0; --i)
#else
        for (i = 0; i < len; ++i)
#endif
            *buf++ = octets[i];
    }

    return pll;
}

int _asn1_vlen_decode(const unsigned char *buf,
                        int *out)
{
    if (buf[0] & 0x80) {
        /* if the first octet is larger than 0x80, the octet
         * itself is the length of length octets */
        *out = _asn1_integer_decode(buf + 1, *buf & 0x7f);
        return (*buf & 0x7f) + 1;
    } else {
        *out = (int)*buf;
        return 1;
    }
}


int _asn1_oid_length(int len)
{
    int i, j, s;
    
    for (i = 3; i >= 0; --i) {
        s = 1;
        for (j = 0; j < i; ++j)
            s *= 128;
        
        if (len / s)
            break;
    }

    if (i == -1)
        return 1;
    else
        return i + 1;
}
