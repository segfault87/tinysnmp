/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/aes.h>

#include "message.h"
#include "tinysnmp.h"

#include "usm.h"

/******************************************************************************
 * privates
 */

#define PRIVATE(ctx) ((struct _snmp_private *)ctx->p)

struct _snmp_private
{
    EVP_MD_CTX *evp;
    unsigned int tmp_len;
};

struct asn1_octetstring* _snmp_create_key(struct snmp_usm_context *ctx,
                                          int auth_method,
                                          struct asn1_octetstring *pass,
                                          struct snmp_engineid *engineid);

struct asn1_octetstring* _snmp_set_salt_des(struct asn1_octetstring *privkey,
                                            struct asn1_octetstring **osalt);
struct asn1_octetstring* _snmp_set_salt_aes(struct asn1_octetstring *privkey,
                                            struct asn1_octetstring **osalt);

struct asn1_octetstring* _snmp_encrypt_des(struct snmp_usm_context *ctx,
                                           unsigned char *plaintext,
                                           int textlen);
struct asn1_octetstring* _snmp_encrypt_aes(struct snmp_usm_context *ctx,
                                           unsigned char *plaintext,
                                           int textlen);

int _snmp_decrypt_des(struct snmp_usm_context *ctx,
                      struct asn1_octetstring *iv,
                      struct asn1_octetstring *cipher,
                      unsigned char *out,
                      unsigned int *outlen);
int _snmp_decrypt_aes(struct snmp_usm_context *ctx,
                      struct asn1_octetstring *iv,
                      struct asn1_octetstring *cipher,
                      unsigned char *out,
                      unsigned int *outlen);

/******************************************************************************
 * impls
 */

/* initialize context */
void snmp_usm_context_initialize(struct snmp_usm_context *ctx)
{
    ctx->auth_type = AUTH_NONE;
    ctx->auth_key = NULL;

    ctx->priv_type = PRIVACY_NONE;
    ctx->priv_key = NULL;
    
    ctx->p = malloc(sizeof(struct _snmp_private));
    
    PRIVATE(ctx)->evp = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
}

/* specified in RFC 2274 */
int snmp_create_auth_key(struct snmp_usm_context *ctx,
                         int auth_method,
                         struct asn1_octetstring *pass,
                         struct snmp_engineid *engineid)
{
    ctx->auth_type = auth_method;
    ctx->auth_key = _snmp_create_key(ctx, auth_method, pass, engineid);

    if (ctx->auth_key)
        return 1;
    else
        return 0;
}

int snmp_create_priv_key(struct snmp_usm_context *ctx,
                         int priv_method,
                         struct asn1_octetstring *pass,
                         struct snmp_engineid *engineid)
{
    if (!ctx->auth_type || !ctx->auth_key)
        return 0;

    ctx->priv_type = priv_method;
    ctx->priv_key = _snmp_create_key(ctx, ctx->auth_type, pass, engineid);

    if (priv_method == PRIVACY_DES)
        ctx->salt = _snmp_set_salt_des(ctx->priv_key, &ctx->priv_param);
    else if (priv_method == PRIVACY_AES)
        ctx->salt = _snmp_set_salt_aes(ctx->priv_key, &ctx->priv_param);

    if (ctx->priv_key && ctx->salt)
        return 1;
    else
        return 0;
}

/* generate authentication param */
struct asn1_octetstring* snmp_encode_auth(struct snmp_usm_context *ctx,
                                          struct asn1_struct *msg)
{
    const EVP_MD *evp_md;
    struct asn1_octetstring *param;
    unsigned char *enc;
    int enclen;
    unsigned char tmp[16];
    unsigned int tmplen = 16;
    
    if (!ctx->auth_key || !ctx->auth_type)
        return NULL;

    param = asn1_data_octetstring_new(NULL, 12);

    enclen = asn1_expected_encoding_length(msg);
    enc = (unsigned char *)malloc(enclen);
    asn1_encode(msg, enc, enclen);

    switch (ctx->auth_type) {
        case AUTH_MD5:
            evp_md = EVP_md5();
            break;
        case AUTH_SHA:
            evp_md = EVP_sha1();
            break;
        default:
            asn1_data_octetstring_del(param);
            free(enc);
            
            return NULL;
    }

    HMAC(evp_md, ctx->auth_key->data, ctx->auth_key->length,
         enc, enclen, tmp, &tmplen);

    memcpy(param->data, tmp, 12);

    free(enc);

    return param;
}

struct asn1_octetstring* snmp_encrypt(struct snmp_usm_context *ctx,
                                      struct asn1_struct *pdu)
{
    struct asn1_octetstring *res;
    unsigned char *pduenc;
    int pdulen;

    /* encode pdu */
    pdulen = asn1_data_sequence_encode_length(pdu) + 5;
    pduenc = (unsigned char *)malloc(pdulen);
    pduenc[0] = NODE_SEQUENCE;
    pdulen = asn1_data_sequence_encode(pdu, pduenc + 1, pdulen - 1) + 1;

    switch (ctx->priv_type) {
        case PRIVACY_DES:
            res = _snmp_encrypt_des(ctx, pduenc, pdulen);
            break;
        case PRIVACY_AES:
            res = _snmp_encrypt_aes(ctx, pduenc, pdulen);
            break;
        default:
            res = NULL;
    }

    free(pduenc);

    return res;
}

struct asn1_struct* snmp_decrypt(struct snmp_usm_context *ctx,
                                 struct asn1_octetstring *iv,
                                 struct asn1_octetstring *cipher)
{
    unsigned char deciphered[65535];
    unsigned int length;
    int ret;

    switch (ctx->priv_type) {
        case PRIVACY_DES:
            ret = _snmp_decrypt_des(ctx, iv, cipher, deciphered, &length);
            break;
        case PRIVACY_AES:
            ret = _snmp_decrypt_aes(ctx, iv, cipher, deciphered, &length);
            break;
        default:
            return NULL;
    }

    if (ret)
        return asn1_decode(deciphered, length);
    else
        return NULL;
}

struct asn1_octetstring* snmp_salt_localize(struct snmp_usm_context *ctx,
                                            struct asn1_octetstring *salt)
{
    struct asn1_octetstring *copy;
    int i;

    if (ctx->priv_type == PRIVACY_DES) {
        copy = asn1_data_octetstring_copy(salt);
        
        for (i = 0; i < copy->length; ++i) {
            copy->data[i] = salt->data[i] ^
                ctx->priv_key->data[i + copy->length];
        }
    } else {
        unsigned int net_boots = 16777216;
        unsigned int net_time = rand();
        
        copy = asn1_data_octetstring_new(NULL, USM_AES_SALT_SIZE);
        memcpy(copy->data, &net_boots, 4);
        memcpy(copy->data + 4, &net_time, 4);
        memcpy(copy->data + 8, salt->data, 8);
    }

    return copy;
}


/******************************************************************************
 * private impls
 */

struct asn1_octetstring* _snmp_create_key(struct snmp_usm_context *ctx,
                                          int auth_method,
                                          struct asn1_octetstring *pass,
                                          struct snmp_engineid *engineid)
{
    struct asn1_octetstring *str;
    EVP_MD_CTX *evp = PRIVATE(ctx)->evp;
    unsigned char buf[USM_HASH_BLOCK], *bufp;
    int nbytes = USM_PP_EXPANDED;
    unsigned int pindex = 0;
    int i;
    
    if (!pass || !engineid)
        return NULL;

    if (pass->length < USM_PASSPHRASE_MIN) {
        fprintf(stderr, "%s: passphrase is too short (%d characters min)\n",
                __func__,
                USM_PASSPHRASE_MIN);
        return NULL;
    }

    if (auth_method == AUTH_MD5)
        EVP_DigestInit(evp, EVP_md5());
    else if (auth_method == AUTH_SHA)
        EVP_DigestInit(evp, EVP_sha1());
    else
        return NULL;

    str = asn1_data_octetstring_new(NULL, 16);

    while (nbytes > 0) {
        bufp = buf;
        for (i = 0; i < USM_HASH_BLOCK; ++i)
            *bufp++ = pass->data[pindex++ % pass->length];
        
        EVP_DigestUpdate(evp, buf, USM_HASH_BLOCK);

        nbytes -= USM_HASH_BLOCK;
    }

    EVP_DigestFinal(evp, str->data, &str->length);

    EVP_MD_CTX_cleanup(evp);

    /* init again */
    if (auth_method == AUTH_MD5)
        EVP_DigestInit(evp, EVP_md5());
    else
        EVP_DigestInit(evp, EVP_sha1());

    nbytes = 0;
    memcpy(buf, str->data, str->length);
    nbytes += str->length;
    memcpy(buf + nbytes, engineid, sizeof(struct snmp_engineid));
    nbytes += sizeof(struct snmp_engineid);
    memcpy(buf + nbytes, str->data, str->length);
    nbytes += str->length;

    EVP_DigestUpdate(evp, buf, nbytes);

    EVP_DigestFinal(evp, str->data, &str->length);

    EVP_MD_CTX_cleanup(evp);

    return str;
}

struct asn1_octetstring* _snmp_set_salt_des(struct asn1_octetstring *privkey,
                                            struct asn1_octetstring **osalt)
{
    struct asn1_octetstring *salt;
    int net_boots = 16777216; // ??
    int net_salt_int = rand();
    int i;
    
    salt = asn1_data_octetstring_new(NULL, USM_DES_SALT_SIZE);

    memcpy(salt->data,
           &net_boots,
           USM_DES_SALT_SIZE / 2);
    memcpy(salt->data + (USM_DES_SALT_SIZE / 2),
           &net_salt_int,
           USM_DES_SALT_SIZE / 2);

    *osalt = asn1_data_octetstring_copy(salt);

    for (i = 0; i < (int)USM_DES_SALT_SIZE; ++i)
        salt->data[i] ^= privkey->data[i + USM_DES_SALT_SIZE];

    return salt;
}

struct asn1_octetstring* _snmp_set_salt_aes(struct asn1_octetstring *privkey,
                                            struct asn1_octetstring **osalt)
{
    struct asn1_octetstring *salt;
    unsigned int net_boots = 16777126;
    unsigned int net_time = (unsigned int)rand();
    unsigned int net_int1 = htonl(rand());
    unsigned int net_int2 = htonl(rand());

    salt = asn1_data_octetstring_new(NULL, USM_AES_SALT_SIZE);

    memcpy(salt->data, &net_boots, 4);
    memcpy(salt->data + 4, &net_time, 4);
    memcpy(salt->data + 8, &net_int1, 4);
    memcpy(salt->data + 12, &net_int2, 4);

    *osalt = asn1_data_octetstring_new(salt->data + 8, USM_AES_SALT_SIZE / 2);

    return salt;
}

struct asn1_octetstring* _snmp_encrypt_des(struct snmp_usm_context *ctx,
                                           unsigned char *plaintext,
                                           int textlen)
{
    unsigned char cipher[65535];
    unsigned int cipherlen = 65535;
    unsigned char pad_block[128];
    unsigned char my_iv[128];
    int pad, plast, pad_size = 0;
    DES_key_schedule key_sched;
    DES_cblock key_struct;

    pad_size = USM_DES_PRIVLEN;
    
    memset(my_iv, 0, 128);
    pad = pad_size - (textlen % pad_size);
    plast = (int)textlen - (pad_size - pad);
    if (pad == pad_size)
        pad = 0;

    if (pad > 0) {
        memcpy(pad_block, plaintext + plast, pad_size - pad);
        memset(&pad_block[pad_size - pad], pad, pad);
    }
    
    memcpy(key_struct, ctx->priv_key->data, sizeof(key_struct));
    DES_key_sched(&key_struct, &key_sched);

    memcpy(my_iv, ctx->salt->data, ctx->salt->length);

    DES_ncbc_encrypt(plaintext, cipher, plast, &key_sched,
                     (DES_cblock *)my_iv, DES_ENCRYPT);

    if (pad > 0) {
        DES_ncbc_encrypt(pad_block, cipher + plast, pad_size, &key_sched,
                         (DES_cblock *)my_iv, DES_ENCRYPT);
        cipherlen = plast + pad_size;
    } else {
        cipherlen = plast;
    }

    return asn1_data_octetstring_new(cipher, cipherlen);
}

struct asn1_octetstring* _snmp_encrypt_aes(struct snmp_usm_context *ctx,
                                           unsigned char *plaintext,
                                           int textlen)
{
    unsigned char cipher[65535];
    unsigned int cipherlen = 65535;
    unsigned char my_iv[128];
    AES_KEY aes_key;
    int new_ivlen = 0;

    (void)AES_set_encrypt_key(ctx->priv_key->data,
                              USM_AES_PRIVLEN * 8,
                              &aes_key);

    memcpy(my_iv, ctx->salt->data, ctx->salt->length);
    
    AES_set_encrypt_key(ctx->priv_key->data, USM_AES_PRIVLEN * 8, &aes_key);

    AES_cfb128_encrypt(plaintext, cipher, textlen,
                       &aes_key, my_iv, &new_ivlen, AES_ENCRYPT);

    return asn1_data_octetstring_new(cipher, cipherlen);
}

int _snmp_decrypt_des(struct snmp_usm_context *ctx,
                      struct asn1_octetstring *iv,
                      struct asn1_octetstring *cipher,
                      unsigned char *out,
                      unsigned int *outlen)
 {
    unsigned char my_iv[128];
    DES_key_schedule key_sched;
    DES_cblock key_struct;

    memset(my_iv, 0, sizeof(my_iv));
    
    memcpy(key_struct, ctx->priv_key->data, sizeof(key_struct));
    (void)DES_key_sched(&key_struct, &key_sched);

    memcpy(my_iv, iv->data, iv->length);
    
    DES_cbc_encrypt(cipher->data, out, cipher->length, &key_sched,
                    (DES_cblock *)my_iv, DES_DECRYPT);
    *outlen = cipher->length;
    
    return 1;
}

int _snmp_decrypt_aes(struct snmp_usm_context *ctx,
                      struct asn1_octetstring *iv,
                      struct asn1_octetstring *cipher,
                      unsigned char *out,
                      unsigned int *outlen)
{
    unsigned char my_iv[128];
    int new_ivlen = 0;
    AES_KEY aes_key;

    (void)AES_set_encrypt_key(ctx->priv_key->data,
                              USM_AES_PRIVLEN * 8,
                              &aes_key);

    memset(my_iv, 0, sizeof(my_iv));
    memcpy(my_iv, iv->data, iv->length);

    AES_cfb128_encrypt(cipher->data, out, cipher->length,
                       &aes_key, my_iv, &new_ivlen, AES_DECRYPT);
    *outlen = cipher->length;

    return 1;
}
