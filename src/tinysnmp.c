/* tinysnmp: A simple SNMP v3 client with minimal feature set
 *
 * (c)2009 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asn1.h"
#include "errors.h"
#include "message.h"
#include "net.h"
#include "pdu.h"
#include "usm.h"
#include "utils.h"

#include "tinysnmp.h"

/******************************************************************************
 * impls
 */

void snmp_context_initialize(struct snmp_context *ctx)
{
    ctx->engine_id = NULL;
    ctx->engine_boot = -1;
    ctx->engine_time = -1;
    
    ctx->context_engine_id = NULL;
    ctx->context_name = NULL;

    ctx->auth_type = AUTH_NONE;
    ctx->auth_passphrase = NULL;
    ctx->priv_type = PRIVACY_NONE;
    ctx->priv_passphrase = NULL;

    ctx->host = NULL;

    ctx->command = -1;
    ctx->bindings = asn1_new();

    ctx->debug = 0;

    ctx->non_repeater = 0;
    ctx->max_repeaters = 10;
}

void snmp_context_free(struct snmp_context *ctx)
{
    if (ctx->engine_id)
        free(ctx->engine_id);

    if (ctx->context_engine_id)
        free(ctx->context_engine_id);

    if (ctx->context_name)
        asn1_data_octetstring_del(ctx->context_name);

    if (ctx->username)
        asn1_data_octetstring_del(ctx->username);

    if (ctx->auth_passphrase)
        asn1_data_octetstring_del(ctx->auth_passphrase);

    if (ctx->priv_passphrase)
        asn1_data_octetstring_del(ctx->priv_passphrase);

    if (ctx->host)
        asn1_data_octetstring_del(ctx->host);
}

/* function name describes it all */
int snmp_parse_arguments(struct snmp_context *ctx,
                         int argc,
                         char *argv[])
{
    int i;
    int opt;

    /* parse option parameters */
    while ((opt = getopt(argc, argv, "dhu:a:A:p:P:e:c:n:b:t:")) != -1) {
        switch (opt) {
            case 'h':
                return 0;
            case 'u':
                ctx->username = asn1_data_octetstring_new(
                    (unsigned char *)optarg, strlen(optarg));
                break;
            case 'a':
                if (strcmp(optarg, "MD5") == 0 ||
                    strcmp(optarg, "md5") == 0)
                    ctx->auth_type = AUTH_MD5;
                else if (strcmp(optarg, "SHA") == 0 ||
                         strcmp(optarg, "sha") == 0)
                    ctx->auth_type = AUTH_SHA;
                else {
                    fprintf(stderr, "Invalid authentication protocol.\n");
                    return 0;
                }
                break;
            case 'A':
                ctx->auth_passphrase = asn1_data_octetstring_new(
                    (unsigned char *)optarg, strlen(optarg));
                break;
            case 'p':
                if (strcmp(optarg, "AES") == 0 ||
                    strcmp(optarg, "aes") == 0)
                    ctx->priv_type = PRIVACY_AES;
                else if (strcmp(optarg, "DES") == 0 ||
                         strcmp(optarg, "des") == 0)
                    ctx->priv_type = PRIVACY_DES;
                else {
                    fprintf(stderr, "Invalid authentication protocol.\n");
                    return 0;
                }
                break;
            case 'P':
                ctx->priv_passphrase = asn1_data_octetstring_new(
                    (unsigned char *)optarg, strlen(optarg));
                break;
            case 'e':
            {
                struct asn1_octetstring *engineid = snmp_hex_to_octet(
                    optarg, strlen(optarg));
                if (!engineid) {
                    fprintf(stderr, "Invalid security engine ID string.\n");
                    return 0;
                }

                ctx->engine_id = (struct snmp_engineid *)malloc(
                    sizeof(struct snmp_engineid));
                memcpy(ctx->engine_id,
                       engineid->data,
                       engineid->length);

                asn1_data_octetstring_del(engineid);
                
                break;
            }
            case 'c':
            {
                struct asn1_octetstring *engineid = snmp_hex_to_octet(
                    optarg, strlen(optarg));
                if (!engineid) {
                    fprintf(stderr, "Invalid security engine ID string.\n");
                    return 0;
                }

                ctx->context_engine_id = (struct snmp_engineid *)malloc(
                    sizeof(struct snmp_engineid));
                memcpy(ctx->context_engine_id,
                       engineid->data,
                       engineid->length);

                asn1_data_octetstring_del(engineid);

                break;
            }
            case 'n':
                ctx->context_name = asn1_data_octetstring_new(
                    (const unsigned char *)optarg, strlen(optarg));
                break;
            case 'b':
                ctx->engine_boot = asn1_create_integer_from_string(
                    optarg, strlen(optarg));
                break;
            case 't':
                ctx->engine_time = asn1_create_integer_from_string(
                    optarg, strlen(optarg));
                break;
            case 'd':
                ctx->debug = 1;
                break;
            case 'r':
                ctx->non_repeater = atoi(optarg);
                break;
            case 'm':
                ctx->max_repeaters = atoi(optarg);
                break;
        }
    }

    if (argc - optind == 0) {
        return 0;
    } else if (argc - optind < 3) {
        fprintf(stderr, "%s: insufficient parameters\n", argv[0]);
        return 0;
    }

    /* parse command type */
    if (strcmp(argv[optind], "get") == 0) {
        ctx->command = COMMAND_GET;
        ctx->pdutype = NODE_GETREQUEST;
    } else if (strcmp(argv[optind], "getnext") == 0) {
        ctx->command = COMMAND_GETNEXT;
        ctx->pdutype = NODE_GETNEXTREQUEST;
    } else if (strcmp(argv[optind], "set") == 0) {
        ctx->command = COMMAND_SET;
        ctx->pdutype = NODE_SETREQUEST;
    } else if (strcmp(argv[optind], "bulkget") == 0) {
        ctx->command = COMMAND_GETBULK;
        ctx->pdutype = NODE_GETBULKREQUEST;
    } else if (strcmp(argv[optind], "walk") == 0) {
        ctx->command = COMMAND_WALK;
        ctx->pdutype = NODE_GETNEXTREQUEST;
    } else if (strcmp(argv[optind], "bulkwalk") == 0) {
        ctx->command = COMMAND_BULKWALK;
        ctx->pdutype = NODE_GETBULKREQUEST;
    } else {
        fprintf(stderr, "%s: invalid command\n", argv[0]);
        return 0;
    }

    ctx->host = asn1_data_octetstring_new((unsigned char *)argv[optind + 1],
                                          strlen(argv[optind + 1]));

    /* parse actual param. */
    if (ctx->pdutype == NODE_SETREQUEST) {
        if ((argc - optind - 2) % 3) {
            fprintf(stderr, "%s: invalid oid-type-value triplet.\n", argv[0]);
            return 0;
        }

        for (i = optind + 2; i < argc; i += 3) {
            void *data;
            unsigned char type;
            struct asn1_oid *oid = asn1_create_oid_from_string(
                argv[i], strlen(argv[i]));

            if (!oid) {
                fprintf(stderr, "%s: invalid oid\n", argv[0]);
                continue;
            }

            if (strcmp(argv[i + 1], "integer") == 0) {
                data = asn1_data_integer_new(
                    asn1_create_integer_from_string(argv[i + 2],
                                                    strlen(argv[i + 2])));
                type = NODE_INTEGER;
            } else if (strcmp(argv[i + 1], "timeticks") == 0) {
                data = asn1_data_integer_new(
                    asn1_create_integer_from_string(argv[i + 2],
                                                    strlen(argv[i + 2])));
                type = NODE_TIMETICKS;
            } else if (strcmp(argv[i + 1], "string") == 0) {
                data = asn1_data_octetstring_new((unsigned char *)argv[i + 2],
                                                 strlen(argv[i + 2]));
                type = NODE_OCTETSTRING;
            } else if (strcmp(argv[i + 1], "oid") == 0) {
                data = asn1_create_oid_from_string(argv[i + 2],
                                                   strlen(argv[i + 2]));
                if (!data) {
                    fprintf(stderr, "%s: invalid oid value\n", argv[0]);
                    asn1_data_oid_del(oid);
                    continue;
                }
                type = NODE_OBJECTID;
            } else if (strcmp(argv[i + 1], "ipaddress") == 0) {
                data = asn1_create_ipaddress_from_string(argv[i + 2],
                                                         strlen(argv[i + 2]));
                if (!data) {
                    fprintf(stderr, "%s: invalid ip address format\n",
                            argv[i + 2]);
                    asn1_data_oid_del(oid);
                    continue;
                }
                type = NODE_IPADDRESS;
            } else {
                fprintf(stderr, "%s: invalid type %s\n", argv[0], argv[i + 1]);
                asn1_data_oid_del(oid);
                continue;
            }
            
            snmp_append_bindings(ctx->bindings, oid, data, type);
        }
    } else {
        for (i = optind + 2; i < argc; ++i) {
            struct asn1_oid *oid = asn1_create_oid_from_string(
                argv[i], strlen(argv[i]));

            if (oid)
                snmp_append_bindings(ctx->bindings, oid, NULL, NODE_NULL);
        }
    }

    if (!ctx->bindings->nodecount)
        return 0;
    
    return 1;
}
    
/* display some help */
void snmp_display_help(const char *progname)
{
    fprintf(stderr, "Usage: %s [OPTIONS] COMMAND HOST OID [OID]..\n", progname);
    fprintf(stderr, "       %s [OPTIONS] set HOST OID TYPE VALUE [OID TYPE "
            "VALUE]...\n", progname);
    fprintf(stderr, "       %s [OPTIONS] walk HOST OID\n\n", progname);
    fprintf(stderr, "available commands are:\n");
    fprintf(stderr, "\tget, getnext, set, walk, bulkget, bulkwalk\n\n");
    fprintf(stderr, "available options are:\n");
    fprintf(stderr, "\t-u USERNAME\tUser name\n");
    fprintf(stderr, "\t-a PROTOCOL\tAuthentication protocol (MD5, SHA)\n");
    fprintf(stderr, "\t-A PASSPHRASE\tAuthentication passphrase\n");
    fprintf(stderr, "\t-p PROTOCOL\tPrivacy protocol (DES, AES)\n");
    fprintf(stderr, "\t-P PASSPHRASE\tPrivacy passphrase\n");
    fprintf(stderr, "\t-e ENGINEID\tSecurity engine ID (in hex)\n");
    fprintf(stderr, "\t-c ENGINEID\tContext engine ID (in hex)\n");
    fprintf(stderr, "\t-b BOOT\t\tEngine boot number\n");
    fprintf(stderr, "\t-t TIME\t\tEngine boot time\n");
    fprintf(stderr, "\t-n CONTEXT\tContext name\n");
    fprintf(stderr, "\t-d\t\tDebug output\n\n");
    fprintf(stderr, "bulkget, bulkwalk specific options:\n");
    fprintf(stderr, "\t-r NUM\t\tnon-repeater\n");
    fprintf(stderr, "\t-m NUM\t\tmax-repeaters\n\n");
    fprintf(stderr, "when using SET, available value types are:\n");
    fprintf(stderr, "\tinteger, timeticks, ipaddress, oid, string\n");
}

int snmp_is_discovery_required(const struct snmp_context *ctx)
{
    if (!ctx->engine_id ||
        ctx->engine_boot == -1 ||
        ctx->engine_time == -1 ||
        !ctx->context_engine_id)
        return 1;
    else
        return 0;
}

/* fill header information */
void snmp_initialize_header(struct snmp_context *ctx)
{
    struct snmp_messageheader *hdr = snmp_message_header_new();

    if (ctx->auth_type != AUTH_NONE && ctx->auth_passphrase)
        hdr->global_data.flags |= FLAGS_AUTHENTICATED;

    if (ctx->priv_type != PRIVACY_NONE && ctx->priv_passphrase)
        hdr->global_data.flags |= FLAGS_ENCRYPTED;

    hdr->global_data.flags |= FLAGS_REPORTABLE;

    hdr->engine_id = (struct snmp_engineid *)malloc(
        sizeof(struct snmp_engineid));
    memcpy(hdr->engine_id,
           ctx->engine_id,
           sizeof(struct snmp_engineid));

    hdr->context_engine_id = (struct snmp_engineid *)malloc(
        sizeof(struct snmp_engineid));
    memcpy(hdr->context_engine_id,
           ctx->context_engine_id,
           sizeof(struct snmp_engineid));

    hdr->engine_boots = ctx->engine_boot;
    hdr->engine_time = ctx->engine_time;

    hdr->username = asn1_data_octetstring_copy(ctx->username);
    hdr->context_name = asn1_data_octetstring_copy(ctx->context_name);

    ctx->header = hdr;
}

void snmp_finalize_header(struct snmp_context *ctx)
{
    if (ctx->header)
        snmp_message_header_del(ctx->header);

    ctx->header = NULL;
}

/* normal operation (get, getnext, set, ...) */
int snmp_query(struct snmp_context *ctx,
               struct snmp_net *net,
               struct snmp_usm_context *usm)
{
    unsigned char type;
    struct asn1_struct *pdu, *msg;
    
    snmp_initialize_header(ctx);
    
    /* consisted of a single pair of send and receive operations */
    pdu = snmp_create_pdu(ctx->header->global_data.msgid,
                          asn1_copy(ctx->bindings));

    if (ctx->command == COMMAND_GETBULK) {
        *AS_INTEGER(asn1_node_at(pdu, 1)->data) = ctx->non_repeater;
        *AS_INTEGER(asn1_node_at(pdu, 2)->data) = ctx->max_repeaters;
    }
    
    msg = snmp_create_message(ctx->header, usm, pdu, ctx->pdutype);
    asn1_destroy(pdu);

    if (ctx->debug) {
        fprintf(stderr, "transmitting following message...\n");
        asn1_print(stderr, msg);
    }

    if (!snmp_send_message(net, msg)) {
        asn1_destroy(msg);
        snmp_finalize_header(ctx);
        
        return 0;
    }

    if (ctx->debug) {
        fprintf(stderr, "got response\n");
        asn1_print(stderr, net->response);
    }

    snmp_decrypt_if_needed(usm, net->response);

    pdu = snmp_get_pdu_section(net->response, &type);
    if (!snmp_display_results(ctx, pdu, type)) {
        asn1_destroy(msg);
        snmp_finalize_header(ctx);
        
        return 0;
    }
    
    asn1_destroy(msg);
    snmp_finalize_header(ctx);
    
    return 1;
}

/* request getNext subsequently */
int snmp_query_walk(struct snmp_context *ctx,
                    struct snmp_net *net,
                    struct snmp_usm_context *usm)
{
    unsigned char type;
    struct asn1_struct *pdu, *msg, *oid;
    struct asn1_oid *oidv, *oido;
    int exitflag = 0;
    int retcode = 1;

    oido = asn1_data_oid_copy(
        AS_SEQUENCE(ctx->bindings->head->next->data)->head->next->data);
    oid = asn1_copy(ctx->bindings);
    
    while (1) {
        struct asn1_struct *respnode;
        
        snmp_initialize_header(ctx);
        
        pdu = snmp_create_pdu(ctx->header->global_data.msgid, oid);

        if (ctx->command == COMMAND_BULKWALK) {
            *AS_INTEGER(asn1_node_at(pdu, 1)->data) = ctx->non_repeater;
            *AS_INTEGER(asn1_node_at(pdu, 2)->data) = ctx->max_repeaters;
        }
        
        msg = snmp_create_message(ctx->header, usm, pdu, ctx->pdutype);
        asn1_destroy(pdu);
        
        if (ctx->debug) {
            fprintf(stderr, "transmitting following message...\n");
            asn1_print(stderr, msg);
        }
        
        if (!snmp_send_message(net, msg)) {
            retcode = 0;
            
            break;
        }
        
        if (ctx->debug) {
            fprintf(stderr, "got response\n");
            asn1_print(stderr, net->response);
        }

        snmp_decrypt_if_needed(usm, net->response);

        pdu = snmp_get_pdu_section(net->response, &type);
        respnode = AS_SEQUENCE(
            AS_SEQUENCE(asn1_node_at(pdu, 3)->data)->tail->prev->data);
        
        if (respnode->head->next->next->type == NODE_ENDOFMIBVIEW)
            break;
        
        if (!snmp_display_results(ctx, pdu, type)) {
            retcode = 0;
            break;
        }

        if (exitflag)
            break;

        oidv = respnode->head->next->data;
        if (!oidv || !asn1_compare_oid(oido, oidv)) {
            if (ctx->command == COMMAND_WALK)
                exitflag = 1;
            else
                break;
        }

        oid = asn1_new();
        snmp_append_bindings(oid, asn1_data_oid_copy(oidv), NULL, NODE_NULL);
        
        asn1_destroy(msg);
        msg = NULL;
        
        snmp_finalize_header(ctx);
    }
    
    if (msg)
        asn1_destroy(msg);
    snmp_finalize_header(ctx);
    
    return retcode;
}

/* parse and display response */
int snmp_display_results(struct snmp_context *ctx,
                         struct asn1_struct *pdu,
                         unsigned char type)
{
    struct asn1_node *node;
    struct asn1_struct *body;

    /* report PDU normally means that something (like USM) went wrong */
    if (type == NODE_REPORT) {
        struct asn1_struct *entry =
            AS_SEQUENCE(AS_SEQUENCE(asn1_node_at(pdu, 3)->
                                    data)->head->next->data);
        
        printf("report: ");
        asn1_print_oid(stdout, AS_OID(asn1_node_at(entry, 0)->data));
        printf(" :: ");
        asn1_print_node(stdout, asn1_node_at(entry, 1));
        printf("\n");
        
        return 0;
    }
    
    /* there is an error */
    node = asn1_node_at(pdu, 1);
    if (*AS_INTEGER(node->data)) {
        fprintf(stderr, "error: %s (%llu)\n",
                snmp_errors[*AS_INTEGER(node->data)],
                *AS_INTEGER(asn1_node_at(pdu, 2)->data));
    }

    /* everything is ok */
    body = AS_SEQUENCE(asn1_node_at(pdu, 3)->data);
    node = body->head->next;
    while (node != body->tail) {
        struct asn1_struct *entry = AS_SEQUENCE(node->data);

        if (asn1_node_at(entry, 1)->type == NODE_ENDOFMIBVIEW)
            break;

        asn1_print_oid(stdout, AS_OID(asn1_node_at(entry, 0)->data));
        printf(" :: ");
        asn1_print_node(stdout, asn1_node_at(entry, 1));
        printf("\n");
        
        node = node->next;
    }

    return 1;
}

void snmp_decrypt_if_needed(struct snmp_usm_context *usm,
                            struct asn1_struct *data)
{
    struct asn1_octetstring *usmdata_e, *priv_param;
    struct asn1_struct *usmdata, *decrypted;

    if (!usm->priv_type)
        return;
    
    data = AS_SEQUENCE(data->head->next->data);

    if (asn1_node_at(data, 3)->type != NODE_OCTETSTRING)
        return;

    usmdata_e = AS_OCTETSTRING(asn1_node_at(data, 2)->data);
    usmdata = asn1_decode(usmdata_e->data, usmdata_e->length);

    priv_param = snmp_salt_localize(
        usm, asn1_node_at(AS_SEQUENCE(usmdata->head->next->data), 5)->data);

    asn1_destroy(usmdata);

    if (!priv_param->length) {
        asn1_data_octetstring_del(priv_param);
        
        return;
    }

    decrypted = snmp_decrypt(usm, priv_param, asn1_node_at(data, 3)->data);

    asn1_data_octetstring_del(priv_param);  

    if (!decrypted) {
        fprintf(stderr, "%s: couldn't decrypt pdu\n", __func__);
    } else {
        asn1_node_remove_last(data);
        asn1_node_append(data, decrypted->head->next->data, NODE_SEQUENCE);
    }
}

/******************************************************************************
 * entrypoint
 */

int main(int argc, char *argv[])
{
    struct snmp_context ctx;
    struct snmp_net net;
    struct snmp_usm_context usm;
    int ret;

    /* initialize contexts */
    snmp_message_initialize();
    snmp_context_initialize(&ctx);
    snmp_usm_context_initialize(&usm);

    if (!snmp_parse_arguments(&ctx, argc, argv)) {
        snmp_display_help(argv[0]);
        return 1;
    }

    if (ctx.debug) {
        fprintf(stderr, "resolving address...");
        fflush(stderr);
    }

    if (!snmp_net_initialize(&net, ctx.host))
        return 2;

    if (ctx.debug)
        fprintf(stderr, "ok\n");

    /* request for additional information (engine id, ...) */
    if (snmp_is_discovery_required(&ctx)) {
        struct snmp_messageheader *header;
        struct asn1_struct *msg = snmp_create_discovery();
        
        if (ctx.debug) {
            fprintf(stderr, "sending discovery request... ");
            fflush(stderr);
        }

        if (!snmp_send_message(&net, msg)) {
            if (ctx.debug)
                fprintf(stderr, "failed\n");
            asn1_destroy(msg);

            return 3;
        }

        if (ctx.debug)
            fprintf(stderr, "ok\n");

        asn1_destroy(msg);

        header = snmp_message_header_decode(net.response);

        if (!ctx.engine_id) {
            ctx.engine_id = (struct snmp_engineid *)malloc(
                sizeof(struct snmp_engineid));
            memcpy(ctx.engine_id,
                   header->engine_id,
                   sizeof(struct snmp_engineid));
        }
        
        if (ctx.engine_boot == -1)
            ctx.engine_boot = header->engine_boots;

        if (ctx.engine_time == -1)
            ctx.engine_time = header->engine_time;

        if (!ctx.context_engine_id) {
            ctx.context_engine_id = (struct snmp_engineid *)malloc(
                sizeof(struct snmp_engineid));
            memcpy(ctx.context_engine_id,
                   header->context_engine_id,
                   sizeof(struct snmp_engineid));
        }

        if (!ctx.context_name)
            ctx.context_name = asn1_data_octetstring_copy(
                header->context_name);

        snmp_message_header_del(header);
    }

    /* initialize usm */
    if (ctx.auth_type && ctx.auth_passphrase) {
        if (!snmp_create_auth_key(&usm,
                                  ctx.auth_type,
                                  ctx.auth_passphrase,
                                  ctx.engine_id)) {
            fprintf(stderr, "could not create authentication key\n");
            
            return 4;
        }

        if (ctx.priv_type && ctx.priv_passphrase) {
            if (!snmp_create_priv_key(&usm,
                                      ctx.priv_type,
                                      ctx.priv_passphrase,
                                      ctx.engine_id)) {
                fprintf(stderr, "could not create privacy key\n");

                return 5;
            }
        }
    }

    switch (ctx.command) {
        case COMMAND_BULKWALK:
        case COMMAND_WALK:
            ret = snmp_query_walk(&ctx, &net, &usm);
            break;
        default:
            ret = snmp_query(&ctx, &net, &usm);
    }

    snmp_context_free(&ctx);
    
    return ret ? 0 : 1;
}
