/* a simple util for debugging ASN.1 stream
 *
 * (c)2008 Park "segfault" Joon-Kyu <mastermind@planetmono.org>
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "asn1.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    struct asn1_struct *asn1;
    unsigned char buf[65535];
    int readlen;
    int fp;

    if (argc < 2) {
        fprintf(stderr, "usage: %s filename", argv[0]);
        return 1;
    }

    fp = open(argv[1], O_RDONLY);
    if (fp == -1) {
        perror("open");
        return 1;
    }
    readlen = read(fp, buf, 65535);
    close(fp);

    asn1 = asn1_decode(buf, readlen);
    asn1_print(stdout, asn1);
    asn1_destroy(asn1);

    return 0;
}

