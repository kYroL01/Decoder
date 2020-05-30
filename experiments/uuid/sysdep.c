/**
   Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
   Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. &
   Digital Equipment Corporation, Maynard, Mass.
   Copyright (c) 1998 Microsoft.
   To anyone who acknowledges that this file is provided "AS IS"
   without any express or implied warranty: permission to use, copy,
   modify, and distribute this file for any purpose is hereby
   granted without fee, provided that the above copyright notices and
   this notice appears in all source code copies, and that none of
   the names of Open Software Foundation, Inc., Hewlett-Packard
   Company, Microsoft, or Digital Equipment Corporation be used in
   advertising or publicity pertaining to distribution of the software
   without specific, written prior permission. Neither Open Software
   Foundation, Inc., Hewlett-Packard Company, Microsoft, nor Digital
   Equipment Corporation makes any representations about the
   suitability of this software for any purpose.
**/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "sysdep.h"

/* system dependent call to get IEEE node ID.
   This sample implementation generates a random node ID. */
void get_ieee_node_identifier(uuid_node_t *node)
{
    static uuid_node_t saved_node;
    char seed[16];
    FILE *fp;

    fp = fopen("/sys/class/net/lo/statistics/rx_packets", "rb");
    if (fp) {
        fread(&saved_node, sizeof saved_node, 1, fp);
        fclose(fp);
    }
    else {
        get_random_info(seed);
        seed[0] |= 0x01;
        memcpy(&saved_node, seed, sizeof saved_node);
    }

    *node = saved_node;
}

/* system dependent call to get the current system time. Returned as
   100ns ticks since UUID epoch, but resolution may be less than
   100ns. */
void get_system_time(uuid_time_t *uuid_time)
{
    struct timeval tp;

    gettimeofday(&tp, (struct timezone *)0);

    /* Offset between UUID formatted times and Unix formatted times.
       UUID UTC base time is October 15, 1582.
       Unix base time is January 1, 1970.*/
    *uuid_time = ((unsigned long long)tp.tv_sec * 10000000)
        + ((unsigned long long)tp.tv_usec * 10)
        + I64(0x01A21DD213814000);
}

/* Sample code, not for use in production; see RFC 1750 */
void get_random_info(char seed[16])
{
    MD5_CTX c;
    struct {
        struct sysinfo s;
        struct timeval t;
        char hostname[257];
    } r;

    MD5_Init(&c);
    sysinfo(&r.s);
    gettimeofday(&r.t, (struct timezone *)0);
    gethostname(r.hostname, 256);
    MD5_Update(&c, &r, sizeof r);
    MD5_Final(seed, &c);
}
