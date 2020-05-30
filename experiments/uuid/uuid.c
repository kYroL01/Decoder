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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sysdep.h"
#include "uuid.h"

/* data type for UUID generator persistent state */
typedef struct {
    uuid_time_t  ts;       /* saved timestamp */
    uuid_node_t  node;     /* saved node ID */
    unsigned16   cs;       /* saved clock sequence */
} uuid_state;

static uuid_state st;

/* functions prototype */
static int read_state(unsigned16 *clockseq, uuid_time_t *timestamp, uuid_node_t *node);
static void write_state(unsigned16 clockseq, uuid_time_t timestamp, uuid_node_t node);
static void uuid_builder(uuid_t *uuid, unsigned16 clockseq,
                         uuid_time_t timestamp, uuid_node_t node);
static void get_current_time(uuid_time_t *timestamp);
static unsigned16 true_random(void);


/* From UUID struct to UUID string hex */
void make_buff_uuid(uuid_t u, char* buff_uuid)
{
    int i, j, n;

    j = snprintf(buff_uuid, 32, "%8.8x-%4.4x-%4.4x-%4.4x-",
                 u.time_low, u.time_mid, u.time_hi_and_version,
                 u.clock_seq_hi_and_reserved, u.clock_seq_low);
    for (i = 0; i < 6; i++)
        j += snprintf(buff_uuid + j, 12, "%2.2x", u.node[i]);

    /**
       Adjust certain bits according to RFC 4122 section 4.4.
       This just means do the following:
       - the digit at position 14 above is always "4"
       - the digit at position 19 is always one of "8", "9", "a" or "b".
    **/
    buff_uuid[14] = '4';
    do {
        n = rand() % 4;
        printf("n = %d\n", n);
    } while(n == 0);
    switch (n) {
     case 1: buff_uuid[19] = '8'; break;
     case 2: buff_uuid[19] = '9'; break;
     case 3: buff_uuid[19] = 'a'; break;
     case 4: buff_uuid[19] = 'b'; break;
    }
}


/* Generate a UUID */
int uuid_create(uuid_t *uuid)
{
     uuid_time_t timestamp, last_time;
     unsigned16 clockseq;
     uuid_node_t node;
     uuid_node_t last_node;
     int f;

     /* get time, node ID, saved state from non-volatile storage */
     get_current_time(&timestamp);
     get_ieee_node_identifier(&node);
     f = read_state(&clockseq, &last_time, &last_node);
     // call true random function
     clockseq = true_random();
     /* save the state for next time */
     /* write_state(clockseq, timestamp, node); */
     /* stuff fields into the UUID */
     uuid_builder(uuid, clockseq, timestamp, node);
     return 1;
}


/* make a UUID from the timestamp, clockseq and node ID */
void uuid_builder(uuid_t* uuid, unsigned16 clock_seq,
                  uuid_time_t timestamp, uuid_node_t node)
{
    /* Construct a version 1 uuid with the information we've gathered
       plus a few constants. */
    uuid->time_low = (unsigned long)(timestamp & 0xFFFFFFFF);
    uuid->time_mid = (unsigned short)((timestamp >> 32) & 0xFFFF);
    uuid->time_hi_and_version = (unsigned short)((timestamp >> 48) & 0x0FFF);
    uuid->time_hi_and_version |= (1 << 12);
    uuid->clock_seq_low = clock_seq & 0xFF;
    uuid->clock_seq_hi_and_reserved = (clock_seq & 0x3F00) >> 8;
    uuid->clock_seq_hi_and_reserved |= 0x80;
    memcpy(&uuid->node, &node, sizeof uuid->node);
}


/* read UUID generator state from non-volatile store */
int read_state(unsigned16 *clockseq, uuid_time_t *timestamp,
               uuid_node_t *node)
{
    FILE *fp;

    /* only need to read state once per boot */
    fp = fopen("/sys/class/net/lo/statistics/rx_bytes", "rb");
    if (fp == NULL)
        return 0;
    fread(&st, sizeof st, 1, fp);
    fclose(fp);

    *clockseq = st.cs;
    *timestamp = st.ts;
    *node = st.node;
    return 1;
}

/* /\* write_state -- save UUID generator state back to non-volatile */
/*    storage *\/ */
/* void write_state(unsigned16 clockseq, uuid_time_t timestamp, */
/*                  uuid_node_t node) */
/* { */
/*     static int inited = 0; */
/*     static uuid_time_t next_save; */
/*     FILE* fp; */
/* if (!inited) { */
/*         next_save = timestamp; */
/*         inited = 1; */
/*     } */

/*     /\* always save state to volatile shared state *\/ */
/*     st.cs = clockseq; */
/*     st.ts = timestamp; */
/*     st.node = node; */
/*     if (timestamp >= next_save) { */
/*         fp = fopen("state", "wb"); */
/*         fwrite(&st, sizeof st, 1, fp); */
/*         fclose(fp); */
/*         /\* schedule next save for 10 seconds from now *\/ */
/*         next_save = timestamp + (10 * 10 * 1000 * 1000); */
/*     } */
/* } */

/* get time as 60-bit 100ns ticks since UUID epoch.
   Compensate for the fact that real clock resolution is
   less than 100ns. */
void get_current_time(uuid_time_t *timestamp)
{
    static uuid_time_t time_last;
    uuid_time_t time_now;

    get_system_time(&time_now);
    *timestamp = time_now + UUIDS_PER_TICK;
}

/* generate a random number. */
static unsigned16 true_random(void)
{
    uuid_time_t time_now;

    get_system_time(&time_now);
    time_now = time_now / UUIDS_PER_TICK;
    srand((unsigned int) (((time_now >> 32) ^ time_now) & 0xffffffff));

    return rand();
}
