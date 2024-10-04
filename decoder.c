/**
   Main module of decoder

   Decoder - test program for network protocols

   Copyright (C) 2016-2024 Michele Campus <michelecampus5@gmail.com>

   This file is part of decoder.

   decoder is free software: you can redistribute it and/or modify it under the
   terms of the GNU General Public License as published by the Free Software
   Foundation, either version 3 of the License, or (at your option) any later
   version.

   decoder is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE. See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along with
   decoder. If not, see <http://www.gnu.org/licenses/>.
**/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include "structures.h"
#include "functions.h"

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 3200

// error
#define DEVICE_ERROR(device, file)                                             \
    fprintf(stderr, "error on #%s or #%s\n", device, file);                    \

char err_buff[PCAP_ERRBUF_SIZE];
// declaration of var signal_flag
volatile sig_atomic_t signal_flag;

// print the correct usage
static void print_usage() {
    fprintf( stderr , "Usage:\n" );
    fprintf( stderr , "      decoder -i <device> | -p <file>\n");
    fprintf( stderr , "    -i <device>  : use <device> for live capture\n" );
    fprintf( stderr , "    -p <file>    : open <file> and read packets\n" );
    /* fprintf( stderr , "    -n <threads> : set number of thread (>1)\n" ); */
    fprintf( stderr , "    -l           : list availlable devices\n" );
    fprintf( stderr , "    -h           : print help on how to use\n" );
    fprintf( stderr , "\n" );
}

// Print the list of availlable devices
static
void print_all_devices()
{
    pcap_if_t *all_devs;
    pcap_if_t *d;
    int i = 0;

    printf("\nList of available devices on your system:\n\n");

    if(pcap_findalldevs(&all_devs, err_buff) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", err_buff);
        print_usage();
        return;
    }

    for(d = all_devs; d; d = d->next)   {
        if((strncmp(d->name, "any", 3) != 0) && (strncmp(d->name, "lo", 2) != 0)) {
            printf("device %d = %s", ++i, d->name);
            if(d->description)
                printf("\t\t (%s)\n", d->description);
            else
                printf("\t\t No description available for this device\n");
        }
    }
}

// signal handler for managing SIGINT - set volatile variable to 1
void
sigint_handler()
{
    signal_flag = 1;
}

/* MAIN */
int main( int argc, char *argv[] )
{
    struct flow_callback_proto * fcp; // for general stats
    pcap_t *pcap_handle;
    struct sigaction sigint_action;   // struct for signal registration
    sigset_t new_set, old_set;        // signal mask
    //long thread_id;
    char *device = NULL, *file = NULL;
    int opt;
    u_int8_t save = 0;


    // initialize error_buffer to 0
    memset(err_buff, 0, PCAP_ERRBUF_SIZE);
    // initialize volatile sigatomic to 0
    signal_flag = 0;

    //parse options
    while(opt = getopt(argc, argv, ":hi:n:p:ls") , opt != -1)
    {
        switch(opt) {

        case 'i':
            device = optarg;
            break;

        case 'h':
            print_usage();
            return EXIT_SUCCESS;

        case 'p':
            file = optarg;
            break;

        case 'l':
            print_all_devices();
            return EXIT_SUCCESS;

        case 's':
            save = 1;
            printf("Certificate(s) are saved in directory <certificates>\n");
            break;

        case ':':
            fprintf( stderr, "Missing argument for option '%c'\n", optopt );
            print_usage();
            return EXIT_FAILURE;

        default:
            fprintf( stderr, "Unknown option '%c'\n", optopt );
            print_usage();
            return EXIT_FAILURE;
        }
    }

    if(device) {

        /* setting signal mask */
        if(sigfillset(&new_set) == -1) {
            perror("ERROR: Cannot set signal mask, ");
            return EXIT_FAILURE;
        }
        /* masking all signals during SIGINT handler initialization */
        if(sigprocmask(SIG_SETMASK, &new_set, &old_set) == -1) {
            perror("ERROR: Cannot set process's signal mask, ");
            return EXIT_FAILURE;
        }
        /* register SIGINT handler */
        memset(&sigint_action,'\0', sizeof(sigint_action));
        sigint_action.sa_handler = &sigint_handler;
        sigint_action.sa_flags = SA_RESTART;
        if(sigaction(SIGINT, &sigint_action, NULL) == -1) {
            perror("ERROR: Cannot install handler for [SIGINT], ");
            return EXIT_FAILURE;
        }
        /* unmasking signals */
        if(sigprocmask(SIG_SETMASK, &old_set, NULL) == -1) {
            perror("ERROR: Cannot restore process's signal mask, ");
            return EXIT_FAILURE;
        }

        printf("Sniffing on device %s\n", device);
        // open device live
        pcap_handle = pcap_open_live(device, SNAP_LEN, 0, 0, err_buff);
        if(!pcap_handle) {
            pcap_fatal("pcap_open_live", err_buff);
            return EXIT_FAILURE;
        }
    }
    else if(file) {
        printf("Opening pcap file %s\n", file);
        // open file pcap
        pcap_handle = pcap_open_offline(file, err_buff);
        if(!pcap_handle) {
            pcap_fatal("pcap_open_offline", err_buff);
        }
    }
    else if(opt == -1) {
        pcap_fatal("Bad argument");
        return EXIT_FAILURE;
    }
    else {
        DEVICE_ERROR(device, err_buff);
        return EXIT_FAILURE;
    }

    /* init struct for flow */
    fcp = flow_callback_proto_init(pcap_handle, save);

    // loop for extract packets
    pcap_loop(fcp->pcap_handle, -1, callback_proto, (u_char*) fcp);

    printf("\n\n<<< DETECTION FINISHED >>>\n\n");

    // print statistics of flows
    print_stats(fcp);

    // terminate the handle pcap function
    pcap_close(fcp->pcap_handle);

    return 0;
}

/**
   TODO
   - extraction name server from client hello and server hello
**/
