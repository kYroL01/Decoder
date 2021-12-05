#
#   Decoder - Makefile
#   Copyright (C) 2021 Michele Campus <fci1908@gmail.com>
#
#   This file is part of decoder.
#
#   Decoder is free software: you can redistribute it and/or modify it under the
#   terms of the GNU General Public License as published by the Free Software
#   Foundation, either version 3 of the License, or (at your option) any later
#   version.
#
#   Decoder is distributed in the hope that it will be useful, but WITHOUT ANY
#   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
#   A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along with
#   decoder. If not, see <http://www.gnu.org/licenses/>.

# VARIABLES ---------------------------------

CC         =  gcc
CFLAGS     = -Wall
OPT        = -g -O0
LDFLAGS    = -lpcap
#LDPTHREAD  = -lpthread

# --------------- DEPENDENCIES ---------------

# DEPS       = structures.h define.h tls_ssl.h functions.h ngcp.h rtp.h rtcp.h rtsp.h globals.h
SOURCES    = decoder.c functions.c tls_ssl.c rtp.c rtcp.c diameter.c ngcp.c rtsp.c
OBJ        = $(SOURCES:.c = .o)
LIBSSL     = -I/usr/include/openssl -lcrypto
LM         = -lm

# --------------- EXECUTABLE -----------------

decoder = $(OBJ)

# --------------- UTILS ----------------------

.PHONY: clean cleanall install uninstall build

clean:
	rm -fr *.o

cleanall: clean
	rm -fr ./decoder

install:
	cp ./decoder /usr/bin

uninstall:
	rm -f /usr/bin/decoder

build : $(OBJ)
	$(CC) $(CFLAGS) $(OPT) $(LDFLAGS) $(LIBSSL) $(LM) $(OBJ) -o decoder

%.o : %.c
	$(CC) $(CFLAGS) -c $<
