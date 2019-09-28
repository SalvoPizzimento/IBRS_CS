#ifndef LIB_IBRS_HELPER_H
#define LIB_IBRS_HELPER_H
#define _GNU_SOURCE

#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#include <unistd.h>
#include <gmp.h>
#include <libgen.h>
#include <stdbool.h>
#include <assert.h>
#include <pbc/pbc.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib-ibrs-params.h"
#include "lib-ibrs-verify.h"
#include "lib-timing.h"
#include <ifaddrs.h>

#define PORT 8888 
#define SA struct sockaddr 
#define prng_sec_level 96
#define default_sec_level 80

void start_exchange(int socket_id);
void start_connection();
int authenticate(char* username, char* groupname);
bool verify(char* groupname, char* filename);
void rcv_data(int socket_id, char* read_buffer, int size);
void snd_data(int socket_id, char* send_buffer);


#endif /* LIB_IBRS_HELPER_H */