/** @file lib-ibrs-helper.h
 *  @brief Prototipi delle funzioni per l'helper del Cloud Server.
 *
 *  Contiene i prototipi per l'helper,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
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
#include <sys/wait.h>

#define PORT 8888 
#define SA struct sockaddr 

#define prng_sec_level 96
#define default_sec_level 80

/** @brief Funzione per iniziare la connessione tramite socket.
 */
void start_connection();

/** @brief Funzione principale per cominciare uno scambio di dati tramite socket.
 *  @param socket_id socket con cui cominciare lo scambio
 */
void start_exchange(int socket_id);

/** @brief Funzione per autenticare un'identità ad un gruppo.
 *  @param username identità da autenticare
 *  @param groupname gruppo su cui autenticare l'identità
 *  @return 1 se l'autenticazione è avvenuta con successo, 0 altrimenti
 */
int authenticate(char* username, char* groupname);

/** @brief Funzione per verificare la firma ricevuta.
 *  @param groupname gruppo dentro cui è stata creata la firma
 *  @param filename nome del file su cui è stata creata la firma
 */
bool ibrs_verify(char* groupname, char* filename);

/** @brief Funzione per ricevere dati da una socket.
 *  @param socket_id socket da cui ricevere i dati
 *  @param read_buffer buffer dove depositare i dati ricevuti
 *  @param size numero di caratteri massimi da ricevere
 */
void rcv_data(int socket_id, char* read_buffer, int size);

/** @brief Funzione per inviare dati ad una socket.
 *  @param socket_id socket a cui mandare i dati
 *  @param buffer buffer di dati da inviare
 *  @param size numero di caratteri massimi da mandare
 */
void snd_data(int socket_id, char* send_buffer, int size);

#endif /* LIB_IBRS_HELPER_H */
