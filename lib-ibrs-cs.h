/** @file lib-ibrs-cs.h
 *  @brief Prototipi delle primitive crittografiche del Cloud Server.
 *
 *  Contiene i prototipi per le primitive,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_CS_H
#define LIB_IBRS_CS_H
#define _GNU_SOURCE

#define SINGLE_ALLOC_SIZE 64

#include "lib-misc.h"
#include "lib-mesg.h"
#include <nettle/sha2.h>

/**
 * @brief Struttura per i parametri pubblici 
 */
typedef struct {
    element_t p;
    element_t ppub;
    pairing_t pairing;

    struct sha256_ctx ctx;
	int size_from_sec_level;
} ibrs_public_params_t;

/**
 * @brief Struttura per il parametro segreto 
 */
typedef struct {
	element_t x;
} ibrs_secret_param_t;

/**
 * @brief Struttura per l'array di identità 
 */
typedef struct {
	char** array;
	size_t size;
} array_ibrs;

/**
 * @brief Struttura per l'array di oggetti element_t 
 */
typedef struct {
	element_t* array;
	size_t size;
} array_element_t_ibrs;

/**
 * @brief Struttura per la coppia di chiavi 
 */
typedef struct {
	element_t qid;
	element_t sid;
} ibrs_key_pair;

/**
 * @brief Struttura per la firma 
 */
typedef struct {
	array_element_t_ibrs u_i;
	element_t v;
} ibrs_sig;

int sec_level;

/**
 * @brief Funzione per inizializzare un array_ibrs
 * @param a array da inizializzare
 * @param size size dell'array da inizializzare
 */
void init_array_ibrs(array_ibrs* a, size_t size);

/**
 * @brief Funzione per inserire un id in un array_ibrs
 * @param a array da riempire
 * @param id identità da inserire nell'array
 * @param index indice dell'array dove inserire l'identità
 */
void insert_id(array_ibrs* a, char* id, int index);

/**
 * @brief Funzione per liberare l'array_ibrs
 * @param a array da liberare
 */
void free_array(array_ibrs* a);

/**
 * @brief Funzione per inizializzare un array_element_t_ibrs
 * @param a array di element_t da inizializzare
 * @param size size dell'array da inizializzare
 */
void init_array_element_t_ibrs(array_element_t_ibrs* a, size_t size);

/**
 * @brief Funzione per inserire un element_t in un array_element_t_ibrs
 * @param a array di element_t da riempire
 * @param element element_t da inserire nell'array
 * @param index indice dell'array dove inserire l'element_t
 */
void insert_element(array_element_t_ibrs* a, element_t element, int index);

/**
 * @brief Funzione per liberare l'array_element_t_ibrs
 * @param a array da liberare
 */
void free_array_element(array_element_t_ibrs* a);

/**
 * @brief Funzione per calcolare la grandezza di un file
 * @param fp file stream del file
 * @return grandezza del file
 */
long get_filesize(FILE *fp);

#endif /* LIB_IBRS_CS_H */