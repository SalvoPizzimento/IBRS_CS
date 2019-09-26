#ifndef LIB_IBRS_CLN_H
#define LIB_IBRS_CLN_H
#define _GNU_SOURCE

#define SINGLE_ALLOC_SIZE 64

#include "lib-misc.h"
#include "lib-mesg.h"
#include <nettle/sha2.h>

typedef struct {
    element_t p;
    element_t ppub;
    pairing_t pairing;

    struct sha256_ctx ctx;
	int size_from_sec_level;
} ibrs_public_params_t;

typedef struct {
	element_t x;
} ibrs_secret_param_t;

typedef struct {
	char** array;
	size_t size;
} array_ibrs;

typedef struct {
	element_t* array;
	size_t size;
} array_element_t_ibrs;

typedef struct {
	element_t qid;
	element_t sid;
} ibrs_key_pair;

typedef struct {
	array_element_t_ibrs u_i;
	element_t v;
} ibrs_sig;

int sec_level;

void init_array_ibrs(array_ibrs* a, size_t size);
void insert_id(array_ibrs* a, char* id, int index);
void free_array(array_ibrs* a);

void init_array_element_t_ibrs(array_element_t_ibrs* a, size_t size);
void insert_element(array_element_t_ibrs* a, element_t element, int index);
void free_array_element(array_element_t_ibrs* a);

long get_filesize(FILE *fp);

void insert_keys(ibrs_key_pair* keys, ibrs_key_pair user_keys, int index);

#endif /* LIB_IBRS_CLN_H */