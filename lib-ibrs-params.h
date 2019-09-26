#ifndef LIB_IBRS_PARAMS_H
#define LIB_IBRS_PARAMS_H
#define _GNU_SOURCE

#include "lib-ibrs-cs.h"

void load_params(ibrs_public_params_t* public_params, int level, FILE* pairing_stream, FILE* param_stream);
void ibrs_public_params_clear(ibrs_public_params_t* public_params);

#endif /* LIB_IBRS_PARAMS_H */