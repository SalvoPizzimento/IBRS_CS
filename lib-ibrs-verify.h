#ifndef LIB_IBRS_VERIFY_H
#define LIB_IBRS_VERIFY_H
#define _GNU_SOURCE

#include "lib-ibrs-cs.h"

void ibrs_import_sign(ibrs_public_params_t* public_params, int length, FILE* sign_stream, ibrs_sig* sign);
bool ibrs_sign_ver(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg, ibrs_sig* sign);
void ibrs_sign_clear(ibrs_sig* sig);

#endif /* LIB_IBRS_VERIFY_H */