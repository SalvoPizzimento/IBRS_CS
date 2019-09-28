/** @file lib-ibrs-params.h
 *  @brief Prototipi dei parametri del Cloud Server.
 *
 *  Contiene i prototipi per i parametri,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_PARAMS_H
#define LIB_IBRS_PARAMS_H
#define _GNU_SOURCE

#include "lib-ibrs-cs.h"

/** @brief Funzione per caricare i parametri dello schema da un file.
 *  @param public_params parametri pubblici per lo schema crittografico
 *  @param level livello di sicurezza crittografica
 *  @param pairing_stream file stream da cui caricare il pairing
 *  @param param_stream file stream da cui caricare i parametri
 */
void load_params(ibrs_public_params_t* public_params, int level, FILE* pairing_stream, FILE* param_stream);

/** @brief Funzione per liberare la struttura parametri.
 *  @param public_params parametri pubblici da liberare
 */
void ibrs_public_params_clear(ibrs_public_params_t* public_params);

#endif /* LIB_IBRS_PARAMS_H */