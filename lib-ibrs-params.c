#include "lib-ibrs-params.h"

void load_params(ibrs_public_params_t* public_params, int level, FILE* pairing_stream, FILE* param_stream) {
    assert(public_params);
	assert((level <= 128) && (level >= 80));

	char* pairing_buffer; 
	long pairing_size;

	pairing_size = get_filesize(pairing_stream);
	pairing_buffer = calloc(pairing_size, sizeof(char));
	if(fread(pairing_buffer, sizeof(char),pairing_size, pairing_stream) != pairing_size) {
		printf("problema nella read di pairing_stream\n");
		exit(EXIT_FAILURE);
	}
	pairing_init_set_buf(public_params->pairing, pairing_buffer, pairing_size);

	//INIT PARAM P
    element_init_G1(public_params->p, public_params->pairing);
	
    //INIT PARAM Ppub
    element_init_G1(public_params->ppub, public_params->pairing);
	
	if(param_stream!=NULL){
        char *line[2];
        size_t len = 0;
        
        for(int i = 0; i < 2; i++) {
			line[i] = NULL;
			len = 0;
			if(i==0){
				if(getline(&line[i], &len, param_stream) != -1){
					element_set_str(public_params->p, line[i], 10);
				}
			}
			else{
				if(getline(&line[i], &len, param_stream) != -1){
					element_set_str(public_params->ppub, line[i], 10);
				}
			}
        }

        fclose(param_stream);
	}
    	
	//INIT sha256 ctx
    sha256_init(&public_params->ctx);
	public_params->size_from_sec_level = level/4;

	fclose(pairing_stream);
    free(pairing_buffer);

    printf("Parameters loaded.\n");
}

void ibrs_public_params_clear(ibrs_public_params_t* public_params) {
    assert(public_params);

	element_clear(public_params->p);
    element_clear(public_params->ppub);
    pairing_clear(public_params->pairing);
}