#include "lib-ibrs-verify.h"

void ibrs_import_sign(ibrs_public_params_t* public_params, int length, FILE* sign_stream, ibrs_sig* sign) {
	
	init_array_element_t_ibrs(&sign->u_i, length);
	element_init_G1(sign->v, public_params->pairing);

	if(sign_stream!=NULL){
        char *line[length];
        int i = 0;
        size_t len = 0;
        
        for(i = 0; i < length; i++) {
			line[i] = NULL;
			len=0;
			element_init_G1(sign->u_i.array[i], public_params->pairing);
			if(getline(&line[i], &len, sign_stream) != -1){
                element_set_str(sign->u_i.array[i], line[i], 10);
            }
        }

		line[i] = NULL;
		len=0;
		if(getline(&line[i], &len, sign_stream) != -1){
                element_set_str(sign->v, line[i], 10);
		}
        fclose(sign_stream);
	}

	printf("Sign imported.\n");
}

bool ibrs_sign_ver(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg, ibrs_sig* sign) {
	assert(public_params);
	assert(l.size>0);
	assert(msg);
	assert(sign);

	element_t el_h_i, el_qid_i, mul, pre_sum, sum, ppub_sum, p_v;

	uint8_t h_i[public_params->size_from_sec_level];
	uint8_t qid_i[public_params->size_from_sec_level];

	size_t length = l.size;
	size_t size_buffer = sizeof(char *)*SINGLE_ALLOC_SIZE;
	char* l_buf =  calloc(l.size, size_buffer);

	char buffer_u[512];
	char* buffer;
	char tmp[64];

	bool result = false;

	//SUM ELEMENTS OF ARRAY_IBRS
	for(int i=0; i<length; i++) {
		snprintf(tmp, sizeof(tmp), "%s", l.array[i]);
		strncat(l_buf, tmp, sizeof(tmp));
	}

	//INIT ELEMENTS ZR
	element_init_Zr(el_h_i, public_params->pairing);

	//INIT ELEMENTS G1
	element_init_G1(sum, public_params->pairing);
	element_init_G1(el_qid_i, public_params->pairing);
	element_init_G1(mul, public_params->pairing);
	element_init_G1(pre_sum, public_params->pairing);

	for(int j=0; j<length; j++) {

		//INIT (m||L||Ui)
		element_snprint(buffer_u, sizeof(buffer_u), sign->u_i.array[j]);

		if(asprintf(&buffer, "%s%s%s", msg, l_buf, buffer_u) != -1) {
			//INIT hi as H0(m||L||Ui)
			sha256_update(&(public_params->ctx), strlen(buffer), (const uint8_t* ) buffer);
			sha256_digest(&(public_params->ctx), public_params->size_from_sec_level, h_i);
		}
		else {
			printf("error on asprint!");
			return false;
		}

		//CAST hi as an element of Zr
		element_from_hash(el_h_i, h_i, public_params->size_from_sec_level);

		//INIT QIDi as H(IDi)
		sha256_update(&(public_params->ctx), strlen(l.array[j]), (const uint8_t* ) l.array[j]);
		sha256_digest(&(public_params->ctx), public_params->size_from_sec_level, qid_i);
		element_from_hash(el_qid_i, qid_i, public_params->size_from_sec_level);

		//INIT hi*QIDi
		element_mul_zn(mul, el_qid_i, el_h_i);

		//SUM of Ui+(hi*QIDi)
		element_add(pre_sum, sign->u_i.array[j], mul);

		//SUM of all Ui+(hi*QIDi)
		element_add(sum, sum, pre_sum);
	}

	//PAIRING e(ppub,sum)
    element_init_GT(ppub_sum, public_params->pairing);
	pairing_apply(ppub_sum, sum, public_params->ppub, public_params->pairing);
	
    //PAIRING e(p,v)
    element_init_GT(p_v, public_params->pairing);
	pairing_apply(p_v, sign->v, public_params->p, public_params->pairing);
	
    if ((result = (element_cmp(ppub_sum, p_v) == 0))) {
		pmesg(msg_very_verbose, "sign verified on message!");
    } else {
        pmesg(msg_very_verbose, "verify failed!");
    }

	//CLEARS of all element used
	element_clear(p_v);
	element_clear(ppub_sum);
	element_clear(el_h_i);
	element_clear(el_qid_i);
	element_clear(mul);
	element_clear(pre_sum);
	element_clear(sum);

	free(l_buf);

	return result;
}

void ibrs_sign_clear(ibrs_sig* sign) {
	assert(sign);
	
	element_clear(sign->v);
	free_array_element(&sign->u_i);
}
