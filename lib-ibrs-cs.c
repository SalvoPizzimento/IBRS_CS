#include "lib-ibrs-cs.h"

//INIT array of strings
void init_array_ibrs(array_ibrs* a, size_t size) {
	a->array = malloc(sizeof(char *) * size);
    for(int i = 0; i < size; i++){
		//single location of array
        a->array[i] = malloc(SINGLE_ALLOC_SIZE);
    }
	//size of array
    a->size = size;
}

//INSERT string id in index location
void insert_id(array_ibrs* a, char* id, int index) {
	strncpy(a->array[index], id, SINGLE_ALLOC_SIZE);
}

//FREE array
void free_array(array_ibrs* a) {
	free(a->array);
	a->size = 0;
}

//INIT array of element_t
void init_array_element_t_ibrs(array_element_t_ibrs* b, size_t size) {
	b->array = malloc(sizeof(element_t) * size);
	//SET size of array
	b->size = size;
}

//FREE array
void free_array_element(array_element_t_ibrs* b) {
	free(b->array);
	b->size = 0;
}

//INSERT keys in index location
void insert_keys(ibrs_key_pair* keys, ibrs_key_pair user_keys, int index) {
	keys[index] = user_keys;
}

long get_filesize(FILE *fp){
    long filesize;

    if(fseek(fp, 0, SEEK_END) != 0)
        exit(EXIT_FAILURE); /* exit with errorcode if fseek() fails */

    filesize = ftell(fp);

    rewind(fp);

    return filesize;
}
