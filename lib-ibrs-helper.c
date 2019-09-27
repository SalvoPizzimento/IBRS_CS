#include "lib-ibrs-helper.h"

int authenticate(char* username, char* groupname){
    FILE* list_file;
    char* file_buffer;
    char* directory;
	long file_size;

	// LETTURA DEL FILE "ids.txt"
	directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/ids.txt", groupname);
    list_file = fopen(directory, "r");
    file_size = get_filesize(list_file);
    file_buffer = calloc(file_size, sizeof(char));
    if(fread(file_buffer, sizeof(char), file_size, list_file) != file_size){
        printf("problema nella read del file %s\n", directory);
        exit(EXIT_FAILURE);
    }
	free(directory);

    char* token;
    token = strtok(file_buffer, "\n");
    while(token != NULL){
        if(strncmp(token, username, strlen(username)) == 0){
            printf("Autenticazione eseguita con successo\n");
            return 1;
        }
        token = strtok(NULL, "\n");
    }
	
    return 0;
}

void start_exchange(int sockfd){
    char* ids_buffer;
    char* username;
    char* groupname;
    char* filename;
    char* directory;
    char* read_buffer;
    struct stat st = {0};
    int auth;

    // RICEZIONE USERNAME E GROUPNAME
    username = calloc(50, sizeof(char));
    groupname = calloc(50, sizeof(char));
    
	if(read(sockfd, groupname, 50) == -1) {
		printf("Problemi nella read dalla socket\n");
        return;
	}

    if(strlen(groupname) <= 1){
    	printf("Username invalido\n");
    	return;
    }
    
	strncpy(username, groupname, strlen(groupname));
    printf("USERNAME: %s\n", username);
    free(groupname);

    if(write(sockfd, "ACK", 3) == -1) {
		printf("Problemi nella write sulla socket\n");
        return;
	}

    if(strncmp(username, "group_admin", 11) == 0){
    	groupname = calloc(50, sizeof(char));
    	if(read(sockfd, groupname, 50) == -1) {
			printf("Problemi nella read dalla socket\n");
            return;
		}

    	if(write(sockfd, "ACK", 3) == -1) {
			printf("Problemi nella write sulla socket\n");
            return;
		}

	    // RICEZIONE LISTA UTENTI DEL GRUPPO
        if (stat(groupname, &st) == -1) {
            mkdir(groupname, 0700);
        }

        // CREAZIONE FILE IDS.TXT DENTRO LA CARTELLA GROUPNAME
        directory = calloc(100, sizeof(char));
        sprintf(directory, "./%s/ids.txt", groupname);

	    FILE *file_to_open;
	    ids_buffer = calloc(1024, sizeof(char));
	    if(read(sockfd, ids_buffer, 1024) == -1) {
			printf("Problemi nella read dalla socket\n");
            return;
		}

	    file_to_open = fopen(directory, "w");
	    fprintf(file_to_open, "%s", ids_buffer);
	    
		fclose(file_to_open);
	    free(ids_buffer);
	    free(directory);

	    // RICEZIONE DATI PAIRING
	    directory = calloc(100, sizeof(char));
	    sprintf(directory, "./%s/pairing.txt", groupname);
	    
		read_buffer = calloc(1024, sizeof(char));
	    if(read(sockfd, read_buffer, 1024) == -1) {
			printf("Problemi nella read dalla socket\n");
            return;
		}
	 
	    file_to_open = fopen(directory, "w");
	    fprintf(file_to_open, "%s", read_buffer);

	    fclose(file_to_open);
	    free(read_buffer);
	    free(directory);
	    
	    // RICEZIONE PARAMETRI
	    directory = calloc(100, sizeof(char));
	    sprintf(directory, "./%s/param.txt", groupname);
	    
		read_buffer = calloc(1024, sizeof(char));
	    if(read(sockfd, read_buffer, 1024) == -1) {
			printf("Problemi nella read dalla socket\n");
            return;
		}

	    file_to_open = fopen(directory, "w");
	    fprintf(file_to_open, "%s", read_buffer);

	    fclose(file_to_open);
	    free(read_buffer);
	    free(directory);
	}
	else{
		char* request;
		char* token;
		
		request = calloc(50, sizeof(char));
		if(read(sockfd, request, 50) == -1) {
			printf("Problemi nella read dalla socket\n");
            return;
		}

	    filename = calloc(50, sizeof(char));
	    groupname = calloc(50, sizeof(char));
		
		token = strtok(request, ",");
	    strncpy(groupname, token, strlen(token));

		token = strtok(NULL, ",");
	    strncpy(filename, token, strlen(token));

		printf("GROUPNAME: %s  FILENAME: %s\n", groupname, filename);

	    // AUTENTICAZIONE UTENTE
	    if (stat(groupname, &st) == -1) {
            if(write(sockfd, "NULL", 4) == -1) {
				printf("Problemi nella write sulla socket\n");
           		return;
			}
            printf("Gruppo Inesistente\n");
        }
        else{
		    auth = authenticate(username, groupname);
			if(auth == 0){
			    if(write(sockfd, "FAIL_AUTH", 9) == -1) {
					printf("Problemi nella write sulla socket\n");
            		return;
				}

			    printf("Autenticazione fallita\n");
			    free(username);
			    free(filename);
			    free(groupname);
			    return;
			}
			else{
	    		if(write(sockfd, "ACK", 3) == -1) {
					printf("Problemi nella read dalla socket\n");
					return;
				}
			}
		}
		free(request);

	    // INSERIRE RICEZIONE FIRMA DEL FILENAME E VERIFICA
	    request = calloc(10240, sizeof(char));
	    while(strcmp(request, "") == 0){
		    if(read(sockfd, request, 10240) == -1){
		    	printf("Errore nella read dellla socket\n");
		    	return;
		    }
		}

		FILE *file_to_open;
        file_to_open = fopen("sign.txt", "w");
        fprintf(file_to_open, "%s", request);
        fclose(file_to_open);
	    free(request);

	    bool result;
	    result = verify(groupname, filename);
		remove("sign.txt");
		
	    if(result){
	    	if(write(sockfd, "ACK", 3) == -1){
		    	printf("Errore nella write sulla socket\n");
		    	return;
	    	}
	    }
	    else{
	    	if(write(sockfd, "FAIL", 4) == -1){
	    		printf("Errore nella write sulla socket\n");
	    		return;
	    	}
	    	printf("Firma errata...\n");
	    	return;
	    }
		
		request = calloc(50, sizeof(char));
		while(strcmp(request, "") == 0){
			if(read(sockfd, request, 50) == -1) {
				printf("Problemi nella read dalla socket\n");
            	return;
			}
		}
		printf("REQUEST: %s\n", request);

		if(strncmp(request, "DOWNLOAD", 8) == 0){

			char* command;
			command = calloc(500, sizeof(char));
			sprintf(command, "\"/usr/bin/sshpass\", \"sshpass\", \"-p\", \"root\", \"/usr/bin/scp\", \"%s\", \"root@172.17.0.3:/home\", (char*)0)", filename);
			execl(command);
			if(write(sockfd, "DOWNLOAD", 8) == -1){
				printf("Errore nella write sulla socket\n");
	    		return;
			}
		}
		else if(strncmp(request, "UPLOAD", 6) == 0){
			if(write(sockfd, "READY", 5) == -1){
				printf("Errore nella write sulla socket\n");
	    		return;
			}
		}

		free(filename);
		free(request);
	}

	free(username);
	free(groupname);
}

void start_connection(){
	int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 
  
    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
  
    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    }
    else{
        printf("Socket successfully binded..\n"); 
    }
  	
  	while(1){
	    // Now server is ready to listen and verification 
	    if ((listen(sockfd, 5)) != 0) { 
	        printf("Listen failed...\n"); 
	        exit(0); 
	    } 
	    else
	        printf("Server listening..\n"); 
	    len = sizeof(cli);
	  
	    // Accept the data packet from client and verification 
	    connfd = accept(sockfd, (SA*)&cli, (socklen_t*)&len); 
	    if (connfd < 0) { 
	        printf("server acccept failed...\n"); 
	        exit(0); 
	    } 
	    else
	        printf("server acccept the client...\n"); 
	  
	    // Function for chatting between client and server 
	    start_exchange(connfd);
	}
    close(sockfd);
}

bool verify(char* groupname, char* filename){
	char* directory;

	srand(time(NULL));
    gmp_randstate_t prng;
    
    // Calibrating tools for timing
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    // Inizializing PRNG
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    ibrs_public_params_t public_params;
    FILE* pairing_stream, *param_stream, *sign_stream;

	directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/pairing.txt", groupname);
    pairing_stream = fopen(directory, "r");
	free(directory);

	directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/param.txt", groupname);
    param_stream = fopen(directory, "r");
	free(directory);

    sign_stream = fopen("sign.txt", "r");

	load_params(&public_params, default_sec_level, pairing_stream, param_stream);
    
    directory = calloc(100, sizeof(char));
    sprintf(directory, "./%s/ids.txt", groupname);
    array_ibrs ids;
	FILE* file_ids = fopen(directory, "r");
	free(directory);
	
	char c;
    int num_lines = 1;

    for (c = getc(file_ids); c != EOF; c = getc(file_ids)){
        if (c == '\n') 
            num_lines += 1;
    }
    
    rewind(file_ids);
    
    if(file_ids!=NULL){
        char* line[num_lines];
        int j = 0;
        size_t len = 0;
        
        init_array_ibrs(&ids, num_lines);
        for(j = 0; j < num_lines; j++) {
            line[j] = NULL;
            len = 0;
            if(getline(&line[j], &len, file_ids) != -1){
				line[j][strcspn(line[j], "\r\n")] = 0;
                insert_id(&ids, line[j], j);
            }
        }
        fclose(file_ids);
	}

  	bool result;	
	ibrs_sig sign;
	
	ibrs_import_sign(&public_params, ids.size, sign_stream, &sign);
    result = ibrs_sign_ver(&public_params, ids, (uint8_t *)filename, &sign);
    
	return result;
}