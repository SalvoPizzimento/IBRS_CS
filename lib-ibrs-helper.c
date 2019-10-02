/** @file lib-ibrs-helper.c
 *  @brief Helper per il Cloud Server.
 *
 *  Helper contenente le funzioni usate nell'applicazione
 *  per la comunicazione tra le classi.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#include "lib-ibrs-helper.h"

int rcv_data(int socket_id, char* read_buffer, int size){
    if(read(socket_id, read_buffer, size) == -1){
        free(read_buffer);
        printf("Problema nella read della socket\n");
        return 0;
    }
    return 1;
}

int snd_data(int socket_id, char* send_buffer, int size){
    if(write(socket_id, send_buffer, size) == -1) {
        printf("problema nella write sulla socket \n");
        free(send_buffer);
        return 0;
    }
    return 1;
}

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
        return 0;
    }
    fclose(list_file);
	free(directory);

    char* token;
    token = strtok(file_buffer, "\n");
    while(token != NULL){
        if(strncmp(token, username, strlen(username)) == 0){
            printf("Autenticazione eseguita con successo\n");
			free(file_buffer);
            return 1;
        }
        token = strtok(NULL, "\n");
    }
	
	free(file_buffer);
    return 0;
}

void start_exchange(int sockfd){
    char* ids_buffer;
    char* username;
    char* groupname;
    char* filename;
    char* directory;
    char* read_buffer;
    char* file_buffer;
    struct stat st = {0};
    long ids_size = 0;
    long sign_size = 0;
    int auth;

    // RICEZIONE USERNAME E GROUPNAME
    username = calloc(50, sizeof(char));
    groupname = calloc(50, sizeof(char));
    
    if(rcv_data(sockfd, groupname, 1024) == 0){
    	free(username);
    	free(groupname);
    	return;
    }

    if(strlen(groupname) <= 1){
    	printf("Username invalido\n");
    	free(username);
    	free(groupname);
    	return;
    }
    
	strncpy(username, groupname, strlen(groupname));
    printf("USERNAME: %s\n", username);
    free(groupname);

    if(snd_data(sockfd, "ACK", 3) == 0){
    	free(username);
    	return;
    }

    // COMUNICAZIONE CON IL GROUP ADMIN
    if(strncmp(username, "group_admin", 11) == 0){
    	groupname = calloc(50, sizeof(char));
    	if(rcv_data(sockfd, groupname, 1024) == 0){
    		free(username);
    		free(groupname);
    		return;
    	}

    	if(snd_data(sockfd, "ACK", 3) == 0){
    		free(username);
    		free(groupname);
    		return;
    	}

	    // RICEZIONE LISTA UTENTI DEL GRUPPO
        if (stat(groupname, &st) == -1) {
            mkdir(groupname, 0700);
        }

        // CREAZIONE FILE IDS.TXT DENTRO LA CARTELLA GROUPNAME
        directory = calloc(100, sizeof(char));
        sprintf(directory, "./%s/ids.txt", groupname);

        read_buffer = calloc(500, sizeof(char));
        if(rcv_data(sockfd, read_buffer, 500) == 0){
        	free(read_buffer);
        	free(username);
        	free(groupname);
        	free(directory);
       		return;
        }
        ids_size = atoi(read_buffer);
        free(read_buffer);

	    FILE *file_to_open;
	    ids_buffer = calloc(ids_size, sizeof(char));
	    if(rcv_data(sockfd, ids_buffer, ids_size) == 0){
	    	free(ids_buffer);
	    	free(username);
        	free(groupname);
        	free(directory);
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
		if(rcv_data(sockfd, read_buffer, 1024) == 0){
			free(read_buffer);
			free(username);
			free(groupname);
			free(directory);
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
		if(rcv_data(sockfd, read_buffer, 1024) == 0){
			free(read_buffer);
			free(username);
			free(groupname);
			free(directory);
			return;
		}

	    file_to_open = fopen(directory, "w");
	    fprintf(file_to_open, "%s", read_buffer);

	    fclose(file_to_open);
	    free(read_buffer);
	    free(directory);
	}
	// COMUNICAZIONE CON IL GROUP MEMBER
	else{
		char* request;
		char* token;
		
		request = calloc(50, sizeof(char));
		if(rcv_data(sockfd, request, 1024) == 0){
			free(request);
			free(username);
			return;
		}

	    filename = calloc(50, sizeof(char));
	    groupname = calloc(50, sizeof(char));
		
		token = strtok(request, ",");
	    strncpy(groupname, token, strlen(token));

		token = strtok(NULL, ",");
	    strncpy(filename, token, strlen(token));

		printf("GROUPNAME: %s  FILENAME: %s\n", groupname, filename);
		free(request);

	    // AUTENTICAZIONE UTENTE
	    if (stat(groupname, &st) == -1) {
	    	if(snd_data(sockfd, "NULL", 4) == 0){
	    		free(username);
	    		free(groupname);
	    		free(filename);
	    		return;
	    	}
            printf("Gruppo Inesistente\n");
            free(username);
            free(groupname);
            free(filename);
            return;
        }
        else{
		    auth = authenticate(username, groupname);
			if(auth == 0){
				if(snd_data(sockfd, "FAIL_AUTH", 9) == 0){
					free(username);
				    free(filename);
				    free(groupname);
					return;
				}
			    printf("Autenticazione fallita\n");
			    free(username);
			    free(filename);
			    free(groupname);
			    return;
			}
			else{
				if(snd_data(sockfd, "ACK", 3) == 0){
					free(username);
				    free(filename);
				    free(groupname);
					return;
				}
				printf("AUTENTICAZIONE EFFETTUATA\n");
			}
		}

		// RICEZIONE DIMENSIONE DEL FILE DI FIRMA
		request = calloc(500, sizeof(char));
	    if(rcv_data(sockfd, request, 500) == 0){
	    	free(request);
	    	free(username);
		    free(filename);
		    free(groupname);
    		return;
	    }
		printf("RICEZIONE SIZE FIRMA\n");
	    sign_size = atoi(request);
	    free(request);

	    // RICEZIONE FIRMA DEL FILENAME E VERIFICA
	    file_buffer = calloc(sign_size, sizeof(char));
	    int offset = 0;

	    while(strlen(file_buffer) < sign_size){
	    	request = calloc(1024, sizeof(char));
	    	if(rcv_data(sockfd, request, 1024) == 0){
	    		free(request);
	    		free(file_buffer);
		    	free(username);
			    free(filename);
			    free(groupname);
	   			return;
	    	}
	    	offset += sprintf(file_buffer+offset, "%s", request);
	    	free(request);
	    }
		printf("RICEVUTA FIRMA\n");

		FILE *file_to_open;
        file_to_open = fopen("sign.txt", "w");
        fprintf(file_to_open, "%s", file_buffer);
		printf("SIGN.TXT CREATO\n");
        fclose(file_to_open);
        free(file_buffer);

	    bool result;
		printf("prima ver\n");
	    result = ibrs_verify(groupname, filename);
		remove("sign.txt");
		printf("dopo ver\n");
		
	    if(result){
	    	if(snd_data(sockfd, "ACK", 3) == 0){
	    		free(username);
		    	free(groupname);
		    	free(filename);
	    		return;
	    	}
	    }
	    else{
	    	if(snd_data(sockfd, "FAIL", 4) == 0){
	    		free(username);
		    	free(groupname);
		    	free(filename);
	    		return;
	    	}
	    	printf("Firma errata...\n");
	    	free(username);
	    	free(groupname);
	    	free(filename);
	    	return;
	    }
		printf("inizio invio keypair\n");
	    FILE* key_file;
        char* read_buffer;
        offset = 0;

        key_file = fopen("/home/ubuntu/.ssh/KeyPair.pem", "r");
        for(int i=0; i<2; i++){
        	fseek(key_file, offset, SEEK_SET);
	        read_buffer = calloc(1024, sizeof(char));
	        if(fread(read_buffer, sizeof(char), 1024, key_file) > 1024){
	            printf("problema nella read del file\n");
	            fclose(key_file);
	            free(read_buffer);
	            free(username);
		    	free(groupname);
		    	free(filename);
	            return;
	        }

	        if(snd_data(sockfd, read_buffer, 1024) == 0){
	        	fclose(key_file);
			free(read_buffer);
	            free(username);
		    	free(groupname);
		    	free(filename);
	        	return;
	        }

	        free(read_buffer);
	        offset = 1024;
	    }
		printf("FILE PEM INVIATO.\n");
		fclose(key_file);
		request = calloc(50, sizeof(char));
		if(rcv_data(sockfd, request, 1024) == 0){
			free(request);
            free(username);
	    	free(groupname);
	    	free(filename);
			return;
		}
		
		printf("REQUEST: %s\n", request);

		if(strncmp(request, "DOWNLOAD", 8) == 0){

			free(request);

			directory = calloc(50, sizeof(char));
			sprintf(directory, "s3://ibrsstorage/%s/%s", groupname, filename);

			pid_t pid = fork();
			if(pid < 0){
				printf("errore nella fork");
			}
			else if(pid == 0){
				execl("/usr/bin/aws", "aws", "s3", "cp", directory, "/home/ubuntu/", (char*)0);
			}
			wait(&pid);

			if(snd_data(sockfd, "DOWNLOAD", 8) == 0){
				free(username);
		    	free(groupname);
		    	free(filename);
		    	free(directory);
				return;
			}
			read_buffer = calloc(1024, sizeof(char));
			if(rcv_data(sockfd, read_buffer, 1024) == 0){
				free(username);
		    	free(groupname);
		    	free(filename);
		    	free(directory);
		    	free(read_buffer);
				return;
			}
			if(strncmp(read_buffer, "ACK", 3) == 0){
				free(directory);
				directory = calloc(50, sizeof(char));
				sprintf(directory, "/home/ubuntu/%s", filename);
				printf("DOWNLOAD EFFETTUATO\n");
				remove(directory);
			}
			free(read_buffer);
			free(directory);
		}
		else if(strncmp(request, "UPLOAD", 6) == 0){

			free(request);
			directory = calloc(50, sizeof(char));
			sprintf(directory, "s3://ibrsstorage/%s/", groupname);
			char* tmp;
			tmp = calloc(50, sizeof(char));
			sprintf(tmp, "/home/ubuntu/%s", filename);

			if(snd_data(sockfd, "READY", 5) == 0){
				free(username);
		    	free(groupname);
		    	free(filename);
		    	free(directory);
		    	free(tmp);
				return;
			}

			read_buffer = calloc(500, sizeof(char));
			if(rcv_data(sockfd, read_buffer, 500) == 0){
				free(username);
		    	free(groupname);
		    	free(filename);
		    	free(directory);
		    	free(tmp);
		    	free(read_buffer);
				return;
			}

			if(strncmp(read_buffer, "ACK", 3) == 0){
				pid_t pid = fork();
				if(pid < 0){
					printf("errore nella fork");
				}
				else if(pid == 0){
					execl("/usr/bin/aws", "aws", "s3", "mv", tmp, directory, (char*)0);
				}
				wait(&pid);
				printf("UPLOAD EFFETTUATO...\n");
			}
			free(read_buffer);
			free(tmp);
			free(directory);
		}
		else{
			free(request);
		}
		free(filename);
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
        return;
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
        close(sockfd);
        return;
    }
    else{
        printf("Socket successfully binded..\n"); 
    }
  	
  	while(1){
	    // Now server is ready to listen and verification 
	    if ((listen(sockfd, 5)) != 0) { 
	        printf("Listen failed...\n"); 
	        break; 
	    } 
	    else
	        printf("Server listening..\n"); 
	    len = sizeof(cli);
	  
	    // Accept the data packet from client and verification 
	    connfd = accept(sockfd, (SA*)&cli, (socklen_t*)&len); 
	    if (connfd < 0) { 
	        printf("server acccept failed...\n"); 
	        break; 
	    } 
	    else
	        printf("server acccept the client...\n"); 
	  
	    // Function for chatting between client and server 
	    start_exchange(connfd);
	}
    close(sockfd);
}

bool ibrs_verify(char* groupname, char* filename){
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
