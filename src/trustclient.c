#include "trustcloud.h"

#define MAXREQ 500


int main (int argc, char *argv[]) {

	/* Check correct number of arguments: at least '-h host' must be provided */
	if(argc < 4){
		printUsageClient();
	}

	/* Initialize OpenSSL */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();

	/* Define variables*/
	Request request;
	BIO * bio;
	SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
	SSL * ssl;

	/* Form and send initial request to host */
	request = formRequest(&argc, &argv);

	char* host;

	host = strdup(request.desthost);
	strcat(host, ":");
	strcat(host, request.port);

	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, & ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(bio, host);

	if(bio == NULL) {
		fatal("creating bio object");
	}

	if(BIO_do_connect(bio) <= 0) {
		fatal("connecting to host");
	}

	if(BIO_do_handshake(bio) <= 0) {
	    fatal("establishing SSL");
	}

	sendBuffer(bio, makeProto(request));

	/* Handle server responses */
	handleResponse(bio, request);

	/* Close bio */
	BIO_free_all(bio);
	SSL_CTX_free(ctx);

	return 0;
}


Request formRequest(int* argc, char** argv[]){

	/*Initialise request*/
	Request request;
	request.type 		= NUL;
	request.desthost 	= NULL;
	request.port 		= DEFPORT;
	request.chainLength = DEFCIR;
	request.fileP 		= NULL;
	request.fileName 	= NULL;
	request.certName 	= NULL;

	char ch;
	char *port;

	/* Create a request based on the input arguments */
	while ((ch = getopt(*argc, *argv, "a:c:f:lu:v:h:")) != -1) {
		switch (ch) {
			case 'a':
				if(request.type != NUL){
					error("Too many commands ");
					printUsageClient();
				}
				request.type = ADD;
				if((request.fileP = fopen(optarg, "r")) == NULL){
					fatal("Opening file ");
				}
				request.fileName = strdup(optarg);
				break;
			case 'c':
				if((request.chainLength = atoi(optarg)) == 0){
					fatal("Chain length must be an integer ");
				}
				break;
			case 'f':
				if(request.type != NUL){
					error("Too many commands ");
					printUsageClient();
				}
				request.type = GET;
				request.fileName = strdup(optarg);
				break;
			case 'h':
				request.desthost = strtok(optarg, ":");
				if((port = strtok(NULL, ":")) != NULL){
					if((request.port = port) == 0){
						request.port = DEFPORT;
						printf("port must be an integer.\nUsing default port %s.\n", DEFPORT);
					}
				}
				break;
			case 'l':
				if (request.type != NUL)
				{
					error("Too many commands ");
					printUsageClient();
				}
				request.type = LIS;
				break;
			case 'u':
				if(request.type != NUL){
					error("Too many commands ");
					printUsageClient();
				}
				request.type = CER;
				if((request.fileP = fopen(optarg, "r")) == NULL){
					fatal("Opening certificate ");
				}
				request.certName = strdup(optarg);
				break;
			case 'v':
				if(*argc < 6)
					printUsageClient();
				if(request.type != NUL){
					error("Too many commands ");
					printUsageClient();
				}
				request.type = VOC;
				request.fileName = strdup(optarg);
				request.certName = strdup((*argv)[optind]);
				break;
			case '?':
				printUsageClient();
				break;
		}
	}
	*argc -= optind;
	*argv += optind;
	return request;
}

/* handle response */
//This function sh/could be restructured perhaps two functions queryServer() and handleResponse() could
// call each other.
void handleResponse(BIO * bio, Request request) {
	char answer[MAXREQ];
	if(request.type != LIS && request.type != GET && request.type != VOC) {
		Request response;

		recvBuffer(bio, answer, MAXREQ);
		response = parseTRCP(answer);
		switch (response.type){
			case ACK:
				sendFile(bio, request.fileP, getFileSize(request.fileP));

				recvBuffer(bio, answer, MAXREQ);
				request = parseTRCP(answer);
				if(request.type == OK) {
					printf("Upload completed successfully.\n");
				} else {
					printf("%s may not have been uploaded correctly.\n", request.fileName);
				}
				break;
			case NF:
				printf("The server couldn't find the requested file.\n");
				break;
			case BAD:
				printf("The server couldn't fulfil the request.\n");
				break;
			default:
				printf("The server responded incorrectly.\n");
				break;
		}
	} else if (request.type == VOC){
		char* loc;
		unsigned char challenge[1024], plain[1024];
		FILE* pem;
		RSA* privkey = RSA_new();
		size_t inf = 0;
		printf("Authenticate with which key?\n> ");
		getline(&loc, &inf, stdin);
		loc[strlen(loc)-1] = '\0';//overwrite newline
		printf("%s\n", loc);
		if ((pem = fopen(loc, "r")) == NULL)
		{
			request.type = BAD;
			sendBuffer(bio, makeProto(request));
			fatal("Opening File: ");
		}
		if((privkey = PEM_read_RSAPrivateKey(pem, &privkey, NULL, NULL)) == NULL){
			request.type = BAD;
			sendBuffer(bio, makeProto(request));
			fatal("Reading certificate: ");
		}
		printf("awaiting challenge\n");
		recvBuffer(bio, (char*)challenge, RSA_size(privkey));
		printf("got challenge: %s\n", challenge);
		printf("len: %i\n", (int)strlen((char*)challenge));

		if ((RSA_private_decrypt(strlen((char*)challenge), challenge, plain, privkey, RSA_PKCS1_PADDING)) == -1){
			ERR_print_errors_fp(stdout);
		}
		// if ((RSA_private_decrypt(sizeof(challenge), challenge, plain, privkey, RSA_NO_PADDING)) == -1){
		// 	ERR_print_errors_fp(stdout);
		// }

		printf("sending plain\n");
		sendBuffer(bio, strcat((char*)plain, "\r\n\r\n"));
		recvBuffer(bio, answer, RSA_size(privkey));
		request = parseTRCP(answer);
		if(request.type != OK){
			printf("Failed authentication\n");
		} else {
			printf("Authenticated successfully\n");
		}

	} else {
		recvFile(bio, stdout);
	}
}
