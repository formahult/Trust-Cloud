#include "trustcloud.h"

#define WEBROOT	"./webroot/" 			// The webserver's root directory
#define LOGDIR "./log/"					// Log directory
#define LOGFILE "./log/trustcloudd.log" // Log filename
#define CERTDIR	"./webroot/certs/"				// Certificate directory
#define DIRFILE "./log/dir.log" 		// Directory listing filename
#define MAXREQ 500						// Maximum string size a request to the server can have

FILE * logFP;							// Log file pointer
FILE * dirFP;							// Directory file pointer
int runDaemon;							// Run as daemon flag
RSA* pubkey;

RSA* extractPubKey(FILE*);

BIO * anewbio, * snewbio, * bnewbio;

//This function is called when the process is killed
void handleShutdown(int signal)
{
	timestamp(logFP);
	fprintf(logFP, "Shutting down.\n");
	fflush(logFP);
	fclose(logFP);
	fflush(dirFP);
	fclose(dirFP);
	exit(0);
}

int main(int argc, char *argv[])
{

	/* Initializing OpenSSL */

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();
	SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method());
	SSL * ssl;

	if (!SSL_CTX_use_certificate_file(ctx,"server.cert",SSL_FILETYPE_PEM)
		|| !SSL_CTX_use_PrivateKey_file(ctx,"server.key",SSL_FILETYPE_PEM)
		|| !SSL_CTX_check_private_key(ctx)) {

        ERR_print_errors_fp(stderr);
		fatal("setting up the context object");
	}

	snewbio = BIO_new_ssl(ctx,0);
	BIO_get_ssl(snewbio, &ssl);

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	bnewbio = BIO_new(BIO_f_buffer());

 	snewbio = BIO_push(bnewbio, snewbio);

	if((anewbio = BIO_new_accept(DEFPORT)) == NULL) {
		fatal("creating bio");
	}
	BIO_set_accept_bios(anewbio,snewbio);

	if(BIO_do_accept(anewbio) <= 0) {
		fatal("setting up bio");
	}


	runDaemon = 1;
	parseARGS(&argc, &argv);

	mkdir(LOGDIR, S_IRWXU|S_IRWXG);
	mkdir(WEBROOT, S_IRWXU|S_IRWXG);
	mkdir(CERTDIR, S_IRWXU|S_IRWXG);

	logFP = fopen(LOGFILE, "a"); //open for append so the logfile is persistant
	if(logFP == NULL)
		fatal("opening log file");

	dirFP = fopen(DIRFILE, "w+");
	if(dirFP == NULL)
		fatal("opening directory file");

	fprintf(dirFP, "Available files:\n");
	fflush(dirFP);

	if (runDaemon) {
		printf("Starting trustcloud daemon.\n");
		if(daemon(1,0) == -1) //Fork to a background process.
			fatal("forking to daemon process");
	}

	signal(SIGTERM, handleShutdown);
	signal(SIGINT, handleShutdown);	//call handleShutdown on shutdown signal

	timestamp(logFP);

	fprintf(logFP, "starting up.\n");
	fflush(logFP);

	// No calls to fatal() past this point to ensure service is provided

	while(1)
	{
		if(BIO_do_accept(anewbio) <= 0) {
			error("accepting bio");
		} else {
			snewbio = BIO_pop(anewbio);

			if(BIO_do_handshake(snewbio) <= 0) {
				error("handshake failed");
			} else {
				handleConnection(snewbio, logFP, dirFP);
			}
		}
	}

	return(0);
}

void parseARGS(int* argc, char** argv[])
{
	char ch;
	while ((ch = getopt(*argc, *argv, "n")) != -1) {
		switch (ch) {
			case 'n':
				runDaemon = 0;
				break;
			case '?':
				printUsageServer();
				break;
		}
	}
}

/*This functon handles the connection on the passed bio and logs to the passed request.fileP. The connection is processed as a web request and this function replies over the connected socket. Finally, the passed bio is freed at the end of the functon.
*/
void handleConnection(BIO * bio, FILE * logFP, FILE * dirFP)
{
	unsigned char crypt[1024], secret[1024];
	char string[MAXREQ] = {""}, logBuffer[500] = {""}, dirBuffer[500] = {""}, resource[500] = {""};
	int length;
	recvBuffer(bio, string, MAXREQ);

	sprintf(logBuffer, "Received: \"%s\"\t", string);

	Request request = parseTRCP(string);

	switch (request.type) {

		case GET:
			strcpy(resource, WEBROOT); // begin with the webroot

			strcat(resource, request.fileName); // need changes to remove any leading '..' or similar, don't want people getting out of webroot
			strcat(logBuffer, resource);
			if( (request.fileP = fopen(resource, "r")) == NULL) {
				request.type = NF;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " NF\n");
			} else {
				if((length = getFileSize(request.fileP)) != -1){
					if((sendFile(bio, request.fileP, length)) == 1)
					{
						strcat(logBuffer, " GET\n");
					}
					else
					{
						strcat(logBuffer, " failure to send\n");
					}
				} else {
					request.type = BAD;
					sendBuffer(bio, makeProto(request));
					strcat(logBuffer, " BAD\n");
				}
				fclose(request.fileP);
			}
			break;

		case ADD:
			strcpy(resource, WEBROOT); // begin with the webroot
			strcat(resource, request.fileName);
			strcat(logBuffer, resource);
			int existed = access(resource, F_OK );

			if((request.fileP = fopen(resource, "w+")) == NULL){
				request.type = BAD;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " BAD\n");
				strcat(logBuffer, strerror(errno));
			} else {
				request.type = ACK; // ready for upload
				sendBuffer(bio, makeProto(request));
				recvFile(bio, request.fileP);

				request.type = OK; // confirmation
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " ADD\n");
				if (existed == -1) {
				    strcat(dirBuffer, request.fileName);
				    strcat(dirBuffer, "\n");
				}
				fclose(request.fileP);
			}
			break;

		case LIS:
			strcpy(resource, DIRFILE); // begin with the webroot

			strcat(logBuffer, resource);
			if( (request.fileP = fopen(resource, "r")) == NULL) {
				request.type = NF;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " no directory listing available\n");
			} else {
				if((length = getFileSize(request.fileP)) != -1){
					if((sendFile(bio, request.fileP, length)) == 1)
					{
						strcat(logBuffer, " LIS\n");
					}
					else
					{
						strcat(logBuffer, " failure to send directory listing\n");
					}
				} else {
					request.type = BAD;
					sendBuffer(bio, makeProto(request));
					strcat(logBuffer, " BAD\n");
				}
				fclose(request.fileP);
			}
			break;

		case CER:
			strcat(resource, CERTDIR); // add the certificate directory
			strcat(resource, request.certName);
			strcat(logBuffer, resource);
			if((request.fileP = fopen(resource, "w+")) == NULL){
				request.type = BAD;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " BAD\n");
				strcat(logBuffer, strerror(errno));
			} else {
				request.type = ACK; // ready for upload
				sendBuffer(bio, makeProto(request));
				recvFile(bio, request.fileP);

				request.type = OK;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " CER\n");

				fclose(request.fileP);
			}
			break;

		case VOC:
			// prove client is who they say they are
			// challenge them using the public key of the cert they specified
			// if they authenticate
			// keep an association between the certificate and the file.
			// probably in somesort of table or lookup structure.
			strcat(resource, CERTDIR); // add the certificate directory
			strcat(resource, request.certName);
			strcat(logBuffer, resource); //
			if((request.certP = fopen(resource, "r")) == NULL){ //find if the certificate exists if not report to the client
				request.type = NF;
				sendBuffer(bio, makeProto(request));
				strcat(logBuffer, " NF\n");
				strcat(logBuffer, strerror(errno));
			} else {
				// it exists
				pubkey = RSA_new();
				pubkey = extractPubKey(request.certP);
				if(pubkey ==  NULL){ // The cert is corrupted
					request.type = BAD;
					sendBuffer(bio, makeProto(request));
					strcat(logBuffer, " BAD\n");
					strcat(logBuffer, ERR_error_string(ERR_get_error(), NULL));
				} else {
					// all G make RSA
					RAND_load_file("/dev/urandom", RSA_size(pubkey));
					RAND_bytes(secret, RSA_size(pubkey)-11);

					secret[117] = '\0';
					printf("maxlen: %i\n", RSA_size(pubkey));
					printf("len: %i\n", (int)strlen((char*)secret));
					printf("len: %i\n", (int)sizeof(secret));

					if((RSA_public_encrypt(strlen((char*)secret), secret, crypt, pubkey, RSA_PKCS1_PADDING)) == -1){
						ERR_print_errors_fp(stdout);
					}

					printf("challenge: %s\n", crypt);

					sendBuffer(bio, strcat((char*)crypt, "\r\n\r\n")); //send encrypted secret
					//sendBuffer(bio, "/r/n/r/n");
					recvBuffer(bio, (char*)crypt, RSA_size(pubkey)); //don't need old crypt
					printf("received plain\n");

					if(strcmp((char*)crypt, (char*)secret) != 0){
						printf("secret: %s\n", secret);
						printf("\tCrypt: %s\n", crypt);
						request.type = BAD;
						sendBuffer(bio, makeProto(request));
						strcat(logBuffer, " couldn't authenticate");
						strcat(logBuffer, " BAD\n");
					} else {
						request.type = OK; // confirmation
						sendBuffer(bio, makeProto(request));
						strcat(logBuffer, " VOC\n"); //dummy vouch for now
					}
				}
			}
			RSA_free(pubkey);
			break;

		case OK:
			// OK nothing else to do
			strcat(logBuffer, " OK\n");
			break;

		case BAD:
			//bad request ignore
			strcat(logBuffer, " BAD\n");
			break;
		default:
			strcat(logBuffer, " Something went wrong!\n");
			break;
	}
	timestamp(logFP);
	length = strlen(logBuffer);
	fprintf(logFP, logBuffer);
	fprintf(dirFP, dirBuffer);
	fflush(logFP);	//Write to the log
	fflush(dirFP);	//Write directory listing changes.

	BIO_free_all(bio);
}

/*This function writes a timestamp string to the open file pointer passed to it. */
void timestamp(FILE * fd){
	time_t now;
	struct tm result;
	char stime[32];

	now = time(NULL);
	localtime_r(&now, &result);
	fprintf(fd, "%s", asctime_r(&result, stime));
	fflush(logFP);
}


RSA* extractPubKey(FILE* fp){

	X509* 	cert 	= NULL;
	EVP_PKEY* ekey = EVP_PKEY_new();
	RSA* pubkey = RSA_new();
	if((cert = PEM_read_X509(fp, &cert, NULL, NULL)) == NULL){
		return NULL;
	}

	ekey = X509_get_pubkey(cert);
	pubkey = EVP_PKEY_get1_RSA(ekey);

	X509_free(cert);
	EVP_PKEY_free(ekey);
	return(pubkey);
}

