#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>


#define OPTIONS "a:c:f:lu:v:h:"
/*
a 	filename 	- Upload a file.
c 	length 		- Provide a circumference length.
f 	filename 	- Fetch a file.
l 			 	- List server contents.
u 	certname 	- Upload a certificate.
v 	filename 	- Vouch for a file.
h 	host		- Specify the destination server address.
*/


#define DEFPORT	"7171"
#define DEFCIR	5
#define NOTYPES 10 // Must be the correct number of types.
#define PROTOV	"TRCP"
#define PRINTREQ 0 // Print out requests.


typedef enum {NUL, ADD, ACK, GET, LIS, CER, VOC, OK, NF, BAD} ReqType;
/*
NUL = No request, default option.
ADD = Request to send a file named in the following argument.
ACK = Permission to send granted.
GET = Request the file name following.
LIS = List server contents.
CER = Upload a certificate with the following name.
VOC = Vouch for the following filename with the postfollowing certificate name.
OK 	= File received okay.
NF	= File not found.
BAD = A bad request, was not understood or the server refuses to comply.
*/


typedef struct Request
{
	ReqType			type; 			// Request type.
	char*			desthost; 		// Destination host.
	char*			port; 			// Send port.
	int				chainLength; 	//
	FILE* 			fileP; 			// File pointer for payloads.
	FILE*			certP;			// **   **		**	certificates
	char* 			fileName; 		// File name.
	char*			certName; 		// Certificate name.
} Request;


void error(char*); 													// Error function for non-critical errors.
void fatal(char*); 													// Error function for critical errors.
void printUsageServer(); 											// Prints the server command-line calling syntax.
void printUsageClient(); 											// Prints the client command-line calling syntax.

int sendBuffer(BIO*, char*); 										// Sends a string across the given socket.
int recvBuffer(BIO*, char*, int); 									// Safely receives a line fron the given socket.
int sendFile(BIO*, FILE *, int); 									// Sends a file across the given socket.
int recvFile(BIO*, FILE *); 											// Receives a file from the given socket.

int getFileSize(FILE *); 											// Returns the file size of the given file.

Request parseTRCP(char*); 											// Parses a string into a TRCP request.
char* makeProto(Request); 											// Parses a TRCP request into a string.

Request formRequest(int*, char***);									// Forms a request from the client startup arguments.
void handleResponse(BIO*, Request); 									// Handles further responses to the client by the server.

void handleConnection(BIO*, FILE *, FILE *);							 	// Handles connections in the server.
void timestamp(FILE *); 											// Writes a timestamp to the specified file.
void parseARGS(int*, char***); 										// Parses startup arguments to the server.
