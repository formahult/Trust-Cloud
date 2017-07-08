/*
File which deals with the externl implementation of the protocol, converting a Request struct understood by
trustcloud into a valid transmission or visa versa.
*/
#include "trustcloud.h"

//Parse a string to form a request structure
char* typeToString[NOTYPES] = {
	"NUL",
	"ADD",
	"ACK",
	"GET",
	"LIS",
	"CER",
	"VOC",
	"OK",
	"NF",
	"BAD"
};


//Valid looking request is similar to HTTP e.g
//TRCP GET fileName /r/n/r/n
Request parseTRCP(char* string){
	if(PRINTREQ)
		printf("Received: %s\n", string);

	Request request;
	request.type 		= BAD;
	request.desthost	= NULL;
	request.port		= DEFPORT;
	request.chainLength = DEFCIR;
	request.fileP		= NULL;
	request.fileName	= NULL;
	request.certName	= NULL;

	char* head = strtok(string, " ");
	if(head == NULL){
		request.type = BAD;
		return request;
	}

	if((strcmp(head,"TRCP")) != 0){
		request.type = BAD;
		return request; // Not TRCP return a BAD request.
	}

	int i=0;
	char* token = strtok(NULL, " ");
	while(strcmp(token, typeToString[i]) && i < NOTYPES - 1)
	{
		i++;
	}
	request.type = (ReqType)i;

	switch(request.type) {
		case ADD:
			if ((token = strtok(NULL, " ")) != NULL)
				request.fileName = strdup(token);
			else
				request.type = BAD;
			break;
		case GET:
			if ((token = strtok(NULL, " ")) != NULL)
				request.fileName = strdup(token);
			else
				request.type = BAD;
			break;
		case CER:
			if ((token = strtok(NULL, " ")) != NULL)
				request.certName = strdup(token);
			else
				request.type = BAD;
			break;
		case VOC:
			if ((token = strtok(NULL, " ")) != NULL)
				request.fileName = strdup(token);
			else
				request.type = BAD;
			if ((token = strtok(NULL, " ")) != NULL)
				request.certName = strdup(token);
			else
				request.type = BAD;
			break;
		default:
			//Nothing further required for other request types
			break;
	}

	return request;
}

char* makeProto(Request request){
	char proto[100];
	strcpy(proto, PROTOV);
	strcat(proto, " ");
	strcat(proto, typeToString[request.type]);
	strcat(proto, " ");
	switch (request.type){
		case ADD:
			strcat(proto, request.fileName);
			break;
		case GET:
			strcat(proto, request.fileName);
			break;
		case CER:
			strcat(proto, request.certName);
			break;
		case VOC:
			strcat(proto, request.fileName);
			strcat(proto, " ");
			strcat(proto, request.certName);
			break;
		default:
			// Nothing further required for other request types.
			break;
	}
	strcat(proto, "\r\n");
	if(PRINTREQ)
		printf("Sending: %s\n", proto);
	return strdup(proto);
}
