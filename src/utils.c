/*Some functions I use commonly*/
#include "trustcloud.h"
#define PARTSIZ 4096

//A function to display an error message and then exit
void fatal(char *message)
{
	char errorMessage[500];

	strcpy(errorMessage, "[!!] Fatal Error: ");
	strncat(errorMessage, message, 483);
	perror(errorMessage);
	exit(EXIT_FAILURE);
}

//A function for non fatal errors.
void error(char *message)
{
	char errorMessage[500];

	strcpy(errorMessage, "Error: ");
	strncat(errorMessage, message, 483);
	perror(errorMessage);
}

void printUsageServer(){
	/*Soft code?*/
	printf("trustcloud [opt]\n");
	printf("Options are: \n");
	printf("-n (no daemon) run in the current process\n");
	exit(EXIT_FAILURE);
}

void printUsageClient(){
	/*Soft code?*/
	printf("trustcloud [opt] -h [hostname]:[port]\n");
	printf("Options are: \n");
	printf("-a filename 	add or replace a file to trustcloud\n");
	printf("-c number 	provide the required circumference (length) of a ring of trust\n");
	printf("-f filename 	fetch an existing file from the trustcloud server (simply sent to stdout)\n");
	printf("-l 	list all stored files and how they are protected\n");
	printf("-u certificate 	upload a certificate to the trustcloud server\n");
	printf("-v filename certificate 	vouch for the authenticity of an existing file in the trustcloud server using the indicated certificate\n");
	exit(EXIT_FAILURE);
}

/*Send a string*/
int sendBuffer(BIO * bio, char *buffer)
{
	unsigned int sentBytes, bytesToSend;
	bytesToSend = strlen(buffer);
	while(bytesToSend > 0)
	{
		sentBytes = BIO_write(bio, buffer, bytesToSend);
		if(BIO_flush(bio))
			//continue happily
		if(sentBytes == -1)
			return 0;// Return 0 on send failure.
		bytesToSend -= sentBytes;
		buffer += sentBytes;
	}
	return 1;
}

int recvBuffer(BIO * bio, char *destBuffer, int size)
{
#define EOL "\r\n" //End-of-line bytes sequence
#define EOL_SIZE 2

	char *ptr;
	int eolMatched = 0;
	int count=0;

	ptr = destBuffer;
	while(BIO_read(bio,ptr,1) == 1) //Read a single byte.
	{
		if(count == size){
			*ptr = '\0';
			return strlen(destBuffer); // Terminate string and finish.
		}
		if(*ptr == EOL[eolMatched]) //Does this byte match terminator?
		{
			eolMatched++;
			if(eolMatched == EOL_SIZE) //If all bytes match terminator.
			{
				*(ptr+1-EOL_SIZE) = '\0'; //terminate the string.
				return strlen(destBuffer); // Return bytes received
			}
		} else
		{
			eolMatched = 0;
		}
		ptr++; //Increment the pointer to the next byte.
		count++; //Count bytes
	}
	return 0; //Didn't find the end-of-line characters.
}

int sendFile(BIO * bio, FILE * fp, int length){
	unsigned int sentBytes, bytesToSend;

	unsigned char* ptr;

	if( (ptr = (unsigned char *) malloc(length)) == NULL){
		error("allocating memory for reading resource");
		return 0; //report failure
	}
	fread(ptr, 1, length, fp);	// Read the file into memory.

	bytesToSend = length;

	while(bytesToSend > 0)
	{
		sentBytes = BIO_write(bio, ptr, bytesToSend);
		if(BIO_flush(bio))
			//continue happily
		if(sentBytes == -1)
			return 0;// Return 0 on send failure.
		bytesToSend -= sentBytes;
		ptr += sentBytes;
	}
	ptr -= length; //put ptr back to where it began
	free(ptr); // free memory

	return 1; // Success
}

int recvFile(BIO * bio, FILE * fp){

	char buf[BUFSIZ];

	int recv_length = BIO_read(bio, buf, PARTSIZ);
	fwrite(&buf, 1, recv_length, fp);

	/* Originally the socket recv() didn't block and we were able to loop until recv() failed
	 * but BIO_read blocks and we haven't been able to chnage it.
	 */
	return 0;
}

/*This function accepts an file pointer and returns the size of the associated file.
* returns -1 on failure.*/
int getFileSize(FILE *fp){
	if (fp == NULL)
		return -1;
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}
