<!---
This file is written in the markdown format, so as to display nicely on GitHub (/formahult/trustcloud/)*
-->
# trustcloud #
This is the 2014 project for the unit "CITS3002 Networks and Security" at the University of Western Australia.
Authored by Kieran Hannigan (21151118) and Aaron Goldsworthy (21108324).

# Additional Notes (July 2017) #

This project is not being developed anymore and is uploaded for portfolio purposes. Resources such as key pairs are included for demonstration purposes only and are not used in any production environment.

## Project Rundown ##
The project is an OpenSSL secured trustring fileserver written in C, and implements a text protocol called
TRCP (TRustCloud Protocol). It is divided into client and server applications.

## Building the Project##
The project can be compiled using a simple "make". There are additional targets 'client' and 'server' to build
the two respective components, as well as targets "item.o" for each "item.c" source file. Finally, there is a
target "make clean" which will remove all binary files and server directories (/log/ /webroot/ and /certs/).

## Files ##
There are a number of files in this project. They are detailed below:

1. README 				- This file. Documents the project.
2. makecerts.sh 		- This creates a number of certificates and private keys for testing purposes.
3. makefile 			- This specifies how the make utility should build the project.
4. trustclient.c 		- This is the source code for the client application.
5. trustcloud-server.c 	- This is the source code for the server application.
6. trustcloud.h 		- This is the header file for the application.
7. trustparser.c 		- This file contains functions used to parse the text protocol.
8. utils.c 				- This file contains utility functions used in the project.

## Submission 1 Remarks ##
The project current only works in plain text as work is still being done on using SSL to provide end
to end encryption.

### Vouching ###
Currently vouching for files is a work in progress.
The intention is to have users upload their x509 certificates which have been signed independantly of the
project. Bob may sign alice's certificate for example, which is then uploaded as alice-bob.cert.
When a user requests that a file be vouched for using a particular certificate, the server will challenge them
using the public key of the certifiate on the server that they indicated. The client will allow the user to
nominate the private key they wish to authenticate using e.g alice.priv. If the server is satisfied the
indicated file will have a digest made that will be kept in a 'table' associating the file with the
certifiate.

### Rings of Trust ###
Rings of trust will be constructed by searching available certificates for a ring of trust.
For example, if there are two certificates that have been uploaded, alice-bob.cert and bob-alice.cert, making
a ring of size 2, then  if either bob of alice voches for a file, that size 2 ring will be associated with it.

The difficulty so far is in extracting and using the public key in the certificates. It seems like it should
be an easy thing to do, but currently it will only accept pure public keys. There is the option to separate public
keys and certificates, though that would require the maintenance of a relationship between the public keys and the
certificates, as well as including an option to upload public keys. The fact this option was not specified
leads us to believe that the project is acheivable without the need to upload public keys alone, and the extra
effort of associating keys with certificates seems more work than neccessary.

The authentication sequence can be tested so far by using a utility like ncat.
for example:

	$ ncat -C localhost 7171

	TRCP VOC file.ext publickey.pem

The server will respond with an encrypted challenge. Since is unlikely you'll randomly pick the plaintext by
mashing the keyboard, after inputting something the server will respond -

	TRCP BAD

	$

- and disconnect you.

Currently the client works for all options but -v.

### Encryption ###
We've elected to use the OpenSSL libraries for encryption. The progress towards end-to-end encryption so far has
been slow. The documentation for the OpenSSL C API has proven difficult to interpret - currently we are looking
in to the usage of BIO I/O abstractions. It hasn't been clear how these interact with ordinary sockets, whether
they are implemented on top of standard system calls for TCP sockets or if they replace and include this
functionality. The tutorial by IBM in the project resources has been a good springboard, but more time spent in
the man pages is required.
