# TRCP #

 ## Adding files and Certs ##
 Client - TRCP ADD new.file
 Server - TRCP ACK
 Client sends raw data ending with EOF
 Server - TRCP OK

If the sever is unable to complete the request
Server - TRCP BAD

## Fetching and listing##
Client - TRCP GET chosen.file
Server sends raw data

or

Client - TRCP LIS
Server sends raw data

If the sever is unable to complete the request
Server - TRCP BAD

If the server can't find the file
Server - TRCP NF

## Vouching ##
Client - TRCP VOC chosen.file chosen.cert
Server - Sends string encrypted with chosen.cert
Client - decrypts and sends plaintext
Server - TRCP OK
