#!/bin/bash

# This file generates some sample 'rings of trust'. The rings created are:
# Alice (self signed only) 				(circumference 1)
# Bob->Alice 							(circumference 2)
# Claire->Bob->Alice 					(circumference 3)
# Dave->Claire->Bob->Alice 				(circumference 4)
# Erin->Dave->Claire->Bob->Alice		(circumference 5)
# Fred->Erin->Dave->Claire->Bob->Alice	(circumference 6)


#Alice's deets
AINFO="-subj /C=AU/ST=WA/L=Perth/CN=Alice/emailAddress=alice@cardswap.tk"
BINFO="-subj /C=AU/ST=WA/L=Perth/CN=Bob/emailAddress=bob@spam.com.ru"
CINFO="-subj /C=AU/ST=WA/L=Perth/CN=Claire/emailAddress=claire@nsa.gov"
DINFO="-subj /C=AU/ST=WA/L=Perth/CN=Dave/emailAddress=dave@tinfoil.onion"
EINFO="-subj /C=AU/ST=WA/L=Perth/CN=Erin/emailAddress=admin@ethicalhackers.org"
FINFO="-subj /C=AU/ST=WA/L=Perth/CN=Fred/emailAddress=2111337@student.uwa.edu.au"

#Make private keys for each user to sign each other's certificates with and to identify themselves with
openssl req -x509 -nodes $AINFO -newkey rsa:1024 -keyout alice.priv -out alice.priv
openssl req -x509 -nodes $BINFO -newkey rsa:1024 -keyout bob.priv -out bob.priv
openssl req -x509 -nodes $CINFO -newkey rsa:1024 -keyout claire.priv -out claire.priv
openssl req -x509 -nodes $DINFO -newkey rsa:1024 -keyout dave.priv -out dave.priv
openssl req -x509 -nodes $EINFO -newkey rsa:1024 -keyout erin.priv -out erin.priv
openssl req -x509 -nodes $FINFO -newkey rsa:1024 -keyout fred.priv -out fred.priv

#make the certificates, each higher ring pretty much implies the previous
#in our project it is presumed the users previous signed each others certs before uploading them
#for simplicity the name-name.cert scheme is presumed throughout the project. Functionality to rename
#uploaded certs to this may be implemented later.
#ring 1
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in alice.priv -out alice-self.cert
#ring 2
openssl x509 -days 365 -CA bob.priv -CAkey bob.priv -CAcreateserial -in alice.priv -out bob-alice.cert
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in bob.priv -out alice-bob.cert
#ring3
openssl x509 -days 365 -CA claire.priv -CAkey claire.priv -CAcreateserial -in bob.priv -out claire-bob.cert
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in claire.priv -out alice-claire.cert
#ring 4
openssl x509 -days 365 -CA dave.priv -CAkey dave.priv -CAcreateserial -in claire.priv -out dave-claire.cert
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in dave.priv -out alice-dave.cert
#ring 5
openssl x509 -days 365 -CA erin.priv -CAkey erin.priv -CAcreateserial -in dave.priv -out erin-dave.cert
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in erin.priv -out alice-erin.cert
#ring 6
openssl x509 -days 365 -CA fred.priv -CAkey fred.priv -CAcreateserial -in erin.priv -out fred-erin.cert
openssl x509 -days 365 -CA alice.priv -CAkey alice.priv -CAcreateserial -in fred.priv -out alice-fred.cert