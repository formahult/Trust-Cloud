client-objects = trustclient.o
server-objects = trustcloud-server.o
common-objects = trustparser.o utils.o
src            = ./src
include        = ./src

headers = trustcloud.h

flags = -std=gnu99 -Wall -Werror -pedantic
libs = -lssl -lcrypto

install: all
	mkdir log
	mkdir webroot
	mkdir webroot/certs

all: trustclient trustcloud-server

trustclient: $(client-objects) $(common-objects)
	gcc $(flags) -o trustclient $(client-objects) $(common-objects) $(libs)

trustcloud-server: $(server-objects) $(common-objects)
	gcc $(flags) -o trustcloud-server $(server-objects) $(common-objects) $(libs)



trustclient.o: $(src)/trustclient.c $(include)/$(headers)
	gcc $(flags) -c $(src)/trustclient.c $(libs)

trustcloud-server.o: $(src)/trustcloud-server.c $(include)/$(headers)
	gcc $(flags) -c $(src)/trustcloud-server.c $(libs)

trustparser.o: $(src)/trustparser.c $(include)/$(headers)
	gcc $(flags) -c $(src)/trustparser.c $(libs)

utils.o: $(src)/utils.c $(include)/$(headers)
	gcc $(flags) -c $(src)/utils.c $(libs)

clean:
	- rm trustclient trustcloud-server $(client-objects) $(server-objects) $(common-objects)
	- rm -R log
	- rm -R webroot
