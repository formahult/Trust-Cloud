*Working server (at current version) at fyik.no-ip.org:7171*


#TODO

##Project
+ Add crypto using OpenSSL.
+ "OK" requests are being sent, but not arriving.

##Server
+ Correctly respond to the rest of the commands.
+ Server persistance, most relevant to certificates and etc. If the server crashes and is restarted it should more or less be in the same state. Obviously uploaded files remain where they are but necessary keys for crypto must be reloaded on startup.

##Client
+ Timeout if a server doesn't respond.
