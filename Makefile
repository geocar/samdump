# Change here to point to the needed OpenSSL libraries & .h files

#SSLPATH=/usr/local/ssl
OSSLPATH=/usr
OSSLLIB=$(OSSLPATH)/lib
OSSLINC=$(OSSLPATH)/include

CC=gcc
CFLAGS= -DUSEOPENSSL -g -I. -I$(OSSLINC) -Wall

# This is to link with whatever we have, SSL crypto lib we put in static
LIBS=-L$(OSSLLIB) $(OSSLLIB)/libcrypto.a

# ** This is for linking with older and more lean libc than installed as default
#    in RH7+ or newer Mandrakes. And probably others. GLIBC has BLOATED!
# Use the reloc (and force it) in rpm to install into /usr/local :)

#LIBS=-L$(OSSLLIB) -L/usr/local/libold -L/usr/local/usr/lib \
$(OSSLLIB)/libcrypto.so /usr/local/usr/lib/crt1.o /usr/local/usr/lib/crti.o \
/usr/local/libold/ld-2.0.5.so \
/usr/local/usr/lib/libc.so /usr/local/libold/libc-2.0.5.so /usr/local/usr/lib/crtn.o 

all: mkntpw samdump
mkntpw: mkntpw.o
	$(CC) $(CFLAGS) -o mkntpw mkntpw.o $(LIBS)
samdump: pwdump.o ntreg.o
	$(CC) $(CFLAGS) -o samdump pwdump.o ntreg.o $(LIBS)

.c.o:
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f *.o samdump mkntpw

