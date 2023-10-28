# Makefile for pwhois_milter

CC = gcc -pthread
CC_OPTIONS = -g -Wall -Wextra
LNK_OPTIONS = -L/usr/lib/libmilter -L/usr/local/lib/libmilter -lrt -lmilter
INCLUDE = -I/usr/include -I/usr/local/include
RM = rm -f
CP = cp

all: pwhois_milter

pwhois_milter: pwhois_milter.o
	$(CC) pwhois_milter.o -o pwhois_milter $(LNK_OPTIONS)

clean:
	$(RM) pwhois_milter.o pwhois_milter

install: pwhois_milter
	$(CP) pwhois_milter /usr/local/bin/

pwhois_milter.o: pwhois_milter.c
	$(CC) $(CC_OPTIONS) pwhois_milter.c -c $(INCLUDE) -o pwhois_milter.o
