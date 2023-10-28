###################################################
#
# Makefile for pwhoisd
# Creator [Xcode -> Makefile Ver: May  8 2006 13:39:03]
# Created: [Tue Feb 13 01:58:19 2007]
#
###################################################

#
# Macros
#

# on FreeBSD sometimes there is no "cc" binary, so changed this
# to be just gcc
CC ?= gcc 
CC_OPTIONS = -ggdb3 -Wall -Wextra -O3
LNK_OPTIONS = -L/usr/local/lib -lpthread


#
# INCLUDE directories for pwhoisd
#

INCLUDE = -I/usr/local/include


all: pwhoisd pwhois-pwdump

#
# Build pwhoisd
#

pwhoisd : \
		main.o\
		pwhois_thread.o\
		geounit.o\
		logger.o\
		IPV4.o \
		patricia.o\
		timeformat.o\
		tst_malloc.o
	$(CC) \
		main.o\
		pwhois_thread.o\
		IPV4.o \
		geounit.o\
		logger.o\
		patricia.o\
		timeformat.o\
		tst_malloc.o\
		-o pwhoisd $(LNK_OPTIONS)

pwhois-pwdump: \
	pwhois_pwdump.o \
	IPV4u.o
	$(CC) \
	pwhois_pwdump.o \
	IPV4u.o \
	-o pwhois-pwdump -L/usr/lib/mysql -L/usr/lib64/mysql -L/usr/local/lib/mysql $(LNK_OPTIONS) -lmysqlclient

clean : 
		rm -f \
		main.o \
		pwhois_thread.o \
		geounit.o \
		logger.o \
		patricia.o \
		timeformat.o \
		tst_malloc.o \
		IPV4.o \
		IPV4u.o \
		pwhoisd \
		pwhois_pwdump.o \
        pwhois-pwdump

install : pwhoisd
		cp pwhoisd pwhoisd

#
# Build the parts of pwhoisd
#


# Item # 1 -- main --
main.o : main.c
	$(CC) $(CC_OPTIONS) main.c -c $(INCLUDE) -o main.o

# Item # 2 -- pwhois_thread --
pwhois_thread.o : pwhois_thread.c
	$(CC) $(CC_OPTIONS) pwhois_thread.c -c $(INCLUDE) -o pwhois_thread.o

# Item # 3 -- geounit --
geounit.o : geounit.c
	$(CC) $(CC_OPTIONS) geounit.c -c $(INCLUDE) -o geounit.o

# Item # 4 -- logger --
logger.o : logger.c
	$(CC) $(CC_OPTIONS) logger.c -c $(INCLUDE) -o logger.o

# Item # 5 -- patricia --
patricia.o : patricia.c
	$(CC) $(CC_OPTIONS) patricia.c -c $(INCLUDE) -o patricia.o

# Item # 6 -- timeformat --
timeformat.o : timeformat.c
	$(CC) $(CC_OPTIONS) timeformat.c -c $(INCLUDE) -o timeformat.o

# Item # 7 -- tst_malloc --
tst_malloc.o : tst_malloc.c
	$(CC) $(CC_OPTIONS) tst_malloc.c -c $(INCLUDE) -o tst_malloc.o

# Item # 8 -- pwhois_pwdump.c --
pwhois_pwdump.o : pwhois_pwdump.c
	$(CC) $(CC_OPTIONS) $(INCLUDE) -c pwhois_pwdump.c -o pwhois_pwdump.o

# Item # 9 -- IPV4.c --
IPV4.o : IPV4.c
	$(CC) $(CC_OPTIONS) IPV4.c -c $(INCLUDE) -o IPV4.o

# Item # 10 -- IPV4u.c --
IPV4u.o : IPV4u.c
	$(CC) $(CC_OPTIONS) IPV4u.c -c $(INCLUDE) -o IPV4u.o

##### END RUN ####
