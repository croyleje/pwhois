CC ?= gcc
CMN ?= -pthread
CC_ ?= $(CC) $(CMN)
LNK_ ?= $(CC_)
# CXTRA=-UNDEBUG -fdiagnostics-color=always
COPT ?= -Ofast -fstrict-aliasing -Wstrict-aliasing -DNDEBUG $(CXTRA)
CDBG ?= -ggdb3
CWRN ?= -Wall -Wextra
CC_OPTIONS ?= $(CDBG) $(CWRN) $(COPT)
LNK_OPTIONS ?= -L/usr/lib/libmilter -L/usr/local/lib/libmilter -lrt -lmilter
INCLUDE ?= -I/usr/include -I/usr/local/include

INSTALL_PREFIX ?= /usr/local
INSTALL_DIR ?= $(INSTALL_PREFIX)/bin
EXE_FNAME ?= pwhois_milter
EXE_FPATH ?= $(INSTALL_DIR)/$(EXE_FNAME)
BAK_FPATH ?= $(EXE_FPATH).old
OBJ_FNAME ?= $(EXE_FNAME).o
SRC_FNAME ?= $(EXE_FNAME).c

RM = rm -vf
MV = mv -nv
MKDIR = mkdir -p
CP = cp -nv

# keep "all" target first

all: $(EXE_FNAME)

clean:
	$(RM) $(OBJ_FNAME) $(EXE_FNAME)

$(EXE_FNAME): $(OBJ_FNAME)
	$(LNK_) $^ -o $@ $(LNK_OPTIONS)

$(OBJ_FNAME): $(SRC_FNAME)
	$(CC_) $(CC_OPTIONS) $^ -c $(INCLUDE) -o $@

install: $(EXE_FNAME)
	$(MKDIR) $(INSTALL_DIR)
	$(RM) $(BAK_FPATH)
	$(MV) $(EXE_FPATH) $(BAK_FPATH)
	$(CP) $^ $(INSTALL_DIR)/

# EOF
