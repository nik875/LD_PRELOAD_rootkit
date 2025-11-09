CC ?= gcc
CFLAGS ?= -fPIC -O2 -Wall -Wextra
LDFLAGS ?= -shared
LDLIBS ?= -ldl -pthread

# Hide process library
HIDE_SRC := hide_process.c
HIDE_TARGET := hide_process.so
HIDE_OBJ := $(HIDE_SRC:.c=.o)

# Self-delete library
SELFDELETE_SRC := apoptosis.c
SELFDELETE_TARGET := apoptosis.so
SELFDELETE_OBJ := $(SELFDELETE_SRC:.c=.o)

# Malicious process binary
BIN_TARGET := malicious_process
BIN_SRC := malicious_process.c

.PHONY: all clean

all: $(HIDE_TARGET) $(SELFDELETE_TARGET) $(BIN_TARGET)

$(HIDE_TARGET): $(HIDE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(SELFDELETE_TARGET): $(SELFDELETE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_TARGET): $(BIN_SRC)
	$(CC) -o $@ $<

clean:
	$(RM) $(HIDE_OBJ) $(HIDE_TARGET) $(SELFDELETE_OBJ) $(SELFDELETE_TARGET) $(BIN_TARGET)
