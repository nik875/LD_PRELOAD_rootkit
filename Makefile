CC ?= gcc
CFLAGS ?= -fPIC -O2 -Wall -Wextra
LDFLAGS ?= -shared
LDLIBS ?= -ldl -pthread

# Hide process library
HIDE_SRC := hide_process.c
HIDE_TARGET := hide_process.so
HIDE_OBJ := $(HIDE_SRC:.c=.o)

# Stealth redirect library
STEALTH_SRC := stealth_redirect.c
STEALTH_TARGET := stealth_redirect.so
STEALTH_OBJ := $(STEALTH_SRC:.c=.o)

# Malicious process binary
BIN_TARGET := malicious_process_net
BIN_SRC := malicious_process_net.c

.PHONY: all clean

all: $(HIDE_TARGET) $(STEALTH_TARGET) $(BIN_TARGET)

$(HIDE_TARGET): $(HIDE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(STEALTH_TARGET): $(STEALTH_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_TARGET): $(BIN_SRC)
	$(CC) -o $@ $<

clean:
	$(RM) $(HIDE_OBJ) $(HIDE_TARGET) $(STEALTH_OBJ) $(STEALTH_TARGET) $(BIN_TARGET)

.PHONY: all clean
