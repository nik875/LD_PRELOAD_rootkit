CC ?= gcc
CFLAGS ?= -fPIC -O2 -Wall -Wextra
LDFLAGS ?= -shared
LDLIBS ?= -ldl
SRC := hide_process.c
TARGET := hide_process.so
OBJ := $(SRC:.c=.o)
BIN_TARGET := malicious_process_net
BIN_SRC := malicious_process_net.c

.PHONY: all clean

all: $(TARGET) $(BIN_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_TARGET): $(BIN_SRC)
	$(CC) -o $@ $<

clean:
	$(RM) $(OBJ) $(TARGET) $(BIN_TARGET)
