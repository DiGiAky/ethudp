GIT_VERSION ?= $(shell git describe --abbrev=4 --dirty --always --tags 2>/dev/null || echo "unknown")
CC ?= gcc

# Linux-only configuration
CFLAGS_BASE = -Wall -DETHUDP_VERSION='"$(GIT_VERSION)"' -D_GNU_SOURCE -I$(INCDIR)
CFLAGS_DEBUG = $(CFLAGS_BASE) -g -O0 -DDEBUG
CFLAGS_RELEASE = $(CFLAGS_BASE) -O3 -march=native -mtune=native -flto -ffast-math -funroll-loops
CFLAGS_OPTIMIZED = $(CFLAGS_RELEASE) -DENABLE_SO_REUSEPORT -DENABLE_CPU_AFFINITY -DENABLE_NUMA_OPT -DENABLE_BATCH_PROCESSING
LIBS = -lpthread -lssl -llz4 -lcrypto -lpcap -lnuma -lm

# Modular source files
SRCDIR = src
INCDIR = include
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin
MODULAR_SOURCES = $(SRCDIR)/main.c \
                  $(SRCDIR)/ethudp_config.c \
                  $(SRCDIR)/ethudp_network.c \
                  $(SRCDIR)/ethudp_utils.c \
                  $(SRCDIR)/ethudp_dynamic.c \
                  $(SRCDIR)/ethudp_workers.c \
                  $(SRCDIR)/ethudp_queues.c \
                  $(SRCDIR)/ethudp_buffers.c \
                  $(SRCDIR)/ethudp_metrics.c \
                  $(SRCDIR)/ethudp_stats.c

MODULAR_HEADERS = $(INCDIR)/ethudp_common.h \
                  $(INCDIR)/ethudp_types.h \
                  $(INCDIR)/ethudp_config.h \
                  $(INCDIR)/ethudp_network.h \
                  $(INCDIR)/ethudp_utils.h \
                  $(INCDIR)/ethudp_dynamic.h \
                  $(INCDIR)/ethudp_workers.h \
                  $(INCDIR)/ethudp_queues.h \
                  $(INCDIR)/ethudp_buffers.h \
                  $(INCDIR)/ethudp_metrics.h \
                  $(INCDIR)/ethudp_stats.h

MODULAR_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(MODULAR_SOURCES))

# Default target (modular debug build)
EthUDP: $(OBJDIR) $(BINDIR) $(MODULAR_OBJECTS)
	$(CC) $(CFLAGS_DEBUG) -o $(BINDIR)/EthUDP $(MODULAR_OBJECTS) $(LIBS)

# Modular optimized release build
run: $(OBJDIR) $(BINDIR) $(MODULAR_OBJECTS)
	$(CC) $(CFLAGS_OPTIMIZED) -o $(BINDIR)/EthUDP $(MODULAR_OBJECTS) $(LIBS)

# Modular performance optimized build for production
production: $(OBJDIR) $(BINDIR) $(MODULAR_OBJECTS)
	$(CC) $(CFLAGS_OPTIMIZED) -DNDEBUG -o $(BINDIR)/EthUDP $(MODULAR_OBJECTS) $(LIBS)
	strip $(BINDIR)/EthUDP

# Modular build without NUMA support (fallback for systems without libnuma)
no-numa: $(OBJDIR) $(BINDIR) $(MODULAR_OBJECTS)
	$(CC) $(CFLAGS_RELEASE) -DENABLE_SO_REUSEPORT -DENABLE_CPU_AFFINITY -DENABLE_BATCH_PROCESSING -o $(BINDIR)/EthUDP $(MODULAR_OBJECTS) -lpthread -lssl -llz4 -lcrypto -lpcap



# Create build directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Object file compilation rules
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(MODULAR_HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS_DEBUG) -c $< -o $@

# Optimized object files for release builds
$(OBJDIR)/%.opt.o: $(SRCDIR)/%.c $(MODULAR_HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS_OPTIMIZED) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILDDIR)
	rm -f *.o *.opt.o core

# Install to system (requires root)
install: production
	install -m 755 $(BINDIR)/EthUDP /usr/local/bin/
	install -m 644 README.md /usr/local/share/doc/ethudp/

# Uninstall from system
uninstall:
	rm -f /usr/local/bin/EthUDP
	rm -rf /usr/local/share/doc/ethudp/

# Check system dependencies
check-deps:
	@echo "Checking system dependencies..."
	@pkg-config --exists libssl && echo "✓ OpenSSL found" || echo "✗ OpenSSL missing"
	@pkg-config --exists liblz4 && echo "✓ LZ4 found" || echo "✗ LZ4 missing"
	@pkg-config --exists libpcap && echo "✓ libpcap found" || echo "✗ libpcap missing"
	@ldconfig -p | grep -q libnuma && echo "✓ NUMA support found" || echo "✗ NUMA support missing (use 'make no-numa')"

# Performance test build (modular)
test: $(OBJDIR) $(BINDIR) $(MODULAR_OBJECTS)
	$(CC) $(CFLAGS_OPTIMIZED) -DBENCHMARK -o $(BINDIR)/EthUDP-test $(MODULAR_OBJECTS) $(LIBS)

# Static analysis
analyze:
	@echo "Running static analysis..."
	@which cppcheck >/dev/null 2>&1 && cppcheck --enable=all --std=c99 $(MODULAR_SOURCES) || echo "cppcheck not found"
	@which clang-tidy >/dev/null 2>&1 && clang-tidy $(MODULAR_SOURCES) -- $(CFLAGS_DEBUG) || echo "clang-tidy not found"

# Help target
help:
	@echo "Available targets:"
	@echo "  EthUDP         - Modular debug build (default)"
	@echo "  run            - Modular optimized build with all features"
	@echo "  production     - Modular production build (optimized + stripped)"
	@echo "  no-numa        - Modular build without NUMA support"
	@echo "  test           - Modular performance test build"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install to system (requires root)"
	@echo "  uninstall      - Remove from system"
	@echo "  check-deps     - Check system dependencies"
	@echo "  analyze        - Run static analysis tools"
	@echo "  indent         - Format source code"
	@echo "  help           - Show this help"

# Code formatting
indent:
	@echo "Formatting source code..."
	@which indent >/dev/null 2>&1 && indent -linux $(MODULAR_SOURCES) || echo "indent not found"

.PHONY: clean install uninstall check-deps test analyze help indent
