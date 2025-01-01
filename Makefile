# compiler-related
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fsanitize=address -fstack-protector -fstack-protector-strong \
         -fsanitize=undefined -fsanitize=leak -fsanitize=pointer-compare -fsanitize=pointer-subtract \
         -D_FORTIFY_SOURCE=2 -fPIE -fstack-clash-protection -Wformat -Wformat-security \
         -Wshadow -Wdouble-promotion -Wnull-dereference -Wno-stringop-truncation \
         -Wstrict-overflow=5 -Wcast-align=strict -Wswitch-default \
         -Wswitch-enum -Wuninitialized -Wredundant-decls -O3

# adding identifier info to the binary name
VERSION = v1.1.0
OPSYS = linux
ARCH = aarch64

# required static libs linkage
ifeq ($(ARCH),x86_64)
    LIB_LOC = -L/usr/lib/x86_64-linux-gnu
    ARCH = x86_64
else ifeq ($(ARCH),aarch64)
    LIB_LOC = -L/usr/lib/aarch64-linux-gnu
endif
LIBS = $(LIB_LOC) -l:libssl.a -l:libcrypto.a 

# binary-related
TARGET = bin/cr_aes_encdec_$(ARCH)_$(VERSION)_$(OPSYS)
SRCS = main.c $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

# basic rule for target binary build
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	rm -f $(OBJS)

# compiling source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(OBJS)
