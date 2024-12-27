# compiler-related
CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic -Wno-unused-function -Wno-unused-parameter

# required static libs linkage
ifeq ($(ARCH),x86_64)
    LIB_LOC = -L/usr/lib/x86_64-linux-gnu
else ifeq ($(ARCH),aarch64)
    LIB_LOC = -L/usr/lib/aarch64-linux-gnu
endif
LIBS = $(LIB_LOC) -l:libssl.a -l:libcrypto.a -ldl -pthread

# binary-related
TARGET = cr_aes_encdec 
SRCS = main.c src/utils.c src/encrypt.c src/decrypt.c
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