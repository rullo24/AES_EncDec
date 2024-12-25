# compiler-related
CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic -Wno-unused-function -Wno-unused-parameter

# required static libs linkage
LIBS = -lssl -lcrypto 

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