CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude -Werror
LDFLAGS = -lsodium

SRC = src/main.c src/crypto.c src/storage.c
OBJ = $(SRC:.c=.o)

all: vault

vault: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) vault
