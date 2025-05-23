CC = gcc
CFLAGS = -Wall -Werror -O2 -g

all: ndn_parser_test

ndn_parser_test: ndn_parser_test.c
	$(CC) $(CFLAGS) -o ndn_parser_test ndn_parser_test.c

clean:
	rm -f ndn_parser_test
