CC=clang
CFLAGS=-Wall -Wextra -Werror -pedantic

all : httpserver

httpserver : httpserver.o 
	$(CC) $(CFLAGS) -o httpserver httpserver.o asgn4_helper_funcs.a

$.o : %.cpp
	$(CC) $(CFLAGS) -c $<

clean :
	rm -f httpserver *.o

