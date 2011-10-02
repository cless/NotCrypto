.PHONY: all clean test

CC = gcc
LD = gcc
CFLAGS = -Wall -Wextra -c -std=c99 -fPIC -I src/include
LDFLAGS = 

SRC = $(wildcard src/*.c)
OBJ = $(subst src/,obj/,$(SRC:.c=.o))

TESTSRC = $(wildcard src/test/*.c)
TESTOBJ = $(subst src/test/,obj/,$(TESTSRC:.c=.o))
TESTBIN = $(subst src/test/,bin/,$(TESTSRC:.c=))

ifdef DEBUG
    CFLAGS += -g3 -DDEBUG
else
    ifdef SIZE
        CFLAGS += -Os
    else
        CFLAGS += -O3 -funroll-loops
    endif
    CFLAGS +=-fomit-frame-pointer
endif

ifdef NOTCRYPTO_DISABLE_WARNING
    CFLAGS += -DNOTCRYPTO_DISABLE_WARNING
endif

all: bin/libnotcrypto.so bin/libnotcrypto.a

test: $(TESTBIN)

$(TESTBIN): bin/% : obj/%.o bin/libnotcrypto.a
	$(CC) -static -Lbin $< -lnotcrypto -o $@

bin/libnotcrypto.so: $(OBJ) bin
	$(LD) $(LDFLAGS) -shared $(OBJ) -o bin/libnotcrypto.so

bin/libnotcrypto.a: $(OBJ) bin
	ar rcs bin/libnotcrypto.a $(OBJ)

$(OBJ): obj/%.o : src/%.c obj
	$(CC) $(CFLAGS) src/$(@F:.o=.c) -o $@

$(TESTOBJ): obj/%.o : src/test/%.c obj
	$(CC) $(CFLAGS) src/test/$(@F:.o=.c) -o $@

obj:
	mkdir obj

bin:
	mkdir bin

clean:
	rm -rf obj bin
