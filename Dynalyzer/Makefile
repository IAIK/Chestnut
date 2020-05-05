all: dynalyzer

CC = clang
CXX = clang++

CFLAGS = -Wno-unused-value
LDFLAGS= -lseccomp

dynalyzer: dynalyzer.c
	${CC} dynalyzer.c -o $@  ${CFLAGS} ${LDFLAGS}


clean:
	rm dynalyzer
