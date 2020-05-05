all: chestnut.o

CFLAGS ?= -Wno-unused-value

chestnut.o: chestnut.c
	clang chestnut.c -c -O ${CFLAGS}
	gcc chestnut.c -o libchestnut.so -shared -fPIC

chestnut_arm.o: chestnut.c
	cp chestnut.c chestnut_arm.c
	aarch64-unknown-linux-musl-clang chestnut_arm.c -c -O ${CFLAGS}
	rm chestnut_arm.c

clean:
	rm *.o libchestnut.so
