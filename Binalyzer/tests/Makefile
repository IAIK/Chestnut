all: test simple dynamic simple2 test2 test2_dynamic

simple: simple.c
	gcc simple.c -static -nostdlib -o simple
	
simple2: simple2.c
	gcc simple2.c -static -nostdlib -o simple2
	
test: test.c
	gcc test.c -static -o test

test2: test2.c
	gcc test2.c -static -o test2 -O3
	
test2_dynamic: test2.c
	gcc test2.c -o test2_dynamic -O3

dynamic: test.c
	gcc test.c -o dynamic	

clean:
	rm -f simple simple2 test test2 test2_dynamic dynamic
