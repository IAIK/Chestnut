all: test simple dynamic simple2 

simple: simple.c
	gcc simple.c -static -nostdlib -o simple
	
simple2: simple2.c
	gcc simple2.c -static -nostdlib -o simple2
	
test: test.c
	gcc test.c -static -o test
	
dynamic: test.c
	gcc test.c -o dynamic
	
	
simple_arm: simple_arm.c
	aarch64-linux-gnu-gcc-8 simple_arm.c -static -nostdlib -o simple_arm
	
wrapper: wrapper.c
	gcc wrapper.c -o wrapper -lseccomp
	
