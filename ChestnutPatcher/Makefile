all: sample-target libchestnut.so

sample-target: sample-target.c 
	$(CC) -g sample-target.c -o sample-target

libchestnut.so: libchestnut.o cJSON.o
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o libchestnut.so -fPIC -lseccomp libchestnut.o cJSON.o

libchestnut.o: libchestnut.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fPIC -c libchestnut.c 
	
cJSON.o: cJSON.c
	$(CC) $(CFLAGS) -c cJSON.c -fPIC

clean:
	rm -f *.o *.so sample-target
	
