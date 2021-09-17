#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

void test_func(char *name) {
  printf("%s", name);
}

void test_func2(int num) {
  char *test;
  if(num > 5)
    test = malloc(sizeof(int) * num);
  else
    test = malloc(sizeof(char) * num);
  free(test);
}

void test_func3(int num) {
  for(int i=0;i<num; i++) {
    // asm volatile("syscall" : : "a"(1), "D"(0), "S"(str), "d"(13));
    asm("syscall" : : "a"(1), "D"(0));
  }
}

int main() {
    puts("Hello World!\n");

    test_func("test\n");
    test_func2(5);
    test_func2(7);
    test_func3(10);
    return 0;
}
