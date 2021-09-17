volatile int dummy;

void ex() {
    asm volatile("syscall" : : "a"(60), "D"(0));   
}

static void bar() {
    const char* str = "Hello World!\n";
    asm volatile("syscall" : : "a"(1), "D"(0), "S"(str), "d"(13));
    ex();
    dummy--;
}

static void foo() {
    dummy++;
    bar();
}

void _start() {
    dummy = 3;
    foo();
    ex();
}
