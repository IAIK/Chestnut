
void _start() {
    const char* str = "Hello World!\n";
    asm volatile("syscall" : : "a"(1), "D"(0), "S"(str), "d"(13));
    asm volatile("syscall" : : "a"(60), "D"(0));
}
