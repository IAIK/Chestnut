
void _start() {
    const char* str = "Hello World!\n";
    /*
    // write 
    asm volatile("mov x0, #1
    ldr x1, =msg
    ldr x2, =len
    mov x8, #64
    svc #0

    // exit 
    mov x0, #0
    mov x8, #93
    svc #0
    */
//     asm volatile("svc #0" : : "x8"(1), "D"(0), "S"(str), "d"(13));
    asm volatile(
        "mov x7, #93\n"
        "mov x8, x7\n"
        "mov x0, #17\n"
        "svc #0");
}
