# Chestnut
Chestnut is a tool that automates sandboxing applications on the system-call level. The compiler extension Sourcealyzer is based on LLVM and statically detects system calls during compilation and linking. Binalyzer can be applied to existing binaries where the source code is not available. Dynalyzer detects system calls during runtime and includes a dynamic permission system that asks a user for confirmation whether the system call should be allowed.

## Prerequsites
For Sourcealyzer, the user needs to patch the LLVM toolchain with the provided patch, which is based on LLVM-10. Once LLVM has been compiled, the user needs to compile the necessary libraries such as musl libc with the new flag *-fautosandbox* to detect all system calls in them. This is also necessary for additional dependencies of applications.

For Binalyzer, it is sufficient to install the required python libraries using pip.

## Warnings
**Warning #1**: We are providing this code as-is. You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. This code may cause unexpected and undesirable behavior to occur on your machine.

**Warning #2**: This code is only a proof-of-concept and developed for testing purposes. Do not run it on any productive systems. Do not run it on any system that might be used by another person or entity.
