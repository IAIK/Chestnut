#define GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <elf.h>
#include <seccomp.h> /* libseccomp */
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>

// needed for dynamic sandboxing
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#define DEBUG //printf

#define SEARCH_STRING "Seccomp:"

static inline void freep(void *p) {
  free(*(void**) p);
}
#define _cleanup_free_ __attribute((cleanup(freep)))
#define NUM_SYSCALLS 600

static int syscalls_allowed[NUM_SYSCALLS] = {0};
static int status;

void cleanup_tracer() {
  if(getenv("LOGFILE")) {
    // save all allowed syscalls to a logfile for debugging purposes
    FILE *file = fopen(getenv("LOGFILE"), "a");
    for(int i=0; i<NUM_SYSCALLS; i++) {
      if(syscalls_allowed[i] == 1) {
        fprintf(file, "%d ", i);
      }
    }
    fprintf(file, "\n");
    fclose(file);
  }
}

void sig_handler(int sig) {
  if(sig == SIGINT) {
    cleanup_tracer();
    exit(WEXITSTATUS(status));
  }
}

uint64_t nospecrdtsc() {
  uint64_t a, d;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void debug(const char *restrict fmt, ...) {
  if(getenv("DEBUG")) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
  }
}

int parse_syscalls(char *filename,int **parsed_syscalls) {
  FILE* f = fopen(filename, "rb");
  fseek(f, 0, SEEK_END);
  size_t fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  char* elf = (char*)malloc(fsize);
  int read = fread(elf, 1, fsize, f);
  (void)read; // just to suppress the warning
  fclose(f);

  Elf64_Ehdr* hdr = (Elf64_Ehdr*)elf;

  Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + hdr->e_shoff);
  Elf64_Shdr symtab = shdr[hdr->e_shstrndx];

  // parse syscall numbers from note section
  _cleanup_free_ char *syscalls = NULL;
  *parsed_syscalls = (int*) malloc(sizeof(int) * 600);
  if(!*parsed_syscalls) {
    debug("Memory allocation failed, terminating now\n");
    exit(1);
  }

  for(int i = 0; i < hdr->e_shnum; i++) {
    if((strcmp((char*)(elf + symtab.sh_offset + shdr[i].sh_name), ".note.syscalls") == 0) && shdr[i].sh_type == SHT_NOTE) {
      Elf64_Nhdr note = *((Elf64_Nhdr*) (elf + shdr[i].sh_offset));
      debug("Syscalls @ %zx (len: %zd, note size: %d)\n", shdr[i].sh_addr, shdr[i].sh_size, note.n_descsz);

      int new_size = sizeof(char) * note.n_descsz + (sizeof(char) * (note.n_descsz/3));
      _cleanup_free_ char * tmp = (char*) malloc(sizeof(char) * note.n_descsz);
      syscalls = (char*) malloc(new_size);

      if(!syscalls || !tmp) {
        debug("Memory allocation failed, terminating now\n");
        exit(1);
      }
      // section offset + size of the note section to skip meta data + sizeof(uint64_t) to skip the name and its padding for 4-byte alignment
      memcpy(tmp, (void*)(elf + shdr[i].sh_offset + sizeof(Elf64_Nhdr) + sizeof(uint64_t)), sizeof(char) * note.n_descsz);
      for(int i=0, j=0; i<sizeof(char) * note.n_descsz; i+=3, j+=4) {
        sprintf(&syscalls[j], "%d%d%d ", tmp[i],tmp[i+1],tmp[i+2]);
      }
      syscalls[new_size - 1] = '\0';
      break;
    }
  }

  // tokenize parsed string for each syscall number
  if(syscalls) {
    char *token = strtok(syscalls, " ");
    int pos = 0;
    debug("Syscalls:");
    while(token) {
      int number = atoi(token);
      debug(" %d", number);
      (*parsed_syscalls)[pos++] = number;
      token = strtok(NULL, " ");
    }
    debug("\nFound %d syscalls\n", pos);
    return pos;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  // first we fork, let the child wait for a signal while parent installs its seccomp filter
  int child = fork();
  if(child == 0) {
    // ptrace the child process
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    _cleanup_free_ int *parsed_syscalls = NULL;
    int pos = parse_syscalls(argv[1], &parsed_syscalls);

    scmp_filter_ctx ctx;
    if(pos == 0) {
      // Finally install the dynamic seccomp filter
      ctx = seccomp_init(SCMP_ACT_TRACE(getpid())); // on default we trace the program, parameter is the process id of our program
      seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
    } else {
      ctx = seccomp_init(SCMP_ACT_TRACE(getpid())); // on default we trace the program, parameter is the process id of our program
      seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
      // setup whitelist
      for(int i=0; i<pos; i++) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, parsed_syscalls[i], 0);
      }
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 59, 0);
    }
    seccomp_load(ctx);
    seccomp_release(ctx);
    if(argc > 1)
      execv(argv[1], &argv[1]);
    else {
      printf("Usage: <program> <program_to_exec> <args>\n");
      return 0;
    }
  } else {
    signal(SIGINT, sig_handler);
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT);

    //track previously allowed syscalls
    int changed_pid = child;
    while(1) {
      ptrace(PTRACE_CONT, changed_pid, 0, 0);
      // wait for status change of one of the childs
      changed_pid = waitpid(-1, &status, __WALL);
      debug("[waitpid status of child %d changed: 0x%08x]\n", changed_pid, status);

      // our primary child died, so we also exit
      if(changed_pid == child && WIFEXITED(status)) {
        cleanup_tracer();
        exit(WEXITSTATUS(status));
      }

      else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))) {
        ptrace(PTRACE_CONT, changed_pid, 0, 0);
      }

      // ptrace a new process forked by our ptraced child
      else if((status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)))
        || (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)))
        || (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)))) {
          long newpid;
          ptrace(PTRACE_GETEVENTMSG, changed_pid, NULL, (long) &newpid);
          debug("forked, new childs pid: %ld\n", newpid);
          ptrace(PTRACE_CONT, newpid, 0, 0);
      }
      // check if the change in status of the child was due to seccomp
      else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))) {
        debug("called forbidden syscall\n");
        // get the syscall number that caused us to get here
        int syscall_number = ptrace(PTRACE_PEEKUSER, changed_pid, sizeof(long)*ORIG_RAX, 0);
        debug("%d\n", syscall_number);
        // if not previously allowed, asked the user
        if(syscalls_allowed[syscall_number] != 1) {
          char question[256];
          sprintf(question, "%s --yesno 'Process (%d) wants to perform syscall %d. Do you want to allow it?'", (getenv("TOOL")) ? getenv("TOOL") : "true", changed_pid, syscall_number);
          int question_result = system(question);
          debug("Return value: %d\n", question_result);
          // user said no, kill the child, the offending process, and the tracer
          if(question_result != 0) {
            kill(child, SIGKILL);
            kill(changed_pid, SIGKILL);
            exit(1);
          } else {
            // remember that the syscall was previously allowed
            syscalls_allowed[syscall_number] = 1;
          }
        }
      }
      // if the child receives a signal that was not handled, it gets killed by the OS
      // WIFSIGNALED indicates that this happened
      else if(WIFSIGNALED(status)) {
        if(child == changed_pid) {
          cleanup_tracer();
          exit(1);
        }
      }
      // if a child receives a signal, the tracer is first notified of it
      // we want to forward the signal without additional checks
      else if(WIFSTOPPED(status)) {
        siginfo_t sig;
        ptrace(PTRACE_GETSIGINFO, changed_pid, NULL, &sig);
        if(sig.si_signo != SIGTRAP) {
          ptrace(PTRACE_CONT, changed_pid, 0, WSTOPSIG(status));
        }
      }
    }
  }
}
