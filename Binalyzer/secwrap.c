#define _GNU_SOURCE
#include <seccomp.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
char* buffer = 0;
size_t n = 0;
int child = 0;
size_t argc = 0;
char* args[256];

int main(int argc, char* argv[],char* envp[])
{
  prctl(PR_SET_NO_NEW_PRIVS, 1);
  prctl(PR_SET_DUMPABLE, 0); 
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  /* RULES */
  seccomp_load(ctx);
  if (argc <= 1) return -1;
  char* cmd = argv[1];
  for (int i = 1; i < argc; ++i) argv[i-1] = argv[i];
  argv[argc-1] = 0;
  execvpe(cmd,argv,envp);
  return 0;
}
