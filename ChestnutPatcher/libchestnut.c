#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <string.h>
#include "cJSON.h"

#define debug(...) do { if(show_debug) printf(__VA_ARGS__); } while(0)

__attribute__((constructor)) void _init_sandbox() {
    int show_debug = !!getenv("SANDBOX_DEBUG");

    debug("[~] Sandboxer loading...\n");

    FILE* f = fopen("/proc/self/exe", "rb");
    fseek(f, -4, SEEK_END);
    unsigned int data_len = 0;
    fread(&data_len, 4, 1, f);
    size_t file_len = ftell(f);
    debug("[+] Data length: %d\n", data_len);
    fseek(f, file_len - (data_len + 4), SEEK_SET);
    char* buffer = calloc(data_len + 1, 1);
    fread(buffer, 1, data_len, f);
    fclose(f);

    debug("[+] Data: ");
    debug("%s\n", buffer);

    debug("[~] Parsing filters\n");
    cJSON *filter_json = cJSON_Parse(buffer);
    if(!filter_json) {
        printf("[-] Sandbox error before: %s\n", cJSON_GetErrorPtr());
        return;
    }
    cJSON* name = cJSON_GetObjectItemCaseSensitive(filter_json, "version");
    if(cJSON_IsNumber(name)) {
        if(name->valueint != 1) {
            printf("[-] Sandbox only supports version 1, file has version %d\n", name->valueint);
            return;
        }
    }

    int seccomp_enforce = SCMP_ACT_KILL;
    cJSON* enforce = cJSON_GetObjectItemCaseSensitive(filter_json, "enforce");
    if(cJSON_IsString(enforce) && enforce->valuestring != NULL) {
        if(!strcmp(enforce->valuestring, "kill")) {
            seccomp_enforce = SCMP_ACT_KILL;
        } else if(!strcmp(enforce->valuestring, "trap")) {
            seccomp_enforce = SCMP_ACT_TRAP;
        } else if(!strcmp(enforce->valuestring, "log")) {
            seccomp_enforce = SCMP_ACT_LOG;
        }
    }

    debug("[~] Preparing seccomp filters\n");
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    prctl(PR_SET_DUMPABLE, 0);
    scmp_filter_ctx ctx;
    ctx = seccomp_init(seccomp_enforce);

    debug("[+] Enforce mode: %d\n", seccomp_enforce);

    cJSON* syscalls = cJSON_GetObjectItemCaseSensitive(filter_json, "syscalls");
    cJSON* syscall = NULL;

    cJSON_ArrayForEach(syscall, syscalls) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, (syscall->valueint), 0);
    }
    cJSON_Delete(filter_json);

    debug("[+] Sandboxer done\n");
    seccomp_load(ctx);
}
