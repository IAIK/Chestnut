import sys
import json
import syscalls
import os
from cfg import cached_results_folder

def filter_file(fname):
    f = fname.replace("/", "_") + ".json"
    if f[0] == ".":
        f = f[1:]
    return f

def main(fname):
    used_syscalls = []
    ffname = os.path.join(cached_results_folder, "syscalls_%s" % filter_file(fname))
    try:
        with open(ffname, "r") as ff:
            used_syscalls = json.loads(ff.read())
    except:
        print("Could not parse syscall filter file %s" % ffname)
        return None
    
    print("[+] %s uses %d syscalls" % (fname, len(used_syscalls)))

    all_blocked = syscalls.get_blocked_syscalls(used_syscalls)
    print("[!] Blocking %d syscalls" % len(all_blocked))
    
    rules = []
    for b in used_syscalls:
        rules.append("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, (%d), 0);" % b)
    
    # required for wrapper
    rules.append("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);")
    
    wrapper = open("secwrap.c", "r").read().replace("/* RULES */", "\n".join(rules))
    with open("modified_binaries/wrapper.c", "w") as o:
        o.write(wrapper)
        
    print("[+] seccomp wrapper created!")
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <binary>" % sys.argv[0])
        sys.exit(1)
    main(sys.argv[1])
