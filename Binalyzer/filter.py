import syscalls
import cfg
import symbols
import sys
import os
import json
import policy
import pprint as pp
import full_ldd

def filter_file(fname):
    f = fname.replace("/", "_") + ".json"
    if f[0] == ".":
        f = f[1:]
    return f


def load_filters(fname):
    filters = {}
    fn = os.path.join(cfg.cached_results_folder, filter_file(fname))
    print("Load filter %s" % fn)
    if not os.path.isfile(fn):
        filters = cfg.extract_syscalls(fname)
        if not filters:
            # cfg-based analysis failed
            return None
        with open(fn, "w") as out:
            json.dump(filters, out, sort_keys=True, indent=4, separators=(',', ': '))
    
    try: 
        with open(fn) as ff:
            filters = json.load(ff)
    except FileNotFoundError:
        filters = None
    return filters

def required_functions(fnames):
    functions = set()
    for fname in fnames:
        sym = symbols.from_elf(fname)
        if ".dynsym" in sym:
            s = sym[".dynsym"]
            functions.update(set(s))
    return functions


def main(fnames):
    os.makedirs(cfg.cached_results_folder, exist_ok=True)

    files = set()
    for fname in fnames:
        files.update([fname])
        files.update(set(syscalls.get_dependencies(fname)))
    print(files)
    
    print("Required functions")
    fncs = required_functions(files)
    
    print("Load whitelist")
    whitelist = {}
    try:
        with open(os.path.join(cfg.cached_results_folder, "function_whitelist.json")) as wl:
            whitelist = json.loads(wl.read())
    except:
        pass

    
    print("Extracting syscalls")
    used_syscalls = set()

    for fname in files:
        # for a static binary we don't need to build the cfg
        # we just extract all syscalls that we find in it
        if full_ldd.is_static(fname):
            used_syscalls.update(set(syscalls.get_syscalls(fname)))
        else:
            filters = load_filters(fname)
            if filters:
                for fnc in fncs:
                    if fnc in filters:
                        used_syscalls.update(set(filters[fnc]))
                    if fnc in whitelist:
                        used_syscalls.update(set(whitelist[fnc]))
            else:
                # cfg analysis failed, fall back to naive method of extracting all syscalls
                used_syscalls.update(set(syscalls.get_syscalls(fname)))
    print("")
    
    # get syscall whitelist (if exists)
    whitelist = {}
    try:
        whitelist = json.load(open("whitelists/whitelist.json"))
    except:
        pass
    
    for fname in files:
        # add all syscalls from dynamic loader 
        if "/ld-" in fname:
            used_syscalls.update(set(syscalls.get_syscalls(fname)))
        for wlib in whitelist:
            if wlib in fname:
                used_syscalls.update(set(whitelist[wlib]))

    used_syscalls.discard(-1)
    syscalls.modify_elf(used_syscalls, fnames[0])
    print("Found %d syscalls" % len(used_syscalls))
    print(sorted(list(used_syscalls)))
    syscalls.print_syscalls(used_syscalls)

    all_blocked = syscalls.get_blocked_syscalls(used_syscalls)
    print("[!] Blocking %d syscalls" % len(all_blocked))

    with open(os.path.join(cfg.cached_results_folder, "syscalls_%s" % filter_file(fnames[0])), "w") as ff:
        json.dump(sorted(list(used_syscalls)), ff);

    with open(os.path.join(cfg.cached_results_folder, "policy_%s" % filter_file(fnames[0])), "w") as ff:
        json.dump(policy.create(used_syscalls), ff)
    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s <binary> [<binary> ...]\n" % (sys.argv[0]))
    else:
        main(sys.argv[1:])
