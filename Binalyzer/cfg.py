import angr
import sys
import syscalls
import json
import time
import logging
import os

logging.getLogger('angr').setLevel('CRITICAL')

cached_results_folder = "cached_results"

callsite_cache = {}
function_cache = {}

current_ms = lambda: int(round(time.time() * 1000))


def build_function_cache(cfg):
    global function_cache
    print("Building function cache...")
    
    for f in cfg.kb.functions:
        start = 2**63
        end = 0
        fnc = cfg.kb.functions[f]
        for block in fnc.blocks:
            if block.size == 0: #skip blocks with size 0
                continue
            start = min(block.addr, start)
            end = max(block.addr + block.size, end)

        function_cache[fnc] = (start, end)

def find_function(cfg, vaddr):
    if len(function_cache) == 0:
        build_function_cache(cfg)

    for f in function_cache:
        if vaddr >= function_cache[f][0] and vaddr < function_cache[f][1]:
            return f

    return None


def function_calling_syscalls(cfg, sys_addrs):
    syslist = {}
    # map all syscall addresses to functions
    for sys_addr in sys_addrs:
        fnc = find_function(cfg, sys_addr)
        if not fnc:
            continue
        if fnc not in syslist:
            syslist[fnc] = set()
        syslist[fnc].add(sys_addr)

    return syslist


def get_call_sites(fnc):
    global callsite_cache

    if fnc not in callsite_cache:
        callsite_cache[fnc] = fnc.get_call_sites()
    return callsite_cache[fnc]
    

def get_call_targets(cfg):
    callees = {}

    # extract all call targets
    for f in cfg.kb.functions:
        fnc = cfg.kb.functions[f]

        call_sites = get_call_sites(fnc)
        calls = []
        for c in call_sites:
            calls.append((c, fnc.get_call_target(c)))

        for call in calls:
            gf = find_function(cfg, call[1])
            if gf:
                if fnc not in callees:
                    callees[fnc] = set()
                callees[fnc].add(gf)
            else:
                continue
    return callees


def get_syscalls(cfg, fnc, callees, syslist, found = set(), traversed = set()):
    if fnc in traversed:
        return found

    traversed.add(fnc)
    if fnc in syslist:
        found.update(syslist[fnc])
    if fnc in callees:
        for c in callees[fnc]:
            found.update(get_syscalls(cfg, c, callees, syslist, found, traversed))
    return found


def syscalls_per_function(cfg, callees, syslist):
    syscaller = {}
    for c in callees:
        calls = get_syscalls(cfg, c, callees, syslist, set(), set())
        if len(calls) > 0:
            syscaller[c.name] = calls

    for c in syslist:
        calls = get_syscalls(cfg, c, callees, syslist, set(), set())
        if len(calls) > 0:
            syscaller[c.name] = calls

    return syscaller

    
def get_cfg(fname):
    p = angr.Project(fname, load_options={'auto_load_libs': False, 'main_opts': {'base_addr': 0}})
    cfg = p.analyses.CFGFast(force_complete_scan=False, resolve_indirect_jumps=False, normalize=True, show_progressbar=True)

    return cfg

current = 0

def start_time():
    global current
    current = current_ms()
    
def stop_time(msg):
    global current
    delta = current_ms() - current
    print("[%dms] %s" % (delta, msg))
    current = current_ms()

def extract_syscalls(fname):
    # clear the function cache if it is not empty, otherwise we get random syscalls based on the order of dependencies being processed
    if(len(function_cache) > 0):
        print("Clearing function cache")
        function_cache.clear()
        callsite_cache.clear()

    start_time()
    try:
        cfg = get_cfg(fname)
    except:
        print("[-] angr could not extract the CFG from %s" % fname)
        return None
    stop_time("Getting CFG")

    insn = syscalls.init(fname)
    stop_time("Syscall Init")
    addrs = syscalls.find_syscall_locations(insn)
    stop_time("Syscall locations")
    sys_addrs = [x[1] for x in addrs]

    syslist = function_calling_syscalls(cfg, sys_addrs)
    stop_time("Syslist")
    callees = get_call_targets(cfg)
    stop_time("Callee list")

    syscaller = syscalls_per_function(cfg, callees, syslist)
    stop_time("Extract syscalls per function")
    
    whitelist = {}
    try:
        with open("whitelists/function_whitelist.json") as wl:
            whitelist = json.loads(wl.read())
    except:
        pass
    
    insn_to_syscall = {}
    used_syscalls = {}
    for fnc in syscaller:
        insn_list = []
        for sysc in syscaller[fnc]:
            for addr in addrs:
                if addr[1] == sysc:
                    if addr[0] not in insn_to_syscall:
                        insn_to_syscall[addr[0]] = syscalls.find_syscall_nr(insn, addr[0])
                    insn_list.append(insn_to_syscall[addr[0]])
        if fnc in whitelist:
            print("Found %s in whitelist, adding %d syscall(s)" % (fnc, len(whitelist[fnc])))
            insn_list += whitelist[fnc]
        used_syscalls[fnc] = sorted(list(set(insn_list))).copy()
    stop_time("Find syscall numbers")

    all_syscalls = set()
    for f in used_syscalls:
        all_syscalls.update(set(used_syscalls[f]))
    used_syscalls[":all"] = sorted(list(all_syscalls))

    return used_syscalls


def main():
    used_syscalls = extract_syscalls(sys.argv[1])
    os.makedirs(cached_results_folder, exist_ok=True)

    with open(os.path.join(cached_results_folder, "cfg.json"), "w") as out:
        json.dump(used_syscalls, out, sort_keys=True, indent=4, separators=(',', ': '))



if __name__ == "__main__":
    main()
