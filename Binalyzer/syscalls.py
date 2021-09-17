import sys
from elftools.elf.elffile import ELFFile
import capstone
import re
import csv
from full_ldd import get_dependencies
import json
import lief
import subprocess
import policy
import os
from cfg import cached_results_folder

MAX_BT = 200

try:
    from subprocess import DEVNULL # py3k
except ImportError:
    import os
    DEVNULL = open(os.devnull, 'wb')

def extend_register(r):
    # 4 general purpose register
    res = re.match("[e|r]*([a-d])[x|l]", r)
    if res: return "r%sx" % res[1]
    res = re.match("[e|r]*([s|d])il?", r)
    if res: return "r%si" % res[1]
    res = re.match("[e|r]*([s|b])pl?", r)
    if res: return "r%sp" % res[1]
    res = re.match("r([0-9]+)[d|w|b]?", r)
    if res: return "r%s" % res[1]
    return r


def recursive_imm_lookup(rset, r):
    if r in rset:
        if rset[r]["type"] == "value":
            return {"type": "value", "value": rset[r]["value"]}
        else:
            return recursive_imm_lookup(rset, rset[r]["value"])
    else:
        return {"type": "register", "value": r}


def find_syscall_nr(insn, i):
    reg_set = {} # we don't know any register values
    # backtrace from syscall to find assignment to *ax
    for bt in range(MAX_BT):
        try:
            (regs_read, regs_write) = insn[i - bt].regs_access()
            # only look at register assignments
            for r in regs_write:
                # for now: only look at movs and xors
                if ("mov" in insn[i - bt].mnemonic or "xor" in insn[i - bt].mnemonic):
                    if len(insn[i - bt].operands) != 2:
                        print("ERROR: instruction type not supported!")
                        print(f'0x{insn[i - bt].address:x}:\t{insn[i - bt].mnemonic}\t{insn[i - bt].op_str}')
                    else:
                        # extract source and target operands
                        target = extend_register(insn[i - bt].reg_name(insn[i - bt].operands[0].value.reg))
                        source = insn[i - bt].operands[1]

                        val = {"type": "value", "value": 0} # default for xor
                        # support registers and immediates (no memory operations, because we don't know what there is)
                        if source.type == capstone.x86.X86_OP_REG and "mov" in insn[i - bt].mnemonic:
                            val = recursive_imm_lookup(reg_set, extend_register(insn[i - bt].reg_name(source.value.reg)))
                        elif source.type == capstone.x86.X86_OP_IMM:
                            val = {"type": "value", "value": source.value.imm}

                        if target not in reg_set:
                            reg_set[target] = val
                else:
                    pass

            # check if we have a numeric value for rax (=syscall number)
            rax = recursive_imm_lookup(reg_set, "rax")
            if rax["type"] == "value":
                return int(rax["value"])
        except:
            pass

    return -1


def find_syscall_locations(insn):
    syscalls = []
    for i in range(len(insn)):
        # find syscall
        try:
            if capstone.x86.X86_GRP_INT in insn[i].groups and "syscall" in insn[i].mnemonic:
                syscalls.append((i, insn[i].address))
        except:
            continue
    return syscalls


def find_syscalls(insn):
    syscalls = set()
    sys_ins = find_syscall_locations(insn)
    for i in range(len(sys_ins)):
        nr = find_syscall_nr(insn, sys_ins[i][0])
        # end of search, check result
        if nr != -1:
            syscalls.add(nr)
        else:
            print("ERROR: could not get syscall number @ %s" % hex(int(sys_ins[i][1])))
            print("--------")
    return list(syscalls)



def print_syscalls(syscalls):
    with open('csv/syscalls_x86_64.csv') as csvfile:
        tbl = csv.reader(csvfile)
        for row in tbl:
            if int(row[0]) in syscalls:
                print(row[1])
                
                
def print_blocked_syscalls(syscalls):
    blocked = 0
    with open('csv/syscalls_x86_64.csv') as csvfile:
        tbl = csv.reader(csvfile)
        for row in tbl:
            if int(row[0]) not in syscalls:
                print(row[1])
                blocked += 1
    return blocked


def get_blocked_syscalls(syscalls):
    blocked = []
    with open('csv/syscalls_x86_64.csv') as csvfile:
        tbl = csv.reader(csvfile)
        for row in tbl:
            if int(row[0]) not in syscalls:
                blocked.append(row[1])
    return blocked

def init(fname):
    with open(fname, 'rb') as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name('.text')
        ops = code.data()
        addr = code['sh_addr']
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        # set skip data otherwise capstone stops when it cannot disasm an instruction
        md.skipdata = True

        # disassemble with meta information
        insn = []
        for i in md.disasm(ops, addr):
            insn.append(i)
        return insn
    return []


def get_syscalls(fname):
    # find syscalls
    try:
        insn = init(fname)
        return find_syscalls(insn)
    except:
        return []


def modify_elf(syscalls, fname):
    print("[+] Modifying %s to add syscalls in note section" % fname)
    os.makedirs("modified_binaries", exist_ok=True)
    binary = lief.ELF.parse(fname)
    # ugly but the framework only allows to encode the list as a single byte
    # extend all syscalls to length 3, create a list of each to split after each char
    # flatten list of lists. Launcher then can extract three consecutive bytes to
    # recreate syscall number
    try:
        _, filename = os.path.split(fname)
        with open(os.path.join(cached_results_folder, filename + "_syscalls"), "w") as f:
            f.write(' '.join([str(x) for x in sorted(syscalls)]))
        list_of_lists = [list(str(x).zfill(3)) for x in syscalls]
        flattened_syscalls = [int(y) for x in list_of_lists for y in x]
        note = lief.ELF.Note("IAIK", lief.ELF.NOTE_TYPES.UNKNOWN, flattened_syscalls)
        note = binary.add(note)
        new_binary = os.path.join("modified_binaries", filename + "_modified")
        # inject sandboxing library
        binary.add_library("libsandboxing.so")
        # add seccomp library as well
        binary.add_library("libseccomp.so.2")
        binary.write(new_binary)
        # note does not have type 0x402 but standalone launcher ignores that value and simply looks for the name
        subprocess.call(["objcopy --rename-section .note=.note.syscalls " + new_binary ], shell=True, stdout=DEVNULL, stderr=subprocess.STDOUT)
    except PermissionError:
        pass


def filter_file(fname):
    f = fname.replace("/", "_") + ".json"
    if f[0] == ".":
        f = f[1:]
    return f


def main(fnames):
    # get set of syscalls that can be blocked for all binaries
    all_syscalls = set()
    files = set()
    for fname in fnames:
        files.update([fname])
        files.update(set(get_dependencies(fname)))
    print(files)

    # get syscall whitelist (if exists)
    whitelist = {}
    try:
        with open("whitelists/function_whitelist.json") as wl:
            whitelist = json.loads(wl.read())
    except:
        pass

    for fname in files:
        syscalls = get_syscalls(fname)
        all_syscalls |= set(syscalls)
        for wlib in whitelist:
            if wlib in fname:
                all_syscalls |= set(whitelist[wlib])
        print("[+] Found %d syscalls for %s (%d in total)" % (len(syscalls), fname, len(all_syscalls)))

    all_blocked = get_blocked_syscalls(all_syscalls)    
    print("[!] Blocking %d syscalls" % len(all_blocked))
    print("[!] Blocked syscalls: ", all_blocked, all_syscalls)
    with open(os.path.join(cached_results_folder, "syscalls_%s" % filter_file(fnames[0])), "w") as ff:
        json.dump(sorted(list(all_syscalls)), ff);

    with open(os.path.join(cached_results_folder, "policy_%s" % filter_file(fnames[0])), "w") as ff:
        json.dump(policy.create(all_syscalls), ff)
    modify_elf(all_syscalls, fnames[0])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s <binary> [<binary> ...]\n" % (sys.argv[0]))
    else:
        main(sys.argv[1:])
    
