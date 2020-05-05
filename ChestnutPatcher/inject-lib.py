import sys
import lief
import json
import struct
import os

def filter_file(fname):
    f = fname.replace("/", "_") + ".json"
    if f[0] == ".":
        f = f[1:]
    return f


def main(fname):
    # load filter
    ffname = "policy_%s" % filter_file(fname)
    filters = None
    try:
        filters = json.loads(open(ffname).read())
    except:
        print("[-] Could not load filter file %s" % ffname)
        return 1
    print("[+] Allowed syscalls: %d" % len(filters["syscalls"]))
    
    # inject sandboxing library
    binary = lief.parse(fname)
    binary.add_library("libchestnut.so")
    # add seccomp library as well
    binary.add_library("libseccomp.so.2")
    binary.write("%s_patched" % fname)
    
    with open("%s_patched" % fname, "ab") as elf:
        filter_data = json.dumps(filters).encode()
        elf.write(filter_data)
        elf.write(struct.pack("I", len(filter_data)))
    os.chmod("%s_patched" % fname, 0o755);
    #print(binary)
    print("[+] Saved patched binary as %s_patched" % fname)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <binary>" % sys.argv[0])
    else:
        main(sys.argv[1])
    
