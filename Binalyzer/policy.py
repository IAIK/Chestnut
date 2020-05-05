
def create(used_syscalls):
    pol = {
        "version": 1,
        "syscalls": sorted(list(set(used_syscalls)))
    }
    return pol


def add_parameter_set(pol, syscall, arg_nr, allowed):
    if "parameters" not in pol:
        pol["parameters"] = {}
    if syscall not in pol["parameters"][syscall]:
        pol["parameters"][syscall] = [ [], [], [], [], [], [] ]
    pol["parameters"][syscall][arg_nr] = sorted(list(set(allowed)))
    
