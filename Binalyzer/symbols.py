import os, sys

try:
    import elftools
except ImportError:
    sys.path.extend(['.', '..'])
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import (
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx )

def get_symbol_tables(fp):
    elffile = ELFFile(fp)
    
    symbols = {}
    
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        if section['sh_entsize'] == 0:
            continue
        
        syms = []
        for nsym, symbol in enumerate(section.iter_symbols()):
            #if symbol.name == "_dl_argv":
                #print(symbol.entry)
            if symbol["st_shndx"] != "SHN_UNDEF":
                continue
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            if symbol["st_info"]["bind"] != "STB_GLOBAL":
                continue
            syms.append(str(symbol.name))
            #self._emitline('%6d: %s %5d %-7s %-6s %-7s %4s %.25s' % (
                #nsym,
                #self._format_hex(symbol['st_value'], fullhex=True, lead0x=False),
                #symbol['st_size'],
                #describe_symbol_type(symbol['st_info']['type']),
                #describe_symbol_bind(symbol['st_info']['bind']),
                #describe_symbol_visibility(symbol['st_other']['visibility']),
                #describe_symbol_shndx(symbol['st_shndx']),
                #bytes2str(symbol.name)))
        symbols[str(section.name)] = syms.copy()
    return symbols


def from_elf(fname):
    symbols = {}
    with open(fname, 'rb') as file:
        try:
            symbols = get_symbol_tables(file)
        except:
            pass
    return symbols
    

def main():
    print(from_elf(sys.argv[1]))


if __name__ == '__main__':
    main()
