#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils
import common


def get_gopclntbl_seg_start_addr():
    seg_start_addr = idc.BADADDR
    # .gopclntab found in (older) PE & ELF binaries, __gopclntab found in macho binaries,
    # runtime.pclntab in .rdata for newer PE binaries
    seg = common.get_seg(['.gopclntab', '__gopclntab'])

    if seg is None:
        seg_start_addr = common.get_seg_start_addr_from_rdata(['runtime.pclntab'])
    else:
        seg_start_addr = seg.start_ea

    return seg_start_addr

class Pclntbl():
    '''
    PcLineTable:
    Refer:
        1. golang.org/s/go12symtab
        2. https://golang.org/src/debug/gosym/pclntab.go

    For an amd64 system, the pclntab symbol begins:

        [4] 0xfffffffb
        [2] 0x00 0x00
        [1] 0x01
        [1] 0x08
        [8] N (size of function symbol table)
        [8] pc0
        [8] func0 offset
        [8] pc1
        [8] func1 offset
        …
        [8] pcN
        [4] int32 offset from start to source file table
        … and then data referred to by offset, in an unspecified order …
    '''
    # Magic number of pclinetable header
    MAGIC = 0xFFFFFFFB

    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.goroot = ""
        self.min_lc = 0 # "instruction size quantum", i.e. minimum length of an instruction code
        self.ptr_sz = 0 # size in bytes of pointers and the predeclared "int", "uint", and "uintptr" types
        self.func_num = 0 # Number of functions
        self.func_tbl_addr = idc.BADADDR
        self.func_tbl_sz = 0 # Size of whole function table
        #self.func_sym_tbl = dict() # pc -> FunctionSymbolTableEntry
        self.end_pc = 0
        self.srcfile_tbl_addr = idc.BADADDR
        self.srcfile_num = 0 # Number of src files
        self.srcfiles = list()

    def parse_hdr(self):
        '''
        Refer: function [go12Init()] in https://golang.org/src/debug/gosym/pclntab.go
        '''
        magic = idc.Dword(self.start_addr) & 0xFFFFFFFF
        if magic != Pclntbl.MAGIC:
            print magic, Pclntbl.MAGIC
            common._error("Invalid pclntbl header magic number!")
            idc.Exit(1)
            #raise Exception("Invalid pclntbl header magic number!")
        idc.MakeDword(self.start_addr)
        idc.MakeComm(self.start_addr, "Magic Number")
        idc.MakeNameEx(self.start_addr, "runtime_symtab", flags=idaapi.SN_FORCE)
        idaapi.autoWait()

        if idc.Word(self.start_addr + 4) & 0xFFFF != 0:
            raise Exception("Invalid pclntbl header")
        idc.MakeWord(self.start_addr + 4)

        self.min_lc = idc.Byte(self.start_addr + 6) & 0xFF
        if (self.min_lc != 1) and (self.min_lc != 2) and (self.min_lc != 4):
            raise Exception("Invalid pclntbl minimum LC!")
        idc.MakeComm(self.start_addr + 6, "instruction size quantum")
        idaapi.autoWait()

        self.ptr_sz = idc.Byte(self.start_addr + 7) & 0xFF
        if (self.ptr_sz != 4) and (self.ptr_sz != 8):
            raise Exception("Invalid pclntbl pointer size!")
        idc.MakeComm(self.start_addr + 7, "ptr size")
        idaapi.autoWait()

    def parse_funcs(self):
        '''
        Parse function struct and rename function
        '''
        self.func_num = common.read_mem(self.start_addr + 8, forced_addr_sz=self.ptr_sz)
        common._info("Total functions number: %d\n" % self.func_num)

        self.func_tbl_sz = self.func_num * 2 * self.ptr_sz
        funcs_entry = self.start_addr + 8
        self.func_tbl_addr = funcs_entry + self.ptr_sz
        idc.MakeComm(funcs_entry, "Functions number")
        idc.MakeNameEx(funcs_entry, "funcs_entry", flags=idaapi.SN_FORCE)
        idaapi.autoWait()
        idc.MakeNameEx(self.func_tbl_addr, "pc0", flags=idaapi.SN_FORCE)
        idaapi.autoWait()
        for func_idx in xrange(self.func_num):
            curr_addr = self.func_tbl_addr + func_idx * 2 * self.ptr_sz

            func_addr = common.read_mem(curr_addr, forced_addr_sz=self.ptr_sz)
            name_off = common.read_mem(curr_addr + self.ptr_sz, forced_addr_sz=self.ptr_sz)

            name_addr = self.start_addr + self.ptr_sz + name_off
            func_st_addr = name_addr - self.ptr_sz
            func_st = FuncStruct(func_st_addr, self)
            func_st.parse()

            # Make comment for name offset
            idc.MakeComm(curr_addr + self.ptr_sz, "Func Struct @ 0x%x" % func_st_addr)
            idaapi.autoWait()

    def parse_srcfile(self):
        '''
        Parse and extract source all file names
        '''
        srcfile_tbl_off = common.read_mem(self.func_tbl_addr + self.func_tbl_sz + self.ptr_sz, forced_addr_sz=4) & 0xFFFFFFFF
        self.srcfile_tbl_addr = self.start_addr + srcfile_tbl_off
        idc.MakeComm(self.func_tbl_addr + self.func_tbl_sz + self.ptr_sz, \
            "Source file table addr: 0x%x" % self.srcfile_tbl_addr)
        idc.MakeNameEx(self.srcfile_tbl_addr, "runtime_filetab", flags=idaapi.SN_FORCE)
        idaapi.autoWait()

        self.srcfile_num = (common.read_mem(self.srcfile_tbl_addr, forced_addr_sz=4) & 0xFFFFFFFF) - 1
        common._info("--------------------------------------------------------------------------------------")
        common._info("Source File paths(Total number: %d, default print results are user-defind files):\n" % self.srcfile_num)
        for idx in xrange(self.srcfile_num):
            srcfile_off = common.read_mem((idx+1) * 4 + self.srcfile_tbl_addr, forced_addr_sz=4) & 0xFFFFFFFF
            srcfile_addr = self.start_addr + srcfile_off
            srcfile_path = idc.GetString(srcfile_addr)

            if srcfile_path is None or len(srcfile_path) == 0:
                common._error("Failed to parse the [%d] src file(off: 0x%x, addr: @ 0x%x)" %\
                    (idx+1, srcfile_off, srcfile_addr))
                continue

            if len(self.goroot) > 0 and (srcfile_path.startswith(self.goroot) or "/pkg/" in srcfile_path or\
                 srcfile_path == "<autogenerated>" or srcfile_path.startswith("_cgo_")):
                # ignore golang std libs and 3rd pkgs
                common._debug(srcfile_path)
            else:
                # User defined function
                self.srcfiles.append(srcfile_path)
                common._info(srcfile_path)

            idc.MakeStr(srcfile_addr, srcfile_addr + len(srcfile_path) + 1)
            idaapi.autoWait()
            idc.MakeComm((idx+1) * 4 + self.srcfile_tbl_addr, "")
            idaapi.add_dref((idx+1) * 4 + self.srcfile_tbl_addr, srcfile_addr, idaapi.dr_O)
            idaapi.autoWait()
        common._info("--------------------------------------------------------------------------------------")

    def parse(self):
        self.parse_hdr()
        self.parse_funcs()
        idaapi.autoWait()
        self.goroot = common.get_goroot()
        parse_func_pointer()
        self.parse_srcfile()


class FuncStruct():
    '''
    Old version:
    Refer: golang.org/s/go12symtab

    struct Func
    {
        uintptr      entry;     // start pc
        int32        name;      // name (offset to C string)
        int32        args;      // size of arguments passed to function
        int32        frame;     // size of function frame, including saved caller PC
        int32        pcsp;      // pcsp table (offset to pcvalue table)
        int32        pcfile;    // pcfile table (offset to pcvalue table)
        int32        pcln;      // pcln table (offset to pcvalue table)
        int32        nfuncdata; // number of entries in funcdata list
        int32        npcdata;   // number of entries in pcdata list
    };

    TODO:
    Latest version:
    Refer: https://golang.org/src/runtime/runtime2.go

    // Layout of in-memory per-function information prepared by linker
    // See https://golang.org/s/go12symtab.
    // Keep in sync with linker (../cmd/link/internal/ld/pcln.go:/pclntab)
    // and with package debug/gosym and with symtab.go in package runtime.
    type _func struct {
    	entry   uintptr // start pc
    	nameoff int32   // function name

    	args        int32  // in/out args size
    	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

    	pcsp      int32
    	pcfile    int32
    	pcln      int32
    	npcdata   int32
    	funcID    funcID  // set for certain special runtime functions
    	_         [2]int8 // unused
    	nfuncdata uint8   // must be last
    }
    '''
    def __init__(self, addr, pclntbl):
        self.pclntbl = pclntbl
        self.addr = addr
        self.name = ""
        self.args = 0
        self.frame = 0
        self.pcsp = 0
        self.pcfile = 0
        self.pcln = 0
        self.nfuncdata = 0
        self.npcdata = 0

    def parse(self, is_test=False):
        func_addr = common.read_mem(self.addr, forced_addr_sz=self.pclntbl.ptr_sz, read_only=is_test)

        name_addr = common.read_mem(self.addr + self.pclntbl.ptr_sz, forced_addr_sz=4, read_only=is_test) \
            + self.pclntbl.start_addr
        raw_name_str = idc.GetString(name_addr)
        if raw_name_str and len(raw_name_str) > 0:
            self.name = common.clean_function_name(raw_name_str)

        if not is_test:
            idc.MakeComm(self.addr, "Func Entry")
            idaapi.autoWait()
            # make comment for func name offset
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz, "Func name offset(Addr @ 0x%x), name string: %s" % (name_addr, raw_name_str))
            idaapi.autoWait()

            # Make name string
            if len(self.name) > 0:
                if idc.MakeStr(name_addr, name_addr + len(raw_name_str) + 1):
                    idaapi.autoWait()
                    common._debug("Match func_name: %s" % self.name)
                else:
                    common._error("Make func_name_str [%s] failed @0x%x" % (self.name, name_addr))

            # Rename function
            real_func_addr = idaapi.get_func(func_addr)
            if len(self.name) > 0 and real_func_addr is not None:
                if idc.MakeNameEx(real_func_addr.startEA, self.name, flags=idaapi.SN_FORCE):
                    idaapi.autoWait()
                    common._debug("Rename function 0x%x: %s" % (real_func_addr.startEA, self.name))
                else:
                    common._error('Failed to rename function @ 0x%x' % real_func_addr.startEA)

        self.args = common.read_mem(self.addr + self.pclntbl.ptr_sz + 4, forced_addr_sz=4, read_only=is_test)
        self.frame = common.read_mem(self.addr + self.pclntbl.ptr_sz + 2*4, forced_addr_sz=4, read_only=is_test)
        self.pcsp = common.read_mem(self.addr + self.pclntbl.ptr_sz + 3*4, forced_addr_sz=4, read_only=is_test)
        self.pcfile = common.read_mem(self.addr + self.pclntbl.ptr_sz + 4*4, forced_addr_sz=4, read_only=is_test)
        self.pcln = common.read_mem(self.addr + self.pclntbl.ptr_sz + 5*4, forced_addr_sz=4, read_only=is_test)
        self.nfuncdata = common.read_mem(self.addr + self.pclntbl.ptr_sz + 6*4, forced_addr_sz=4, read_only=is_test)
        self.npcdata = common.read_mem(self.addr + self.pclntbl.ptr_sz + 7*4, forced_addr_sz=4, read_only=is_test)

        if not is_test:
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 4, "args")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 2*4, "frame")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 3*4, "pcsp")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 4*4, "pcfile")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 5*4, "pcln")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 6*4, "nfuncdata")
            idc.MakeComm(self.addr + self.pclntbl.ptr_sz + 7*4, "npcdata")
            idaapi.autoWait()


# Function pointers are often used instead of passing a direct address to the
# function -- this function names them based off what they're currently named
# to ease reading
#
# lea     rax, main_GetExternIP_ptr <-- pointer to actual function
# mov     [rsp+1C0h+var_1B8], rax <-- loaded as arg for next function
# call    runtime_newproc <-- function is used inside a new process

def parse_func_pointer():
    renamed = 0

    text_seg = common.get_text_seg()
    if text_seg is None:
        debug('Failed to get text segment')
        return

    for addr in idautils.Functions(text_seg.startEA, text_seg.endEA):
        name = idc.GetFunctionName(addr)

        # Look at data xrefs to the function - find the pointer that is located in .rodata
        data_ref = idaapi.get_first_dref_to(addr)
        while data_ref != idc.BADADDR:
            if 'rodata' in idc.get_segm_name(data_ref):
                # Only rename things that are currently listed as an offset; eg. off_9120B0
                if 'off_' in idc.GetTrueName(data_ref):
                    if idc.MakeNameEx(data_ref, ('%s_ptr' % name), flags=idaapi.SN_FORCE):
                        idaapi.autoWait()
                        renamed += 1
                    else:
                        common._error('Failed to name pointer @ 0x%02x for %s' % (data_ref, name))

            data_ref = idaapi.get_next_dref_to(addr, data_ref)

    common._info("Rename %d function pointers.\n" % renamed)
