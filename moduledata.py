#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi
idaapi.require("pclntbl")
idaapi.require("common")
from common import ADDR_SZ, read_mem

def is_stripped():
    '''
    Check Binary file if is stripped by find [.go.plt] segment
    '''
    goplt_seg = common.get_seg([".go.plt", "__go_plt"])
    if not goplt_seg: # None
        return True # is stripped
    return False # not stripped

def get_mdata_seg_addr():
    seg_start_addr = 0

    ftype = idc.get_inf_attr(idc.INF_FILETYPE)
    if ftype == idc.FT_PE or ftype == idc.FT_EXE or ftype == idc.FT_EXE_OLD:
        seg = common.get_seg([".data"])
    else:
        seg = common.get_seg([".noptrdata", "__noptrdata"])

    if seg is None:
        # runtime.pclntab in .rdata for newer PE binaries
        seg_start_addr = common.get_seg_start_addr_from_rdata(['runtime.noptrdata'])
    else:
        seg_start_addr = seg.start_ea

    return seg_start_addr


def test_firstmoduledata(possible_addr):
    '''
    Check if current addr is first module data
    '''
    mod_data = ModuleData(possible_addr)
    mod_data.parse(is_test=True)

    if read_mem(mod_data.pclntbl_addr + 8 + ADDR_SZ, read_only=True) == mod_data.text_addr:
        print("Find firstmoduledata @ 0x%x" % possible_addr)
        return True
    return False


def find_first_moduledata_addr():
    first_moduledata_addr = idc.BADADDR

    if not is_stripped(): # not stripped, find firstmoduledata by symbol name
        common._debug("Binary file is not stripped")
        for addr, name in idautils.Names():
            if name == "runtime.firstmoduledata":
                first_moduledata_addr = addr
                break
    else: # is stripped, find firstmodule data by bruteforce searching
        common._debug("Binary file is stripped")
        magic_num = pclntbl.Pclntbl.MAGIC
        # firstmoduledata is contained in segment [.noptrdata]
        mdata_seg_addr = get_mdata_seg_addr()
        if mdata_seg_addr == None:
            raise Exception("Invalid address of segment [.noptrdata]")
        if mdata_seg_addr == 0:
            common._error("Failed to find valid segment [.noptrdata]")

        curr_addr = mdata_seg_addr
        while curr_addr <= idc.BADADDR:
            if idc.Dword(read_mem(curr_addr, read_only=True)) & 0xFFFFFFFF == magic_num: # possible firstmoduledata
                if test_firstmoduledata(curr_addr):
                    break
            curr_addr += ADDR_SZ
        
        if curr_addr >= idc.BADADDR:
            raise Exception("Failed to find firstmoduledata address!")
        first_moduledata_addr = curr_addr

    return first_moduledata_addr

class ModuleData():
    '''
    Refer: https://golang.org/src/runtime/symtab.go

    // moduledata records information about the layout of the executable
    // image. It is written by the linker. Any changes here must be
    // matched changes to the code in cmd/internal/ld/symtab.go:symtab.
    // moduledata is stored in statically allocated non-pointer memory;
    // none of the pointers here are visible to the garbage collector.
    type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr

        textsectmap []textsect
        typelinks   []int32 // offsets from types
        itablinks   []*itab

        ptab []ptabEntry

        pluginpath string
        pkghashes  []modulehash

        modulename   string
        modulehashes []modulehash

        hasmain uint8 // 1 if module contains the main function, 0 otherwise

        gcdatamask, gcbssmask bitvector

        typemap map[typeOff]*_type // offset to *_rtype in previous module

        bad bool // module failed to load and should be ignored

        next *moduledata
    }
    '''
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.pclntbl_addr = idc.BADADDR
        self.pclntbl_sz = 0
        self.pclntbl_cap = 0
        self.ftab_addr = idc.BADADDR
        self.func_num = 0
        self.ftab_cap = 0
        self.filetab_addr = idc.BADADDR
        self.srcfile_num = 0
        self.srcfile_tab_cap = 0
        self.findfunctab = idc.BADADDR
        self.min_pc = idc.BADADDR
        self.max_pc = idc.BADADDR
        self.text_addr = idc.BADADDR
        self.etext_addr = idc.BADADDR
        self.noptrdata_addr = idc.BADADDR
        self.enoptrdata_addr = idc.BADADDR
        self.data_addr = idc.BADADDR
        self.edata_addr = idc.BADADDR
        self.bss_addr = idc.BADADDR
        self.ebss_addr = idc.BADADDR
        self.noptrbss_addr = idc.BADADDR
        self.enoptrbss_addr = idc.BADADDR
        self.end_addr = idc.BADADDR
        self.gcdata_addr = idc.BADADDR
        self.gcbss_addr = idc.BADADDR
        self.types_addr = idc.BADADDR
        self.etypes_addr = idc.BADADDR
        self.textsecmap_addr = idc.BADADDR
        self.textsecmap_len = 0
        self.textsecmap_cap = 0
        self.typelink_addr = idc.BADADDR
        self.type_num = 0
        self.type_cap = 0
        self.itablink_addr = idc.BADADDR
        self.itab_num = 0
        self.itab_cap = 0
        self.ptab_addr = idc.BADADDR
        self.ptab_num = 0
        self.ptab_cap = 0
        self.pluginpath = ""
        self.modulename = ""
        self.hasmain = False
        self.next = idc.BADADDR

    def parse(self, is_test=False):
        if is_test:
            common._info("Test firstmoduledata addr: 0x%x" % self.start_addr)

        self.pclntbl_addr = read_mem(self.start_addr, read_only=is_test)
        self.pclntbl_sz = read_mem(self.start_addr+ADDR_SZ, read_only=is_test)
        self.pclntbl_cap = read_mem(self.start_addr+2*ADDR_SZ, read_only=is_test)
        self.ftab_addr = read_mem(self.start_addr+3*ADDR_SZ, read_only=is_test)
        self.func_num = read_mem(self.start_addr+4*ADDR_SZ, read_only=is_test)
        self.ftab_cap = read_mem(self.start_addr+5*ADDR_SZ, read_only=is_test)
        self.filetab_addr = read_mem(self.start_addr+6*ADDR_SZ, read_only=is_test)
        self.srcfile_num = read_mem(self.start_addr+7*ADDR_SZ, read_only=is_test)
        self.srcfile_tab_cap = read_mem(self.start_addr+8*ADDR_SZ, read_only=is_test)
        self.findfunctab = read_mem(self.start_addr+9*ADDR_SZ, read_only=is_test)
        self.min_pc = read_mem(self.start_addr+10*ADDR_SZ, read_only=is_test)
        self.max_pc = read_mem(self.start_addr+11*ADDR_SZ, read_only=is_test)
        self.text_addr = read_mem(self.start_addr+12*ADDR_SZ, read_only=is_test)
        self.etext_addr = read_mem(self.start_addr+13*ADDR_SZ, read_only=is_test)
        if is_test:
            return
        self.noptrdata_addr = read_mem(self.start_addr+14*ADDR_SZ, read_only=is_test)
        self.enoptrdata_addr = read_mem(self.start_addr+15*ADDR_SZ, read_only=is_test)
        self.data_addr = read_mem(self.start_addr+16*ADDR_SZ, read_only=is_test)
        self.edata_addr = read_mem(self.start_addr+17*ADDR_SZ, read_only=is_test)
        self.bss_addr = read_mem(self.start_addr+18*ADDR_SZ, read_only=is_test)
        self.ebss_addr = read_mem(self.start_addr+19*ADDR_SZ, read_only=is_test)
        self.noptrbss_addr = read_mem(self.start_addr+20*ADDR_SZ, read_only=is_test)
        self.enoptrbss_addr = read_mem(self.start_addr+21*ADDR_SZ, read_only=is_test)
        self.end_addr = read_mem(self.start_addr+22*ADDR_SZ, read_only=is_test)
        self.gcdata_addr = read_mem(self.start_addr+23*ADDR_SZ, read_only=is_test)
        self.gcbss_addr = read_mem(self.start_addr+24*ADDR_SZ, read_only=is_test)
        self.types_addr = read_mem(self.start_addr+25*ADDR_SZ, read_only=is_test)
        self.etypes_addr = read_mem(self.start_addr+26*ADDR_SZ, read_only=is_test)
        self.textsecmap_addr = read_mem(self.start_addr+27*ADDR_SZ, read_only=is_test)
        self.textsecmap_len = read_mem(self.start_addr+28*ADDR_SZ, read_only=is_test)
        self.textsecmap_cap = read_mem(self.start_addr+29*ADDR_SZ, read_only=is_test)
        self.typelink_addr = read_mem(self.start_addr+30*ADDR_SZ, read_only=is_test)
        self.type_num = read_mem(self.start_addr+31*ADDR_SZ, read_only=is_test)
        self.type_cap = read_mem(self.start_addr+32*ADDR_SZ, read_only=is_test)
        self.itablink_addr = read_mem(self.start_addr+33*ADDR_SZ, read_only=is_test)
        self.itab_num = read_mem(self.start_addr+34*ADDR_SZ, read_only=is_test)
        self.itab_cap = read_mem(self.start_addr+35*ADDR_SZ, read_only=is_test)
        self.ptab_addr = read_mem(self.start_addr+36*ADDR_SZ, read_only=is_test)
        self.ptab_num = read_mem(self.start_addr+37*ADDR_SZ, read_only=is_test)
        self.ptab_cap = read_mem(self.start_addr+38*ADDR_SZ, read_only=is_test)

        pluginpath_addr = read_mem(self.start_addr+39*ADDR_SZ, read_only=is_test)
        pluginpath_len = read_mem(self.start_addr+40*ADDR_SZ, read_only=is_test)
        self.pluginpath = str(idc.GetManyBytes(pluginpath_addr, pluginpath_len))

        modulename_addr = read_mem(self.start_addr+44*ADDR_SZ, read_only=is_test)
        modulename_len = read_mem(self.start_addr+45*ADDR_SZ, read_only=is_test)
        self.modulename = str(idc.GetManyBytes(modulename_addr, modulename_len))

        self.hasmain = idc.Byte(self.start_addr+49*ADDR_SZ)
        self.next = read_mem(self.start_addr+54*ADDR_SZ+1, read_only=is_test)

        if not is_test:
            idc.MakeNameEx(self.start_addr, "runtime.firstmoduledata", flags=idaapi.SN_FORCE)
            idaapi.autoWait()

            idc.MakeComm(self.start_addr, "pclntbl addr")
            idc.MakeComm(self.start_addr + ADDR_SZ, "pclntbl size")
            idc.MakeComm(self.start_addr + 2*ADDR_SZ, "pclntbl capacity")
            idc.MakeComm(self.start_addr + 3*ADDR_SZ, "funcs table addr")
            idc.MakeComm(self.start_addr + 4*ADDR_SZ, "funcs number")
            idc.MakeComm(self.start_addr + 5*ADDR_SZ, "funcs table capacity")
            idc.MakeComm(self.start_addr + 6*ADDR_SZ, "source files table addr")
            idc.MakeComm(self.start_addr + 7*ADDR_SZ, "source files number")
            idc.MakeComm(self.start_addr + 8*ADDR_SZ, "source files table capacity")
            idc.MakeComm(self.start_addr + 9*ADDR_SZ, "findfunctable addr")
            idc.MakeComm(self.start_addr + 10*ADDR_SZ, "min pc")
            idc.MakeComm(self.start_addr + 11*ADDR_SZ, "max pc")
            idc.MakeComm(self.start_addr + 12*ADDR_SZ, "text start addr")
            idc.MakeComm(self.start_addr + 13*ADDR_SZ, "text end addr")
            idc.MakeComm(self.start_addr + 14*ADDR_SZ, "noptrdata start addr")
            idc.MakeComm(self.start_addr + 15*ADDR_SZ, "noptrdata end addr")
            idc.MakeComm(self.start_addr + 16*ADDR_SZ, "data section start addr")
            idc.MakeComm(self.start_addr + 17*ADDR_SZ, "data section end addr")
            idc.MakeComm(self.start_addr + 18*ADDR_SZ, "bss start addr")
            idc.MakeComm(self.start_addr + 19*ADDR_SZ, "bss end addr")
            idc.MakeComm(self.start_addr + 20*ADDR_SZ, "noptrbss start addr")
            idc.MakeComm(self.start_addr + 21*ADDR_SZ, "noptrbss end addr")
            idc.MakeComm(self.start_addr + 22*ADDR_SZ, "end addr of whole image")
            idc.MakeComm(self.start_addr + 23*ADDR_SZ, "gcdata addr")
            idc.MakeComm(self.start_addr + 24*ADDR_SZ, "gcbss addr")
            idc.MakeComm(self.start_addr + 25*ADDR_SZ, "types start addr")
            idc.MakeComm(self.start_addr + 26*ADDR_SZ, "types end addr")
            idc.MakeComm(self.start_addr + 27*ADDR_SZ, "test section map addr")
            idc.MakeComm(self.start_addr + 28*ADDR_SZ, "test section map length")
            idc.MakeComm(self.start_addr + 29*ADDR_SZ, "test section map capacity")
            idc.MakeComm(self.start_addr + 30*ADDR_SZ, "typelink addr")
            idc.MakeComm(self.start_addr + 31*ADDR_SZ, "types number")
            idc.MakeComm(self.start_addr + 32*ADDR_SZ, "types table capacity")
            idc.MakeComm(self.start_addr + 33*ADDR_SZ, "itabslink addr")
            idc.MakeComm(self.start_addr + 34*ADDR_SZ, "itabs number")
            idc.MakeComm(self.start_addr + 35*ADDR_SZ, "itabs caapacity")
            idc.MakeComm(self.start_addr + 36*ADDR_SZ, "ptab addr")
            idc.MakeComm(self.start_addr + 37*ADDR_SZ, "ptab num")
            idc.MakeComm(self.start_addr + 38*ADDR_SZ, "ptab capacity")
            idc.MakeComm(self.start_addr + 39*ADDR_SZ, "plugin path addr")
            idc.MakeComm(self.start_addr + 40*ADDR_SZ, "plugin path length")
            idc.MakeComm(self.start_addr + 44*ADDR_SZ, "module name addr")
            idc.MakeComm(self.start_addr + 45*ADDR_SZ, "module name length")
            idc.MakeComm(self.start_addr + 49*ADDR_SZ, "hasmain flag")
            idc.MakeComm(self.start_addr + 54*ADDR_SZ+1, "next moduledata addr")
            idaapi.autoWait()

            idc.MakeStr(modulename_addr, modulename_addr+modulename_len)
            idaapi.autoWait()
            idc.MakeStr(pluginpath_addr, pluginpath_addr+pluginpath_len)
            idaapi.autoWait()
