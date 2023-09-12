#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, ida_segment
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

    if seg_start_addr is None:
        seg_start_addr = 0
    return seg_start_addr


def test_firstmoduledata(possible_addr, magic_number):
    '''
    Check if current addr is first module data
    '''
    mod_data = ModuleData(possible_addr, magic_number)
    mod_data.parse(is_test=True)

    if magic_number == common.MAGIC_112:
        if read_mem(mod_data.pclntbl_addr + 8 + ADDR_SZ, read_only=True) == mod_data.text_addr:
            common._info(f"Find firstmoduledata @ {possible_addr:#x}, magic number: {magic_number:#x}")
            return True
        else:
            common._debug(f"Not firstmoduledata addr: @ {possible_addr:#x}")
    elif magic_number == common.MAGIC_116:
        funcnametab_off = read_mem(mod_data.pcheader_addr + 8 + 2*ADDR_SZ, read_only=True)
        filetab_off     = read_mem(mod_data.pcheader_addr + 8 + 4*ADDR_SZ, read_only=True)
        pctab_off       = read_mem(mod_data.pcheader_addr + 8 + 5*ADDR_SZ, read_only=True)
        pclntbl_off     = read_mem(mod_data.pcheader_addr + 8 + 6*ADDR_SZ, read_only=True)

        if (mod_data.pcheader_addr + funcnametab_off) == mod_data.funcnametab_addr \
                and (mod_data.pcheader_addr + filetab_off) == mod_data.filetab_addr \
                and (mod_data.pcheader_addr + pctab_off) == mod_data.pctab_addr \
                and (mod_data.pcheader_addr + pclntbl_off) == mod_data.pclntbl_addr:
            common._info(f"Find firstmoduledata @ {possible_addr:#x}, magic number: {magic_number:#x}")
            return True
        else:
            common._debug(f"Not firstmoduledata addr: @ {possible_addr:#x}")
    elif magic_number == common.MAGIC_118 or magic_number == common.MAGIC_120:
        funcnametab_off = read_mem(mod_data.pcheader_addr + 8 + 3*ADDR_SZ, read_only=True)
        filetab_off     = read_mem(mod_data.pcheader_addr + 8 + 5*ADDR_SZ, read_only=True)
        pctab_off       = read_mem(mod_data.pcheader_addr + 8 + 6*ADDR_SZ, read_only=True)
        pclntbl_off     = read_mem(mod_data.pcheader_addr + 8 + 7*ADDR_SZ, read_only=True)

        pcheader_textaddr = read_mem(mod_data.pcheader_addr + 8 + 2*ADDR_SZ, read_only=True)

        if (mod_data.pcheader_addr + funcnametab_off) == mod_data.funcnametab_addr \
                and (mod_data.pcheader_addr + filetab_off) == mod_data.filetab_addr \
                and (mod_data.pcheader_addr + pctab_off) == mod_data.pctab_addr \
                and (mod_data.pcheader_addr + pclntbl_off) == mod_data.pclntbl_addr:
                # and pcheader_textaddr == mod_data.text_addr:
            common._info(f"Find firstmoduledata @ {possible_addr:#x}, magic number: {magic_number:#x}")
            return True
        else:
            if (mod_data.pcheader_addr + funcnametab_off) != mod_data.funcnametab_addr:
                common._debug("Funcname table addr not eqeual")
                common._debug(f"moddata.pcheader_addr: {mod_data.pcheader_addr:#x}")
                common._debug(f"funcnametab_off: {funcnametab_off:#x}")
                common._debug(f"moddata.funcnametab_addr: {mod_data.funcnametab_addr:#x}")

            if (mod_data.pcheader_addr + filetab_off) != mod_data.filetab_addr:
                common._debug("File table addr not equal.")
                common._debug(f"moddata.pcheader_addr: {mod_data.pcheader_addr:#x}")
                common._debug(f"pctab_off: {pctab_off:#x}")
                common._debug(f"moddata.pctab_addr: {mod_data.pctab_addr:#x}")

            if (mod_data.pcheader_addr + pclntbl_off) != mod_data.pclntbl_addr:
                common._debug("pclntab addr not equal.")
                common._debug(f"moddata.pcheader_addr: {mod_data.pcheader_addr:#x}")
                common._debug(f"pclntbl_off: {pclntbl_off:#x}")
                common._debug(f"moddata.pclntbl_addr: {mod_data.pclntbl_addr:#x}")

            #if pcheader_textaddr != mod_data.text_addr:
            #    common._debug("text addr not equal.")
            #    common._debug(f"pcheader textaddr: {pcheader_textaddr:#x}")
            #    common._debug(f"moddata textaddr: {mod_data.text_addr:#x}")

            common._debug(f"Not firstmoduledata addr: @ {possible_addr:#x}")

    return False

def find_first_moduledata_addr_by_brute(magic_number):
    first_moduledata_addr = idc.BADADDR

    segn = ida_segment.get_segm_qty()
    for idx in range(segn):
        curr_seg = ida_segment.getnseg(idx)
        if curr_seg.type == 3: # Pure Data segment
            curr_addr = curr_seg.start_ea
            common._info(f"Search seg [{curr_seg.name}], start: {curr_seg.start_ea:#x}, end: {curr_seg.end_ea:#x}, type: {curr_seg.type}")
            while curr_addr <= curr_seg.end_ea:
                common._debug(f"Test firstmoduledata @ {curr_addr:#x} for magic_number {magic_number:#x}")
                if idc.get_wide_dword(read_mem(curr_addr, read_only=True)) & 0xFFFFFFFF == magic_number: # possible firstmoduledata
                    if test_firstmoduledata(curr_addr, magic_number):
                        break
                curr_addr += ADDR_SZ

            if curr_addr >= curr_seg.end_ea:
                continue

            first_moduledata_addr = curr_addr
            break

    return first_moduledata_addr

def find_first_moduledata_addr():
    first_moduledata_addr = idc.BADADDR
    magic_number = common.MAGIC_112 # Default magic number

    if not is_stripped(): # not stripped, find firstmoduledata by symbol name
        common._debug("Binary file is not stripped")
        for addr, name in idautils.Names():
            if name == "runtime.firstmoduledata":
                first_moduledata_addr = addr
                break
    else: # is stripped, find firstmodule data by bruteforce searching
        common._debug("Binary file is stripped")
        magic_numbers = [common.MAGIC_116, common.MAGIC_112, common.MAGIC_118, common.MAGIC_120]
        # firstmoduledata is often contained in segment [.noptrdata]
        mdata_seg_addr = get_mdata_seg_addr()
        common._info("Finding firstmoduledata object...")
        if mdata_seg_addr == 0:
            common._error("Failed to find valid segment [.noptrdata]")

        if mdata_seg_addr >0:
            for tmp_magic_number in magic_numbers:
                common._info(f"Finding firstmoduledata with magic number {tmp_magic_number:#x} ...")
                curr_addr = mdata_seg_addr
                while curr_addr <= common.MAX_EA:
                    #common._debug(f"Test firstmoduledata @ {curr_addr:#x} for magic_number {tmp_magic_number:#x}")
                    if idc.get_wide_dword(read_mem(curr_addr, read_only=True)) & 0xFFFFFFFF == tmp_magic_number:
                        # possible firstmoduledata
                        if test_firstmoduledata(curr_addr, tmp_magic_number):
                            magic_number = tmp_magic_number
                            break
                    curr_addr += ADDR_SZ

                if curr_addr < common.MAX_EA:
                    first_moduledata_addr = curr_addr
                    break

        if first_moduledata_addr == idc.BADADDR:# and mdata_seg_addr == 0:
            common._info("Now find firstmoduledata object by bruteforcing...")
            for tmp_magic_number in magic_numbers:
                common._info(f"Finding firstmoduledata with magic number {tmp_magic_number:#x} by bruteforcing...")
                first_moduledata_addr = find_first_moduledata_addr_by_brute(tmp_magic_number)
                if first_moduledata_addr != idc.BADADDR:
                    magic_number = tmp_magic_number
                    break

        if first_moduledata_addr == idc.BADADDR:
            raise Exception("Failed to find firstmoduledata address!")

    return first_moduledata_addr, magic_number

class ModuleData():
    '''
    Refer: https://golang.org/src/runtime/symtab.go

    // moduledata records information about the layout of the executable
    // image. It is written by the linker. Any changes here must be
    // matched changes to the code in cmd/internal/ld/symtab.go:symtab.
    // moduledata is stored in statically allocated non-pointer memory;
    // none of the pointers here are visible to the garbage collector.
    type moduledata struct {    // Go version 1.12~1.16
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

    type moduledata struct {    // Go version 1.16+
        pcHeader     *pcHeader
        funcnametab  []byte
        cutab        []uint32
        filetab      []byte
        pctab        []byte
        pclntable    []byte
        ftab         []functab
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr
        rodata                uintptr               // Starts from 1.18
        gofunc                uintptr // go.func.*  // Starts from 1.18

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

    type moduledata struct {    // Go version 1.20+
        pcHeader     *pcHeader
        funcnametab  []byte
        cutab        []uint32
        filetab      []byte
        pctab        []byte
        pclntable    []byte
        ftab         []functab
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        covctrs, ecovctrs     uintptr // Starts from 1.20
        end, gcdata, gcbss    uintptr
        types, etypes         uintptr
        rodata                uintptr               // Starts from 1.18
        gofunc                uintptr // go.func.*  // Starts from 1.18

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

    type pcHeader struct {     // Go version 1.16+
        magic          uint32  // 0xFFFFFFFA
        pad1, pad2     uint8   // 0, 0
        minLC          uint8   // min instruction size
        ptrSize        uint8   // size of a ptr in bytes
        nfunc          int     // number of functions in the module
        nfiles         uint    // number of entries in the file tab.
        funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
        cuOffset       uintptr // offset to the cutab variable from pcHeader
        filetabOffset  uintptr // offset to the filetab variable from pcHeader
        pctabOffset    uintptr // offset to the pctab varible from pcHeader
        pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    }

    // pcHeader holds data used by the pclntab lookups.
    type pcHeader struct {     // Go version 1.18+
        magic          uint32  // 0xFFFFFFF0
        pad1, pad2     uint8   // 0, 0
        minLC          uint8   // min instruction size
        ptrSize        uint8   // size of a ptr in bytes
        nfunc          int     // number of functions in the module
        nfiles         uint    // number of entries in the file tab
        textStart      uintptr // base for function entry PC offsets in this module, equal to moduledata.text
        funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
        cuOffset       uintptr // offset to the cutab variable from pcHeader
        filetabOffset  uintptr // offset to the filetab variable from pcHeader
        pctabOffset    uintptr // offset to the pctab variable from pcHeader
        pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    }
    '''
    def __init__(self, start_addr, magic_number):
        self.start_addr      = start_addr
        self.magic_number    = magic_number
        self.pcheader_addr   = idc.BADADDR  # Starts from version 1.16
        self.pclntbl_addr    = idc.BADADDR
        self.pclntbl_sz      = 0
        self.pclntbl_cap     = 0
        self.ftab_addr       = idc.BADADDR
        self.func_sz         = 0
        self.ftab_cap        = 0
        self.filetab_addr    = idc.BADADDR
        self.srcfile_sz      = 0
        self.srcfile_tab_cap = 0
        self.findfunctab     = idc.BADADDR
        self.min_pc          = idc.BADADDR
        self.max_pc          = idc.BADADDR
        self.text_addr       = idc.BADADDR
        self.etext_addr      = idc.BADADDR
        self.noptrdata_addr  = idc.BADADDR
        self.enoptrdata_addr = idc.BADADDR
        self.data_addr       = idc.BADADDR
        self.edata_addr      = idc.BADADDR
        self.bss_addr        = idc.BADADDR
        self.ebss_addr       = idc.BADADDR
        self.noptrbss_addr   = idc.BADADDR
        self.enoptrbss_addr  = idc.BADADDR
        self.end_addr        = idc.BADADDR
        self.gcdata_addr     = idc.BADADDR
        self.gcbss_addr      = idc.BADADDR
        self.types_addr      = idc.BADADDR
        self.etypes_addr     = idc.BADADDR
        self.textsecmap_addr = idc.BADADDR
        self.textsecmap_len  = 0
        self.textsecmap_cap  = 0
        self.typelink_addr   = idc.BADADDR
        self.type_cnt        = 0
        self.type_cap        = 0
        self.itablink_addr   = idc.BADADDR
        self.itab_cnt         = 0
        self.itab_cap        = 0
        self.ptab_addr       = idc.BADADDR
        self.ptab_sz         = 0
        self.ptab_cap        = 0
        self.pluginpath      = ""
        self.modulename      = ""
        self.hasmain         = False
        self.next            = idc.BADADDR

        # Go 1.16 +
        self.funcnametab_addr = idc.BADADDR
        self.funcnametab_sz   = 0
        self.funcnametab_cap  = 0
        self.cutab_addr       = idc.BADADDR
        self.cutab_sz         = 0
        self.cutab_cap        = 0
        self.pctab_addr       = idc.BADADDR
        self.pctab_sz         = 0
        self.pctab_cap        = 0
        # Go 1.18+
        self.rodata_addr      = idc.BADADDR
        self.gofunc_addr      = idc.BADADDR


    def parse(self, is_test=False):
        if is_test:
            common._info(f"Test firstmoduledata addr: {self.start_addr:#x}")

        if self.magic_number == common.MAGIC_112:
            self.pclntbl_addr    = read_mem(self.start_addr, read_only=is_test)
            self.pclntbl_sz      = read_mem(self.start_addr + ADDR_SZ, read_only=is_test)
            self.pclntbl_cap     = read_mem(self.start_addr + 2*ADDR_SZ, read_only=is_test)
            self.ftab_addr       = read_mem(self.start_addr + 3*ADDR_SZ, read_only=is_test)
            self.func_sz         = read_mem(self.start_addr + 4*ADDR_SZ, read_only=is_test)
            self.ftab_cap        = read_mem(self.start_addr + 5*ADDR_SZ, read_only=is_test)
            self.filetab_addr    = read_mem(self.start_addr + 6*ADDR_SZ, read_only=is_test)
            self.srcfile_sz      = read_mem(self.start_addr + 7*ADDR_SZ, read_only=is_test)
            self.srcfile_tab_cap = read_mem(self.start_addr + 8*ADDR_SZ, read_only=is_test)
            self.findfunctab     = read_mem(self.start_addr + 9*ADDR_SZ, read_only=is_test)
            self.min_pc          = read_mem(self.start_addr + 10*ADDR_SZ, read_only=is_test)
            self.max_pc          = read_mem(self.start_addr + 11*ADDR_SZ, read_only=is_test)
            self.text_addr       = read_mem(self.start_addr + 12*ADDR_SZ, read_only=is_test)
            self.etext_addr      = read_mem(self.start_addr + 13*ADDR_SZ, read_only=is_test)
        else:
            self.pcheader_addr    = read_mem(self.start_addr, read_only=is_test)
            self.funcnametab_addr = read_mem(self.start_addr + ADDR_SZ, read_only=is_test)
            self.funcnametab_sz   = read_mem(self.start_addr + 2*ADDR_SZ, read_only=is_test)
            self.funcnametab_cap  = read_mem(self.start_addr + 3*ADDR_SZ, read_only=is_test)
            self.cutab_addr       = read_mem(self.start_addr + 4*ADDR_SZ, read_only=is_test)
            self.cutab_sz         = read_mem(self.start_addr + 5*ADDR_SZ, read_only=is_test)
            self.cutab_cap        = read_mem(self.start_addr + 6*ADDR_SZ, read_only=is_test)
            self.filetab_addr     = read_mem(self.start_addr + 7*ADDR_SZ, read_only=is_test)
            self.srcfile_sz       = read_mem(self.start_addr + 8*ADDR_SZ, read_only=is_test)
            self.srcfile_tab_cap  = read_mem(self.start_addr + 9*ADDR_SZ, read_only=is_test)
            self.pctab_addr       = read_mem(self.start_addr + 10*ADDR_SZ, read_only=is_test)
            self.pctab_sz         = read_mem(self.start_addr + 11*ADDR_SZ, read_only=is_test)
            self.pctab_cap        = read_mem(self.start_addr + 12*ADDR_SZ, read_only=is_test)
            self.pclntbl_addr     = read_mem(self.start_addr + 13*ADDR_SZ, read_only=is_test)
            self.pclntbl_sz       = read_mem(self.start_addr + 14*ADDR_SZ, read_only=is_test)
            self.pclntbl_cap      = read_mem(self.start_addr + 15*ADDR_SZ, read_only=is_test)
            self.ftab_addr        = read_mem(self.start_addr + 16*ADDR_SZ, read_only=is_test)
            self.func_sz          = read_mem(self.start_addr + 17*ADDR_SZ, read_only=is_test)
            self.ftab_cap         = read_mem(self.start_addr + 18*ADDR_SZ, read_only=is_test)
            self.findfunctab      = read_mem(self.start_addr + 19*ADDR_SZ, read_only=is_test)
            self.min_pc           = read_mem(self.start_addr + 20*ADDR_SZ, read_only=is_test)
            self.max_pc           = read_mem(self.start_addr + 21*ADDR_SZ, read_only=is_test)
            self.text_addr        = read_mem(self.start_addr + 22*ADDR_SZ, read_only=is_test)
            self.etext_addr       = read_mem(self.start_addr + 23*ADDR_SZ, read_only=is_test)

        if is_test: return

        # Set comment for firstmoduledata struct object
        idc.set_name(self.start_addr, "runtime.firstmoduledata", flags=idaapi.SN_FORCE)
        idaapi.auto_wait()

        if self.magic_number == common.MAGIC_112:
            self.noptrdata_addr  = read_mem(self.start_addr + 14*ADDR_SZ, read_only=is_test)
            self.enoptrdata_addr = read_mem(self.start_addr + 15*ADDR_SZ, read_only=is_test)
            self.data_addr       = read_mem(self.start_addr + 16*ADDR_SZ, read_only=is_test)
            self.edata_addr      = read_mem(self.start_addr + 17*ADDR_SZ, read_only=is_test)
            self.bss_addr        = read_mem(self.start_addr + 18*ADDR_SZ, read_only=is_test)
            self.ebss_addr       = read_mem(self.start_addr + 19*ADDR_SZ, read_only=is_test)
            self.noptrbss_addr   = read_mem(self.start_addr + 20*ADDR_SZ, read_only=is_test)
            self.enoptrbss_addr  = read_mem(self.start_addr + 21*ADDR_SZ, read_only=is_test)
            self.end_addr        = read_mem(self.start_addr + 22*ADDR_SZ, read_only=is_test)
            self.gcdata_addr     = read_mem(self.start_addr + 23*ADDR_SZ, read_only=is_test)
            self.gcbss_addr      = read_mem(self.start_addr + 24*ADDR_SZ, read_only=is_test)
            self.types_addr      = read_mem(self.start_addr + 25*ADDR_SZ, read_only=is_test)
            self.etypes_addr     = read_mem(self.start_addr + 26*ADDR_SZ, read_only=is_test)
            self.textsecmap_addr = read_mem(self.start_addr + 27*ADDR_SZ, read_only=is_test)
            self.textsecmap_len  = read_mem(self.start_addr + 28*ADDR_SZ, read_only=is_test)
            self.textsecmap_cap  = read_mem(self.start_addr + 29*ADDR_SZ, read_only=is_test)
            self.typelink_addr   = read_mem(self.start_addr + 30*ADDR_SZ, read_only=is_test)
            self.type_cnt        = read_mem(self.start_addr + 31*ADDR_SZ, read_only=is_test)
            self.type_cap        = read_mem(self.start_addr + 32*ADDR_SZ, read_only=is_test)
            self.itablink_addr   = read_mem(self.start_addr + 33*ADDR_SZ, read_only=is_test)
            self.itab_cnt        = read_mem(self.start_addr + 34*ADDR_SZ, read_only=is_test)
            self.itab_cap        = read_mem(self.start_addr + 35*ADDR_SZ, read_only=is_test)
            self.ptab_addr       = read_mem(self.start_addr + 36*ADDR_SZ, read_only=is_test)
            self.ptab_sz         = read_mem(self.start_addr + 37*ADDR_SZ, read_only=is_test)
            self.ptab_cap        = read_mem(self.start_addr + 38*ADDR_SZ, read_only=is_test)

            pluginpath_addr = read_mem(self.start_addr + 39*ADDR_SZ, read_only=is_test)
            pluginpath_len  = read_mem(self.start_addr + 40*ADDR_SZ, read_only=is_test)
            self.pluginpath = "" if (pluginpath_len==0x0 or pluginpath_addr ==0x0) else \
                idc.get_bytes(pluginpath_addr, pluginpath_len).decode()

            modulename_addr = read_mem(self.start_addr+44*ADDR_SZ, read_only=is_test)
            modulename_len  = read_mem(self.start_addr+45*ADDR_SZ, read_only=is_test)
            self.modulename ="" if modulename_addr == 0x0 or modulename_len == 0 else \
                idc.get_bytes(modulename_addr, modulename_len).decode()

            self.hasmain = idc.get_wide_byte(self.start_addr + 49*ADDR_SZ)
            self.next    = read_mem(self.start_addr + 54*ADDR_SZ+1, read_only=is_test)

            # Set comment for each field
            idc.set_cmt(self.start_addr, "pclntbl addr",0)
            idc.set_cmt(self.start_addr + ADDR_SZ, "pclntbl size",0)
            idc.set_cmt(self.start_addr + 2*ADDR_SZ, "pclntbl capacity",0)
            idc.set_cmt(self.start_addr + 3*ADDR_SZ, "funcs table addr",0)
            idc.set_cmt(self.start_addr + 4*ADDR_SZ, "funcs count",0)
            idc.set_cmt(self.start_addr + 5*ADDR_SZ, "funcs table capacity",0)
            idc.set_cmt(self.start_addr + 6*ADDR_SZ, "source files table addr",0)
            idc.set_cmt(self.start_addr + 7*ADDR_SZ, "source files count",0)
            idc.set_cmt(self.start_addr + 8*ADDR_SZ, "source files table capacity",0)
            idc.set_cmt(self.start_addr + 9*ADDR_SZ, "findfunctable addr",0)
            idc.set_cmt(self.start_addr + 10*ADDR_SZ, "min pc",0)
            idc.set_cmt(self.start_addr + 11*ADDR_SZ, "max pc",0)
            idc.set_cmt(self.start_addr + 12*ADDR_SZ, "text start addr",0)
            idc.set_cmt(self.start_addr + 13*ADDR_SZ, "text end addr",0)
            idc.set_cmt(self.start_addr + 14*ADDR_SZ, "noptrdata start addr",0)
            idc.set_cmt(self.start_addr + 15*ADDR_SZ, "noptrdata end addr",0)
            idc.set_cmt(self.start_addr + 16*ADDR_SZ, "data section start addr",0)
            idc.set_cmt(self.start_addr + 17*ADDR_SZ, "data section end addr",0)
            idc.set_cmt(self.start_addr + 18*ADDR_SZ, "bss start addr",0)
            idc.set_cmt(self.start_addr + 19*ADDR_SZ, "bss end addr",0)
            idc.set_cmt(self.start_addr + 20*ADDR_SZ, "noptrbss start addr",0)
            idc.set_cmt(self.start_addr + 21*ADDR_SZ, "noptrbss end addr",0)
            idc.set_cmt(self.start_addr + 22*ADDR_SZ, "end addr of whole image",0)
            idc.set_cmt(self.start_addr + 23*ADDR_SZ, "gcdata addr",0)
            idc.set_cmt(self.start_addr + 24*ADDR_SZ, "gcbss addr",0)
            idc.set_cmt(self.start_addr + 25*ADDR_SZ, "types start addr",0)
            idc.set_cmt(self.start_addr + 26*ADDR_SZ, "types end addr",0)
            idc.set_cmt(self.start_addr + 27*ADDR_SZ, "text section map addr",0)
            idc.set_cmt(self.start_addr + 28*ADDR_SZ, "text section map length",0)
            idc.set_cmt(self.start_addr + 29*ADDR_SZ, "text section map capacity",0)
            idc.set_cmt(self.start_addr + 30*ADDR_SZ, "typelink addr",0)
            idc.set_cmt(self.start_addr + 31*ADDR_SZ, "types count",0)
            idc.set_cmt(self.start_addr + 32*ADDR_SZ, "types table capacity",0)
            idc.set_cmt(self.start_addr + 33*ADDR_SZ, "itabslink addr",0)
            idc.set_cmt(self.start_addr + 34*ADDR_SZ, "itabs count",0)
            idc.set_cmt(self.start_addr + 35*ADDR_SZ, "itabs caapacity",0)
            idc.set_cmt(self.start_addr + 36*ADDR_SZ, "ptab addr",0)
            idc.set_cmt(self.start_addr + 37*ADDR_SZ, "ptab count",0)
            idc.set_cmt(self.start_addr + 38*ADDR_SZ, "ptab capacity",0)
            idc.set_cmt(self.start_addr + 39*ADDR_SZ, "plugin path addr",0)
            idc.set_cmt(self.start_addr + 40*ADDR_SZ, "plugin path length",0)
            idc.set_cmt(self.start_addr + 44*ADDR_SZ, "module name addr",0)
            idc.set_cmt(self.start_addr + 45*ADDR_SZ, "module name length",0)
            idc.set_cmt(self.start_addr + 49*ADDR_SZ, "hasmain flag",0)
            idc.set_cmt(self.start_addr + 54*ADDR_SZ+1, "next moduledata addr",0)

            idaapi.auto_wait()

            idc.create_strlit(modulename_addr, modulename_addr+modulename_len)
            idaapi.auto_wait()

            idc.create_strlit(pluginpath_addr, pluginpath_addr+pluginpath_len)
            idaapi.auto_wait()
        elif self.magic_number == common.MAGIC_116 or self.magic_number == common.MAGIC_118:
            self.noptrdata_addr  = read_mem(self.start_addr + 24*ADDR_SZ, read_only=is_test)
            self.enoptrdata_addr = read_mem(self.start_addr + 25*ADDR_SZ, read_only=is_test)
            self.data_addr       = read_mem(self.start_addr + 26*ADDR_SZ, read_only=is_test)
            self.edata_addr      = read_mem(self.start_addr + 27*ADDR_SZ, read_only=is_test)
            self.bss_addr        = read_mem(self.start_addr + 28*ADDR_SZ, read_only=is_test)
            self.ebss_addr       = read_mem(self.start_addr + 29*ADDR_SZ, read_only=is_test)
            self.noptrbss_addr   = read_mem(self.start_addr + 30*ADDR_SZ, read_only=is_test)
            self.enoptrbss_addr  = read_mem(self.start_addr + 31*ADDR_SZ, read_only=is_test)
            self.end_addr        = read_mem(self.start_addr + 32*ADDR_SZ, read_only=is_test)
            self.gcdata_addr     = read_mem(self.start_addr + 33*ADDR_SZ, read_only=is_test)
            self.gcbss_addr      = read_mem(self.start_addr + 34*ADDR_SZ, read_only=is_test)
            self.types_addr      = read_mem(self.start_addr + 35*ADDR_SZ, read_only=is_test)
            self.etypes_addr     = read_mem(self.start_addr + 36*ADDR_SZ, read_only=is_test)

            if self.magic_number == common.MAGIC_116: # Go 1.16+
                self.textsecmap_addr = read_mem(self.start_addr + 37*ADDR_SZ, read_only=is_test)
                self.textsecmap_len  = read_mem(self.start_addr + 38*ADDR_SZ, read_only=is_test)
                self.textsecmap_cap  = read_mem(self.start_addr + 39*ADDR_SZ, read_only=is_test)
                self.typelink_addr   = read_mem(self.start_addr + 40*ADDR_SZ, read_only=is_test)
                self.type_cnt        = read_mem(self.start_addr + 41*ADDR_SZ, read_only=is_test)
                self.type_cap        = read_mem(self.start_addr + 42*ADDR_SZ, read_only=is_test)
                self.itablink_addr   = read_mem(self.start_addr + 43*ADDR_SZ, read_only=is_test)
                self.itab_cnt        = read_mem(self.start_addr + 44*ADDR_SZ, read_only=is_test)
                self.itab_cap        = read_mem(self.start_addr + 45*ADDR_SZ, read_only=is_test)
                self.ptab_addr       = read_mem(self.start_addr + 46*ADDR_SZ, read_only=is_test)
                self.ptab_sz         = read_mem(self.start_addr + 47*ADDR_SZ, read_only=is_test)
                self.ptab_cap        = read_mem(self.start_addr + 48*ADDR_SZ, read_only=is_test)

                pluginpath_addr = read_mem(self.start_addr+49*ADDR_SZ, read_only=is_test)
                pluginpath_len  = read_mem(self.start_addr+50*ADDR_SZ, read_only=is_test)
                self.pluginpath = "" if (pluginpath_len==0x0 or pluginpath_addr ==0x0) else \
                    idc.get_bytes(pluginpath_addr, pluginpath_len).decode()

                modulename_addr = read_mem(self.start_addr+54*ADDR_SZ, read_only=is_test)
                modulename_len  = read_mem(self.start_addr+55*ADDR_SZ, read_only=is_test)
                self.modulename = "" if modulename_addr ==0x0 or modulename_len ==0 else \
                    idc.get_bytes(modulename_addr, modulename_len).decode()

                self.hasmain = idc.get_wide_byte(self.start_addr+59*ADDR_SZ)
                self.next    = read_mem(self.start_addr+64*ADDR_SZ+1, read_only=is_test)
            else: # Go 1.18+
                self.rodata_addr = read_mem(self.start_addr + 37*ADDR_SZ, read_only=is_test)
                self.gofunc_addr = read_mem(self.start_addr + 38*ADDR_SZ, read_only=is_test)

                self.textsecmap_addr = read_mem(self.start_addr + 39*ADDR_SZ, read_only=is_test)
                self.textsecmap_len  = read_mem(self.start_addr + 40*ADDR_SZ, read_only=is_test)
                self.textsecmap_cap  = read_mem(self.start_addr + 41*ADDR_SZ, read_only=is_test)
                self.typelink_addr   = read_mem(self.start_addr + 42*ADDR_SZ, read_only=is_test)
                self.type_cnt        = read_mem(self.start_addr + 43*ADDR_SZ, read_only=is_test)
                self.type_cap        = read_mem(self.start_addr + 44*ADDR_SZ, read_only=is_test)
                self.itablink_addr   = read_mem(self.start_addr + 45*ADDR_SZ, read_only=is_test)
                self.itab_cnt        = read_mem(self.start_addr + 46*ADDR_SZ, read_only=is_test)
                self.itab_cap        = read_mem(self.start_addr + 47*ADDR_SZ, read_only=is_test)
                self.ptab_addr       = read_mem(self.start_addr + 48*ADDR_SZ, read_only=is_test)
                self.ptab_sz         = read_mem(self.start_addr + 49*ADDR_SZ, read_only=is_test)
                self.ptab_cap        = read_mem(self.start_addr + 50*ADDR_SZ, read_only=is_test)

                pluginpath_addr = read_mem(self.start_addr + 51*ADDR_SZ, read_only=is_test)
                pluginpath_len  = read_mem(self.start_addr + 52*ADDR_SZ, read_only=is_test)
                self.pluginpath = "" if (pluginpath_len == 0x0 or pluginpath_addr == 0x0) else \
                    idc.get_bytes(pluginpath_addr, pluginpath_len).decode()

                modulename_addr = read_mem(self.start_addr + 56*ADDR_SZ, read_only=is_test)
                modulename_len  = read_mem(self.start_addr + 57*ADDR_SZ, read_only=is_test)
                self.modulename ="" if modulename_addr == 0x0 or modulename_len == 0x0 else \
                    idc.get_bytes(modulename_addr, modulename_len).decode()

                self.hasmain = idc.get_wide_byte(self.start_addr + 61*ADDR_SZ)
                self.next    = read_mem(self.start_addr + 66*ADDR_SZ+1, read_only=is_test)

            # Set comment for each field
            idc.set_cmt(self.start_addr, "pcHeader", 0)
            idc.set_cmt(self.start_addr + ADDR_SZ, "funcnametab addr", 0)
            idc.set_cmt(self.start_addr + 2*ADDR_SZ, "funcnametab size", 0)
            idc.set_cmt(self.start_addr + 3*ADDR_SZ, "funcnametab capacity", 0)
            idc.set_cmt(self.start_addr + 4*ADDR_SZ, "cutab addr", 0)
            idc.set_cmt(self.start_addr + 5*ADDR_SZ, "cutab count", 0)
            idc.set_cmt(self.start_addr + 6*ADDR_SZ, "cutab capacity", 0)
            idc.set_cmt(self.start_addr + 7*ADDR_SZ, "source files table addr",0)
            idc.set_cmt(self.start_addr + 8*ADDR_SZ, "source files count",0)
            idc.set_cmt(self.start_addr + 9*ADDR_SZ, "source files table capacity",0)
            idc.set_cmt(self.start_addr + 10*ADDR_SZ, "pc table addr", 0)
            idc.set_cmt(self.start_addr + 11*ADDR_SZ, "pc table size", 0)
            idc.set_cmt(self.start_addr + 12*ADDR_SZ, "pc table capacity", 0)
            idc.set_cmt(self.start_addr + 13*ADDR_SZ, "pclntbl addr",0)
            idc.set_cmt(self.start_addr + 14*ADDR_SZ, "pclntbl size",0)
            idc.set_cmt(self.start_addr + 15*ADDR_SZ, "pclntbl capacity",0)
            idc.set_cmt(self.start_addr + 16*ADDR_SZ, "funcs table addr",0)
            idc.set_cmt(self.start_addr + 17*ADDR_SZ, "funcs count",0)
            idc.set_cmt(self.start_addr + 18*ADDR_SZ, "funcs table capacity",0)
            idc.set_cmt(self.start_addr + 19*ADDR_SZ, "findfunctable addr",0)
            idc.set_cmt(self.start_addr + 20*ADDR_SZ, "min pc",0)
            idc.set_cmt(self.start_addr + 21*ADDR_SZ, "max pc",0)
            idc.set_cmt(self.start_addr + 22*ADDR_SZ, "text start addr",0)
            idc.set_cmt(self.start_addr + 23*ADDR_SZ, "text end addr",0)
            idc.set_cmt(self.start_addr + 24*ADDR_SZ, "noptrdata start addr",0)
            idc.set_cmt(self.start_addr + 25*ADDR_SZ, "noptrdata end addr",0)
            idc.set_cmt(self.start_addr + 26*ADDR_SZ, "data section start addr",0)
            idc.set_cmt(self.start_addr + 27*ADDR_SZ, "data section end addr",0)
            idc.set_cmt(self.start_addr + 28*ADDR_SZ, "bss start addr",0)
            idc.set_cmt(self.start_addr + 29*ADDR_SZ, "bss end addr",0)
            idc.set_cmt(self.start_addr + 30*ADDR_SZ, "noptrbss start addr",0)
            idc.set_cmt(self.start_addr + 31*ADDR_SZ, "noptrbss end addr",0)
            idc.set_cmt(self.start_addr + 32*ADDR_SZ, "end addr of whole image",0)
            idc.set_cmt(self.start_addr + 33*ADDR_SZ, "gcdata addr",0)
            idc.set_cmt(self.start_addr + 34*ADDR_SZ, "gcbss addr",0)
            idc.set_cmt(self.start_addr + 35*ADDR_SZ, "types start addr",0)
            idc.set_cmt(self.start_addr + 36*ADDR_SZ, "types end addr",0)
            if self.magic_number == common.MAGIC_116: # Go 1.16+
                idc.set_cmt(self.start_addr + 37*ADDR_SZ, "text section map addr",0)
                idc.set_cmt(self.start_addr + 38*ADDR_SZ, "text section map length",0)
                idc.set_cmt(self.start_addr + 39*ADDR_SZ, "text section map capacity",0)
                idc.set_cmt(self.start_addr + 40*ADDR_SZ, "typelink addr",0)
                idc.set_cmt(self.start_addr + 41*ADDR_SZ, "types count",0)
                idc.set_cmt(self.start_addr + 42*ADDR_SZ, "types table capacity",0)
                idc.set_cmt(self.start_addr + 43*ADDR_SZ, "itabslink addr",0)
                idc.set_cmt(self.start_addr + 44*ADDR_SZ, "itabs count",0)
                idc.set_cmt(self.start_addr + 45*ADDR_SZ, "itabs caapacity",0)
                idc.set_cmt(self.start_addr + 46*ADDR_SZ, "ptab addr",0)
                idc.set_cmt(self.start_addr + 47*ADDR_SZ, "ptab count",0)
                idc.set_cmt(self.start_addr + 48*ADDR_SZ, "ptab capacity",0)
                idc.set_cmt(self.start_addr + 49*ADDR_SZ, "plugin path addr",0)
                idc.set_cmt(self.start_addr + 50*ADDR_SZ, "plugin path length",0)
                idc.set_cmt(self.start_addr + 54*ADDR_SZ, "module name addr",0)
                idc.set_cmt(self.start_addr + 55*ADDR_SZ, "module name length",0)
                idc.set_cmt(self.start_addr + 59*ADDR_SZ, "hasmain flag",0)
                idc.set_cmt(self.start_addr + 64*ADDR_SZ+1, "next moduledata addr",0)
            else:
                idc.set_cmt(self.start_addr + 37*ADDR_SZ, "rodata addr",0)
                idc.set_cmt(self.start_addr + 38*ADDR_SZ, "go func pointer addr",0)
                idc.set_cmt(self.start_addr + 39*ADDR_SZ, "text section map addr",0)
                idc.set_cmt(self.start_addr + 40*ADDR_SZ, "text section map length",0)
                idc.set_cmt(self.start_addr + 41*ADDR_SZ, "text section map capacity",0)
                idc.set_cmt(self.start_addr + 42*ADDR_SZ, "typelink addr",0)
                idc.set_cmt(self.start_addr + 43*ADDR_SZ, "types count",0)
                idc.set_cmt(self.start_addr + 44*ADDR_SZ, "types table capacity",0)
                idc.set_cmt(self.start_addr + 45*ADDR_SZ, "itabslink addr",0)
                idc.set_cmt(self.start_addr + 46*ADDR_SZ, "itabs count",0)
                idc.set_cmt(self.start_addr + 47*ADDR_SZ, "itabs caapacity",0)
                idc.set_cmt(self.start_addr + 48*ADDR_SZ, "ptab addr",0)
                idc.set_cmt(self.start_addr + 49*ADDR_SZ, "ptab count",0)
                idc.set_cmt(self.start_addr + 50*ADDR_SZ, "ptab capacity",0)
                idc.set_cmt(self.start_addr + 51*ADDR_SZ, "plugin path addr",0)
                idc.set_cmt(self.start_addr + 52*ADDR_SZ, "plugin path length",0)
                idc.set_cmt(self.start_addr + 56*ADDR_SZ, "module name addr",0)
                idc.set_cmt(self.start_addr + 57*ADDR_SZ, "module name length",0)
                idc.set_cmt(self.start_addr + 61*ADDR_SZ, "hasmain flag",0)
                idc.set_cmt(self.start_addr + 66*ADDR_SZ+1, "next moduledata addr",0)

            idaapi.auto_wait()

            idc.create_strlit(modulename_addr, modulename_addr+modulename_len)
            idaapi.auto_wait()

            idc.create_strlit(pluginpath_addr, pluginpath_addr+pluginpath_len)
            idaapi.auto_wait()
        else: # MAGIC_120
            self.noptrdata_addr  = read_mem(self.start_addr + 24*ADDR_SZ, read_only=is_test)
            self.enoptrdata_addr = read_mem(self.start_addr + 25*ADDR_SZ, read_only=is_test)
            self.data_addr       = read_mem(self.start_addr + 26*ADDR_SZ, read_only=is_test)
            self.edata_addr      = read_mem(self.start_addr + 27*ADDR_SZ, read_only=is_test)
            self.bss_addr        = read_mem(self.start_addr + 28*ADDR_SZ, read_only=is_test)
            self.ebss_addr       = read_mem(self.start_addr + 29*ADDR_SZ, read_only=is_test)
            self.noptrbss_addr   = read_mem(self.start_addr + 30*ADDR_SZ, read_only=is_test)
            self.enoptrbss_addr  = read_mem(self.start_addr + 31*ADDR_SZ, read_only=is_test)
            self.covctrs_addr    = read_mem(self.start_addr + 32*ADDR_SZ, read_only=is_test)
            self.ecovctrs_addr   = read_mem(self.start_addr + 33*ADDR_SZ, read_only=is_test)
            self.end_addr        = read_mem(self.start_addr + 34*ADDR_SZ, read_only=is_test)
            self.gcdata_addr     = read_mem(self.start_addr + 35*ADDR_SZ, read_only=is_test)
            self.gcbss_addr      = read_mem(self.start_addr + 36*ADDR_SZ, read_only=is_test)
            self.types_addr      = read_mem(self.start_addr + 37*ADDR_SZ, read_only=is_test)
            self.etypes_addr     = read_mem(self.start_addr + 38*ADDR_SZ, read_only=is_test)
            self.rodata_addr     = read_mem(self.start_addr + 39*ADDR_SZ, read_only=is_test)
            self.gofunc_addr     = read_mem(self.start_addr + 40*ADDR_SZ, read_only=is_test)
            self.textsecmap_addr = read_mem(self.start_addr + 41*ADDR_SZ, read_only=is_test)
            self.textsecmap_len  = read_mem(self.start_addr + 42*ADDR_SZ, read_only=is_test)
            self.textsecmap_cap  = read_mem(self.start_addr + 43*ADDR_SZ, read_only=is_test)
            self.typelink_addr   = read_mem(self.start_addr + 44*ADDR_SZ, read_only=is_test)
            self.type_cnt        = read_mem(self.start_addr + 45*ADDR_SZ, read_only=is_test)
            self.type_cap        = read_mem(self.start_addr + 46*ADDR_SZ, read_only=is_test)
            self.itablink_addr   = read_mem(self.start_addr + 47*ADDR_SZ, read_only=is_test)
            self.itab_cnt        = read_mem(self.start_addr + 48*ADDR_SZ, read_only=is_test)
            self.itab_cap        = read_mem(self.start_addr + 49*ADDR_SZ, read_only=is_test)
            self.ptab_addr       = read_mem(self.start_addr + 50*ADDR_SZ, read_only=is_test)
            self.ptab_sz         = read_mem(self.start_addr + 51*ADDR_SZ, read_only=is_test)
            self.ptab_cap        = read_mem(self.start_addr + 52*ADDR_SZ, read_only=is_test)

            pluginpath_addr = read_mem(self.start_addr + 53*ADDR_SZ, read_only=is_test)
            pluginpath_len  = read_mem(self.start_addr + 54*ADDR_SZ, read_only=is_test)
            self.pluginpath = "" if (pluginpath_len == 0x0 or pluginpath_addr == 0x0) else \
                idc.get_bytes(pluginpath_addr, pluginpath_len).decode("utf-8", errors="ignore")

            modulename_addr = read_mem(self.start_addr + 58*ADDR_SZ, read_only=is_test)
            modulename_len  = read_mem(self.start_addr + 59*ADDR_SZ, read_only=is_test)
            self.modulename ="" if modulename_addr == 0x0 or modulename_len == 0x0 else \
                idc.get_bytes(modulename_addr, modulename_len).decode("utf-8", errors="ignore")

            self.hasmain = idc.get_wide_byte(self.start_addr + 63*ADDR_SZ)
            self.next    = read_mem(self.start_addr + 69*ADDR_SZ+1, read_only=is_test)

            # Set comment for each field
            idc.set_cmt(self.start_addr, "pcHeader", 0)
            idc.set_cmt(self.start_addr + ADDR_SZ, "funcnametab addr", 0)
            idc.set_cmt(self.start_addr + 2*ADDR_SZ, "funcnametab size", 0)
            idc.set_cmt(self.start_addr + 3*ADDR_SZ, "funcnametab capacity", 0)
            idc.set_cmt(self.start_addr + 4*ADDR_SZ, "cutab addr", 0)
            idc.set_cmt(self.start_addr + 5*ADDR_SZ, "cutab count", 0)
            idc.set_cmt(self.start_addr + 6*ADDR_SZ, "cutab capacity", 0)
            idc.set_cmt(self.start_addr + 7*ADDR_SZ, "source files table addr",0)
            idc.set_cmt(self.start_addr + 8*ADDR_SZ, "source files count",0)
            idc.set_cmt(self.start_addr + 9*ADDR_SZ, "source files table capacity",0)
            idc.set_cmt(self.start_addr + 10*ADDR_SZ, "pc table addr", 0)
            idc.set_cmt(self.start_addr + 11*ADDR_SZ, "pc table size", 0)
            idc.set_cmt(self.start_addr + 12*ADDR_SZ, "pc table capacity", 0)
            idc.set_cmt(self.start_addr + 13*ADDR_SZ, "pclntbl addr",0)
            idc.set_cmt(self.start_addr + 14*ADDR_SZ, "pclntbl size",0)
            idc.set_cmt(self.start_addr + 15*ADDR_SZ, "pclntbl capacity",0)
            idc.set_cmt(self.start_addr + 16*ADDR_SZ, "funcs table addr",0)
            idc.set_cmt(self.start_addr + 17*ADDR_SZ, "funcs count",0)
            idc.set_cmt(self.start_addr + 18*ADDR_SZ, "funcs table capacity",0)
            idc.set_cmt(self.start_addr + 19*ADDR_SZ, "findfunctable addr",0)
            idc.set_cmt(self.start_addr + 20*ADDR_SZ, "min pc",0)
            idc.set_cmt(self.start_addr + 21*ADDR_SZ, "max pc",0)
            idc.set_cmt(self.start_addr + 22*ADDR_SZ, "text start addr",0)
            idc.set_cmt(self.start_addr + 23*ADDR_SZ, "text end addr",0)
            idc.set_cmt(self.start_addr + 24*ADDR_SZ, "noptrdata start addr",0)
            idc.set_cmt(self.start_addr + 25*ADDR_SZ, "noptrdata end addr",0)
            idc.set_cmt(self.start_addr + 26*ADDR_SZ, "data section start addr",0)
            idc.set_cmt(self.start_addr + 27*ADDR_SZ, "data section end addr",0)
            idc.set_cmt(self.start_addr + 28*ADDR_SZ, "bss start addr",0)
            idc.set_cmt(self.start_addr + 29*ADDR_SZ, "bss end addr",0)
            idc.set_cmt(self.start_addr + 30*ADDR_SZ, "noptrbss start addr",0)
            idc.set_cmt(self.start_addr + 31*ADDR_SZ, "noptrbss end addr",0)
            idc.set_cmt(self.start_addr + 32*ADDR_SZ, "code coverage counters start addr",0)
            idc.set_cmt(self.start_addr + 33*ADDR_SZ, "code coverage counters end addr",0)
            idc.set_cmt(self.start_addr + 34*ADDR_SZ, "end addr of whole image",0)
            idc.set_cmt(self.start_addr + 35*ADDR_SZ, "gcdata addr",0)
            idc.set_cmt(self.start_addr + 36*ADDR_SZ, "gcbss addr",0)
            idc.set_cmt(self.start_addr + 37*ADDR_SZ, "types start addr",0)
            idc.set_cmt(self.start_addr + 38*ADDR_SZ, "types end addr",0)
            idc.set_cmt(self.start_addr + 39*ADDR_SZ, "rodata addr",0)
            idc.set_cmt(self.start_addr + 40*ADDR_SZ, "go func pointer addr",0)
            idc.set_cmt(self.start_addr + 41*ADDR_SZ, "text section map addr",0)
            idc.set_cmt(self.start_addr + 42*ADDR_SZ, "text section map length",0)
            idc.set_cmt(self.start_addr + 43*ADDR_SZ, "text section map capacity",0)
            idc.set_cmt(self.start_addr + 44*ADDR_SZ, "typelink addr",0)
            idc.set_cmt(self.start_addr + 45*ADDR_SZ, "types count",0)
            idc.set_cmt(self.start_addr + 46*ADDR_SZ, "types table capacity",0)
            idc.set_cmt(self.start_addr + 47*ADDR_SZ, "itabslink addr",0)
            idc.set_cmt(self.start_addr + 48*ADDR_SZ, "itabs count",0)
            idc.set_cmt(self.start_addr + 49*ADDR_SZ, "itabs caapacity",0)
            idc.set_cmt(self.start_addr + 50*ADDR_SZ, "ptab addr",0)
            idc.set_cmt(self.start_addr + 51*ADDR_SZ, "ptab count",0)
            idc.set_cmt(self.start_addr + 52*ADDR_SZ, "ptab capacity",0)
            idc.set_cmt(self.start_addr + 53*ADDR_SZ, "plugin path addr",0)
            idc.set_cmt(self.start_addr + 54*ADDR_SZ, "plugin path length",0)
            idc.set_cmt(self.start_addr + 55*ADDR_SZ, "module name addr",0)
            idc.set_cmt(self.start_addr + 56*ADDR_SZ, "module name length",0)
            idc.set_cmt(self.start_addr + 63*ADDR_SZ, "hasmain flag",0)
            idc.set_cmt(self.start_addr + 69*ADDR_SZ+1, "next moduledata addr",0)

            idaapi.auto_wait()

            idc.create_strlit(modulename_addr, modulename_addr+modulename_len)
            idaapi.auto_wait()

            idc.create_strlit(pluginpath_addr, pluginpath_addr+pluginpath_len)
            idaapi.auto_wait()
