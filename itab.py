#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi
import common

class ItabElem():
    '''
    Interface table
    Refer: https://golang.org/src/runtime/runtime2.go

    type itab struct {
        inter *interfacetype
        _type *_type
        hash  uint32 // copy of _type.hash. Used for type switches.
        _     [4]byte
        fun   [1]uintptr // variable sized. fun[0]==0 means _type does not implement inter.
    }
    '''
    def __init__(self, addr, type_parser):
        self.addr = addr
        self.type_parser = type_parser
        self.itype = None
        self.rtype = None
        self.hash = 0
        self.methods = list()
        self.meth_num = 0

    def parse(self):
        itype_addr = common.read_mem(self.addr) & 0xFFFFFFFFFFFFFFFF
        self.itype = self.type_parser.parse_type(type_addr=itype_addr)

        rtype_addr = common.read_mem(self.addr+common.ADDR_SZ) & 0xFFFFFFFFFFFFFFFF
        self.rtype = self.type_parser.parse_type(type_addr=rtype_addr)

        self.hash = common.read_mem(self.addr + 2*common.ADDR_SZ, forced_addr_sz=4) & 0xFFFFFFFF

        # methods start addr(if has method)
        curr_addr = self.addr + 3*common.ADDR_SZ
        while True:
            if len(idaapi.get_ea_name(curr_addr)) > 0:
                # stop at next itab_elem addr
                # next itab elem is labeled a head name by ida pro
                break

            meth_addr = common.read_mem(curr_addr)
            if idaapi.get_func(meth_addr):
                meth_name = idaapi.get_ea_name(meth_addr)
                self.methods.append(meth_name)
                self.meth_num += 1

            curr_addr += common.ADDR_SZ

        idc.MakeComm(self.addr, "interface: %s" % self.itype.name)
        idc.MakeComm(self.addr+common.ADDR_SZ, "rtype: %s" % self.rtype.name)
        idc.MakeComm(self.addr+2*common.ADDR_SZ, "rtype hash")
        idaapi.autoWait()

        itab_elem_name = "go_itab__%s_%s" % (self.rtype.name_obj.name_str, self.itype.name)
        idc.MakeNameEx(self.addr, itab_elem_name,flags=idaapi.SN_FORCE)
        common._debug("Go itab %s(@ 0x%x) parsed." % (itab_elem_name, self.addr))
        idaapi.autoWait()

def parse_itab(moddata, type_parser):
    common._info("Start to parse Itab")
    itab_addr = idc.BADADDR
    itab_end_addr = idc.BADADDR
    itab_num = 0
    # comfirm Itab's start_addr and end_addr
    if moddata == None:
        itab_seg = common.get_seg([".itablink", "__itablink"])
        if itab_seg:
            itab_addr = itab_seg.start_ea
            itab_end_addr = itab_seg.end_ea
            itab_num = (itab_end_addr - itab_addr) / common.ADDR_SZ
    else:
        itab_addr = moddata.itablink_addr
        itab_num = moddata.itab_num
        itab_end_addr = itab_addr + itab_num * common.ADDR_SZ

    curr_addr = itab_addr
    while curr_addr < itab_end_addr:
        curr_itabelem_addr = common.read_mem(curr_addr)
        itab_elem = ItabElem(curr_itabelem_addr, type_parser)
        itab_elem.parse()
        itab_num += 1
        curr_addr += common.ADDR_SZ

    common._info("Itab parsing done, total number: %d" % itab_num)    
