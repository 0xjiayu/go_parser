#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils
import string

DEBUG = False
ADDR_SZ = 4 # Default: 32-bit
GOVER = ""

if idaapi.get_inf_structure().is_64bit():
    ADDR_SZ = 8

def _info(info_str):
    print(info_str)

def _error(err_str):
    print('[ERROR] - %s' % err_str)

def _debug(dbg_str):
    global DEBUG
    if DEBUG:
        print('[DEBUG] - %s' % dbg_str)

def get_seg(seg_names):
    seg = None
    for seg_name in seg_names:
        seg = idaapi.get_segm_by_name(seg_name)
        if seg:
            return seg

    return seg

def get_seg_start_addr_from_rdata(seg_names):
    for seg_name in seg_names:
        for ea, name in idautils.Names():
            if name == seg_name:
                return ea

    return None

def get_text_seg():
    # .text found in PE & ELF binaries, __text found in macho binaries
    return get_seg(['.text', '__text'])

def find_func_by_name(func_name):
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.SegEnd(segea)):
            if func_name == idaapi.get_func_name(funcea):
                return idaapi.get_func(funcea)
    return None

def read_mem(addr, forced_addr_sz=None, read_only=False):
    global ADDR_SZ

    if not read_only:
        if forced_addr_sz:
            idc.MakeUnknown(addr, forced_addr_sz, idc.DOUNK_SIMPLE)
        else:
            idc.MakeUnknown(addr, ADDR_SZ, idc.DOUNK_SIMPLE)
        idaapi.autoWait()

    if forced_addr_sz == 2:
        if not read_only:
            idc.MakeWord(addr)
            idaapi.autoWait()
        return idc.Word(addr)
    if forced_addr_sz == 4 or ADDR_SZ == 4:
        if not read_only:
            idc.MakeDword(addr)
            idaapi.autoWait()
        return idc.Dword(addr)
    if forced_addr_sz == 8 or ADDR_SZ == 8:
        if not read_only:
            idc.MakeQword(addr)
            idaapi.autoWait()
        return idc.Qword(addr)

def get_goroot():
    goroot_path_str = ""
    '''
    Get GOROOT path string
    '''
    func_goroot = find_func_by_name("runtime_GOROOT")
    if func_goroot is None:
        _error("Failed to find func contains goroot")
        return goroot_path_str

    goroot_flowchart = idaapi.FlowChart(f=func_goroot)
    ret_cbs = find_ret_cb(goroot_flowchart)
    '''
    runtime.GOROOT() normally has 2 return code blocks:
    1. False return
        mov     [rsp+28h+arg_0], rax
        mov     [rsp+28h+arg_8], rcx
        mov     rbp, [rsp+28h+var_8]
        add     rsp, 28h
        retn

    2. True return(Which we needed):

        (1). goroot string length as ptr
        mov     rax, cs:runtime_internal_sys_DefaultGoroot
        mov     rcx, cs:qword_D9AB58
        mov     [rsp+28h+arg_0], rax
        mov     [rsp+28h+arg_8], rcx
        mov     rbp, [rsp+28h+var_8]
        add     rsp, 28h
        retn

        (2). goroot string length as instant number
        lea     rax, unk_7220B5
        mov     [rsp+28h+arg_0], rax
        mov     [rsp+28h+arg_8], 0Dh
        mov     rbp, [rsp+28h+var_8]
        add     rsp, 28h
        retn
    '''
    for cb_idx in ret_cbs:
        if idc.GetOpType(goroot_flowchart[cb_idx].startEA, 0) == 1:
            # e.g.: mov     rax, cs:runtime_internal_sys_DefaultGoroot
            '''
            Op Types refer: https://www.hex-rays.com/products/ida/support/sdkdoc/ua_8hpp.html#aaf9da6ae7e8b201108fc225adf13b4d9
                o_void  =      0  # No Operand               
                o_reg  =       1  # General Register (al,ax,es,ds...)    reg
                o_mem  =       2  # Direct Memory Reference  (DATA)      addr
                o_phrase  =    3  # Memory Ref [Base Reg + Index Reg]    phrase
                o_displ  =     4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
                o_imm  =       5  # Immediate Value                      value
                o_far  =       6  # Immediate Far Address  (CODE)        addr
                o_near  =      7  # Immediate Near Address (CODE)        addr
                ......
            '''
            goroot_path_len = 0
            goroot_path_addr = 0

            curr_addr = goroot_flowchart[cb_idx].startEA
            goroot_path_addr_val = idc.GetOperandValue(curr_addr, 1)

            end_addr = goroot_flowchart[cb_idx].endEA
            curr_addr = idc.FindCode(curr_addr, idaapi.SEARCH_DOWN)
            # find goroot path length and OpType of length(instant len number or addr of len)
            while curr_addr <= end_addr:
                len_optype = idc.GetOpType(curr_addr, 1)
                if len_optype == 2:
                    # addr of len
                    # mov     rcx, cs:qword_D9AB58
                    goroot_path_addr = read_mem(goroot_path_addr_val)
                    goroot_path_len = read_mem(goroot_path_addr_val + ADDR_SZ)
                    break
                elif len_optype == 5:
                    # instant number as len
                    # mov     [rsp+28h+arg_8], 0Dh
                    goroot_path_addr = goroot_path_addr_val
                    goroot_path_len = idc.GetOperandValue(curr_addr, 1)
                    break

                curr_addr = idc.FindCode(curr_addr, idaapi.SEARCH_DOWN)

            if goroot_path_len == 0 or goroot_path_addr == 0:
                raise Exception("Invalid GOROOT Address ang Length")

            goroot_path_str = str(idc.GetManyBytes(goroot_path_addr, goroot_path_len))
            if goroot_path_str is None or len(goroot_path_str)==0:
                raise Exception("Invalid GOROOT")
            idc.MakeStr(goroot_path_addr, goroot_path_addr+goroot_path_len)
            idaapi.autoWait()
            break

    if len(goroot_path_str) > 0:
        _info("Go ROOT Path: %s\n" % goroot_path_str)

    return goroot_path_str.replace("\\", "/")

def find_ret_cb(flow_chart):
    '''
    Find the ret block indexes of a functions' flow chart
    '''
    ret_cb_list = []
    ret = 0
    for idx in xrange(flow_chart.size):
        if flow_chart[idx].type == idaapi.fcb_ret:
            # Refer: https://www.hex-rays.com/products/ida/support/sdkdoc/gdl_8hpp.html#afa6fb2b53981d849d63273abbb1624bd 
            ret_cb_list.append(idx)
    return ret_cb_list    


STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(name_str):
    '''
    Clean generic 'bad' characters
    '''
    name_str = filter(lambda x: x in string.printable, name_str)

    for c in STRIP_CHARS:
        name_str = name_str.replace(c, '')

    for c in REPLACE_CHARS:
        name_str = name_str.replace(c, '_')

    return name_str

def get_goversion():
    global GOVER

    func_goroot = find_func_by_name("runtime_schedinit")
    if func_goroot is None:
        _error("Failed to find func runtime_schedinit")
        return

    schedinit_flowchart = idaapi.FlowChart(f=func_goroot)
    _debug("Flowchart number of runtime_schedinit: %d" % schedinit_flowchart.size)

    for fc_idx in xrange(schedinit_flowchart.size):
        fc = schedinit_flowchart[fc_idx]
        _debug("Current flowchart start addr: 0x%x" % fc.startEA)
        # mov     dword_AD744C, 7 ; dword_AD744C stores length of Go Version string
        if idc.GetMnem(fc.startEA) == "mov" and idc.GetOpType(fc.startEA, 0) == 2 \
            and str(idc.GetOperandValue(fc.startEA, 1)) == "7":
            _debug("Find length of go version string @ 0x%x" % fc.startEA)
            possible_goversion_len_addr = idc.GetOperandValue(fc.startEA, 0)
            _debug("Possible go version string len addr: 0x%x" % possible_goversion_len_addr)
            possible_goversion_str_ptr_addr = possible_goversion_len_addr - ADDR_SZ
            possible_goversion_str_addr = read_mem(possible_goversion_str_ptr_addr)
            _debug("Possible go version string addr: 0x%x" % possible_goversion_str_addr)
            possible_goversion_len = read_mem(possible_goversion_len_addr)
            _debug("Real go version string len: %d" % possible_goversion_len)
            if possible_goversion_len >=5 and possible_goversion_len < 10:
                if idc.MakeStr(possible_goversion_str_addr, possible_goversion_str_addr + possible_goversion_len):
                    idaapi.autoWait()
                    goversion_str = str(idc.GetManyBytes(possible_goversion_str_addr, possible_goversion_len))
                    _debug(goversion_str)
                    if goversion_str.startswith("go"):
                        GOVER = goversion_str[2:]
                        _info("\nGo version: %s\n" % GOVER)
                    else:
                        _debug("Invalid go string")
                else:
                    _debug("Failed to create go version string")
            else:
                _debug("Invalid go version len")
