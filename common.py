#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils
import string

DEBUG = False
ADDR_SZ = 4 # Default: 32-bit

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
    text_seg = get_text_seg()
    if text_seg is None:
        return None

    for addr in idautils.Functions(text_seg.startEA, text_seg.endEA):
        if func_name == idaapi.get_func_name(addr):
            return idaapi.get_func(addr)
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
        mov     rax, cs:runtime_internal_sys_DefaultGoroot
        mov     rcx, cs:qword_D9AB58
        mov     [rsp+28h+arg_0], rax
        mov     [rsp+28h+arg_8], rcx
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
            goroot_path_str_addr = read_mem(idc.GetOperandValue(goroot_flowchart[cb_idx].startEA, 1))
            goroot_path_str = idc.GetString(goroot_path_str_addr)
            if goroot_path_str is None or len(goroot_path_str)==0:
                raise Exception("Invalid GOROOT")
            idc.MakeStr(goroot_path_str_addr, goroot_path_str_addr+len(goroot_path_str)+1)
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
