#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils
import common
import sys

'''
# pattern string with golang 1.15.6 windows/amd64
.text:000000000002822C                 ADRL            X0, unk_C440E    # str "runtime: full="
.text:0000000000028234                 STR             X0, [SP,#0xA0+var_98]
.text:0000000000028238                 MOV             X0, #0xE         # str_len
.text:000000000002823C                 STR             X0, [SP,#0xA0+var_90]
.text:0000000000028240                 BL              runtime.printstring

.text:00000000000880FC                 MOV             X1, #0x12        # str_len
.text:0000000000088100                 STR             X1, [X0,#8]
.text:0000000000088104                 ADRL            X1, unk_C4EE7    # str "reflect.Value.Type"

.text:00000000000128FC                 ADRL            X2, unk_C623B
.text:0000000000012904                 STR             X2, [SP,#0x50+var_40]
.text:0000000000012908                 MOV             X2, #0x18

.text:00000000000164A8                 ADRL            X3, unk_C5B2B
.text:00000000000164B0                 STR             X3, [SP,#0x120+var_68]
.text:00000000000164B4                 MOV             X3, #0x16

.text:00000000000-                 ADRL            X4, unk_C4C02
.text:00000000000859A0                 STR             X4, [SP,#0xA0+var_90]
.text:00000000000859A4                 MOV             X4, #0x11
'''

'''
# pattern str_array with golang 1.15.6 windows/amd64
.text:000000000009B748                 ADRL            X27, main.typeFiles      # str_array
.text:000000000009B750                 LDR             X1, [X27] ; off_15F020   # 
对于字符串数组，没有很好的pattern进行识别，因为在golang中数组都是集中存放的，因此很难分辨出数组中哪些是字符串元素哪些是其他类型元素。

'''


# Currently it's normally x0-x7(arm64)
VALID_REGS = ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7', 'R0', 'R1', 'R2', 'R3']

# Currently it's normally 
VALID_DEST = ['SP']

def is_string_patt(addr):
    # Check for first parts instruction and what it is loading -- also ignore function pointers we may have renamed
    if (idc.print_insn_mnem(addr) != 'ADRL') or (idc.get_operand_type(addr, 1) != 5) \
        or idc.print_operand(addr, 1)[:4] != 'unk_':
        return False
    # Validate that the string offset actually exists inside the binary
    if idc.get_segm_name(idc.get_operand_value(addr, 1)) is None:
        return False

    # Could be unk_, asc_, 'offset ', XXXXh, ignored ones are loc_ or inside []
    # 这里并没有去适配旧版的golang binary
    if idc.print_operand(addr,0) in VALID_REGS:
        # check for second part
        # .text:0000000000085A84                 STR             X0, [SP,#0xA0+var_70]
        addr_2 = idc.find_code(addr, idaapi.SEARCH_DOWN)
        if (idc.print_insn_mnem(addr_2) != 'STR' or idc.get_operand_type(addr_2, 1) != 4 ):
            return False

        try:
            des_reg = idc.print_operand(addr_2, 1)[idc.print_operand(addr_2, 1).index('[') + 1:idc.print_operand(addr_2, 1).index(',')]
        except ValueError:
            return False
        
        if des_reg not in VALID_DEST:
            return False
        
        addr_3 = idc.find_code(addr_2, idaapi.SEARCH_DOWN)
        if (idc.print_insn_mnem(addr_3) != 'MOV' or idc.get_operand_type(addr_3,0) != 1 or idc.get_operand_type(addr_3,1) != 5):
            return False
    
        return True
    else:
        return False


'''
# pattern str_ptr with golang 1.15.6 windows/amd64

# arm 32
.text:000A0C54                 LDR             R0, =unk_B98C8   # string
.text:000A0C58                 STR             R0, [SP,#0x2C+var_8]
.text:000A0C5C                 LDR             R0, =off_E3828   # str_ptr ==> [str_addr,str_len]

.text:000000000009B740                 ADRL            X0, unk_AA960    # string
.text:000000000009B748                 STR             X0, [SP,#0x60+var_18]
.text:000000000009B74C                 ADRL            X0, off_E0B20    # str_ptr ==> [str_addr,str_len]
'''

'''
#define o_void        0  // No Operand                           ----------
#define o_reg         1  // General Register (al, ax, es, ds...) reg
#define o_mem         2  // Direct Memory Reference  (DATA)      addr
#define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
#define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
#define o_imm         5  // Immediate Value                      value
#define o_far         6  // Immediate Far Address  (CODE)        addr
#define o_near        7  // Immediate Near Address (CODE)        addr
#define o_idpspec0    8  // IDP specific type
#define o_idpspec1    9  // IDP specific type
#define o_idpspec2   10  // IDP specific type
#define o_idpspec3   11  // IDP specific type
#define o_idpspec4   12  // IDP specific type
#define o_idpspec5   13  // IDP specific type
'''

def parse_str_ptr(addr):
    if idc.print_insn_mnem(addr) != 'ADRL':
        return False

    # Validate that the string offset actually exists inside the binary
    if idc.get_segm_name(idc.get_operand_value(addr, 1)) is None:
        return False

    # Check the operands' type:
    # - first one must be a register;
    # - second one must be a memory address (Immediate Value 5 这里不太明白为什么是立即数呢？不应该是内存地址？这个内存地址类型是怎么定义的？)
    if idc.get_operand_type(addr, 0) != 1 or idc.get_operand_type(addr, 1) != 5:
        return False
    
    # Jump STR instruction
    addr_2 = idc.find_code(addr, idaapi.SEARCH_DOWN) 
    addr_3 = idc.find_code(addr_2, idaapi.SEARCH_DOWN)
    # same operands' type for addr_3
    if idc.print_insn_mnem(addr_3) != 'ADRL' or idc.get_operand_type(addr_3, 0) != 1 or idc.get_operand_type(addr_3, 1) != 5:
        return False

    opnd_val_1 = idc.get_operand_value(addr, 1)   # str_ptr or string
    opnd_val_2 = idc.get_operand_value(addr_3, 1)   # string or str_ptr

    # constant 0x10 字符串指针的特征之一，就认为顺序是一样的
    if common.read_mem(opnd_val_1) != 0x10:
        return False

    str_ptr_addr = opnd_val_2
    str_len_addr = opnd_val_2 + common.ADDR_SZ
    str_addr = common.read_mem(str_ptr_addr)
    str_len = common.read_mem(str_len_addr)
    # set max str len
    if str_len > 64:
        return False
    if 'rodata' not in idc.get_segm_name(str_addr) and 'text' not in idc.get_segm_name(str_addr):
        return False
    common._debug("------------------------------")
    common._debug("Possible str ptr:")
    common._debug("Code addr: 0x%x , str_ptr_addr: 0x%x , str_len_addr: 0x%x" % (addr,str_ptr_addr, str_len_addr))
    common._debug("str_addr: 0x%x , str_len: 0x%x" % (str_addr, str_len))
    #if create_string(str_addr, str_len):
    if str_len > 1:
        # 先将原有的删除，以便IDA能自动识别，这里有没有必要删除，不是很清楚。
        idc.del_items(str_addr,idc.DELIT_SIMPLE, str_len)
        idaapi.auto_wait()
        if idc.create_strlit(str_addr, str_addr + str_len):
            idaapi.auto_wait()
            # 这里应该把字符串的值 直接注释到代码中
            for addr in idautils.DataRefsTo(str_ptr_addr):
                str_value = idc.get_strlit_contents(str_addr, str_len)
                idaapi.set_cmt(addr,"%s" % (str_value),0)   # 0 是否重复注释
                idaapi.auto_wait()
            
            idaapi.add_dref(str_ptr_addr, str_addr, idaapi.dr_O)  # 在字符串上添加 数据的交叉引用
            idaapi.auto_wait()
            return True
    
    return False

def create_string(addr, string_len):
    if idc.get_segm_name(addr) is None:
        common._debug('Cannot load a string which has no segment - not creating string @ 0x%02x' % addr)
        return False

    common._debug('Found string load @ 0x%x with length of %d' % (addr, string_len))
    # This may be overly aggressive if we found the wrong area...
    if idc.get_str_type(addr) is not None and idc.get_strlit_contents(addr) is not None and len(idc.get_strlit_contents(addr)) != string_len:
        common._debug('It appears that there is already a string present @ 0x%x' % addr)
        idc.del_items(addr, idc.DELIT_SIMPLE,string_len)
        idaapi.auto_wait()

    if idc.get_strlit_contents(addr) is None and idc.create_strlit(addr, addr + string_len):
        idaapi.auto_wait()
        return True
    else:
        # If something is already partially analyzed (incorrectly) we need to MakeUnknown it
        idc.del_items(addr,idc.DELIT_SIMPLE, string_len)
        idaapi.auto_wait()
        if idc.create_strlit(addr, addr + string_len):
            idaapi.auto_wait()
            return True
        common._debug('Unable to make a string @ 0x%x with length of %d' % (addr, string_len))

    return False

def create_offset(addr):
    if idc.op_plain_offset(addr, 1, 0):
        return True
    else:
        common._debug('Unable to make an offset for string @ 0x%x ' % addr)

    return False


def parse_strings():
    strings_added = 0
    retry = []
    for segea in idautils.Segments():
        for addr in idautils.Functions(segea, idc.get_segm_end(segea)):
            name = idc.get_func_name(addr)
            # 获取函数
            end_addr = idautils.Chunks(addr).__next__()[1]
            if(end_addr < addr):
                common._error('Unable to find good end for the function %s' % name)
                pass

            common._debug('Found function %s starting/ending @ 0x%x 0x%x' %  (name, addr, end_addr))
            while addr <= end_addr:
            # if True:
            #     addr = 0x29D84 
                if parse_str_ptr(addr):
                    strings_added += 1
                    addr = idc.find_code(addr, idaapi.SEARCH_DOWN)
                elif is_string_patt(addr):
                    if 'rodata' not in idc.get_segm_name(addr) and 'text' not in idc.get_segm_name(addr):
                        common._debug('Should a string be in the %s section?' % idc.get_segm_name(addr))
                    string_addr = idc.get_operand_value(addr, 1)
                    addr_3 = idc.find_code(idc.find_code(addr, idaapi.SEARCH_DOWN), idaapi.SEARCH_DOWN)
                    string_len = idc.get_operand_value(addr_3, 1)

                    if string_len > 1 and string_len < 64:
                        if create_string(string_addr, string_len):
                            if create_offset(addr):
                                strings_added += 1
                        else:
                            # There appears to be something odd that goes on with IDA making some strings, always works
                            # the second time, so lets just force a retry...
                           retry.append((addr, string_addr, string_len))

                    # Skip the extra mov lines since we know it won't be a load on any of them
                    addr = idc.find_code(addr_3, idaapi.SEARCH_DOWN)
                else:
                    addr = idc.find_code(addr, idaapi.SEARCH_DOWN)

    for instr_addr, string_addr, string_len in retry:
        if create_string(string_addr, string_len):
            if create_offset(instr_addr):
                strings_added += 1
        else:
            common._error('Unable to make a string @ 0x%x with length of %d for usage in function @ 0x%x' % (string_addr, string_len, instr_addr))

    return strings_added


parse_strings()
