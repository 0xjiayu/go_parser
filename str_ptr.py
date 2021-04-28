#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
go_parser.py:
IDA Plugin for Golang Executable file parsing.
'''

__author__ = "JiaYu"
__license__ = "MIT"
__version__ = "1.0"
__email__ = ["jiayu0x@gmail.com"]

import idc, idaapi, idautils
idaapi.require("common") # ==> import common


START_EA = 0xE0A30
END_EA = 0xE0A40

curr_addr = START_EA
while curr_addr <= END_EA:
    curr_str_addr = common.read_mem(curr_addr)
    curr_str_len = common.read_mem(curr_addr + common.ADDR_SZ)
    if curr_str_addr > 0 and curr_str_addr != idc.BADADDR and curr_str_len > 1:
        idc.del_items(curr_str_addr,idc.DELIT_SIMPLE, curr_str_len)
        idaapi.auto_wait()
        if idc.create_strlit(curr_str_addr, curr_str_addr + curr_str_len):
            # 建议在所有相应的代码处增加一个注释，直接将字符串注释在代码中
            for addr in idautils.DataRefsTo(curr_addr):
                str_value = idc.get_strlit_contents(curr_str_addr,curr_str_len)
                idaapi.set_cmt(addr,"%s" % (str_value),0)
                # print("0x%x %s" % (addr,idc.generate_disasm_line(addr,0)))
            idaapi.add_dref(curr_addr, curr_str_addr, idaapi.dr_O)  # 由于添加交叉引用后，IDA会自动在代码旁注释字符串。
            idaapi.auto_wait()

            curr_str = idc.get_bytes(curr_str_addr, curr_str_len).decode()
            print("@ 0x%x: %s" % (curr_str_addr, curr_str))

    curr_addr += 2 * common.ADDR_SZ