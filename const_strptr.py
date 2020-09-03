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

import idc, idaapi
idaapi.require("common")

#ADDR_SZ = 8
START_EA = 0x98C710
END_EA = 0x990F58

curr_addr = START_EA
while curr_addr <= END_EA:
    curr_str_addr = common.read_mem(curr_addr)
    curr_str_len = common.read_mem(curr_addr + common.ADDR_SZ)
    if curr_str_addr > 0 and curr_str_addr != idc.BADADDR and curr_str_len > 1:
        if idc.MakeStr(curr_str_addr, curr_str_addr + curr_str_len):
            idaapi.autoWait()

            curr_str = str(idc.GetManyBytes(curr_str_addr, curr_str_len))
            print("@ 0x%x: %s" % (curr_str_addr, curr_str))

    curr_addr += 2 * common.ADDR_SZ