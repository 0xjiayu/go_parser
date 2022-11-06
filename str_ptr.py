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

START_EA = 0x586B08 # first str pointer address
END_EA = 0x587C18 # last str pointer address

str_ptr_cnt = 0

curr_addr = START_EA
while curr_addr <= END_EA:
    curr_str_addr = common.read_mem(curr_addr)
    curr_str_len = common.read_mem(curr_addr + common.ADDR_SZ)
    if curr_str_addr > 0 and curr_str_addr != idc.BADADDR and curr_str_len > 1:
        if idc.create_strlit(curr_str_addr, curr_str_addr + curr_str_len):
            idaapi.auto_wait()

            curr_str = idc.get_bytes(curr_str_addr, curr_str_len).decode("utf-8", errors="ignore")
            print(f"@ {curr_str_addr:#x}: {curr_str}")
            str_ptr_cnt += 1

    curr_addr += 2 * common.ADDR_SZ

print(f"\n=> Success to parse {str_ptr_cnt} string pointers")
