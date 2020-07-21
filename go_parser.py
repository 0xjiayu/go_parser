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

#import common, strings, pclntbl, moduledata, types_builder, itab
import idautils, idc, idaapi

import sys
import string

sys.setrecursionlimit(10000)

idaapi.require("common")
idaapi.require("strings")
idaapi.require("pclntbl")
idaapi.require("moduledata")
idaapi.require("types_builder")
idaapi.require("itab")
idaapi.require("idc")

def main():
    pclntbl_start_addr = pclntbl.get_gopclntbl_seg_start_addr()
    if pclntbl_start_addr == idc.BADADDR:
        raise Exception("Bad pclntbl addr")

    # parse pclntab(functions/srcfiles and function pointers)
    pclntab = pclntbl.Pclntbl(pclntbl_start_addr)
    pclntab.parse()

    # parse strings
    parse_str_cnt = strings.parse_strings()
    common._info("Parsed string count: %d" % parse_str_cnt)

    # parse firstmoduledata
    firstmoddata_addr = moduledata.find_first_moduledata_addr(pclntbl_start_addr)
    firstmoddata = moduledata.ModuleData(firstmoddata_addr)
    firstmoddata.parse()

    # parse data types
    type_parser = types_builder.TypesParser(firstmoddata)
    type_parser.build_all_types()

    # parse itabs
    itab.parse_itab(firstmoddata, type_parser)

if __name__ == '__main__':
    main()
