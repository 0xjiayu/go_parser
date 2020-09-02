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

def main():
    # find and parsefirfst moduledata
    firstmoddata_addr = moduledata.find_first_moduledata_addr()
    firstmoddata = moduledata.ModuleData(firstmoddata_addr)
    firstmoddata.parse()

    common._info("pclntbl addr: 0x%x\n" % firstmoddata.pclntbl_addr)
    # parse pclntab(functions/srcfiles and function pointers)
    pclntab = pclntbl.Pclntbl(firstmoddata.pclntbl_addr)
    pclntab.parse()

    common.get_goversion()

    # parse strings
    parse_str_cnt = strings.parse_strings()
    common._info("Parsed %d strings\n" % parse_str_cnt)

    # parse data types
    type_parser = types_builder.TypesParser(firstmoddata)
    type_parser.build_all_types()

    # parse itabs
    itab.parse_itab(firstmoddata, type_parser)

if __name__ == '__main__':
    main()
