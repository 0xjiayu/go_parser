#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi
idaapi.require("moduledata")
idaapi.require("common")
from common import read_mem, ADDR_SZ
import sys
sys.setrecursionlimit(10000)

STANDARD_PACKAGES = ['archive/tar', 'archive/zip', 'bufio', 'builtin', 'bytes', 'compress/bzip2', 'compress/flate', 'compress/gzip', 'compress/lzw', 'compress/zlib', 'container/heap', 'container/list', 'container/ring', 'context', 'crypto', 'crypto/aes', 'crypto/cipher', 'crypto/des', 'crypto/dsa', 'crypto/ecdsa', 'crypto/ed25519', 'crypto/elliptic', 'crypto/hmac', 'crypto/md5', 'crypto/rand', 'crypto/rc4', 'crypto/rsa', 'crypto/sha1', 'crypto/sha256', 'crypto/sha512', 'crypto/subtle', 'crypto/tls', 'crypto/x509', 'crypto/x509/pkix', 'database/sql', 'database/sql/driver', 'debug/dwarf', 'debug/elf', 'debug/gosym', 'debug/macho', 'debug/pe', 'debug/plan9obj', 'encoding', 'encoding/ascii85', 'encoding/asn1', 'encoding/base32', 'encoding/base64', 'encoding/binary', 'encoding/csv', 'encoding/gob', 'encoding/hex', 'encoding/json', 'encoding/pem', 'encoding/xml', 'errors', 'expvar', 'flag', 'fmt', 'go/ast', 'go/build', 'go/constant', 'go/doc', 'go/format', 'go/importer', 'go/parser', 'go/printer', 'go/scanner', 'go/token', 'go/types', 'hash', 'hash/adler32', 'hash/crc32', 'hash/crc64', 'hash/fnv', 'html', 'html/template', 'image', 'image/color', 'image/color/palette', 'image/draw', 'image/gif', 'image/jpeg', 'image/png', 'index/suffixarray', 'io', 'io/ioutil', 'log', 'log/syslog', 'math', 'math/big', 'math/bits', 'math/cmplx', 'math/rand', 'mime', 'mime/multipart', 'mime/quotedprintable', 'net', 'net/http', 'net/http/cgi', 'net/http/cookiejar', 'net/http/fcgi', 'net/http/httptest', 'net/http/httptrace', 'net/http/httputil', 'net/http/pprof', 'net/mail', 'net/rpc', 'net/rpc/jsonrpc', 'net/smtp', 'net/textproto', 'net/url', 'os', 'os/exec', 'os/signal', 'os/user', 'path', 'path/filepath', 'plugin', 'reflect', 'regexp', 'regexp/syntax', 'runtime', 'runtime/cgo', 'runtime/debug', 'runtime/pprof', 'runtime/race', 'runtime/trace', 'sort', 'strconv', 'strings', 'sync', 'sync/atomic', 'syscall', 'syscall/js', 'testing', 'testing/iotest', 'testing/quick', 'text/scanner', 'text/tabwriter', 'text/template', 'text/template/parse', 'time', 'unicode', 'unicode/utf16', 'unicode/utf8', 'unsafe']
#import IPython

class TypesParser():
    '''
    Parse and construct all the types
    '''

    RAW_TYPES = ['Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128', 'UnsafePointer', 'String']

    def __init__(self, firstmoduledata):
        self.moddata = firstmoduledata
        self.parsed_types = dict()
        self.itabs = list()

    def is_raw_type(self, kind):
        return kind in self.RAW_TYPES

    def build_all_types(self, depth=1):
        common._info("Building all types...\n")
        common._info(f"Typelinks address is {self.moddata.typelink_addr:#x}.")
        for idx in range(self.moddata.type_cnt):
            type_off = read_mem(self.moddata.typelink_addr + idx*4, forced_addr_sz=4) & 0xFFFFFFFF
            if type_off == 0:
                continue
            type_addr = self.moddata.types_addr + type_off
            idc.set_cmt(self.moddata.typelink_addr + idx*4, f"type @ {type_addr:#x}", 0)
            idaapi.auto_wait()
            common._debug(f"{idx+1}th type, offset: {type_off:#x}, addr: {type_addr:#x}")
            if type_addr in self.parsed_types.keys():
                common._debug("  "*depth + 'already parsed')
                continue
            #print self.parsed_types.keys()
            #try:
            self.parse_type(type_addr=type_addr)
            #except Exception as e:
            #    common._error("Failed to parse type_off( 0x%x ) @ 0x%x" % (type_off, type_addr))
            #    raise Exception(e)

        common._info(f"types building finished. Total types number: {len(self.parsed_types.keys())}")

    def parse_type(self, type_addr=idc.BADADDR, depth=1):
        if type_addr == 0 or type_addr == idc.BADADDR:
            return None

        if type_addr in self.parsed_types.keys():
            common._debug("  "*depth + 'already parsed')
            return self.parsed_types[type_addr].rtype

        common._debug(f"Parsing type @ {type_addr:#x}")
        rtype = RType(type_addr, self.moddata, self)
        rtype.parse()
        common._debug(f"Type name @ {type_addr:#x}: {rtype.name}")

        if rtype.size == 0:
            common._info("  "*depth + f"> WARNNING: empty type @ {type_addr:#x}")

        # parse the specific kind of data type
        if rtype.get_kind() == "Ptr":
            ptr_type = PtrType(type_addr, self, rtype)
            self.parsed_types[type_addr] = ptr_type
            ptr_type.parse()
            common._debug("  "*depth + ptr_type.name)
        elif rtype.get_kind() == "Struct":
            st_type = StructType(type_addr, self, rtype)
            self.parsed_types[type_addr] = st_type
            st_type.parse()
            common._debug("  "*depth + st_type.name)
        elif rtype.get_kind() == "Array":
            arr_type = ArrayType(type_addr, self, rtype)
            self.parsed_types[type_addr] = arr_type
            arr_type.parse()
            common._debug("  "*depth + arr_type.name)
        elif rtype.get_kind() == "Slice":
            slice_type = SliceType(type_addr, self, rtype)
            self.parsed_types[type_addr] = slice_type
            slice_type.parse()
            common._debug("  "*depth + slice_type.name)
        elif rtype.get_kind() == "Interface":
            itype = InterfaceType(type_addr, self, rtype)
            self.parsed_types[type_addr] = itype
            itype.parse()
            common._debug("  "*depth + itype.name)
        elif rtype.get_kind() == "Chan":
            ch_type = ChanType(type_addr, self, rtype)
            self.parsed_types[type_addr] = ch_type
            ch_type.parse()
            common._debug("  "*depth + ch_type.name)
        elif rtype.get_kind() == "Func":
            func_type = FuncType(type_addr, self, rtype)
            self.parsed_types[type_addr] = func_type
            func_type.parse()
            common._debug("  "*depth + func_type.name)
        elif rtype.get_kind() == "Map":
            map_type = MapType(type_addr, self, rtype)
            self.parsed_types[type_addr] = map_type
            map_type.parse()
            common._debug("  "*depth + map_type.name)
        elif self.is_raw_type(rtype.get_kind()):
            self.parsed_types[type_addr] = RawType(type_addr, rtype)
            common._debug("  "*depth + rtype.name)
        else:
          raise Exception(f"Unknown type (kind:{rtype.get_kind()})")

        # process uncommon type, i.e. types with mothods
        #if rtype.get_kind() != "Map" and rtype.is_uncomm():
        if rtype.is_uncomm():
            prim_type = self.parsed_types[type_addr]
            uncomm_type = UncommonType(prim_type, self)
            self.parsed_types[type_addr] = uncomm_type
            uncomm_type.parse()

        return rtype

    def has_been_parsed(self, addr):
        return (addr in self.parsed_types.keys())

class RType():
    '''
    A single RType struct
    Refer: https://golang.org/src/reflect/type.go

    type rtype struct {
        size       uintptr
        ptrdata    uintptr  // number of bytes in the type that can contain pointers
        hash       uint32   // hash of type; avoids computation in hash tables
        tflag      tflag    // extra type information flags
        align      uint8    // alignment of variable with this type
        fieldAlign uint8    // alignment of struct field with this type
        kind       uint8    // enumeration for C
        alg        *typeAlg // algorithm table
        gcdata     *byte    // garbage collection data
        str        nameOff  // string form
        ptrToThis  typeOff  // type for pointer to this type, may be zero
    }
    '''
    # Refer: https://golang.org/pkg/reflect/#Kind
    TYPE_KINDS = ['Invalid Kind','Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128','Array','Chan','Func','Interface','Map','Ptr','Slice','String','Struct','UnsafePointer']

    # see https://golang.org/src/reflect/type.go for constants definition
    TFLAG_UNCOMM        = 0x1
    TFLAG_STARPREFIX    = 0x2
    TFLAG_NAMED         = 0x4
    KIND_DIRECT_IFACE   = 1 << 5
    KIND_GCPROG         = 1 << 6 # Type.gc points to GC program
    KIND_MASK           = (1 << 5) - 1

    def __init__(self, addr, firstmoduledata, type_parser):
        self.addr = addr
        self.moddata = firstmoduledata
        self.type_parser = type_parser
        self.size = 0
        self.ptrdata = 0
        self.hash = None
        self.tflag = None
        self.align = 0
        self.field_align = 0
        self.kind = 0
        self.alg = None
        self.gcdata = None
        self.name_off = 0
        self.name_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.ptrtothis = None
        self.ptrtothis_off = 0
        self.ptrtothis_addr = idc.BADADDR
        self.self_size = 0x20 if ADDR_SZ == 4 else 0x30

    def parse(self):
        common._debug(f"RType @ {self.addr:#x}")
        self.size = read_mem(self.addr)
        self.ptrdata = read_mem(self.addr + ADDR_SZ)
        self.hash = read_mem(self.addr + 2*ADDR_SZ, forced_addr_sz = 4)
        self.tflag = idc.get_wide_byte(self.addr + 2*ADDR_SZ + 4) & 0xFF
        self.align = idc.get_wide_byte(self.addr + 2*ADDR_SZ + 5) & 0xFF
        self.field_align = idc.get_wide_byte(self.addr + 2*ADDR_SZ + 6) & 0xFF
        self.kind = idc.get_wide_byte(self.addr + 2*ADDR_SZ + 7) & 0xFF & RType.KIND_MASK
        self.alg = read_mem(self.addr + 2*ADDR_SZ + 8)
        self.gcdata = read_mem(self.addr + 3*ADDR_SZ + 8)

        self.name_off = read_mem(self.addr + 4*ADDR_SZ + 8, forced_addr_sz=4) & 0xFFFFFFFF
        self.name_addr = (self.moddata.types_addr + self.name_off) & 0xFFFFFFFF

        self.ptrtothis_off = read_mem(self.addr + 4*ADDR_SZ + 12, forced_addr_sz=4) & 0xFFFFFFFF

        if self.ptrtothis_off > 0:
            self.ptrtothis_addr = (self.moddata.types_addr + self.ptrtothis_off) & 0xFFFFFFFF

        idc.set_cmt(self.addr, "type size", 0)
        idc.set_cmt(self.addr + ADDR_SZ, "type ptrdata", 0)
        idc.set_cmt(self.addr + 2*ADDR_SZ, "type hash", 0)

        tflag_comm = "tflag:"
        if self.has_star_prefix():
            tflag_comm += " Star Prefix;"
        if self.is_named():
            tflag_comm += " Named;"
        if self.is_uncomm():
            tflag_comm += " Uncommon"
        idc.set_cmt(self.addr + 2*ADDR_SZ + 4, tflag_comm, 0)
        common._debug(tflag_comm)

        idc.set_cmt(self.addr + 2*ADDR_SZ + 5, "align", 0)
        idc.set_cmt(self.addr + 2*ADDR_SZ + 6, "field align", 0)
        idc.set_cmt(self.addr + 2*ADDR_SZ + 7, f"kind: {self.get_kind()}", 0)
        if self.moddata.magic_number == common.MAGIC_112:
            idc.set_cmt(self.addr + 2*ADDR_SZ + 8, "alg", 0)
        else:
            idc.set_cmt(self.addr + 2*ADDR_SZ + 8, "equal func", 0)
        idc.set_cmt(self.addr + 3*ADDR_SZ + 8, "gcdata", 0)
        common._debug(f"kind: {self.get_kind()}")

        if self.ptrtothis_off > 0:
            idc.set_cmt(self.addr + 4*ADDR_SZ + 12, f"ptrtothis addr: {self.ptrtothis_addr:#x}", 0)
        else:
            idc.set_cmt(self.addr + 4*ADDR_SZ + 12, "ptrtothis addr", 0)
        idaapi.auto_wait()

        self.name_obj = Name(self.name_addr, self.moddata)
        self.name_obj.parse(self.has_star_prefix())
        self.name = self.name_obj.simple_name
        idc.set_cmt(self.addr + 4*ADDR_SZ + 8, f"name(@ {self.name_addr:#x} ): {self.name_obj.orig_name_str}", 0)
        common._debug(f"name(@ {self.name_addr:#x} ): {self.name_obj.orig_name_str}")

        # if a raw type is un-named, and name string is erased, the name it as it's kind string
        if len(self.name) == 0 and self.type_parser.is_raw_type(self.get_kind()) and not self.is_named():
            self.name = self.get_kind()

        # if an un-raw type is named, then concat a kind string as suffix with it's name
        if len(self.name) > 0 and self.is_named() and not self.type_parser.is_raw_type(self.get_kind()):
            self.name += ("_%s" % self.get_kind().lower())

        if self.get_kind() == "Struct" and not self.is_named(): # un-named struct type
            self.name = "_struct_"

        if self.get_kind() == "Func" and not self.is_named(): # un-named func type
            self.name = "_func_"

        if self.get_kind() == "Ptr":
            self.name += "_ptr"

        if len(self.name) > 0:
            idc.set_name(self.addr, self.name, flags=idaapi.SN_FORCE)
            idaapi.auto_wait()

        # parse type pointer
        if self.ptrtothis_off > 0 and self.ptrtothis_addr != idc.BADADDR:
            if self.type_parser.has_been_parsed(self.ptrtothis_addr):
                self.ptrtothis = self.type_parser.parsed_types[self.ptrtothis_addr]
            else:
                self.ptrtothis = self.type_parser.parse_type(type_addr=self.ptrtothis_addr)
            idaapi.auto_wait()

        common._debug(f"RType @ {self.addr:#x} parse finished.")
    def get_kind(self):
        return self.TYPE_KINDS[self.kind]

    def has_star_prefix(self):
        return self.tflag & RType.TFLAG_STARPREFIX != 0

    def is_named(self):
        return self.tflag & RType.TFLAG_NAMED != 0

    def is_uncomm(self):
        return self.tflag & RType.TFLAG_UNCOMM != 0

    def get_name(self):
        return self.name.simple_name

    def __str__(self):
        return self.get_name()

class Name():
    '''
    A rtype name struct
    Refer: https://golang.org/src/reflect/type.go

    name is an encoded type name with optional extra data.

    The first byte is a bit field containing:

        1<<0 the name is exported
        1<<1 tag data follows the name
        1<<2 pkgPath nameOff follows the name and tag

    # If Go version < 1.8
        The next two bytes are the data length:

            l := uint16(data[1])<<8 | uint16(data[2])

        Bytes [3:3+l] are the string data.

        If tag data follows then bytes 3+l and 3+l+1 are the tag length,
        with the data following.
    # IF Go version >= 1.8
        Following that, there is a varint-encoded length of the name,
        followed by the name itself.

        If tag data is present, it also has a varint-encoded length
        followed by the tag itself.

    If the import path follows, then 4 bytes at the end of
    the data form a nameOff. The import path is only set for concrete
    methods that are defined in a different package than their type.

    If a name starts with "*", then the exported bit represents
    whether the pointed to type is exported.

    type name struct {
        bytes *byte
    }

    # If Go version >= 1.18
    // readVarint parses a varint as encoded by encoding/binary.
    // It returns the number of encoded bytes and the encoded value.
    func (n name) readVarint(off int) (int, int) {
        v := 0
        for i := 0; ; i++ {
            x := *n.data(off+i, "read varint")
            v += int(x&0x7f) << (7 * i)
            if x&0x80 == 0 {
                return i + 1, v
            }
        }
    }
    '''
    EXPORTED = 0x1
    FOLLOWED_BY_TAG = 0x2
    FOLLOWED_BY_PKGPATH = 0x4

    def __init__(self, addr, moddata):
        self.addr                   = addr
        self.moddata                = moddata
        self.len                    = 0
        self.namestr_off            = 0
        self.is_exported            = None
        self.is_followed_by_tag     = None
        self.is_followed_by_pkgpath = None
        self.orig_name_str          = ""
        self.name_str               = ""
        self.simple_name            = ""
        self.full_name              = ""
        self.pkg                    = ""
        self.pkg_len                = 0
        self.tag                    = ""
        self.tag_len                = 0
        self.tag_off_sz             = 0

    def parse(self, has_star_prefix):
        common._debug(f"Name Type @ {self.addr:#x}")
        flag_byte = idc.get_wide_byte(self.addr) & 0xFF
        self.is_exported = flag_byte & self.EXPORTED != 0
        self.is_followed_by_tag = flag_byte & self.FOLLOWED_BY_TAG != 0
        self.is_followed_by_pkgpath = flag_byte & self.FOLLOWED_BY_PKGPATH != 0

        self.orig_name_str = 'None'
        if self.moddata.magic_number == common.MAGIC_112 or self.moddata.magic_number == common.MAGIC_116:
            self.len = ((idc.get_wide_byte(self.addr + 1) & 0xFF << 8) | \
                (idc.get_wide_byte(self.addr + 2) & 0xFF)) & 0xFFFF

            if self.len > 0:
                tmp_str = idc.get_bytes(self.addr + 3, self.len)
                if tmp_str:
                    self.orig_name_str = tmp_str.decode("UTF-8", errors="ignore")
        else:
            self.namestr_off, self.len = self.read_varint(1)
            if self.len > 0:
                tmp_str = idc.get_bytes(self.addr + 1 + self.namestr_off, self.len)
                if tmp_str:
                    self.orig_name_str = tmp_str.decode("UTF-8", errors="ignore")

        self.name_str = self.orig_name_str
        # delete star_prefix:
        while True:
            if len(self.name_str) > 0 and self.name_str[0] == '*':
                self.name_str = self.name_str[1:]
            else:
                break

        if self.is_followed_by_tag:
            if self.moddata.magic_number == common.MAGIC_112 or self.moddata.magic_number == common.MAGIC_116:
                self.tag_len = (idc.get_wide_byte(self.addr+ 3 + self.len) & 0xFF << 8) | \
                    (idc.get_wide_byte(self.addr + 3 + self.len + 1) & 0xFF)
                tmp_tag = idc.get_bytes(self.addr + 3 + self.len + 2, self.tag_len)
                if tmp_tag:
                    self.tag = tmp_tag.decode("UTF-8", errors="ignore")
            else:
                if self.len > 0 and self.namestr_off > 0:
                    self.tag_off_sz, self.tag_len = self.read_varint(1 + self.namestr_off + self.len)
                    if self.tag_len > 0:
                        tmp_tag = idc.get_bytes(self.addr + self.tag_off_sz, self.tag_len)
                        if tmp_tag:
                            self.tag = tmp_tag.decode("UTF-8", errors="ignore")

        # if name was reased, the replace name string with tag string
        if (not self.name_str or len(self.name_str) == 0) and self.tag and self.tag_len > 0:
            self.name_str = self.tag
            self.len = self.tag_len

        if self.is_followed_by_pkgpath:
            if self.moddata.magic_number == common.MAGIC_112 or self.moddata.magic_number == common.MAGIC_116:
                pkgpath_off_addr = self.addr + 3 + self.len
                if self.is_followed_by_tag:
                    pkgpath_off_addr += (self.tag_len + 2)
            else:
                pkgpath_off_addr = self.addr + 1 + self.namestr_off + self.len
                if self.is_followed_by_tag:
                    pkgpath_off_addr += (self.tag_len + self.tag_off_sz)

            pkgpath_off = read_mem(pkgpath_off_addr, forced_addr_sz=4)
            common._debug(f"pkgpath_off: {pkgpath_off:#x}")
            if pkgpath_off > 0 and pkgpath_off != 0xffffffff: # if error return 0xffffffff
            # if c_int(pkgpath_off).value > 0:
                pkgpath_addr = self.moddata.types_addr + pkgpath_off
                pkgpath_name_obj = Name(pkgpath_addr, self.moddata)
                common._debug(f"pkgpath_addr: {pkgpath_addr:#x}")
                # idc.auto_wait()
                pkgpath_name_obj.parse(False)
                self.pkg = pkgpath_name_obj.name_str
                self.pkg_len = len(self.pkg)

                if self.pkg_len:
                    idc.set_cmt(pkgpath_off_addr, f"pkgpath(@ {pkgpath_addr:#x}): {self.pkg}", 0)
                    idaapi.auto_wait()

        self.full_name = "%s%s%s" % (self.pkg if self.pkg else "", ("_%s" % self.name_str) \
            if self.pkg else self.name_str, ('_%s' % self.tag) if self.tag else "")
        self.simple_name = "%s%s" % (self.pkg if self.pkg else "", ("_%s" % self.name_str) \
            if self.pkg else self.name_str)

        flag_comm_str = "flag: "
        if self.is_exported:
            flag_comm_str += "exported"
        if self.is_followed_by_tag:
            if self.is_exported:
                flag_comm_str += ", followed by tag"
            else:
                flag_comm_str += "followed by tag"
        if self.is_followed_by_pkgpath:
            if self.is_exported or self.is_followed_by_tag:
                flag_comm_str += ", followed by pkgpath"
            else:
                flag_comm_str += "followed by pkgpath"
        if len(flag_comm_str) > 6: # has valid flag
            idc.set_cmt(self.addr, flag_comm_str, 0)
            idaapi.auto_wait()

        if self.moddata.magic_number == common.MAGIC_112 or self.moddata == common.MAGIC_116:
            idc.create_strlit(self.addr + 3, self.addr + 3 + self.len)
        else:
            idc.create_strlit(self.addr + 1 + self.namestr_off, self.addr + 1 + self.namestr_off + self.len)
        idaapi.auto_wait()

        if self.is_followed_by_tag:
            if self.moddata.magic_number == common.MAGIC_112 or self.moddata == common.MAGIC_116:
                idc.create_strlit(self.addr + 1 + self.namestr_off + self.tag_off_sz, \
                    self.addr + 1 + self.namestr_off + self.tag_off_sz + self.tag_len)
                idc.set_cmt(self.addr + 1 + self.namestr_off + self.tag_off_sz, f"tag of @ {self.addr:#x}", 0)
            else:
                 idc.create_strlit(self.addr + 3 + self.len + 2, self.addr + 3 + self.len + 2 + self.tag_len)
            idaapi.auto_wait()

    def read_varint(self, offset):
        '''
        For Go 1.18+, name bytes are encoded by Varint
        Refer:
            - https://go.dev/src/reflect/type.go
            - https://developers.google.com/protocol-buffers/docs/encoding
        '''
        val = 0
        idx = 0
        while True:
            x = idc.get_wide_byte(self.addr + offset + idx) & 0xFF
            val += int(x & 0x7F) << (7 * idx)
            if (x & 0x80) & 0xFF == 0:
                return idx + 1, val
            idx += 1

class PtrType():
    '''
    Pointer type
    Refer: https://golang.org/src/reflect/type.go

    type ptrType struct {
        rtype
        elem *rtype // pointer element (pointed at) type
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = rtype.self_size + ADDR_SZ
        self.target_type_addr = idc.BADADDR
        self.target_rtype = None
        self.target_rtype_origname = ""
        self.name = ""

    def parse(self):
        common._debug(f"PtrType @ {self.addr:#x}")
        self.target_type_addr = read_mem(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(self.target_type_addr):
            self.target_rtype = self.type_parser.parsed_types[self.target_type_addr]
            self.target_rtype_origname = self.target_rtype.rtype.name_obj.orig_name_str
        else:
            self.target_rtype = self.type_parser.parse_type(type_addr=self.target_type_addr)
            self.target_rtype_origname = self.target_rtype.name_obj.orig_name_str
        if self.target_rtype:
            self.name = self.target_rtype.name + "_ptr"

        idc.set_cmt(self.addr + self.rtype.self_size, f"target rtype: {self.target_rtype_origname}", 0)
        idaapi.auto_wait()
        common._debug(f"target rtype: {self.target_rtype_origname}")
        common._debug(f"PtrType @ {self.addr:#x} parse finished.")
    def __str__(self):
        return self.name

class StructType():
    '''
    Struct type
    Refer: https://golang.org/src/reflect/type.go

    type structType struct {
        rtype
        pkgPath name          // !! pointer
        fields  []structField // sorted by offset
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = self.rtype.self_size + 4 * ADDR_SZ
        self.fields = list()
        self.pkg_path_addr = idc.BADADDR
        self.pkg_path_obj = None
        self.pkg_path = ""
        self.name = rtype.name

    def parse(self):
        common._debug(f"Struct Type @ {self.addr:#x}")
        # parse pkg path
        self.pkg_path_addr = read_mem(self.addr + self.rtype.self_size)
        if self.pkg_path_addr > 0 and self.pkg_path_addr != idc.BADADDR:
            common._debug(f"self.pkg_path_addr {self.pkg_path_addr:#x}.")
            self.pkg_path_obj = Name(self.pkg_path_addr, self.type_parser.moddata)
            self.pkg_path_obj.parse(False)
            self.pkg_path = self.pkg_path_obj.simple_name

        # parse fields
        fields_start_addr = read_mem(self.addr + self.rtype.self_size + ADDR_SZ)
        fields_cnt = read_mem(self.addr + self.rtype.self_size + 2*ADDR_SZ)
        fields_cap = read_mem(self.addr + self.rtype.self_size + 3*ADDR_SZ)
        for idx in range(fields_cnt):
            field = StructFiled(fields_start_addr + idx*3*ADDR_SZ, self.type_parser)
            field.parse()
            self.fields.append(field)

        idc.set_cmt(self.addr + self.rtype.self_size, "pkg path%s" % \
            (f"(@ {self.pkg_path_addr:#x}): {self.pkg_path}" if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""), 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 2*ADDR_SZ, f"fields count: {fields_cnt:#x}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 3*ADDR_SZ, f"fileds capacity: {fields_cap:#x}", 0)
        idaapi.auto_wait()
        common._debug("Struct pkg path: %s" % (f"(@ {self.pkg_path_addr:#x}): {self.pkg_path}" \
            if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""))
        common._debug(f"Struct fields num: {fields_cnt:#x}")

        if len(self.rtype.name) > 0 and fields_cnt > 0:
            idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, "fields start address", 0)
            idc.set_name(fields_start_addr, f"{self.rtype.name}_fields", flags=idaapi.SN_FORCE)
            idaapi.auto_wait()
            common._debug(f"Struct fields start addr: {fields_start_addr:#x}")
        common._debug(f"Struct Type @ {self.addr:#x} parse finished.")
    def __str__(self):
        if self.rtype:
            ret_str = f"> Struct: {self.rtype.name} ( {len(self.fields)} fields)\n"
            for f in self.fields:
                ret_str += f"\t\t- {f}\n"
            return ret_str
        else:
            return ""

class StructFiled():
    '''
    Struct filed
    Refer: https://golang.org/src/reflect/type.go

    type structField struct {
        name        name    // name is always non-empty
        typ         *rtype  // type of field
        offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
    }
    '''
    def __init__(self, addr, type_parser):
        self.addr = addr
        self.type_parser = type_parser
        self.name_obj_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.rtype_addr = idc.BADADDR
        self.rtype = None
        self.offset = 0
        self.is_embeded = False
        self.size = 3 * ADDR_SZ

    def parse(self):
        common._debug(f"Struct StructFiled @ {self.addr:#x}")
        self.name_obj_addr = read_mem(self.addr)
        if self.name_obj_addr == 0 or self.name_obj_addr == idc.BADADDR:
            raise Exception(f"Invalid name address when parsing struct field @ {self.addr:#x}")
        self.name_obj = Name(self.name_obj_addr, self.type_parser.moddata)
        self.name_obj.parse(False)
        self.name = self.name_obj.simple_name

        self.rtype_addr = read_mem(self.addr + ADDR_SZ)
        if self.rtype_addr == 0 or self.rtype_addr == idc.BADADDR:
            raise Exception(f"Invalid rtype address when parsing struct field @ {self.addr:#x}")
        if self.type_parser.has_been_parsed(self.rtype_addr):
            self.rtype = self.type_parser.parsed_types[self.rtype_addr]
        else:
            self.rtype = self.type_parser.parse_type(type_addr=self.rtype_addr)

        off_embeded = read_mem(self.addr + 2*ADDR_SZ)
        self.offset = off_embeded >> 1
        self.is_embeded = (off_embeded & 1) != 0

        idc.set_cmt(self.addr, f"field name: { self.name_obj.name_str}", 0)
        idaapi.auto_wait()
        idc.set_cmt(self.addr + ADDR_SZ, f"field rtype: {self.rtype.name}", 0)
        idaapi.auto_wait()
        common._debug(f"Struct field name: {self.name_obj.name_str}")
        common._debug(f"Struct field rtype: {self.rtype.name}")
        common._debug(f"Struct StructFiled @ {self.addr:#x} parse finished.")
    def __str__(self):
        return self.name

class ArrayType():
    '''
    Array type
    Refer: https://golang.org/src/reflect/type.go

    type arrayType struct {
        rtype
        elem  *rtype // array element type
        slice *rtype // slice type
        len   uintptr
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.name = rtype.name
        self.size = rtype.self_size + 3*ADDR_SZ
        self.elem_type = None
        self.slice_type = None
        self.len = 0

    def parse(self):
        common._debug(f"Array Type @ {self.addr:#x}")
        elem_type_addr = read_mem(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)

        slice_type_addr = read_mem(self.addr + self.rtype.self_size + ADDR_SZ)
        if self.type_parser.has_been_parsed(slice_type_addr):
            self.slice_type = self.type_parser.parsed_types[slice_type_addr]
        else:
            self.slice_type = self.type_parser.parse_type(type_addr=slice_type_addr)

        self.len = read_mem(self.addr + self.rtype.self_size + 2 * ADDR_SZ)

        idc.set_cmt(self.addr + self.rtype.self_size, f"elem type: {self.elem_type.name}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, f"slice type: {self.slice_type.name}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 2 * ADDR_SZ, f"array length: {self.len}", 0)
        idc.set_name(self.addr, f"{self.elem_type.name}_array", flags=idaapi.SN_FORCE)
        idaapi.auto_wait()
        common._debug(f"Array elem type: {self.elem_type.name}")
        common._debug(f"Array slice type: {self.slice_type.name}")
        common._debug(f"Array Type @ {self.addr:#x} parse finished.")
    def __str__(self):
        return f"{self.elem_type.name} array(len: {self.len})"

class SliceType():
    '''
    Slice type
    Refer: https://golang.org/src/reflect/type.go

    type sliceType struct {
        rtype
        elem *rtype // slice element type
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.name = rtype.name
        self.size = self.rtype.self_size + ADDR_SZ

    def parse(self):
        common._debug(f"Slice Type @ {self.addr:#x}")

        self.elem_type_addr = read_mem(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(self.elem_type_addr):
            self.elem_rtype = self.type_parser.parsed_types[self.elem_type_addr]
        else:
            self.elem_rtype = self.type_parser.parse_type(type_addr=self.elem_type_addr)

        idc.set_cmt(self.addr + self.rtype.self_size, f"elem rtype: {self.elem_rtype.name}", 0)
        idc.set_name(self.addr, f"{self.elem_rtype.name}_slice", flags=idaapi.SN_FORCE)
        idaapi.auto_wait()
        common._debug(f"Slice elem rtype: {self.elem_rtype.name}")
        common._debug(f"Slice Type @ {self.addr:#x} parse finished.")
    def __str__(self):
        if self.elem_rtype:
            return f"Slice {self.elem_rtype.name}"
        else:
            return ""

class InterfaceType():
    '''
    Interface type
    Refer: https://golang.org/src/reflect/type.go

    type interfaceType struct {
        rtype
        pkgPath name      // import path
        methods []imethod // sorted by hash
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = rtype.self_size + 4*ADDR_SZ
        self.pkg_path_addr = idc.BADADDR
        self.pkg_path_obj = None
        self.pkg_path = ""
        self.name = rtype.name
        self.methods = list()

    def parse(self):
        common._debug(f"Interface @ {self.addr:#x}")
        # parse pkg path
        self.pkg_path_addr = read_mem(self.addr + self.rtype.self_size)
        if self.pkg_path_addr > 0 and self.pkg_path_addr != idc.BADADDR:
            self.pkg_path_obj = Name(self.pkg_path_addr, self.type_parser.moddata)
            self.pkg_path_obj.parse(False)
            self.pkg_path = self.pkg_path_obj.name_str

        # parse fields
        methods_start_addr = read_mem(self.addr + self.rtype.self_size + ADDR_SZ)
        methods_cnt = read_mem(self.addr + self.rtype.self_size + 2*ADDR_SZ)
        methods_cap = read_mem(self.addr + self.rtype.self_size + 3*ADDR_SZ)
        for idx in range(methods_cnt):
            imeth = IMethodType(methods_start_addr + idx*2*4, self.type_parser)
            imeth.parse()
            self.methods.append(imeth)

        idc.set_cmt(self.addr + self.rtype.self_size, "pkg path%s" % \
            (f"(@ {self.pkg_path_addr:#x}): self.pkg_path" if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""), 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 2*ADDR_SZ, f"methods count: {methods_cnt:#x}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 3*ADDR_SZ, f"methods capacity: {methods_cap:#x}", 0)
        idaapi.auto_wait()

        common._debug("Interface pkg path%s" % \
            (f"(@ {self.pkg_path_addr:#x}): {self.pkg_path}" if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""))
        common._debug(f"Interface methods count: {methods_cnt:#x}")

        if len(self.rtype.name) > 0:
            idc.set_name(methods_start_addr, f"{self.rtype.name}_methods", flags=idaapi.SN_FORCE)
            idaapi.auto_wait()
        common._debug(f"Interface @ {self.addr:#x} parse finished.")
    def __str__(self):
        if self.rtype:
            ret_str = f"> Interface: {self.rtype.name} ( {len(self.methods)} methods)\n"
            for m in self.methods:
                ret_str += f"\t\t- {m}\n"
            return ret_str
        else:
            return ""


class IMethodType():
    '''
    IMethod type
    Refer: https://golang.org/src/reflect/type.go

    type imethod struct {
        name nameOff // name of method
        typ  typeOff // .(*FuncType) underneath
    }
    '''
    def __init__(self, addr, type_parser):
        self.addr = addr
        self.type_parser = type_parser
        self.types_addr = type_parser.moddata.types_addr
        self.size = 8
        self.name_obj = None
        self.name = ""
        self.type = None

    def parse(self):
        common._debug(f"Imethod Type @ {self.addr:#x}")
        name_off = read_mem(self.addr, forced_addr_sz=4)
        name_addr = (self.types_addr + name_off) & 0xFFFFFFFF
        self.name_obj = Name(name_addr, self.type_parser.moddata)
        self.name_obj.parse(False)
        self.name = self.name_obj.simple_name

        type_off = read_mem(self.addr+4, forced_addr_sz=4)
        type_addr = (self.types_addr + type_off) & 0xFFFFFFFF
        if type_off > 0 and type_addr != idc.BADADDR:
            if self.type_parser.has_been_parsed(type_addr):
                self.type = self.type_parser.parsed_types[type_addr].rtype
            else:
                self.type = self.type_parser.parse_type(type_addr=type_addr)

        if name_off > 0 and name_off != idc.BADADDR:
            idc.set_cmt(self.addr, f"imethod name(@ {name_addr:#x}): {self.name}", 0)
            idaapi.auto_wait()
            common._debug(f"Interface imethod name(@ {name_addr:#x}): {self.name}")

        if type_off > 0 and type_addr != idc.BADADDR:
            idc.set_cmt(self.addr + 4, f"imethod type(@ {type_addr:#x}): {self.type.name_obj.name_str}", 0)
            idaapi.auto_wait()
            common._debug(f"Interface imethod type(@ {type_addr:#x}): {self.type.name_obj.name_str}")
        common._debug(f"Imethod Type @ {self.addr:#x} parsed finished.")

    def __str__(self):
        if self.name:
            return self.name_obj.full_name
        else:
            return ""

class ChanType():
    '''
    Channel type
    Refer: https://golang.org/src/reflect/type.go

    type chanType struct {
        rtype
        elem *rtype  // channel element type
        dir  uintptr // channel direction (ChanDir)
    }
    '''
    RECV_DIR = 1
    SEND_DIR = 2
    BOTH_DIR = 3

    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = self.rtype.self_size + 2 * ADDR_SZ
        self.direction = ""
        self.name = ""

    def parse(self):
        common._debug(f"Channel Type @ {self.addr:#x}")
        elem_type_addr = read_mem(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)
        self.elem_type.parse()

        dir_code = read_mem(self.addr + self.rtype.self_size + ADDR_SZ)
        self.direction = self.get_direction(dir_code)

        self.name = f"channel {self.rtype.name} (direction: {self.direction})"

        idc.set_cmt(self.addr + self.rtype.self_size, f"elem type: {self.elem_type.name}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, f"chan direction: {self.direction}", 0)
        idaapi.auto_wait()
        common._debug(f"Channel Type @ {self.addr:#x} parse finished.")

    def get_direction(self, dir_code):
        if dir_code == self.RECV_DIR:
          return 'recv'
        elif dir_code == self.SEND_DIR:
          return 'send'
        else:
          return 'send & recv'

    def __str__(self):
        return self.name

class FuncType():
    '''
    Function Type
    Refer: https://golang.org/src/reflect/type.go

    type funcType struct {
        rtype
        inCount  uint16
        outCount uint16 // top bit is set if last input parameter is ...

        padding  uint32 // ! only on some architectures (e.g. x64)
    }

    Note: "A *rtype for each in and out parameter is stored in an array that
    directly follows the funcType (and possibly its uncommonType)."
    '''
    VARIADIC_FLAG = 0x8000
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.para_cnt = 0
        self.ret_cnt = 0
        self.padding = -1
        self.is_variadic = False
        self.para_types = list()
        self.para_type_addrs = list()
        self.ret_types = list()
        self.ret_type_addrs = list()
        self.name = rtype.name
        self.size = rtype.self_size + 2*2 # without padding

    def parse(self):
        common._debug(f"Func Type @ {self.addr:#x}")
        self.para_cnt = read_mem(self.addr + self.rtype.self_size, forced_addr_sz=2) & 0xFFFF
        self.ret_cnt = read_mem(self.addr + self.rtype.self_size + 2, forced_addr_sz=2) & 0xFFFF
        if self.ret_cnt & FuncType.VARIADIC_FLAG:
            self.is_variadic = True
            self.ret_cnt = self.ret_cnt & 0x7FFF
        self.padding = read_mem(self.addr + self.rtype.self_size + 4, forced_addr_sz=4) & 0xFFFFFFFF
        if self.padding == 0: # skip padding if present
            self.size += 4
        curr_addr = self.addr + self.size
        if self.rtype.is_uncomm():
            curr_addr += UncommonType.SIZE

        for in_idx in range(self.para_cnt):
            curr_para_type = None
            curr_para_type_off = curr_addr + in_idx*ADDR_SZ
            para_type_addr = read_mem(curr_para_type_off)
            self.para_type_addrs.append(para_type_addr)
            if self.type_parser.has_been_parsed(para_type_addr):
                curr_para_type = self.type_parser.parsed_types[para_type_addr]
            else:
                curr_para_type = self.type_parser.parse_type(type_addr=para_type_addr)
            self.para_types.append(curr_para_type)
            idaapi.auto_wait()

        curr_addr += self.para_cnt * ADDR_SZ
        for out_idx in range(self.ret_cnt):
            curr_ret_type = None
            curr_ret_type_off = curr_addr + out_idx*ADDR_SZ
            ret_type_addr = read_mem(curr_ret_type_off)
            self.ret_type_addrs.append(ret_type_addr)
            if self.type_parser.has_been_parsed(ret_type_addr):
                curr_ret_type = self.type_parser.parsed_types[ret_type_addr]
            else:
                curr_ret_type = self.type_parser.parse_type(type_addr=ret_type_addr)
            self.ret_types.append(curr_ret_type)
            idaapi.auto_wait()

        idc.set_cmt(self.addr + self.rtype.self_size, f"Parameter count: {self.para_cnt}", 0)
        idc.set_cmt(self.addr + self.rtype.self_size + 2, "%s%s" % ("Flag: Varidic;" \
            if self.ret_cnt & FuncType.VARIADIC_FLAG else "", f"Return value count: {self.ret_cnt}"), 0)
        idaapi.auto_wait()
        common._debug(f"Func Type @ {self.addr:#x} parse finished.")
    def __str__(self):
        return "> func %s (para: %d %s  -  return: %d)\n" % (self.rtype.name, self.para_cnt, \
            "+ [...]" if self.is_variadic else "", self.ret_cnt)

class MapType():
    '''
    Map type
    Refer: https://golang.org/src/reflect/type.go

    type mapType struct {
        rtype
        key    *rtype // map key type
        elem   *rtype // map element (value) type
        bucket *rtype // internal bucket structure
        // function for hashing keys (ptr to key, seed) -> hash
        hasher     func(unsafe.Pointer, uintptr) uintptr // go version <1.14 has no this field
        keysize    uint8  // size of key slot
        valuesize  uint8  // size of value slot
        bucketsize uint16 // size of bucket
        flags      uint32
    }
    '''
    def __init__(self, addr, type_parser, rtype):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.key_type = None
        self.elem_type = None
        self.buck_type = None
        self.hasher_func_addr = 0
        self.key_size = 0
        self.val_size = 0
        self.buck_size = 0
        self.flags = -1
        self.name = ""
        self.go_subver = 0
        common._debug(f"GOVER in map struct: {common.GOVER}")
        if len(common.GOVER) > 0:
            self.go_subver = int(common.GOVER.split(".")[1])
            if self.go_subver >= 14:
                self.size = rtype.self_size + 4 * ADDR_SZ + 1 + 1 + 2 + 4
            else:
                self.size = rtype.self_size + 3 * ADDR_SZ + 1 + 1 + 2 + 4
        else:
            self.size = rtype.self_size + 4 * ADDR_SZ + 1 + 1 + 2 + 4

    def parse(self):
        common._debug(f"Map Type @ {self.addr:#x}")
        map_attr_addr = self.addr + self.rtype.self_size

        key_type_addr = read_mem(map_attr_addr)
        if self.type_parser.has_been_parsed(key_type_addr):
            self.key_type = self.type_parser.parsed_types[key_type_addr]
        else:
            self.key_type = self.type_parser.parse_type(type_addr=key_type_addr)

        elem_type_addr = read_mem(map_attr_addr + ADDR_SZ)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)

        buck_type_addr = read_mem(map_attr_addr + 2*ADDR_SZ)
        if self.type_parser.has_been_parsed(buck_type_addr):
            self.buck_type = self.type_parser.parsed_types[buck_type_addr]
        else:
            self.buck_type = self.type_parser.parse_type(type_addr=buck_type_addr)

        if self.go_subver < 14:
            self.key_size = idc.get_wide_byte(map_attr_addr + 3*ADDR_SZ) & 0xFF
            self.val_size = idc.get_wide_byte(map_attr_addr + 3*ADDR_SZ + 1) & 0xFF
            self.buck_size = read_mem(map_attr_addr + 3*ADDR_SZ + 2, forced_addr_sz=2) & 0xFFFF
            self.flags = read_mem(map_attr_addr + 3*ADDR_SZ + 4, forced_addr_sz=4) & 0xFFFFFFFF
        else:
            self.hasher_func_addr = read_mem(map_attr_addr + 3*ADDR_SZ) & 0xFFFFFFFFFFFFFFFF
            self.key_size = idc.get_wide_byte(map_attr_addr + 4*ADDR_SZ) & 0xFF
            self.val_size = idc.get_wide_byte(map_attr_addr + 4*ADDR_SZ + 1) & 0xFF
            self.buck_size = read_mem(map_attr_addr + 4*ADDR_SZ + 2, forced_addr_sz=2) & 0xFFFF
            self.flags = read_mem(map_attr_addr + 4*ADDR_SZ + 4, forced_addr_sz=4) & 0xFFFFFFFF

        self.name = f"map [{self.key_type.name}]{self.elem_type.name}"

        idc.set_cmt(map_attr_addr, f"Key type: {self.key_type.name}", 0)
        idc.set_cmt(map_attr_addr + ADDR_SZ, f"Elem type: {self.elem_type.name} ", 0)
        idc.set_cmt(map_attr_addr + 2*ADDR_SZ, f"Bucket type: {self.buck_type.name}", 0)
        if self.go_subver < 14:
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ, f"Key size: {self.key_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 1, f"Value size: {self.val_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 2, f"Bucket size: {self.buck_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 4, f"Flags: {self.flags:#x}", 0)
        else:
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ, "hash function for hashing keys (ptr to key, seed) -> hash", 0)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ, f"Key size: {self.key_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 1, f"Value size: {self.val_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 2, f"Bucket size: {self.buck_size:#x}", 0)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 4, f"Flags: {self.flags:#x}", 0)
        idaapi.auto_wait()

        common._debug(f"Map Key type: {self.key_type.name}")
        common._debug(f"Map Elem type: {self.elem_type.name}")
        common._debug(f"Map Type @ {self.addr:#x} parse finished.")

    def __str__(self):
        return self.name

class UncommonType():
    '''
    Uncommon type
    Refer: https://golang.org/src/reflect/type.go

    Wrapper around primaryType to access uncommon type:

    // uncommonType is present only for defined types or types with methods
    // (if T is a defined type, the uncommonTypes for T and *T have methods).
    // Using a pointer to this struct reduces the overall size required
    // to describe a non-defined type with no methods
    type uncommonType struct {
        pkgPath nameOff // import path; empty for built-in types like int, string
        mcount  uint16  // number of methods
        xcount  uint16  // number of exported methods
        moff    uint32  // offset from this uncommontype to [mcount]method
        _       uint32  // unused
    }
    '''
    SIZE = 16

    def __init__(self, prim_type, type_parser):
        self.addr = prim_type.addr
        self.prim_type = prim_type
        self.type_parser = type_parser
        self.rtype = prim_type.rtype
        self.uncomm_type_addr = prim_type.addr + prim_type.size
        self.types_addr = type_parser.moddata.types_addr
        self.meth_cnt = 0
        self.xmeth_cnt = 0
        self.meth_off = 0
        self.unused = 0
        self.methods = list()
        self.pkgpath_addr = idc.BADADDR
        self.pkg_path = ""
        self.name = prim_type.name
        self.size = UncommonType.SIZE

    def parse(self):
        common._debug(f"Start to parse Uncommon type @ {self.addr:#x} , Uncommon field start addr @ {self.uncomm_type_addr:#x}")
        pkgpath_off = read_mem(self.uncomm_type_addr, forced_addr_sz=4) & 0xFFFFFFFF
        if pkgpath_off != 0:
            self.pkgpath_addr = self.types_addr + pkgpath_off
            pkg_path_obj = Name(self.pkgpath_addr, self.type_parser.moddata)
            pkg_path_obj.parse(False)
            self.pkg_path = pkg_path_obj.name_str

        self.meth_cnt = read_mem(self.uncomm_type_addr + 4, forced_addr_sz=2) & 0xFFFF
        self.xmeth_cnt = read_mem(self.uncomm_type_addr + 6, forced_addr_sz=2) & 0xFFFF
        self.meth_off = read_mem(self.uncomm_type_addr + 8, forced_addr_sz=4) & 0xFFFFFFFF
        self.unused = read_mem(self.uncomm_type_addr + 12, forced_addr_sz=4) & 0xFFFFFFFF

        # parse methods
        methods_start_addr = (self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF
        for i in range(self.meth_cnt):
            #meth_addr = self.uncomm_type_addr + i * self.size
            meth = MethodType(methods_start_addr, self.type_parser)
            meth.parse()
            self.methods.append(meth)
            methods_start_addr += meth.size

        idc.set_cmt(self.uncomm_type_addr, "pkg path%s" % \
            (f"(@ {self.pkgpath_addr:#x}): {self.pkg_path}" if (pkgpath_off>0 and len(self.pkg_path)>0) else ""), 0)
        common._debug("Ucommon type pkg path%s" % \
            (f"(@ {self.pkgpath_addr:#x}): {self.pkg_path}" if (pkgpath_off>0 and len(self.pkg_path)>0) else ""))
        idc.set_cmt(self.uncomm_type_addr + 4, f"methods number: {self.meth_cnt}", 0)
        common._debug(f"Uncommon type methods number: {self.meth_cnt}")
        idc.set_cmt(self.uncomm_type_addr + 6, f"exported methods number: {self.xmeth_cnt}", 0)
        if self.meth_cnt > 0:
            idc.set_cmt(self.uncomm_type_addr + 8, f"methods addr: {(self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF:#x}", 0)
            common._debug(f"Uncommon type methods addr: {(self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF:#x}")
        else:
            idc.set_cmt(self.uncomm_type_addr + 8, "methods offset", 0)
        idc.set_cmt(self.uncomm_type_addr + 12, f"unused field: {self.unused}", 0)
        idaapi.auto_wait()
        common._debug(f"finished to parse Uncommon type @ {self.addr:#x} , Uncommon field start addr @ {self.uncomm_type_addr:#x}")

    def __str__(self):
        ret_str = "%s" % self.prim_type
        if self.meth_cnt > 0:
            ret_str += f"\n\t\t> {self.meth_cnt} methods:\n"
            for meth in self.methods:
                ret_str += f"\t\t - {meth.name}\n"

        return ret_str


class MethodType():
    '''
    Method type of no-interface type
    Refer: https://golang.org/src/reflect/type.go

    type method struct {
        name nameOff // name of method
        mtyp typeOff // method type (without receiver) // offset to an *rtype
        ifn  textOff // fn used in interface call (one-word receiver) // offset from top of text section
        tfn  textOff // fn used for normal method call // offset from top of text section
    }
    '''
    def __init__(self, addr, type_parser):
        self.addr = addr
        self.type_parser = type_parser
        self.types_addr = type_parser.moddata.types_addr
        self.text_addr = type_parser.moddata.text_addr
        self.name_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.mtype_addr = idc.BADADDR
        self.mtype = None
        self.ifn_addr = idc.BADADDR
        self.ifn_off = 0
        self.tfn_addr = idc.BADADDR
        self.tfn_off = 0
        self.size = 4*4

    def parse(self):
        common._debug("MethodType @ {self.addr:#x}")
        name_off = read_mem(self.addr, forced_addr_sz=4) & 0xFFFFFFFF
        if name_off > 0:
            self.name_addr = self.types_addr + name_off
            self.name_obj = Name(self.name_addr, self.type_parser.moddata)
            self.name_obj.parse(False)
            self.name = self.name_obj.simple_name

        # note: some methods are actually not present in the binary
        # for those, typeOff, ifn, tfn are 0
        type_off = read_mem(self.addr + 4, forced_addr_sz=4) & 0xFFFFFFFF
        if type_off > 0 and type_off != 0xFFFFFFFF:
            self.mtype_addr = self.types_addr + type_off
            if self.type_parser.has_been_parsed(self.mtype_addr):
                self.mtype = self.type_parser.parsed_types[self.mtype_addr].rtype
            else:
                self.mtype = self.type_parser.parse_type(type_addr=self.mtype_addr)

        self.ifn_off = read_mem(self.addr + 8, forced_addr_sz=4) & 0xFFFFFFFF
        self.tfn_off = read_mem(self.addr + 12, forced_addr_sz=4) & 0xFFFFFFFF

        idc.set_cmt(self.addr, "Method Name%s" % \
            (f"(@ {self.name_addr:#x}): {self.name}" if (name_off>0 and len(self.name)>0) else ""), 0)
        common._debug("Ucommon type Method Name%s" % \
            (f"(@ {self.name_addr:#x}): {self.name}" if (name_off>0 and len(self.name)>0) else ""))

        idc.set_cmt(self.addr + 4, "Method Type%s" % \
            (f"(@ {self.mtype_addr:#x}): {self.mtype.name_obj.name_str}" if (type_off>0 and self.mtype is not None) else ""), 0)
        common._debug("Uncommon type Method Type%s" % \
            (f"(@ {self.mtype_addr:#x}): {self.mtype.name_obj.name_str}" if (type_off>0 and self.mtype is not None) else ""))

        self.ifn_addr = (self.text_addr + self.ifn_off) & 0xFFFFFFFF
        ifn_name = idc.get_func_name(self.ifn_addr)
        if ifn_name is None or len(ifn_name) == 0:
            if self.mtype is not None:
                ifn_name = self.mtype.name
            else:
                ifn_name == "_func_"
        idc.set_cmt(self.addr + 8, "ifn%s" % \
            (f"(@ {self.ifn_addr:#x}): {ifn_name}" if self.ifn_off>0 else ""), 0)

        self.tfn_addr = (self.text_addr + self.tfn_off) & 0xFFFFFFFF
        tfn_name = idc.get_func_name(self.tfn_addr)
        if tfn_name is None or len(tfn_name) == 0:
            if self.mtype is not None:
                tfn_name = self.mtype.name
            else:
                tfn_name = "_func_"
        idc.set_cmt(self.addr + 12, "tfn%s" % \
            (f"(@ {self.tfn_addr:#x}): {tfn_name}" if self.tfn_off>0 else ""), 0)

        idaapi.auto_wait()
        common._debug("MethodType @ 0x%x finished." % self.addr)

class RawType():
    '''
    Wrapper for built-in types (contains only rtype)
    '''
    def __init__(self, addr, rtype):
        self.addr = addr
        self.rtype = rtype
        self.name = rtype.name
        self.size = rtype.self_size

    def __str__(self):
        return "> raw type: %s\n" % self.name
