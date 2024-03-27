import idaapi
import ida_segment
import ida_bytes
import struct

idaapi.require("libs.utils")

from libs.utils import cstr

class Objc2Class(object):
    length = struct.calcsize('<QQQQQ')

    def __init__(self, data, offset=0):
        (self.isa, self.superclass, self.cache, self.vtable, self.info)\
            = struct.unpack_from('<QQQQQ', data, offset)


class Objc2ClassRo(object):
    length = struct.calcsize('<IIIIQQQQQQQ')

    def __init__(self, data, offset=0):
        self.flags, self.ivar_base_start, self.ivar_base_size, self.reserved, self.ivar_lyt, self.name, self.base_meths, self.base_prots, self.ivars, self.weak_ivar_lyt, self.base_props\
            = struct.unpack_from('<IIIIQQQQQQQ', data, offset)


class Objc2Method(object):
    length = struct.calcsize('<QQQ')

    def __init__(self, data, offset=0):
        self.name, self.types, self.imp = struct.unpack_from('<QQQ', data, offset)

def method_list(ea):
    if not ea:
        return

    for i in range(ida_bytes.get_dword(ea + 4)):
        ea_method_t = ea + 8 + i * Objc2Method.length
        data = ida_bytes.get_bytes(ea_method_t, Objc2Method.length)
        yield Objc2Method(data)


class Base(object):
    def __init__(self, name, ea):
        self.name = name
        self.ea = ea

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name}>"


class Clazz(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = {}


class Protocol(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = []


class ClassDump(object):
    def __init__(self, output=None, verbose=False):
        self.classes = []
        self.protocols = []
        self.class_lookup = {}
        self.protocol_lookup = {}
        self.lookup = {}
        self.output = output

    def parse(self):
        protocol_list_seg = ida_segment.get_segm_by_name('__objc_protolist')
        if protocol_list_seg:
            for ea in range(protocol_list_seg.start_ea, protocol_list_seg.end_ea, 8):
                self.handle_protocol(ea)

        class_list_seg = ida_segment.get_segm_by_name('__objc_classlist')
        if class_list_seg:
            for ea in range(class_list_seg.start_ea, class_list_seg.end_ea, 8):
                self.handle_class(ea)

    def handle_protocol(self, ea):
        protocol_ea = ida_bytes.get_qword(ea)
        p = parse_protocol(protocol_ea)
        self.protocols.append(p)
        self.protocol_lookup[p.name] = p
        self.lookup[ea] = p

    def handle_class(self, ea):
        clazz_ea = ida_bytes.get_qword(ea)
        c = parse_class(clazz_ea)
        self.classes.append(c)
        self.class_lookup[c.name] = c
        self.lookup[ea] = c


def parse_class(ea):
    clazz = Objc2Class(ida_bytes.get_bytes(ea, Objc2Class.length))
    clazz.info = (clazz.info >> 3) << 3
    clazz_info = Objc2ClassRo(ida_bytes.get_bytes(clazz.info, Objc2ClassRo.length))
    c = Clazz(cstr(clazz_info.name), ea)
    
    for method in method_list(clazz_info.base_meths):
        if not cstr(method.name):
            continue
        key = '- ' + cstr(method.name)
        c.methods[key] = method.imp
        
    meta_class = Objc2Class(ida_bytes.get_bytes(clazz.isa, Objc2Class.length))
    meta_class.info = (meta_class.info >> 3) << 3
    meta_info = Objc2ClassRo(ida_bytes.get_bytes(meta_class.info, Objc2ClassRo.length))

    for method in method_list(meta_info.base_meths):
        if not cstr(method.name):
            continue
        sel = '+ ' + cstr(method.name)
        c.methods[sel] = method.imp

    return c


def parse_protocol(ea):
    protocol_name = cstr(ida_bytes.get_qword(ea + 8))
    method_list_ea = ida_bytes.get_qword(ea + 3 * 8)
    p = Protocol(protocol_name, ea)

    for method in method_list(method_list_ea):
        if not cstr(method.name):
            continue
        sel = '- ' + cstr(method.name)
        p.methods.append(sel)

    return p
