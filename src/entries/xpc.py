import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_name

idaapi.require('libs.utils')
idaapi.require('visitors.unordered')
idaapi.require('visitors.simulation')

from libs.utils import genmc, has_macsdk, load_header, symbol
import visitors.unordered as vu
import visitors.simulation as vs
from collections import namedtuple

xpcSym = namedtuple('xpcSym', ['ea', 'name'])

set_handler = xpcSym(symbol('_xpc_connection_set_event_handler'), '_xpc_connection_set_event_handler')
create_service = xpcSym(symbol('_xpc_connection_create_mach_service'), '_xpc_connection_create_mach_service')
create_listener = xpcSym(symbol('_xpc_connection_create_listener'), '_xpc_connection_create_listener')


class NameFinder(vs.SimVisitor):
    def __init__(self, mba, target:xpcSym):
        super().__init__(mba)
        self.target = target
        self.names = set()

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Call) and expr.func.name == self.target.name and len(expr.args) > 1:
            arg0 = expr.args[0]
            if isinstance(arg0, vu.StringLiteral):
                self.names.add(str(arg0))
            elif isinstance(arg0, vu.LocalVar):
                if isinstance(self.local_vars.get(arg0.idx), vu.StringLiteral):
                    self.names.add(self.local_vars.get(arg0.idx))


class HandlerFinder(vu.Visitor):
    def __init__(self, mba):
        super().__init__(mba)

        # must run a pass first to resolve block literals
        self.sim = vs.SimVisitor(mba)
        self.handlers = set()

    def visit(self):
        self.sim.visit()
        super().visit()

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Call) and expr.func.name == '_xpc_connection_set_event_handler':
            if len(expr.args) < 2:  # invalid ast
                return expr

            block = expr.args[1]
            if isinstance(block, vu.LocalVar):
                block_info = self.sim.local_vars.get(block.idx)
                if isinstance(block_info, vu.StackBlock):
                    self.handlers.add(block_info.invoke)

            elif isinstance(block, vu.GlobalBlock):
                self.handlers.add(block.invoke)


def find_names():
    for creator in [create_listener, create_service]:
        if creator.ea == idc.BADADDR:
            continue

        for xref in idautils.CodeRefsTo(creator.ea, False):
            mba = genmc(xref)
            visitor = NameFinder(mba, creator)
            visitor.visit()
            yield from visitor.names


def find_handler_setters():
    if set_handler.ea == idc.BADADDR:
        return

    for xref in idautils.CodeRefsTo(set_handler.ea, False):
        yield ida_funcs.get_func(xref).start_ea


def find_event_handlers():
    if set_handler.ea == idc.BADADDR:
        return

    for xref in idautils.CodeRefsTo(set_handler.ea, False):
        mba = genmc(xref)
        visitor = HandlerFinder(mba)
        visitor.visit()
        yield from visitor.handlers

def xpc_entries():
    xpc_entries = set(find_event_handlers())
    xpc_fnames = [ida_name.get_ea_name(xpc_ea) for xpc_ea in xpc_entries]
    extra_setters = set()
    for handler in xpc_entries:
        if not list(idautils.DataRefsTo(handler)): continue
        xref = list(idautils.DataRefsTo(handler))[0]
        module_and_name = idc.get_segm_name(xref)
        if module_and_name == '__text':     # stackblock
            setter = ida_funcs.get_func(xref).start_ea
        elif module_and_name == '__const':  # globalblock
            if handler == ida_bytes.get_qword(xref + 0x10):
                setter = ida_funcs.get_func(list(idautils.DataRefsTo(xref))[0]).start_ea
        if setter not in xpc_entries:
            extra_setters.add(setter)
    xpc_entries.update(extra_setters)
            
    return xpc_entries, xpc_fnames
