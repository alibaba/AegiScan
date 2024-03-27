import idc
import idaapi
import idautils
import ida_bytes
import ida_name
import ida_segment

idaapi.require('libs.utils')
idaapi.require('libs.hint')
idaapi.require('libs.classdump')
idaapi.require('visitors.unordered')
idaapi.require('visitors.simulation')

from libs.utils import genmc, cstr, classname
from libs.hint import objc_ret_as_is
from libs.classdump import parse_protocol
import visitors.unordered as vu
import visitors.simulation as vs
from visitors.sideeffects import WriteOnceDetection, SideEffectsRecorder


class NSXPCService:
    def __init__(self, name):
        self.name = name


class ListenerProtocol:
    def __init__(self, ea):
        self.ea = ea
        self.name = ida_name.get_ea_name(ea)[len('_OBJC_PROTOCOL_$_'):]

    def __repr__(self):
        return '<ListenerProtocol %s>' % self.name


class AuthVisitor(vs.SimVisitor):
    def __init__(self, mba, clazz):
        super().__init__(mba)
        self.side_effects = SideEffectsRecorder(mba).parse()
        self.exported_obj = None
        self.exported_interface = None
        self.protocols = {}

    def visit_top_insn(self, insn):
        expr = super().visit_top_insn(insn)
        if isinstance(expr, vu.Assign) and isinstance(expr.dest, vu.LocalVar):
            detector = WriteOnceDetection(
                self.mba, self.side_effects, expr.dest.idx)
            if not detector.check(self.cur_block):
                return expr

            if isinstance(expr.source, vu.LocalVar) and expr.source.idx in self.protocols:
                self.protocols[expr.dest.idx] = self.protocols.get(expr.source.idx)
            elif isinstance(expr.source, ListenerProtocol):
                self.local_types[expr.dest.idx] = 'NSXPCInterface'
                self.protocols[expr.dest.idx] = expr.source
            elif isinstance(expr.source, vu.Call) and expr.source.func.name in objc_ret_as_is:
                arg0 = expr.source.args[0]
                if isinstance(arg0, vu.LocalVar) and arg0.idx in self.protocols:
                    self.protocols[expr.dest.idx] = self.protocols.get(arg0.idx)

        # todo: decorator
        return expr

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Msg):
            sel = expr.selector.name
            if sel == 'interfaceWithProtocol:' and classname(expr.receiver.raw):
                ea = expr.args[0].ea
                return ListenerProtocol(ea)

            if sel == 'setExportedObject:':
                # todo: receiver
                t = self.local_types.get(expr.args[0].idx)
                try: 
                    self.exported_obj = t.get_pointed_object()
                except:
                    self.exported_obj = t

            if sel == 'setExportedInterface:':
                self.exported_interface = self.protocols.get(expr.args[0].idx)

            # todo: sink
            if sel == 'processIdentifier':
                print('access to pid found', hex(insn.ea))

        return expr


class DelegateFinderVisitor(vs.SimVisitor):
    services = {}
    delegates = {}
    justServices = set()

    def visit_top_insn(self, insn):
        expr = super().visit_top_insn(insn)
        if isinstance(expr, vu.Assign) and isinstance(expr.source, NSXPCService):
            index = expr.dest.idx
            self.services[index] = expr.source.name
            self.local_types[index] = 'NSXPCListener'

        return expr

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Msg) and isinstance(expr.receiver, vu.LocalVar):
            index = expr.receiver.idx
            if self.local_types.get(index) == 'NSXPCListener':
                if expr.selector.name == 'initWithMachServiceName:':
                    p = ida_bytes.get_qword(expr.args[0].ea + 0x10)
                    name = cstr(p)
                    self.justServices.add(name)
                    return NSXPCService(name)

                if expr.selector.name == 'setDelegate:':
                    self.delegates[index] = self.local_types.get(expr.args[0].idx)
        
        if isinstance(expr, vu.Call) and (expr.name=='_sandbox_init_with_parameters'):
            if isinstance(expr.args[0], vu.StringLiteral):
                name = expr.args[0].str
                self.justServices.add(name)
                return NSXPCService(name)

        return expr
    

def find_service_name():
    clazz_listener = ida_name.get_name_ea(
    idc.BADADDR, '_OBJC_CLASS_$_NSXPCListener')

    try:
        clazz_listener_ref = next(
            xref for xref in idautils.DataRefsTo(clazz_listener) if
            ida_segment.get_segm_name(ida_segment.getseg(xref)) == '__objc_classrefs')
    except StopIteration:
        return []

    names = []

    for xref in idautils.DataRefsTo(clazz_listener_ref):
        mba = genmc(xref)
        visitor = DelegateFinderVisitor(mba)
        visitor.visit()
        # names.extend(list(visitor.services.values()))
        names.extend(list(visitor.justServices))
        names = list(set(names))
    
    return names


def find_authenticator():
    clazz_listener = ida_name.get_name_ea(
        idc.BADADDR, '_OBJC_CLASS_$_NSXPCListener')

    try:
        clazz_listener_ref = next(
            xref for xref in idautils.DataRefsTo(clazz_listener) if
            ida_segment.get_segm_name(ida_segment.getseg(xref)) == '__objc_classrefs')
    except StopIteration:
        return []

    auths = []

    for xref in idautils.DataRefsTo(clazz_listener_ref):
        mba = genmc(xref)
        visitor = DelegateFinderVisitor(mba)
        visitor.visit()

        # print(f"Delegates found: {visitor.delegates.values()}\n\n")
        
        for delegate in visitor.delegates.values():
            method = '-[%s listener:shouldAcceptNewConnection:]' % delegate
            authenticator = ida_name.get_name_ea(idc.BADADDR, method)
            auths.append((delegate, authenticator))
    
    return auths


def find_nsxpc():
    for delegate, authenticator in find_authenticator():
        mba = genmc(authenticator)
        av = AuthVisitor(mba, delegate)
        av.visit()
        if av.exported_obj and av.exported_interface:
            p = parse_protocol(av.exported_interface.ea)
            for method in p.methods:
                name = '-[%s %s]' % (av.exported_obj, method[len(' -'):])
                ea = ida_name.get_name_ea(idc.BADADDR, name)
                if ea != idc.BADADDR:
                    yield ea 

def nsxpc_entries():
    nsxpc_entries = set(find_nsxpc())
    nsxpc_fnames = [ida_name.get_ea_name(nsxpc_ea) for nsxpc_ea in nsxpc_entries]
    if nsxpc_entries:
        auths = find_authenticator()
        if auths:
            for _, authenticator in auths:
                nsxpc_entries.add(authenticator)
    
    return nsxpc_entries, nsxpc_fnames
