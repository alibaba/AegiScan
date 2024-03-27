import idc
import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_xref

from libs.utils import is_dsc

def c(name):
    def code_refs(ea):
        for x in idautils.CodeRefsTo(ea, True):
            segm_name = idc.get_segm_name(x)
            if is_dsc():
                _, seg = segm_name.split(':')
            else:
                seg = segm_name

            if seg in ['__stubs', '__auth_stubs']:
                func = ida_funcs.get_func(x)
                if func:
                    yield from code_refs(func.start_ea)

            if seg == '__text':
                yield x

    ea = ida_name.get_name_ea(idc.BADADDR, '_' + name)
    if ea == idc.BADADDR:
        return

    if is_dsc() and not idc.get_segm_name(ea).endswith(':__text'):
        ea = next(x.to for x in idautils.XrefsFrom(ea, ida_xref.XREF_DATA))
        segm = idc.get_segm_name(ea)
        if segm.endswith('_got'):
            ea = ida_bytes.get_qword(ea)
        elif not segm.endswith(':__text'):
            print('unknown segment name %s' % segm)

    yield from code_refs(ea)


def selector(sel: str):
    if sel.startswith('+ ') or sel.startswith('- '):
        sel = sel[2:]

    if is_dsc():
        name = 'sel_%s' % sel
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        for x in idautils.DataRefsTo(ea):
            seg_name = idc.get_segm_name(x)
            if seg_name.endswith(':__text'):
                yield x

    name = 'selRef_%s' % sel
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    if ea == idc.BADADDR:
        return

    isdsc = is_dsc()
    if isdsc:
        ea = ida_bytes.get_qword(ea)

    for x in idautils.DataRefsTo(ea):
        seg_name = idc.get_segm_name(x)

        if isdsc:
            valid = seg_name.endswith(':__text')
        else:
            valid = (seg_name == '__text')

        if valid:
            yield x


def clazz(name, subclasses=True):
    prefix = '_OBJC_CLASS_$_'
    symbol = ida_name.get_name_ea(idc.BADADDR, prefix + name)

    for xref in idautils.DataRefsTo(symbol):
        if subclasses:
            symbol_name = ida_name.get_ea_name(xref)
            if symbol_name.startswith(prefix):
                yield from clazz(symbol_name[len(prefix):])

        if idc.get_segm_name(xref).endswith('__objc_classrefs'):
            for ea in idautils.DataRefsTo(xref):
                seg_name = idc.get_segm_name(ea)
                if seg_name.endswith('__text'):
                    yield ea
