import idc
import idaapi
import idautils
import ida_name
import ida_bytes

idaapi.require('models.graph')
idaapi.require('libs.utils')
idaapi.require('visitors.unordered')

from libs.utils import rule, is_dsc

def escape_selector(selector: str):
    def escape(name: str):
        return 'selRef_%s' % name

    if selector.startswith('+ ') or selector.startswith('- '):
        return escape(selector[2:])

    return escape(selector)


def objc_sinks():
    sink_objc = rule('objc')

    # check dyld_shared_cache
    dsc = is_dsc()
    for clazz, rules in sink_objc.items():
        if ida_name.get_name_ea(idc.BADADDR, 'classRef_%s' % clazz) == idc.BADADDR:
            continue

        for selector, args in rules.items():
            name = escape_selector(selector)
            ea = ida_name.get_name_ea(idc.BADADDR, name)
            if ea != idc.BADADDR:
                if dsc:
                    ea = ida_bytes.get_qword(ea)

                xrefs = [x for x in idautils.DataRefsTo(ea)]

                # xrefs = [x for x in idautils.DataRefsTo(ea) if
                #          ida_segment.getseg(x).perm & ida_segment.SEGPERM_EXEC]

                yield clazz, selector, ea, xrefs, args


def c_sinks():
    dsc = is_dsc()

    for dylib, rules in rule('c').items():
        for name, args in rules.items():
            ea = ida_name.get_name_ea(idc.BADADDR, '_%s' % name)
            if ea == idc.BADADDR:
                continue

            xrefs = list(idautils.CodeRefsTo(ea, False))
            yield name, ea, xrefs, args
 

def get_oc_sinks_map():
    sink_objc = rule('objc')
    sinks = {}
    for clazz, sels in sink_objc.items():
        for sel, args in sels.items():
            name = f"{sel[0]}[{clazz} {sel[2:]}]"
            sinks[name] = args

    return sinks


def get_c_sinks_map():
    sinks = {}
    for rules in rule('c').values():
        for fname, args in rules.items():
            sinks[f"_{fname}"] = args

    return sinks
