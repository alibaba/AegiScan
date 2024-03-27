import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_range
import ida_nalt
import ida_name
import ida_segment
import ida_hexrays as hr
import ida_typeinf
import re


def genmc(ea, maturity=hr.MMAT_LVARS):
    # mark_stack_blocks(ea)
    f = ida_funcs.get_func(ea)
    if not f: return None
    if not ida_bytes.is_code(ida_bytes.get_flags(f.start_ea)):
        raise ValueError('invalid ea 0x%x' % ea)

    hf = hr.hexrays_failure_t()
    mbr = hr.mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(f.start_ea, f.end_ea))
    mba = hr.gen_microcode(mbr, hf, None, hr.DECOMP_WARNINGS |
                           hr.DECOMP_NO_CACHE, maturity)
    return mba

def escape_selector(selector: str):
    def escape(name: str):
        return 'selRef_%s' % name

    if selector.startswith('+ ') or selector.startswith('- '):
        return escape(selector[2:])

    return escape(selector)

def mark_stack_blocks(ea):
    run_objc_plugin(ea, 5)


def has_macsdk():
    import subprocess
    from pathlib import Path
    try:
        s = subprocess.check_output(
            ['xcrun', '--show-sdk-path']).strip().decode()
        return Path(s).exists()
    except:
        return False


def load_header():
    # load function prototypes
    if idaapi.IDA_SDK_VERSION < 750 or not has_macsdk():
        from pathlib import Path
        header = str(Path(__file__).parent.parent /
                     'IDAObjcTypes' / 'IDA.h')
        idaapi.idc_parse_types(header, idc.PT_FILE)


def cstr(ea):
    try:
        return ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C).decode()
    except Exception as e:
        print('Unable to decode string at %s' % hex(ea))
        return None


def symbol(name):
    return ida_name.get_name_ea(idc.BADADDR, name)


def is_class_ref(ea):
    # todo: dsc
    for xref in idautils.DataRefsTo(ea):
        seg = ida_segment.getseg(xref)
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name == '__objc_classrefs':
            return True

    return False


# TODO:error designing here
def is_imported_class_ref(ea):
    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg)
    return seg_name == 'UNDEF'


def classname(op):
    # todo: check op type
    ea = op.g
    if is_class_ref(ea) or is_imported_class_ref(ea):
        return ida_name.get_ea_name(ea)[len('_OBJC_CLASS_$_'):]


def rule(name: str):
    import yaml
    from pathlib import Path
    filename = Path(__file__).parent.parent / 'rules' / (name + '.yaml')
    with filename.open() as fp:
        return yaml.load(fp, Loader=yaml.FullLoader)


def is_dsc():
    return bool(ida_segment.get_segm_by_name('Foundation:__objc_selrefs'))


'''
Example for summary (en/de)coder
[6,2,4,6] means:
       ret recv arg0 arg1
ret     0    0    0    0  (always 0)
recv    1    0    1    1
arg0    1    1    0    1
arg1    0    0    0    0
sum     6    2    4    6
The metric indicates:
* ret(0) is effected by recv(1) and arg0(2)
* recv(1) is effected by arg0(2)
* arg0(2) is effected by recv(1)
* arg1(3) is effected by recv(1) and arg0(2)
'''

def encode_summary(dep : dict) -> list:
    summary = []
    l = len(dep.keys())
    for _, vars in dep.items():
        tmp = 0
        for var in vars:
            tmp += 2**(l-var-1)
        summary.append(tmp)
    
    return summary


def decode_summary(summary : list) -> dict:
    l = len(summary) - 1
    dep = {}
    for i in range(len(summary)):
        dep[i] = []
        item = f"{{:0{l}b}}".format(summary[i])
        for j in range(l):
            if int(item[j]):
                dep[i].append(j+1)
    
    return dep


nullability_annotations = [
    'nonnull',
    'nullable',
    '__nonnull',
    '__nullable',
    '_Nonnull',
    '_Nullable'
]


def tp_sanitizer(tp : str) -> str:
    if not tp: return
    if not isinstance(tp, str): return
    if 'const' in tp:
        tp = ''.join(tp.split('const'))
    for anno in nullability_annotations:
        if anno not in tp: continue
        tp = ''.join(tp.split(anno))
        break
    # Fill out conformed protocol, e.g., 'id<NSCopying>', 'NSDictionary<KeyType, ObjectType>'
    if "<" in tp:
        tp = tp[:tp.index("<")]
    # No need for pointer, e.g., 'NSFastEnumerationState *'
    if "*" in tp:
        tp = tp[:tp.index("*")-1]
    tp = tp.replace(' ', '')
    if tp in ['ObjectType', 'KeyType', 'id']:
        return None
    if tp.endswith('_meta'):
        tp = tp[:-5]
    return tp


def run_objc_plugin(ea, opt):
    '''
    opt = 1: parse all Objective-C type information embedded in the binary
    opt = 2: calculate the address of method that is being invoked
    opt = 3: analyze objc info for a specific library
    opt = 4: perform global block analysis on a specific function
    opt = 5: perform stack block analysis on a specific function
    '''
    n = idaapi.netnode()
    n.create("$ objc")
    n.altset(1, ea, 'R')
    ret = idaapi.load_and_run_plugin("objc", opt)
    return ret


def get_summary(summary_set:dict, fname:str):
    if fname in summary_set:
        return summary_set.get(fname)
    placeholder = "UNKNOWN"
    prefix = fname.split(' ')[0].split('[')[0] + placeholder
    unk_fname = ''.join([prefix, fname.split(' ')[-1]])
    if unk_fname in summary_set:
        return summary_set.get(unk_fname)
    
    return None


def arr2set(arr):
    s = set(map(symbol, arr))
    if idc.BADADDR in s:
        s.remove(idc.BADADDR)
    return s


# allocators = arr2set(objc_cls_alloc)
# arc = arr2set(objc_ret_as_is)

def scan_seg4cstr(start_ea, end_ea):
    ret = {}
    cursor = start_ea
    while cursor < end_ea:
        content = ida_bytes.get_strlit_contents(cursor, -1, ida_nalt.STRTYPE_C)
        if not content:
            cursor += 1
            continue
        try:
            strlit = content.decode()
            ret[cursor] = strlit
            cursor = cursor + len(strlit) + 1
        except:
            cursor += (len(content)+1)
    return ret   


def get_cstrings():
    cstr_map = {}
    for segname in ["__cstring", "_D_cstring", "__objc_methname", "_D_objc_methname", "_l_objc_methname", "_l_objc_methname_2"]:
        # dcstr_seg = ida_segment.get_segm_by_name("_D_cstring")
        seg = ida_segment.get_segm_by_name(segname)
        if seg:
            cstr_map.update(scan_seg4cstr(seg.start_ea, seg.end_ea))
    
    return cstr_map


def get_cfstrings():
    def scan_cfstrings(start_ea, end_ea):
        ret = {}
        cstr_seg = ida_segment.get_segm_by_name("__cstring")
        dcstr_seg = ida_segment.get_segm_by_name("_D_cstring")
        ustr_seg = ida_segment.get_segm_by_name("__ustring")
        dustr_seg = ida_segment.get_segm_by_name("_D_ustring")
        bss_seg = ida_segment.get_segm_by_name("__bss")
        cursor = start_ea
        while cursor < end_ea:
            data = ida_bytes.get_qword(cursor+0x10)
            if cstr_seg.contains(data) or (dcstr_seg and dcstr_seg.contains(data)):
                content = ida_bytes.get_strlit_contents(data, -1, ida_nalt.STRTYPE_C)
                if content:
                    strlit = content.decode()
                    ret[cursor] = strlit
                else:
                    for i in range(0x20):
                        data += 1
                        content = ida_bytes.get_strlit_contents(data, -1, ida_nalt.STRTYPE_C)
                        if content:
                            strlit = content.decode()
                            ret[cursor] = strlit
                            break
                    if not ret.get(cursor):
                        print(f"Emtpy cstring item: {hex(cursor)}")
            elif ustr_seg and ustr_seg.contains(data):
                length = 0
                ptr = data
                while True:
                    if (ida_bytes.get_bytes(ptr, 2) == b"\x00\x00"):
                        length += ptr - data
                        break
                    ptr += 2
                if ida_bytes.get_bytes(data, length):
                    strlit = ida_bytes.get_bytes(data, length).decode('utf-16')
                    ret[cursor] = strlit
            elif dustr_seg and dustr_seg.contains(data):
                pass
            elif bss_seg.contains(data):
                pass
            else:
                pass
                    
            cursor += 0x20
        return ret
    
    cfstr_map = {}
    cfstr_seg = ida_segment.get_segm_by_name("__cfstring")
    dcfstr_seg = ida_segment.get_segm_by_name("_D_cfstring")
    cfstr_map.update(scan_cfstrings(cfstr_seg.start_ea, cfstr_seg.end_ea))
    if dcfstr_seg:
        cfstr_map.update(scan_cfstrings(dcfstr_seg.start_ea, dcfstr_seg.end_ea))
    
    return cfstr_map
    

def get_ustrings():
    ustr_map = {}
    seg = ida_segment.get_segm_by_name("__ustring")
    if not seg:
        return ustr_map
    cursor = seg.start_ea
    while cursor < seg.end_ea:   
        length = 0
        ptr = cursor
        while True:
            if (ida_bytes.get_bytes(ptr, 2) == b"\x00\x00"):
                length += ptr - cursor
                break
            ptr += 2
        strlit = ida_bytes.get_bytes(cursor, length).decode('utf-16')
        ustr_map[cursor] = strlit
        cursor = cursor + length + 2
    
    return ustr_map


def search_inherent(orig):
    family = [orig]
    for i in range(ida_typeinf.get_ordinal_qty(None)):
        struc = ida_typeinf.idc_get_local_type(i, -1)
        if not struc: 
            continue
        for parent in family:
            if f"{parent} super" in struc:
                son = ida_typeinf.idc_get_local_type_name(i)
                family.append(son)
    
    return family

def get_segname(ea):
    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg)
    return seg_name


def find_selref(sel):
    selref = escape_selector(sel)
    ea = ida_name.get_name_ea(idc.BADADDR, selref)
    if ea != idc.BADADDR:
        return selref, hex(ea)
    
    return None, None

def find_sel_usage(sel):
    usage = set()
    selref = find_selref(sel)
    if not selref[1]:
        return usage
    for ea in idautils.DataRefsTo(int(selref[1], 16)):
        if (get_segname(ea) in ['__text']) and ida_funcs.get_func(ea):
            usage.add(ida_funcs.get_func(ea).start_ea)
        elif (get_segname(ea) in ['__objc_stubs']) and ida_name.get_ea_name(ea).startswith('_objc_msgSend$'):
            stub_ea = ida_funcs.get_func(ea).start_ea
            for cref in idautils.CodeRefsTo(stub_ea, 1):
                if (get_segname(cref) in ['__text']) and ida_funcs.get_func(cref):
                    usage.add(ida_funcs.get_func(cref).start_ea)
    
    return usage

def search_str(s):
    cstr_map = get_cstrings()
    cfstr_map = get_cfstrings()
    cstrs, cfstrs = [], []
    for k, v in cstr_map.items():
        if v == s:
           cstrs.append(k) 
    for k, v in cfstr_map.items():
        if v == s:
            cfstrs.append(k)
    
    return cstrs, cfstrs    

def filter_by_str(target):
    usage = set()
    cstrs, cfstrs = search_str(target)
    strs = set.union(set(cstrs), set(cfstrs))
    for s in strs:
        for ea in idautils.DataRefsTo(s):
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name in ['__text'] and ida_funcs.get_func(ea):
                usage.add(ida_funcs.get_func(ea).start_ea)
                
    return usage

def get_meth_impl_map():
    meth_name_map = {} # ea : name
    meth_impl_map = {}
    for segname in ["__objc_methname", "_D_objc_methname", "_l_objc_methname", "_l_objc_methname_2"]:
        seg = ida_segment.get_segm_by_name(segname)
        if seg:
            meth_name_map.update(scan_seg4cstr(seg.start_ea, seg.end_ea))
    
    for sel_ea, sel_value in meth_name_map.items():
        for ea in idautils.DataRefsTo(sel_ea):
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name in ['__objc_const', '_D_objc_const'] and ida_bytes.get_qword(ea+0x10):
                impl_ea = ida_bytes.get_qword(ea+0x10)
                fullname = ida_name.get_ea_name(impl_ea)
                meth_impl_map[fullname] = impl_ea
    
    return meth_impl_map

def filter_meth_by_hint(hint):
    meth_impl_map = get_meth_impl_map()
    ret = {}
    for meth, impl in meth_impl_map.items():
        if re.match(hint, meth):
            ret[meth] = impl
    
    return ret

def find_impl_by_sel(sel):
    cstr_map = get_cstrings()
    cstr_ea = None
    for k, v in cstr_map.items():
        if v == sel:
            cstr_ea = k
            break
    if not cstr_ea:
        return None, None
    for usage in list(idautils.DataRefsTo(cstr_ea)):
        seg = ida_segment.getseg(usage)
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in ['__objc_const', '_D_objc_const'] and ida_bytes.get_qword(usage+0x10):
            impl_ea = ida_bytes.get_qword(usage+0x10)
            fullname = ida_name.get_ea_name(impl_ea)
            return fullname, impl_ea # TODO: maybe more
    
    return None, None

def get_cstr_usage(strea):
    usage = set()
    for ea in list(idautils.DataRefsTo(strea)):
        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in ['__cfstring', '_D_cfstring']:
            for _ in list(idautils.DataRefsTo(ea)):
                seg = ida_segment.getseg(_)
                seg_name = ida_segment.get_segm_name(seg)
                if seg_name in ['__text'] and ida_funcs.get_func(_):
                    usage.add(ida_funcs.get_func(_).start_ea)
                elif seg_name in ['__const', '_D_const']:
                    for sub_ in list(idautils.DataRefsTo(_)):
                        sub_seg = ida_segment.getseg(sub_)
                        sub_seg_name = ida_segment.get_segm_name(sub_seg)
                        if sub_seg_name in ['__text'] and ida_funcs.get_func(sub_):
                            usage.add(ida_funcs.get_func(sub_).start_ea)
        elif seg_name in ['__text'] and ida_funcs.get_func(ea):
            usage.add(ida_funcs.get_func(ea).start_ea)
    
    return usage

def get_all_str():
    cstr_map = get_cstrings()
    cfstr_map = get_cfstrings()
    str_map = {}
    str_map.update(cstr_map)
    str_map.update(cfstr_map)
    
    return str_map