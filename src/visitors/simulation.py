import idaapi
import ida_hexrays as hr
import ida_name
import idc
import idautils

idaapi.require('visitors.unordered')
idaapi.require('visitors.sideeffects')
idaapi.require('libs.utils')
idaapi.require('libs.hint')

from .unordered import Clazz, FakeClazz, FakeRaw_GL, FakeRaw_NC, Selector, Visitor, Assign, Arith, Msg, Call, Jmp, HelperFunc, GlobalLiteral, LocalVar, StackVar, NumConst, StackBlock, BlockByref, Factory, MemOp, Load, Store, MemObj, CFString, Op, AssamVisitor, Result, StkInvoke
from .sideeffects import SideEffectsRecorder, WriteOnceDetection
from libs.utils import classname, symbol, rule, tp_sanitizer
import libs.hint


class SimVisitor(Visitor):
    stack_block_isa = symbol('__NSConcreteStackBlock')
    proto_types = rule('proto')

    def __init__(self, mba):
        super().__init__(mba)
        if mba:
            self.side_effects = SideEffectsRecorder(mba).parse()
        self.local_types = {}
        self.local_vars = {}
        self.const_vars = {}
        self.stk_layout = {}
        self.alias_map = {}
        self.snapshot = None 
        if mba:
            self.fname = ida_name.get_ea_name(mba.entry_ea)
            self.get_arg_types()

    def get_arg_types(self):
        for i in self.mba.argidx:
            arg = self.mba.arg(i)
            t, n = arg.type(), arg.name
            if self.fname.startswith(('+', '-')) and (i==0):
                lt = self.fname.split(' ')[0][2:]
            else: 
                if str(t) in ['SEL', 'id', 'void']: continue
                if str(t).startswith('_'): continue # e.g., _QWORD
                if t.is_ptr():
                    lt = str(t.get_pointed_object())
                else:
                    lt = str(t)
                if lt.endswith('_meta'):
                    lt = lt[:-5]
            idx = list(self.mba.vars).index(arg)
            self.local_types[idx] = lt
    
    def update_local_types(self, lv:int, tp:str):
        tp = tp_sanitizer(tp)
        if not tp: return
        if lv==0: return # do not overwrite self type
        self.local_types[lv] = tp
        alias = lv
        while alias in self.alias_map:
            alias = self.alias_map.get(alias)
            self.local_types[alias] = tp
            if alias == self.alias_map.get(alias):
                break
    
    def visit_top_insn(self, insn):
        # print(insn.ea, insn._print())
        def assign_to_stkblk(stkblk:StackBlock, offset:int, var):
            if isinstance(var, LocalVar):
                if (var.idx in self.local_vars) and isinstance(self.local_vars.get(var.idx), BlockByref):
                    stkblk.assign(offset, self.local_vars.get(var.idx))
                else:
                    stkblk.assign(offset, var)
                    if var.idx in self.local_types:
                        stkblk.assign(offset, self.local_types.get(var.idx))
            elif isinstance(var, MemObj):
                if isinstance(var.base, LocalVar) and (var.base.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(var.base.idx), StackBlock): # Now only support stkblk
                    val, tp = self.local_vars.get(var.base.idx).load(var.off)
                else:
                    val, tp = var.val, var.type
                stkblk.assign(offset, val)
                stkblk.assign(offset, tp)
            else:
                stkblk.assign(offset, var)
 
            lv, lt = stkblk.load(offset)
            return MemObj(stkblk, offset, '+', lt, lv)

        expr = super().visit_top_insn(insn)

        # Transfer load and store expr into assignment
        if isinstance(expr, MemOp):
            if isinstance(expr.base, LocalVar) and (expr.base.idx in self.local_vars):
                if isinstance(self.local_vars.get(expr.base.idx), StackBlock): # Now only support it
                    expr.base = self.local_vars.get(expr.base.idx)
            if expr.memobj:
                if isinstance(expr, Load):
                    expr = Assign(expr.memobj, expr.dest)
                elif isinstance(expr, Store):
                    expr = Assign(expr.source, expr.memobj) #TODO: here to tag global memory object
        
        elif isinstance(expr, Assign) and isinstance(expr.source, Arith) and not(expr.source.dest):
            expr.source.dest = expr.dest
            expr = expr.source

        # Exclude the expr which is not an assignment
        if not isinstance(expr, Assign):
            if isinstance(expr, Call) and (expr.func.name in libs.hint.objc_ret_as_is):
                source = expr.args[0]
                if insn.d.f.retregs.size():
                    dest = self.visit_op(list(insn.d.f.retregs)[0])
                    expr = Assign(source, dest)
                else:
                    return expr
            else:
                return expr

        # Deal with Call/Msg to get the truly source
        if isinstance(expr.source, Call):
            if expr.source.func.name in libs.hint.objc_ret_as_is:
                while isinstance(expr.source, Call) and expr.source.func.name in libs.hint.objc_ret_as_is:
                    expr.source = expr.source.args[0]
                if isinstance(expr.source, LocalVar) and isinstance(expr.dest, LocalVar):
                    self.alias_map[expr.dest.idx] = expr.source.idx
                else:
                    pass#TODO
                        
            elif expr.source.func.name in libs.hint.objc_weak_ret:
                arg = expr.source.args[0]
                if isinstance(arg, Arith) and not(arg.dest):
                    if isinstance(arg.left, LocalVar):
                        if (arg.left.idx in self.local_vars) \
                            and isinstance(self.local_vars.get(arg.left.idx), StackBlock):
                            base = self.local_vars.get(arg.left.idx)
                            if isinstance(arg.right, NumConst):
                                off = arg.right.val
                                val, tp = base.load(off)
                                expr.source = MemObj(base, off, '+', tp, val)
                        else:
                            base = arg.left
                            if isinstance(arg.right, NumConst):
                                off = arg.right.val
                                expr.source = MemObj(base, off, arg.tp, None, None)
            else:
                pass
        
        # Deal with memobj represented by arith without load
        if isinstance(expr.dest, Arith) and not(expr.dest.dest):
            arg = expr.dest
            if isinstance(arg.left, LocalVar):
                if (arg.left.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(arg.left.idx), StackBlock):
                    base = self.local_vars.get(arg.left.idx)
                    if isinstance(arg.right, NumConst):
                        off = arg.right.val
                        val, tp = base.load(off)
                        expr.dest = MemObj(base, off, '+', tp, val)
                else:
                    base = arg.left
                    if isinstance(arg.right, NumConst):
                        off = arg.right.val
                        expr.dest = MemObj(base, off, expr.dest.tp, None, None)

        if isinstance(expr.dest, StackBlock):
            offset = expr.dest.raw.l.off
            expr.dest.assign(offset, expr.source)
            if isinstance(expr.source, LocalVar) and expr.source.idx in self.local_types:
                expr.dest.assign(offset, self.local_types.get(expr.source.idx))
            elif isinstance(expr.source, MemObj):
                expr.dest.assign(offset, expr.source.type)
            lv, lt = expr.dest.load(offset)
            expr.dest = MemObj(expr.dest, offset, '+', lt, lv)

        elif isinstance(expr.dest, LocalVar):                
            # In case IDA fails to identify a lvar which causes a new stackVar used (ida7.5 has such a problem)
            if isinstance(self.snapshot, StackBlock) and (expr.dest.var.get_stkoff() >= self.snapshot.stkoff):
                offset = expr.dest.var.get_stkoff() - self.snapshot.stkoff
                expr.dest = assign_to_stkblk(self.snapshot, offset, expr.source)
                # print(f"loc-1: {self.cur_block}, {self.snapshot}, {offset}, {expr}")
            
            elif isinstance(expr.source, (GlobalLiteral, Selector)):
                # A StackBlock starts to be assigned
                if expr.source.ea == self.stack_block_isa:
                    layout = str(list(self.mba.vars)[expr.dest.idx].type())
                    if not layout.startswith('Block_layout_'):
                        layout = f"Block_layout_{hex(insn.ea)[2:].upper()}"
                    self.local_types[expr.dest.idx] = layout
                    expr.dest.local_type = layout
                    stkblk = StackBlock(expr.dest.idx, layout)
                    stkblk.stkoff = expr.dest.var.get_stkoff()
                    self.local_vars[expr.dest.idx] = stkblk
                    self.snapshot = stkblk
                else:
                    self.local_vars[expr.dest.idx] = expr.source
                    expr.dest.local_type = self.type_infer(expr.source)
                    self.update_local_types(expr.dest.idx, expr.dest.local_type)
            
            elif isinstance(expr.source, MemObj):
                if isinstance(expr.source.base, LocalVar) and (expr.source.base.idx in self.local_vars):
                    var = self.local_vars.get(expr.source.base.idx)
                    if isinstance(var, (GlobalLiteral, Selector)) and var.ea:
                        if expr.source.opt and isinstance(expr.source.off, int) :
                            ea = eval(f"{self.local_vars.get(expr.source.base.idx).ea}{expr.source.opt}{expr.source.off}")
                            self.local_vars[expr.dest.idx] = Factory.make_global(FakeRaw_GL(6, ea))
                    elif isinstance(var, StackBlock) and isinstance(expr.source.base, StackVar) and expr.source.base.layout:
                        stkblk = var
                        lv, lt = stkblk.load(expr.source.base.layout)
                        expr.source = lv
                        if isinstance(lv, LocalVar):
                            if expr.dest.idx in self.local_vars:
                                self.local_vars.pop(expr.dest.idx)
                            if lv.idx in self.local_vars:
                                self.local_vars[expr.dest.idx] = self.local_vars.get(lv.idx)
                            expr.dest.local_type = self.type_infer(lv)
                            self.update_local_types(expr.dest.idx, expr.dest.local_type)

            elif isinstance(expr.source, LocalVar):
                if expr.dest.idx in self.local_vars:
                    self.local_vars.pop(expr.dest.idx)
                if expr.source.idx in self.local_vars:
                    self.local_vars[expr.dest.idx] = self.local_vars.get(expr.source.idx)
                expr.dest.local_type = self.type_infer(expr.source)
                self.update_local_types(expr.dest.idx, expr.dest.local_type)

            elif isinstance(expr.source, StackBlock):
                if expr.source.layout == self.local_types[0]:
                    self.local_vars[expr.dest.idx] = self.local_vars.get(0)
                else:
                    self.local_vars[expr.dest.idx] = self.local_vars.get(expr.source.idx)
                    
            elif isinstance(expr.source, NumConst):
                if (expr.dest.idx in self.local_vars) and isinstance(self.local_vars.get(expr.dest.idx), GlobalLiteral):
                    if self.local_vars.get(expr.dest.idx).ea == expr.source.val:
                        pass # Don't fresh loval_vars
                self.const_vars[expr.dest.idx] = expr.source
            
            else:
                expr.dest.local_type = self.type_infer(expr.source)
                self.update_local_types(expr.dest.idx, expr.dest.local_type)
                if expr.dest.idx in self.local_vars:
                    self.local_vars.pop(expr.dest.idx)
                    # print(f"[*]Debug: {expr}@{self.cur_block} pop-2 local_var dict {self.local_vars}")

        elif isinstance(expr.dest, MemObj):
            # Deal with memobj on the stack (e.g., stackblock, array)
            if isinstance(expr.dest.base, StackVar) and expr.dest.base.layout:
                base = expr.dest.base
                if base.idx in self.local_vars:
                    if not base.idx in self.stk_layout:
                        self.stk_layout[base.idx] = {}
                        self.stk_layout[base.idx][0] = self.local_vars.get(base.idx)
                    if isinstance(expr.source, (NumConst, GlobalLiteral, Selector)):
                        self.stk_layout[base.idx][base.layout] = expr.source
                    elif isinstance(expr.source, LocalVar) and expr.source.idx in self.local_vars:
                         self.stk_layout[base.idx][base.layout] = self.local_vars.get(expr.source.idx)
            
                if isinstance(self.local_vars.get(base.idx), StackBlock) and isinstance(self.snapshot, StackBlock):
                    stkblk = self.local_vars.get(base.idx)
                    offset = expr.dest.base.layout
                    expr.dest = assign_to_stkblk(stkblk, offset, expr.source)
                    # print(f"loc-2: {self.cur_block}, {self.snapshot}, {offset}, {expr}")                    
            
        return expr

    def visit_op(self, op):
        '''
        Since the local variables can be reused, we can not replace
        all of them by the value in local_val
        '''
        ret = super().visit_op(op)
        if isinstance(ret, LocalVar):
            if ret.idx in self.local_types:
                ret.local_type = self.local_types.get(ret.idx)
            # elif ret.idx in self.const_vars:
            #     ret = self.const_vars[ret.idx]
        
        return ret

    def visit_insn(self, insn):
        '''
        Deal with specific insn apart first, i.e., sel not Selector but regs or other types.
        '''
        def set_sel(args):
            if isinstance(args[1], LocalVar):
                if args[1].idx in self.local_vars:
                    sel = self.local_vars[args[1].idx]
                    args[1] = sel
            elif isinstance(args[1], MemObj) and (args[1].off == 0) and (args[1].base.idx in self.local_vars) \
                and isinstance(self.local_vars.get(args[1].base.idx), Selector):
                sel = self.local_vars.get(args[1].base.idx)
                args[1] = sel
            elif isinstance(args[1], Selector) and args[1].name.startswith("performSelector:"):
                refactor = False
                # print(f"args are changed from {args}")
                if isinstance(args[2], Selector):
                    refactor = True
                elif isinstance(args[2], MemObj) and isinstance(args[2].base, StackBlock):
                    stkblk, off = args[2].base, args[2].off
                    sel = stkblk.load(off)[0]
                    if isinstance(sel, Selector):
                        args[2] = sel
                        refactor = True
                if refactor:
                    arg_num = min(args[1].name.count(':')-1, len(args)-3)
                    args[1] = args[2]
                    for i in range(arg_num):
                        args[i+2] = args[i+3]
                        a = [1,2]
                    args.pop()
                # print(f"args are changed to {args}")
        
        expr = None

        if insn.opcode == hr.m_call:
            func = self.visit_op(insn.l)
            if isinstance(func, (GlobalLiteral, HelperFunc)) and func.name.startswith('_objc_msgSend'):
                args = self.visit_op(insn.d)
                set_sel(args)
                for arg in args:
                    if isinstance(arg, LocalVar) and isinstance(self.local_vars.get(arg.idx), StackBlock) and isinstance(self.snapshot, StackBlock):
                        self.snapshot = None
                    elif isinstance(arg, MemObj) and isinstance(arg.base, LocalVar) and isinstance(self.local_vars.get(arg.base.idx), BlockByref):
                        arg.base = self.local_vars.get(arg.base.idx)
                        
                expr = Factory.make_call(func, args, insn.ea)
                if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
                    ret_type = self.infer_within_msg(expr)
                    if ret_type: expr.ret_type = ret_type

            elif isinstance(func, (GlobalLiteral, HelperFunc)) and \
                ((func.name in libs.hint.objc_weak_mov) or (func.name in libs.hint.objc_strong_mov)):
                args = self.visit_op(insn.d)
                src, dst = args[1], args[0]
                if isinstance(src, Arith) and not(src.dest):
                    if isinstance(src.left, LocalVar) and (src.left.idx in self.local_vars) \
                        and isinstance(self.local_vars.get(src.left.idx), StackBlock):
                        base = self.local_vars.get(src.left.idx)
                        if isinstance(src.right, NumConst):
                            off = src.right.val
                            val, tp = base.load(off)
                            src = MemObj(base, off, '+', tp, val)
                expr = Assign(src, dst)

            elif isinstance(self.snapshot, StackBlock) and isinstance(func, (GlobalLiteral, HelperFunc)) and \
                (func.name.startswith('_dispatch') or func.name in ['_xpc_connection_set_event_handler', '_objc_retainBlock']):
                self.snapshot = None

        elif insn.opcode == hr.m_icall and hr.get_mreg_name(insn.l.r, 2):
            if insn.r.t == hr.mop_l and self.local_vars.get(insn.r.l.idx):
                lv =  self.local_vars.get(insn.r.l.idx)
                if isinstance(lv, (GlobalLiteral, HelperFunc)):
                    func, args = lv, self.visit_op(insn.d)
                    if len(args)>1:
                        if func.startswith('_objc_msgSend'):
                            set_sel(args)
                        expr = Factory.make_call(func, args, insn.ea)
                        if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
                            ret_type = self.infer_within_msg(expr)
                            if ret_type: expr.ret_type = ret_type
                elif isinstance(lv, StackBlock):
                    stkinv = StkInvoke(lv)
                    args = self.visit_op(insn.d)
                    expr = Factory.make_call(stkinv, args, insn.ea)
            # print('unhandled icall:', insn._print())

        if not expr:
            expr =  super().visit_insn(insn)

        if isinstance(expr, Load) and not(expr.dest):
            if  expr.memobj:
                if isinstance(expr.memobj.base, LocalVar) and (expr.memobj.base.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(expr.memobj.base.idx), StackBlock): # Now only support stkblk
                    expr.base = self.local_vars.get(expr.memobj.base.idx)
                    expr.const = expr.memobj.off

                return expr.memobj
        
        elif isinstance(expr, Assign):
            if not(expr.dest):
                return expr.source
            
            if isinstance(self.snapshot, BlockByref) and isinstance(expr.dest, StackVar):
                offset = expr.dest.offset-self.snapshot.stkoff
                self.snapshot.assign(offset, expr.source)
                dest = MemObj(self.snapshot, offset, '+', None, expr.source)
                if self.snapshot.size and (expr.dest.offset + 8 == self.snapshot.size + self.snapshot.stkoff):
                    self.snapshot = None
                expr.dest = dest
            
            if isinstance(expr.source, StackVar) and isinstance(expr.dest, StackVar):
                if (insn.l.t == hr.mop_a) and (expr.dest.offset == expr.source.offset + 8):
                    self.snapshot = BlockByref(expr.source.idx, 0, expr.source, expr.source.offset)
                    self.local_vars[expr.source.idx] = self.snapshot
                    self.local_vars[expr.dest.idx] = self.snapshot
                    offset = expr.dest.offset-self.snapshot.stkoff
                    dest = MemObj(self.snapshot, offset, '+', None, expr.source)
                    expr.dest = dest
        
        elif isinstance(expr, Arith):
            if isinstance(expr.right, LocalVar) and (expr.right.idx in self.const_vars):
                expr.right = self.const_vars.get(expr.right.idx)

        elif isinstance(expr, (Msg, Call)):
            if (insn.opcode == hr.m_call) and insn.is_tailcall:
                if isinstance(expr, Call) and expr.name.startswith('_objc_autorelease'):
                    idx = self.mba.retvaridx
                    var = list(self.mba.vars)[idx]
                    expr.tailcall = Result(var, idx)
                if isinstance(expr, Call) and expr.name in ['_NSStringFromClass']:
                    arg = expr.args[0]
                    if isinstance(arg, Msg):
                        expr.ret_type = arg.ret_type
                    elif isinstance(arg, LocalVar):
                        expr.ret_type = self.local_types.get(arg.idx)
            for i in range(len(expr.args)):
                arg = expr.args[i]
                if isinstance(arg, StackBlock) and isinstance(self.snapshot, StackBlock):
                    self.snapshot = None
                elif isinstance(arg, LocalVar):
                    if (arg.idx in self.local_vars) and \
                        isinstance(self.local_vars.get(arg.idx), StackBlock) and isinstance(self.snapshot, StackBlock):
                        self.snapshot = None
                elif isinstance(arg, Load):
                    expr.args[i] = arg.memobj
            if isinstance(expr, Msg) and isinstance(expr.receiver, LocalVar):
                if expr.receiver.idx in self.local_vars:
                    expr.tp = '+'
                                 
        elif isinstance(expr, Jmp) and expr.cond:
            for i in range(len(expr.cond)):
                # Extract var from arithmetic
                if isinstance(expr.cond[i], Arith): #TODO: Do we need to consider arithmetic.right?
                    if isinstance(expr.cond[i].left, LocalVar) or isinstance(expr.cond[i].left, Msg):
                        expr.cond[i] = expr.cond[i].left
            
        return expr

    @property
    def readable_types(self):
        return {k: str(v) for k, v in self.local_types.items()}

    def infer_within_msg(self, expr : Msg):
        # Check if the new class is the parent class of previous class
        def is_inherit(prev:str, next:str) -> bool:
            if prev.startswith('NS') and next.startswith('NS'):
                return next[2:] in prev[2:]
            return False
            
        def parse_proto(pt : str) -> dict:
            import re

            tp = None
            if pt[0] in ['+', '-']: tp = pt[0]

            blk = re.compile(r'\(\^\)\((?:.|\s)*?\)')
            pt = ''.join(re.split(blk, pt))
            
            if pt.startswith("@property"):
                return tp, pt.split(' ')[-1][1:-1], None, pt.split(' ')[-2]

            types = re.findall(re.compile(r'[(](.*?)[)]', re.S), pt)
            for i in range(len(types)):
                types[i] = tp_sanitizer(types[i])
 
            ret = types[0]
            args = types[1:]

            parts = pt.split(':')
            tmp = [parts[i].split(' ')[-1] for i in range(1, len(parts)-1)]
            tmp.insert(0,parts[0].split(')')[-1])
            sel = ':'.join(tmp) + ':'
            
            return tp, sel, args, ret

        ret_type = None
        clazz = None
        sel = expr.selector.name
        if sel in ['performSelector:', 'performSelector:withObject:', 'performSelector:withObject:withObject:']:
            return ret_type
        
        # Solve the receiver to get class name
        # [class] For receiver of GlobalLiteral or further Clazz Op, which we can directly get clazz name
        if isinstance(expr.receiver, GlobalLiteral):
            clazz = classname(expr.receiver.raw)
            if clazz:
                if clazz.endswith('_meta'): clazz = clazz[:-5]
                expr.recv_type = clazz
                if sel in ('new', 'alloc', 'client', 'sharedInstance', 'class', 'instance', 'shareInstance'): # TODO: more
                    ret_type = clazz
                else:
                    ret_type = libs.hint.class_methods.get(clazz, {}).get(sel)
                if ret_type: return ret_type
            elif isinstance(expr.receiver, CFString):
                clazz = 'NSString'
            else:
                pass
                # print(f"No class name in GlobalLiteral @{self.cur_block}: {repr(expr)}")

        # [instance] For receiver of memobj, infer clazz name
        elif isinstance(expr.receiver, MemObj):
            clazz = expr.receiver.type
        # [instance] For receiver of local var, infer clazz name
        elif isinstance(expr.receiver, LocalVar):
            clazz = self.local_types.get(expr.receiver.idx)
        
        if clazz and not(clazz == 'id') and not expr.recv_type:
            expr.recv_type = clazz

        # If class name is not solved, infer it from sel; else we get (recv,sel) pair from selected prototypes
        # To void the missing of match by wrong infered class type, we traverse all the items
        for cla in self.proto_types:
            for pt in self.proto_types.get(cla):
                tp, _, args, ret = parse_proto(pt)
                if _ != sel: continue
                if tp: expr.tp = tp
                # infer recv's class
                if not(clazz == cla) and not(cla == 'UNKNOWN'):
                    replace = 1
                    if isinstance(expr.receiver, LocalVar) and expr.receiver.local_type \
                        and is_inherit(expr.receiver.local_type, cla):
                        replace = 0
                    if replace:
                        clazz = cla
                        expr.recv_type = clazz
                        if isinstance(expr.receiver, LocalVar):
                            expr.receiver.local_type = clazz
                            self.update_local_types(expr.receiver.idx, clazz)
                else:
                    if (sel == 'isKindOfClass:') and expr.args and isinstance(expr.args[0], LocalVar):
                        if expr.args[0].local_type or self.local_types.get(expr.args[0].idx):
                            clazz = expr.args[0].local_type
                            expr.receiver.local_type = clazz
                            if isinstance(expr.receiver, LocalVar):
                                self.update_local_types(expr.receiver.idx, clazz)
                # infer ret's type
                if ret == 'instancetype':
                    ret_type = clazz
                elif ret in ['ObjectType', 'Class']:
                    pass
                else:
                    ret_type = ret
                # infer args' type
                if args and (len(args) == len(expr.args)): 
                    for i in range(len(args)):
                        if args[i] in ['Class', 'ObjectType']: #TODO:more
                            continue
                        if isinstance(expr.args[i], LocalVar):
                            expr.args[i].local_type = args[i]
                            self.update_local_types(expr.args[i].idx, args[i])
                return ret_type
        
        # If no proto type is matched, check if sel is init-like method
        if sel == 'init' or sel.startswith('initWith'):
            ret_type = clazz
        else:
            ret_type = libs.hint.instance_methods.get(clazz, {}).get(sel)
            
        return ret_type

    def type_infer(self, expr)->str:
        if isinstance(expr, StackBlock):
            return expr.layout

        if isinstance(expr, Clazz):
            return expr.name
            
        if isinstance(expr, MemObj):
            return expr.type

        if isinstance(expr, LocalVar):
            return self.local_types.get(expr.idx)

        if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
            ret_type = self.infer_within_msg(expr)
            if ret_type:
                expr.ret_type = ret_type
                return ret_type
            else:
                pass

        if isinstance(expr, Call) and len(expr.args):
            arg0 = expr.args[0]
            if expr.func.name in libs.hint.objc_ret_as_is:
                return self.type_infer(arg0)
            elif expr.func.name in libs.hint.objc_cls_alloc and isinstance(arg0, GlobalLiteral):
                clazz = classname(arg0.raw)
                return clazz
            elif expr.ret_type:
                return expr.ret_type