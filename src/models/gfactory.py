import visitors.unordered as vu
from models.graph import *

class gFactory:
    @staticmethod
    def make_statement(insn, bfloc):
        stn = None
        binary, fname, loc = bfloc.split('$', 1)[0], bfloc.split('$', 1)[1].rsplit('$', 1)[0], bfloc.rsplit('$',1)[1]
        floc = bfloc.split('$', 1)[-1]

        if isinstance(insn, vu.Msg):
            stn = gMsg()
            stn.cate = "MsgSend"
            stn.recv_type = insn.recv_type
            stn.name = insn.name
            stn.clazz = stn.name.split(' ')[0][2:]
            stn.selector = stn.name.split(' ')[1][:-1]
            stn.ret_type = insn.ret_type
            rev = gFactory.make_operand(insn.receiver, fname, binary)
            if rev: stn.recv.add(rev)

        elif isinstance(insn, vu.Call):
            stn = gCall()
            stn.cate = "Call"
            stn.name = insn.name

        elif isinstance(insn, vu.Assign):
            if not insn.dest: return
            stn = gAssign()
            stn.cate = "Assignment"
            src = gFactory.make_operand(insn.source, fname, binary)
            dst = gFactory.make_operand(insn.dest, fname, binary)
            if src: stn.source.add(src)
            if dst: stn.dest.add(dst)

        elif isinstance(insn, vu.Arith):
            stn = gArith()
            stn.cate = "Arithmetic"
            if insn.tp:
                stn.tp = insn.tp
            left = gFactory.make_operand(insn.left, fname, binary)
            right = gFactory.make_operand(insn.right, fname, binary)
            if insn.dest:
                dst = gFactory.make_operand(insn.dest, fname, binary)
            else:
                dst = gTmp()
                dst.loc = floc
            if left: stn.source.add(left)
            if right: stn.source.add(right)
            if dst: stn.dest.add(dst)

        elif isinstance(insn, vu.Jmp):
            stn = gJmp()
            stn.cate = "Jump"
            stn.dest = insn.dest
            stn.func_dep = []
            if insn.cond:
                stn.is_goto = 0
                for var in insn.cond:
                    # Deal with: jz low.1(call $_objc_msgSend<...>.8), #0.1, @8
                    if isinstance(var, vu.Assign) and not var.dest:
                        var = var.source
                    if isinstance(var, vu.Call) or isinstance(var, vu.Msg):
                        stn.func_dep.append(var.name)
                    op = gFactory.make_operand(var, fname, binary)
                    if op: stn.conditions.add(op)
            else: stn.is_goto = 1

        elif isinstance(insn, vu.Unhandled):
            stn = gUnhandled()
            stn.raw = insn.raw.dstr()

        elif not insn:
            stn = gEnd()
            stn.cate = 'End'

        if stn: 
            stn.location = floc
            stn.func = fname
            stn.binary = binary
            stn.block = int(loc.split('_')[0])

            if isinstance(stn, gCall) or isinstance(stn, gMsg):
                if isinstance(stn, gMsg) and (stn.clazz == 'UNKNOWN') and insn.fuzzy:
                    for callee in insn.fuzzy:
                        func = Func()
                        func.name = callee
                        func.binary = binary
                        stn.callee.add(func)
                else:       
                    func = Func()
                    func.name = stn.name
                    func.binary = binary
                    stn.callee.add(func)
                
                if isinstance(stn, gCall) and insn.tailcall:
                    result = gLocalVar()
                    result.vid = '$'.join([fname, str(insn.tailcall.idx)])
                    result.name = insn.tailcall.name
                    stn.ret.add(result) 
                else:
                    ret = gRet()
                    ret.callsite = stn.location
                    ret.binary = binary
                    ret.func = fname
                    ret.call_name = stn.name
                    stn.ret.add(ret)    

                for arg in insn.args:
                    op = gFactory.make_operand(arg, fname, binary)
                    if op: stn.args.add(op, argidx=insn.args.index(arg))

        return stn
        

    @staticmethod
    def make_operand(var, fname, binary):
        import ida_hexrays as hr

        op = None
        if isinstance(var, vu.LocalVar):
            op = gLocalVar()
            op.vid = '$'.join([fname, str(var.idx)])
            op.name = var.name
            op.local_type = var.local_type
            # Connect the local var and corresponding stackblock
            if op.local_type and op.local_type.startswith('Block_layout_'):
                blk = gStkBlk()
                blk.layout = '$'.join([fname, op.local_type])
                op.alias.add(blk)

        elif isinstance(var, vu.MemObj):
            if not var.vid:
                print(f'[WARNING] Missing vid of {var} in {fname}')
                return
            op = gMemObj()
            op.vid = '$'.join([fname,var.vid])
            op.off = var.vid.rsplit('_', 1)[-1]
            if isinstance(var.base, list):
                base = gFactory.make_operand(var.base[0], fname, binary)
            else:
                base = gFactory.make_operand(var.base, fname, binary)
                if isinstance(var.base, vu.StackBlock):
                    _, tp = var.base.load(int(op.off))
                    if tp: op.local_type = tp
            op.base.add(base)

        elif isinstance(var, vu.StackBlock):
            op = gStkBlk()
            op.layout = '$'.join([fname, var.layout])
            
        elif isinstance(var, vu.BlockByref):
            op = gBlkRef()
            op.loc = '$'.join([fname, str(var.stkoff)])
            op.flags = var.flags
            op.size = var.size
            value = gFactory.make_operand(var.value, fname, binary)
            op.value.add(value)

        elif isinstance(var, vu.GlobalLiteral):
            op = gGlobalLiteral()
            op.ea = var.ea
            op.name = var.name
            if isinstance(var, vu.CFString) or isinstance(var, vu.StringLiteral):
                op.value = var.str
            elif var.value:
                op.value = var.value
                
                
        elif isinstance(var, vu.Selector):
            op = gSelector()
            op.value = var.sel_name
                
        elif isinstance(var, vu.NumConst):
            op = gConst()
            
            if var.is_positive:
                value = var.val
            elif var.is_negative:
                value = -((var.val-1)^0xffffffffffffffff)
            else:
                value = 0
            op.value = f"{fname}${value}"

        if op:
            op.binary = binary
            op.func = fname

        return op