import idaapi

idaapi.require('libs.utils')
idaapi.require('libs.hint')
idaapi.require('visitors.unordered')
idaapi.require('visitors.simulation')

from libs.utils import genmc, rule, encode_summary, decode_summary, get_summary
import libs.hr
from visitors.simulation import SimVisitor
import visitors.unordered as vu
from collections import namedtuple

Sink = namedtuple('Sink',['clazz', 'selector', 'args'])

class GraphGenerator(SimVisitor):
    def __init__(self, mba):
        super().__init__(mba)
        self.node_set = {}
        self.curr_trace = '0'
        self.args_map = {} # argidx: argvid
        
    def map_args(self):
        for i in self.mba.argidx:
            arg = self.mba.arg(i)
            self.args_map[i] = list(self.mba.vars).index(arg)
            
    def get_msgsend_name(self, node : vu.Msg)->str:
        name, tp, recv, sel = None, None, None, None
        if isinstance(node.receiver, vu.LocalVar):
            if node.tp: tp = node.tp
            elif node.receiver.idx in self.local_vars: tp = '+'
            else: tp = '-'
            if node.recv_type:
                recv = node.recv_type
            elif not self.local_types.get(node.receiver.idx) == 'id':
                recv = self.local_types.get(node.receiver.idx)
        elif isinstance(node.receiver, vu.MemObj):
            tp = '-'
            if node.recv_type:
                recv = node.recv_type
            else:
                recv = node.receiver.type
        elif isinstance(node.receiver, vu.CFString):
            tp = '-'
            recv = 'NSString'
        elif isinstance(node.receiver, vu.Clazz):
            recv, tp = node.receiver.name, '+'
        elif node.recv_type:
            recv, tp = node.recv_type, '-'

        if isinstance(node.selector, vu.Selector):
            sel = node.selector.name
        elif isinstance(node.selector, vu.LocalVar):
            sel = self.local_vars.get(node.selector.idx)

        if not tp: tp = "*"
        if not recv: recv = "UNKNOWN"

        if not sel: sel = "UNKNOWN"
        else: node.sel_val = sel

        name = f"{tp}[{recv} {sel}]"
        node.name = name

        return name      
    
    def visit(self):
        super().visit()
        self.map_args()
 
    def visit_block(self, mblock):
        self.node_set[self.cur_block] = []            
        super().visit_block(mblock)

    def post_order_traversal(self, expr, insn):
        parts = []
        if isinstance(expr, vu.Assign):
            parts = [expr.source, expr.dest]
            
        elif isinstance(expr, vu.Arith):
            parts = [expr.left, expr.right, expr.dest]

        elif isinstance(expr, vu.Jmp):
            if expr.jtp in libs.hr.m_jmp2:
                parts = expr.cond
                
        for p in parts:
            if isinstance(p, vu.Node):
                self.post_order_traversal(p, insn)

        self.node_set[self.cur_block].append(expr)
        if isinstance(expr, vu.Msg) and isinstance(expr.selector, vu.Selector):
            # Check if ida misses arguments, such as "MOV X2, X0"
            argidx = expr.selector.name.count(':')
            if len(expr.args)<argidx and idaapi.get_inf_structure().procname in ['ARM', 'AARCH64']:
                for i in range(len(expr.args), argidx):
                    arg = None
                    start = vu.AssamVisitor.get_BL_addr(insn.ea)
                    _, src = vu.AssamVisitor.get_reg_backward(start, [f'X{2+i}'])
                    if src == 'X0' and len(self.node_set[self.cur_block])>2:
                        for j in range(5): # 5 steps may enough
                            if len(self.node_set[self.cur_block])<(3+j):
                                break
                            if isinstance(self.node_set[self.cur_block][-2-j], vu.Assign) and isinstance(self.node_set[self.cur_block][-2-j].source, vu.Msg) and isinstance(self.node_set[self.cur_block][-3-j], vu.Ret):
                                arg = self.node_set[self.cur_block][-2-j].dest
                                break
                    elif src.startswith('#'):
                        if src.startswith('#0x'):
                            arg = vu.Factory.make_const(vu.FakeRaw_NC(2, int(src[1:], 16), 1))
                        else:
                            arg = vu.Factory.make_const(vu.FakeRaw_NC(2, int(src[1:]), 1))
                    else: # In case get wrong order of arg list
                        break
                    if arg:
                        expr.args.append(arg)
                        # print(f"[*] recover X{2+i} of {expr.selector.name}@{self.cur_block}: {arg}")
                    else:
                        break

            tp, val, dep = None, None, None
            tp = self.type_infer(expr)
            ret = vu.Factory.make_ret(tp, val, dep)
            self.node_set[self.cur_block].append(ret)
    
    def visit_top_insn(self, insn):
        expr = super().visit_top_insn(insn)
        self.post_order_traversal(expr, insn)

        return expr

    def visit_insn(self, insn):
        expr =  super().visit_insn(insn)
        return expr
    
    def visit_op(self, op):
        return super().visit_op(op)
    
    def collect_msg_by_sel(self, sel):
        ret = []
        for nodes in self.node_set.values():
            for node in nodes:
                if not isinstance(node, vu.Msg):
                    continue
                if node.sel_val == sel:
                    ret.append(node)
        return ret


class DataFlowExtractor(GraphGenerator):
    def __init__(self, mba, pre):
        super().__init__(mba)
        self.sources = set()
        if mba:
            for i in range(self.mba.argidx.size()):
                self.sources.add(list(self.mba.vars)[i].name)
        self.sink_map = {}
        self.transfers = {}
        self.preliminary = rule('summary')
        self.traces = set()
        if pre:
            self.preliminary.update(pre)

    @property
    def readable_types(self):
        return {list(self.mba.vars)[k].name: str(v) for k, v in self.local_types.items()}
    
    @property
    def readable_vars(self):
        return {list(self.mba.vars)[k].name: str(v) for k, v in self.local_vars.items()}
    
    @property
    def trans(self):
        trans = {}
        for blk in self.transfers:
            curr = {}
            for vid, deps in self.transfers[blk].items():
                vname = list(self.mba.vars)[self.vid2idx(vid)].name
                ndeps = [list(self.mba.vars)[self.vid2idx(dep)].name for dep in deps]
                if not ndeps: continue
                if vname not in curr:
                    curr[vname] = set(ndeps)
                else:
                    curr[vname] |= set(ndeps)
            trans[blk] = curr
        
        return trans
    
    @staticmethod
    def vid2idx(vid):
        if not '_' in vid:
            return int(vid)
        else:
            return int(vid.split('_')[0])

    # Generate or complete vid for operands
    def get_vid(self, op):
        if isinstance(op, vu.MemObj):
            if isinstance(op.base, list):
                prefix = '&'+'&'.join([self.get_vid(v) for v in op.base])
            else:
                prefix = self.get_vid(op.base)
            if isinstance(op.off, list):
                suffix = '&'+'&'.join([self.get_vid(v) for v in op.off])
            else:
                suffix = str(op.off)
            if not prefix:
                return
            vid = '_'.join([prefix, suffix])
            op.vid = vid
        elif isinstance(op, vu.LocalVar):
            idx = op.idx
            vid = str(idx)
        elif isinstance(op, (vu.StackBlock, vu.BlockByref)):
            vid = str(op.idx)
        else:
            # print(f'WARNING: type {type(op)} is supported!')
            return

        return vid

    def visit(self):
        super().visit()
        for i in range(1, self.mba.qty):
            self.transfers[i] = self.forward_in_block(i)
            
    def repair(self, callees): # TODO: remove it
        tmp = {}
        for callee in callees:        
            if not callee[1] == '[':
                continue
            clazz, method = callee.split(' ')[0][2:], callee.split(' ')[1][:-1]
            if clazz == "UNKNOWN":
                continue
            tmp[method] = callee
        for nodes in self.node_set.values():
            for node in nodes:
                if not isinstance(node, vu.Msg):
                    continue
                if (node.sel_val in tmp.keys()) and not node.recv_type:
                    print(f"Repair {tmp.get(node.sel_val)}")
                    node.name = tmp.get(node.sel_val)
                    node.recv_type = node.name.split(' ')[0][2:]
                    if isinstance(node.receiver, vu.LocalVar):
                        self.local_types[node.receiver.idx] = node.recv_type
        for i in range(1, self.mba.qty):
            self.transfers[i] = self.forward_in_block(i)
                
    # Used to print dataflow in a single block for human read
    def print_transfer(self, transfer : dict):
        for idx, idxs in transfer.items():
            vars = [list(self.mba.vars)[i].name for i in idxs]
            print(f"{list(self.mba.vars)[idx].name}({idx}) is effected by: {' '.join(vars)}") 

    # Used to generate dataflow in a single block
    def forward_in_block(self, block : int):
        transfer = {}
        nodes = self.node_set.get(block)

        def cared(op):
            if isinstance(op, (vu.LocalVar, vu.MemObj)):
                return True

        def add_pair(dst, *srcs):
            dst_vid = self.get_vid(dst)
            if not dst_vid: return
            transfer[dst_vid] = []

            for src in srcs:
                src_vid = self.get_vid(src)
                if not src_vid: continue
                transfer[dst_vid].append(src_vid)

        for i in range(len(nodes)):
            node = nodes[i]
            if isinstance(node, vu.Assign):
                src, dest = node.source, node.dest
                if cared(src): 
                    self.get_vid(src)
                if cared(dest):
                    self.get_vid(dest)
                    if isinstance(src, vu.Msg):
                        transfer[self.get_vid(dest)] = []
                        ret_node = nodes[i-1]
                        if isinstance(ret_node, vu.Ret):
                            transfer[self.get_vid(dest)].extend(ret_node.dep)
                    elif isinstance(src, vu.Call):
                        add_pair(dest, *src.args)
                    elif cared(src):
                        add_pair(dest, src)
            
            elif isinstance(node, vu.Arith):
                left, right, dest = node.left, node.right, node.dest
                self.get_vid(left)
                self.get_vid(right)
                if cared(node.dest):
                    add_pair(dest, left, right)

            elif isinstance(node, vu.Load):
                if node.memobj:
                    src = node.memobj
                else:
                    src = node.base
                dest = node.dest
                if cared(node.dest):
                    add_pair(dest, src)

            elif isinstance(node, vu.Msg):
                # Record the vid of the recv each arg
                self.get_vid(node.receiver)
                for arg in node.args:
                    self.get_vid(arg)

                name = self.get_msgsend_name(node)
                if not name:
                    continue
                if ':' not in name:
                    continue
                # Depend on predefined or pre-generated pattern
                summary = get_summary(self.preliminary, name)
                if summary:
                    effect = decode_summary(summary)
                    mapping = {} # map the idx of arglist to the var of current context
                    for idx in effect.keys():
                        # Receiver TODO: which fields?
                        if idx == 1 and isinstance(node.receiver, vu.LocalVar):
                            mapping[idx] = node.receiver
                        # Arguments
                        if idx > 1 and len(node.args)>idx:
                            if isinstance(node.args[idx-2], vu.LocalVar):
                                mapping[idx] = node.args[idx-2]
                    for idx, vars in effect.items():
                        # Store the dependencies of ret value into ret-node
                        if idx == 0 and isinstance(nodes[i+1], vu.Ret):
                            ret_node = nodes[i+1]
                            ret_node.dep.extend(\
                                [self.get_vid(mapping[var]) for var in vars if var in mapping])
                        if idx not in mapping: continue
                        vid = self.get_vid(mapping.get(idx))
                        if vid not in transfer:
                            transfer[vid] = []
                        transfer[vid].extend(\
                            [self.get_vid(mapping[var]) for var in vars if var in mapping])
                else:
                    pass
                
            elif isinstance(node, vu.Call):
                for arg in node.args:
                    self.get_vid(arg)

            elif isinstance(node, vu.Jmp):
                # Just to save vid to the depended var of jmp TODO
                if node.cond:
                    for var in node.cond:
                        self.get_vid(var)

        return transfer