import idc
import idaapi
import idautils
import ida_name
import ida_segment
import ida_bytes
import ida_funcs

idaapi.require('libs.symbols')
idaapi.require('libs.utils')
idaapi.require('libs.classdump')
idaapi.require('libs.hint')
idaapi.require('visitors.unordered')
idaapi.require('intra_procedural')
idaapi.require('sinks.sinks')
idaapi.require('entries.nsxpc')
idaapi.require('entries.xpc')

from libs.utils import rule, genmc, find_impl_by_sel
from libs.classdump import ClassDump
from libs.symbols import imps, clazz2libs
from intra_procedural import GraphGenerator, Sink, DataFlowExtractor
from visitors.unordered import Msg, Call, StackBlock, Selector, LocalVar, GlobalLiteral

from collections import namedtuple

FuncProc = namedtuple("FuncProc", ["cate", "addr", "name", "selarg"])
MAX_CALLSTACK_DEPTH = 10

class Procedure:
    def __init__(self, ea:int, name:str) -> None:
        self.ea = ea
        self.name = name
        self.caller = set()
        self.graph = DataFlowExtractor(genmc(ea), None)
        self.visited = False
        self.callees = set()
        self.sinks = []
        self.is_callback = False
    
    def visit(self):
        if not self.visited:
            self.graph.visit()
            self.visited = True
    
    def __repr__(self) -> str:
        return f"<Procedure {self.name}>"

class CallGraphGenerator:
    def __init__(self, entries=None, binary=None, db=False, max_depth=MAX_CALLSTACK_DEPTH) -> None:
        self.binary = binary
        self.entry_points = set()
        self.sensitve_func = set()
        self.xpc_entry = []
        self.db = db
        self.procedure_map: dict[str:Procedure] = {}
        self.dump = ClassDump()
        self.dump.parse()
        self.externals = {}
        self.make_entry_procs(entries)
        self.curr_procedure = None
        self.max_depth = max_depth
    
    # Generate mba for all methods dumped (not used)
    def mba_factory(self):
        worklist = []
        for clazz in self.dump.classes:
            for method in clazz.methods:
                name = f"{method[0]}[{clazz.name} {method[2:]}]"
                ea = clazz.methods[method]
                worklist.append((ea, name))
        for entry, name in worklist:
            self.procedure_map[name] = Procedure(entry, name)

    def make_entry_procs(self, entries):
        for entry in entries:
            name = ida_name.get_ea_name(entry)
            if name not in self.procedure_map:
                p = Procedure(entry, name)
                if not p.graph.mba: continue
                self.procedure_map[name] = p
            self.entry_points.add(self.procedure_map.get(name))
    
    def make_entry_points(self, entries):
        for entry in entries:
            clazz = entry.split(' ')[0][2:]
            if '(' in clazz and ')' in clazz:
                clazz = clazz.split('(')[0]
            method = ' '.join([entry.split('[')[0],entry.split(' ')[1][:-1]])
            if (clazz in self.dump.class_lookup) and \
                (method in self.dump.class_lookup.get(clazz).methods):
                addr = self.dump.class_lookup.get(clazz).methods.get(method)
                if entry not in self.procedure_map:
                    self.procedure_map[entry] = Procedure(addr, entry)
                self.entry_points.add(self.procedure_map.get(entry))
            
    def add_single_func(self, ea, fname):
        p = Procedure(ea, fname)
        self.procedure_map[fname] = p
        self.curr_procedure = p
        p.visit()
        nodes = []
        for bnodes in p.graph.node_set.values():
            nodes.extend(bnodes)
        for node in nodes:
            callees = self.node_filter(node)
            for callee in callees:
                if callee.cate == 'call':
                    if not (callee.addr and callee.name):
                        continue
                    self.curr_procedure.callees.add(callee.name)
                elif callee.cate == 'msg':
                    if not callee.name:
                        continue
                    self.curr_procedure.callees.add(callee.name)
                    
        lvars = self.curr_procedure.graph.local_vars
        stkblks = [lvars[idx] for idx in lvars if idx and isinstance(lvars[idx], StackBlock)]
        for blk in stkblks:
            if not blk.invoke: continue
            name = ida_name.get_ea_name(blk.invoke, 1)
            self.curr_procedure.callees.add(name)
        
        for f in self.curr_procedure.callees:
            if self.procedure_map.get(f):
                callee = self.procedure_map.get(f)
                callee.caller.add(self.curr_procedure.name)

    '''
    Build call relations in binary and add involved function into procedure map
    '''
    def build_call_relations(self, blacklist=[]):
        worklist = []       # Store the name of procedures to be analyzed
        recorder = set()    # Record the procedure analyzed
        makelist = set()    # Store the names of callees of current procedure

        for p in self.entry_points:
            if p.name in worklist: continue
            worklist.append((p.name, 0)) # (fname, depth)
        cnt = 0
        while worklist:
            recorder.add(worklist[0][0])
            self.curr_procedure = self.procedure_map.get(worklist[0][0])
            try:
                self.curr_procedure.visit()
            except:
                worklist.pop(0)
                continue
            if worklist[0][1] > self.max_depth:
                worklist.pop(0)
                continue
            nodes = []
            for bnodes in self.curr_procedure.graph.node_set.values():
                nodes.extend(bnodes)
            
            selarg_map = {}
            stkblk_map = {}
            for node in nodes:
                callees = self.node_filter(node)
                for callee in callees:
                    if callee.cate == 'call':
                        if not (callee.addr and callee.name):
                            continue
                        callee_name = callee.name
                        for c in ['+', '-', '[', ']', ' ', ':']:
                            callee_name = callee_name.replace(c, '_')
                        self.curr_procedure.callees.add(callee_name)
                        makelist.add((callee.addr, callee_name, 0))
                    elif callee.cate == 'msg':
                        if not callee.name:
                            continue
                        self.curr_procedure.callees.add(callee.name)
                        if not callee.addr:
                            continue
                        fn_low = callee.name.lower()
                        skip = False
                        for kw in blacklist:
                            if kw in fn_low:
                                skip = True
                        if skip:
                            continue
                        makelist.add((callee.addr, callee.name, 0))
                        selarg_map[callee.name] = callee.selarg
            
            lvars = self.curr_procedure.graph.local_vars
            stkblks = [lvars[idx] for idx in lvars if idx and isinstance(lvars[idx], StackBlock)]
            for blk in stkblks:
                if not blk.invoke: continue
                name = ida_name.get_ea_name(blk.invoke, 1)
                self.curr_procedure.callees.add(name)
                makelist.add((blk.invoke, name, 1))
                stkblk_map[name] = blk

            for callee_ea, callee_name, is_callback in makelist:
                if callee_name not in self.procedure_map:
                    proc = Procedure(callee_ea, callee_name)
                    if is_callback:
                        proc.is_callback = True
                    self.procedure_map[callee_name] = proc

                proc:Procedure = self.procedure_map.get(callee_name)
                proc.caller.add(self.curr_procedure.name)

                # Propagate StkBlk into callee
                if callee_name in stkblk_map:
                    stkblk = stkblk_map.get(callee_name)
                    stkblk_dup = stkblk.duplicate()
                    for idx, lv in stkblk.lvars.items():
                        lv_map = self.curr_procedure.graph.local_vars
                        if isinstance(lv, LocalVar) and (lv.idx in lv_map):
                            var = lv_map.get(lv.idx)
                            if isinstance(var, Selector):
                                stkblk_dup.lvars[idx] = var
                    proc.graph.local_vars[0] = stkblk_dup
                if callee_name in selarg_map:
                    selarg = selarg_map.get(callee_name)
                    proc.graph.local_vars.update(selarg)

                if (callee_name not in recorder) and (callee_name not in worklist):
                    worklist.append((callee_name, worklist[0][1]+1))      

            makelist.clear()
            worklist.pop(0)

        self.curr_procedure = None
        
    '''
    Parse the msg node to get the callee info
    '''
    def node_filter(self, node):
        callees = []
        if isinstance(node, Call) and node.func and node.name:
            if node.name.startswith("_objc_") or node.name.startswith('_dispatch'):
                return callees
            if isinstance(node.func, GlobalLiteral) and node.func.ea:
                callees.append(FuncProc('call', node.func.ea, node.name, None))
                return callees
        if not isinstance(node, Msg):
            return callees
        name = self.curr_procedure.graph.get_msgsend_name(node)
        if not name:
            return callees
        clazz = name.split(' ')[0][2:]
        if '(' in clazz and ')' in clazz:
            clazz = clazz.split('(')[0]
        sel = name.split(' ')[1][:-1]
        selarg = {}
        for arg in node.args:
            if isinstance(arg, Selector):
                idx = node.args.index(arg)+2
                selarg[idx] = arg
        # If clazz has resolved
        if clazz in self.dump.class_lookup.keys():
            methods = self.dump.class_lookup[clazz].methods
            for method, ea in methods.items():
                if sel == method[2:]:
                    name = method[0]+name[1:] # Fix type(+/-)
                    node.name = name # Make sure the msg node has correct fname
                    if ida_name.get_name_ea(idc.BADADDR, name) == idc.BADADDR:
                        impl = ea
                    else:
                        impl = ida_name.get_name_ea(idc.BADADDR, name)
                    callees.append(FuncProc('msg', impl, name, selarg)) # make sure the ea is correct...
                    return callees # only contains a fixed callee
        elif (clazz in clazz2libs) and not(clazz.startswith('NS')):
            lib_path = clazz2libs.get(clazz)
            if not lib_path in self.externals:
                self.externals[lib_path] = set()
            self.externals[lib_path].add(name)
            callees.append(FuncProc('msg', None, name, selarg))
            return callees
        elif clazz.startswith('NS'): # TODO: check, if wrong, goto unknown logic
            callees.append(FuncProc('msg', None, name, selarg))
            return callees
        # If clazz is UNKNOWN
        elif (clazz == "UNKNOWN"):
            for cand in self.dump.class_lookup.keys():
                methods = self.dump.class_lookup[cand].methods
                for method, ea in methods.items():
                    if sel == method[2:]:                    
                        name = f"{method[0]}[{cand} {method[2:]}]" # Fix type(+/-)
                        callees.append(FuncProc('msg', ea, name, selarg))
            if not callees:
                name, ea = find_impl_by_sel(sel) # TODO: maybe more options?
                if name and ea:
                    node.name = name
                    callees.append(FuncProc('msg', ea, name, selarg))
                    return callees
            if len(callees)<5 and len(sel)>10:
                node.fuzzy = [callee.name for callee in callees]
                return callees
        
        return []
    
    '''
    Store call graph in a structure can be pickled
    '''
    def dump_callgraph(self):
        cg = CallGraph()
        for entry in self.entry_points:
            cg.entry_points.append(entry.name)
        
        for fname in self.procedure_map:
            proc = self.procedure_map.get(fname)
            if not proc.visited: # means decompile failed
                continue
            item = {}
            item['is_callback'] = proc.is_callback
            item['callees'] = list(proc.callees)
            item['caller'] = list(proc.caller)
            item['ea'] = proc.graph.mba.entry_ea
            cg.procedure_map[fname] = item
        
        return cg


class CallGraph:
    def __init__(self) -> None:
        self.entry_points = []
        self.procedure_map = {}
        self.base = []