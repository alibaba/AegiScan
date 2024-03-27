import idaapi

idaapi.require('visitors.unordered')
idaapi.require('inter_procedural')
idaapi.require('libs.utils')
idaapi.require('models.gfactory')

from libs.utils import encode_summary, decode_summary, get_summary, rule
from inter_procedural import CallGraphGenerator, CallGraph, Procedure
from models.gfactory import *
from py2neo import Subgraph
from py2neo.matching import \
    NodeMatcher, RelationshipMatcher, \
    EQ, NE, LT, LE, GT, GE, \
    STARTS_WITH, ENDS_WITH, CONTAINS, LIKE, \
    IN, AND, OR, XOR

def make_loc(binary, fname, blk, idx):
    tmp = '_'.join([str(blk), str(idx)])
    return '$'.join([binary, fname, tmp])


class Recorder:
    def __init__(self) -> None:
        self.graph, self.repo = connect()
        self.summary = rule('summary')
        self.curr_cgg = None
        self.curr_callgraph = None
    
    def update_db(self, binary):
        self.graph, self.repo = connect(binary)
        
    def exist_db(self, binary):
        dbs = self.graph.run("SHOW DATABASES").to_series()
        return binary.lower() in dbs.values

    '''
    Helper function: transfer
    To transfer from base model to submodel
    '''
    def transfer(self, obj):
        if isinstance(obj, Statement):
            model = cate2model[obj.cate]
            primary_value = obj.__primaryvalue__
        elif isinstance(obj, Node):
            model = cate2model[obj.get('cate')]
            primary_value = obj.get('location')
        else:
            return None
        
        return self.repo.get(model, primary_value)
    
    '''
    Helper function: get_invoke
    To get the callback func of the blocl
    '''
    def get_invoke(self, blk):
        fname = None
        for r in self.graph.match((blk,None),r_type='CONTAIN').all():
            if r.end_node.get('vid').endswith('_16'):
                invoke_field = r.end_node
                for ar in self.graph.match((None,invoke_field),r_type='ASSIGN_TO').all():
                    assign = ar.start_node
                    gl = self.graph.match((assign,None),r_type='ASSIGN_FROM').first().end_node
                    if gl.has_label('gGlobalLiteral'):
                        if gl.get('name') and gl.get('name').startswith('sub_'):
                            fname = gl.get('name')
                            break
                break
        
        return fname

    def refactor_stkblk(self, fname):
        stkblks = []
        for stkblk in self.repo.match(gStkBlk).where(layout=STARTS_WITH(fname)).all():
            stkblks.append((stkblk.__node__.identity, stkblk))
        stkblk_map = dict(stkblks)
        to_update = []
        to_update.extend(list(stkblk_map.values()))
        
        # Build PointTo relationship for blockbyref using forwarding ptr
        for blkref in self.repo.match(gBlkRef).where(loc=STARTS_WITH(fname)).all():
            r = self.graph.match((None, blkref.__node__), r_type="REFER_TO").first()
            vid = r.start_node.get('vid').rsplit('_', 1)[0]
            var = self.repo.match(gLocalVar).where(vid=vid).first()
            self.graph.create(POINT_TO(var.__node__, blkref.__node__))
            forwarding = self.repo.match(gMemObj).where(vid='_'.join([vid, '8'])).first()
            self.graph.create(POINT_TO(forwarding.__node__, blkref.__node__))

        # Build RelateTo relationship from stkblk to memobj
        for memobj in self.repo.match(gMemObj).where(vid=STARTS_WITH(fname)).all():
            base = list(memobj.base.triples())[0][2]
            if base.__primaryvalue__ in stkblk_map:
                stkblk = stkblk_map.get(base.__primaryvalue__)
                stkblk.lvars.add(memobj)

        # Remove duplication of localvars which equal to existing memobj
        for stkblk in stkblk_map.values():
            if not list(stkblk.lvars.triples()): 
                continue
            op = list(stkblk.lvars.triples())[0][2]
            node = self.graph.nodes.get(op.__node__.identity)
            base_vid = node.get('vid').rsplit('_', 1)[0]

            lv_nodes = self.graph.nodes.match('gLocalVar').where(vid=STARTS_WITH(f"{base_vid}_")).all()
            memobj_map = dict([(memobj.vid, memobj) for memobj in \
                self.repo.match(gMemObj).where(vid=STARTS_WITH(f"{base_vid}_")).all()])

            for lv_node in lv_nodes:
                memobj = memobj_map[lv_node.get('vid')]
                rs = self.graph.match((None,lv_node), r_type="USE").all()
                for r in rs: #TODO:call or msg
                    call = self.repo.match(gCall, r.start_node.get('location')).first()
                    call.args.add(memobj, argidx=r.get('argidx'))
                    self.graph.separate(r)
                    to_update.append(call)
            for lv_node in lv_nodes: 
                self.graph.delete(lv_node)

        # Guide the memobj from localvars, which point to the stkblk, to the stkblk itself
        for stkblk in stkblk_map.values():
            alias_nodes = [r.start_node for r in self.graph.match((None, stkblk.__node__), r_type="POINT_TO").all()]
            for alias_node in alias_nodes:
                rs = self.graph.match((None, alias_node), r_type="REFER_TO").all()
                for r in rs:
                    memobj = self.repo.get(gMemObj, r.start_node.get('vid'))
                    self.graph.separate(r)
                    memobj.base.add(stkblk)
                    stkblk.lvars.add(memobj)
                    to_update.append(memobj)
        
        self.repo.save(to_update)


    def refactor_jump(self, fname):
        for jmp in self.repo.match(Statement).where("_.cate ='Jump'", location=STARTS_WITH(fname)).all():
            jmp = self.transfer(jmp)
            curr_blk = jmp.location.rsplit('_', 1)[0]
            loc = '_'.join([str(jmp.dest), '0'])
            floc = '$'.join([fname, loc])
            tar = self.repo.get(Statement, floc)
            jmp.succs.add(tar)
            for name in jmp.func_dep:
                op = self.repo.match(Statement).where(f"_.name = '{name}'", \
                    location=STARTS_WITH(f'{curr_blk}_')).all()[-1]
                ret = self.repo.get(gRet, op.location)
                jmp.conditions.add(ret)
            if jmp.is_goto:
                next_blk = '$'.join([curr_blk.split('$')[0] , str(int(curr_blk.split('$')[-1])+1)])
                fake_succ = self.repo.match(Statement).where(f"_.location = '{next_blk}_0'").first()
                jmp.succs.remove(fake_succ)
            self.repo.save(jmp)
    
    
    def refactor_jump(self, fname):
        for jmp in self.repo.match(Statement).where("_.cate ='Jump'", location=STARTS_WITH(fname)).all():
            jmp = self.transfer(jmp)
            curr_blk = jmp.location.rsplit('_', 1)[0]
            loc = '_'.join([str(jmp.dest), '0'])
            floc = '$'.join([fname, loc])
            tar = self.repo.get(Statement, floc)
            jmp.succs.add(tar)
            for name in jmp.func_dep:
                op = self.repo.match(Statement).where(f"_.name = '{name}'", \
                    location=STARTS_WITH(f'{curr_blk}_')).all()[-1]
                ret = self.repo.get(gRet, op.location)
                jmp.conditions.add(ret)
            if jmp.is_goto:
                next_blk = '$'.join([curr_blk.split('$')[0] , str(int(curr_blk.split('$')[-1])+1)])
                fake_succ = self.repo.match(Statement).where(f"_.location = '{next_blk}_0'").first()
                jmp.succs.remove(fake_succ)
            self.repo.save(jmp)
    
    def complete(self, cpg, fname):
        # Complete relations not convenient to add by gFactory
        refers = self.graph.match(None, r_type="REFER_TO").all()
        for r in refers:
            if not self.graph.match((r.end_node, r.start_node), r_type="CONTAIN").all():
                self.graph.merge(CONTAIN(r.end_node, r.start_node))
        
        # Make a gClazz node to represent truly self object
        if fname.startswith(('+', '-')):
            cname = fname.split(' ')[0][2:]
            clazz = self.repo.get(gClazz, cname)
            if not clazz:
                clazz = gClazz()
                clazz.name = cname
            for idx, tp in cpg.local_types.items():
                if not(tp == clazz.name):
                    continue
                vid = '$'.join([fname, str(idx)])
                lv = self.repo.get(gLocalVar, vid)
                if not lv: continue
                self.graph.merge(POINT_TO(lv.__node__, clazz.__node__))
                self.resolve_alias(clazz.__node__, lv.__node__, 1)      

    def commit_callgraph(self, binary, cg:CallGraph):
        func_map = {}
        node_ls, relation_ls = [], []
        for fname, info in cg.procedure_map.items():
            func = Func()
            func.name = fname
            func.binary = binary
            func.entry_ea = info.get('ea')
            func_map[fname] = func
            # Skip some unnecessary info
            node_ls.append(func.__node__)
        for caller_name, info in cg.procedure_map.items():
            caller = func_map.get(caller_name)
            for callee_name in info.get('callees'):
                if caller_name == callee_name:
                    continue
                if callee_name.startswith('+[NS') or callee_name.startswith('-[NS'):
                    callee = Func()
                    callee.name, callee.binary, callee.entry_ea = callee_name, binary, None
                    node_ls.append(callee.__node__)
                else:
                    callee = func_map.get(callee_name)
                if not callee:
                    continue
                r1 = Relationship(caller.__node__, "CALLEE", callee.__node__)
                r2 = Relationship(callee.__node__, "CALLER", caller.__node__)
                relation_ls.extend([r1, r2])
        sg = Subgraph(node_ls, relation_ls)
        self.graph.create(sg)
            
    def commit_func(self, proc_graph, fname, binary):
        self.build_func(proc_graph, fname, binary)
        self.refactor_stkblk(fname)
        self.complete(proc_graph, fname)

    def build_func(self, proc_graph, fname, binary):
        func = Func()
        func.name = fname
        func.binary = binary
        func.argidx_size = proc_graph.mba.argidx.size()
        func.retvaridx = proc_graph.mba.retvaridx
        func.entry_ea = proc_graph.mba.entry_ea

        stn_set = {}
        for blk, nodes in proc_graph.node_set.items():
            if not nodes: continue
            stns = self.build_each_blk(nodes, binary, fname, blk)
            if not stns: continue
            self.graph.push(stns[0])
            stn_set[blk] = (stns[0].location, stns[-1].location)
            
        bfloc = make_loc(binary, fname, len(proc_graph.node_set), 0)
        end = gFactory.make_statement(None, bfloc)
        self.graph.push(end)
        stn_set[len(proc_graph.node_set)] = (end.location, end.location)
        
        func.start.add(self.repo.get(Statement, stn_set[1][0]))
        to_update = [func]
        for blk, start_end in stn_set.items():
            cursor = self.repo.get(Statement, start_end[1])
            if cursor.cate == 'Jump':
                jmp = self.transfer(cursor)
                entry = self.repo.get(Statement, stn_set[jmp.dest][0])
                jmp.succs.add(entry)
                entry.preds.add(jmp)
                if (not jmp.is_goto) and (blk < len(stn_set)):
                    entry = self.repo.get(Statement, stn_set[blk+1][0])
                    jmp.succs.add(entry)
                    entry.preds.add(jmp)
                for name in jmp.func_dep:
                    curr_blk = jmp.location.rsplit('_', 1)[0]
                    op = self.repo.match(Statement).where(f"_.name = '{name}'", \
                        location=STARTS_WITH(f'{curr_blk}_')).all()[-1]
                    ret = self.repo.get(gRet, op.location)
                    jmp.conditions.add(ret)
                to_update.append(jmp)
            elif blk < len(stn_set):
                entry = self.repo.get(Statement, stn_set[blk+1][0])
                cursor.succs.add(entry)
                entry.preds.add(cursor)
                to_update.append(cursor)
                
        self.repo.save(to_update)

    def build_each_blk(self, nodes, binary, fname, blk):
        stns = []
        for node in nodes:
            bfloc = make_loc(binary, fname, blk, len(stns))
            try:
                stn = gFactory.make_statement(node, bfloc)            
                if stn and isinstance(node, vu.Assign):
                    if isinstance(node.source, (vu.Call, vu.Msg)) and stns:
                        stn.source.add(list(stns[-1].ret.triples())[0][2])
                    elif isinstance(node.source, vu.Arith) and stns:
                        stn.source.add(list(stns[-1].dest.triples())[0][2])

                if stn: 
                    if isinstance(node, vu.Assign):
                        if isinstance(node.source, (vu.Call, vu.Msg)):
                            stn.source.add(list(stns[-1].ret.triples())[0][2])
                        elif isinstance(node.source, vu.Arith):
                            stn.source.add(list(stns[-1].dest.triples())[0][2])
                    elif isinstance(node, vu.Arith):
                        for item in [node.left, node.right]:
                            if isinstance(item, (vu.Call, vu.Msg)):
                                stn.source.add(list(stns[-1].ret.triples())[0][2])
                    stns.append(stn)
            except:
                print(f"Error@{bfloc}")
                continue
        
        for i in range(len(stns)):
            if i: 
                stns[i].preds.add(stns[i-1])
            if i < len(stns) - 1:
                stns[i].succs.add(stns[i+1])

        return stns

    '''
    Transfer the relations from the duplication to the original object
    '''
    def migrate(self, dup_n, ori_m):
        to_update = []

        for r in self.graph.match((None, dup_n),None):
            # Deal with the relation between statements and dup_memobj
            if r.start_node.has_label('Statement'):
                stm = self.transfer(r.start_node)

                rname = r.__repr__().split('(',1)[0]
                if rname == 'USE':
                    stm.args.add(ori_m, argidx=r.get('argidx'))
                elif rname == 'ASSIGN_FROM':
                    stm.source.add(ori_m)
                elif rname == 'ASSIGN_TO':
                    stm.dest.add(ori_m)
                elif rname == 'RECEIVER':
                    stm.recv.add(ori_m)
                elif rname == 'DEP_ON':
                    stm.conditions.add(ori_m)
                else: 
                    print(f"TODO: Unsolved stm: {ori_m}\n{dup_n}-{stm}:{rname}")

                self.graph.separate(r)
                to_update.append(stm)

            # Deal with the relation between dup_memobj and based dup_memobj
            elif r.start_node.has_label('gMemObj'):
                obj = self.repo.get(gMemObj, r.start_node.get('vid'))
                obj.base.add(ori_m)
                self.graph.separate(r)
                to_update.append(obj)

        return to_update

    '''
    Combine the context between the caller and the callee [within binary]
    '''
    def combine_context(self, binary):
        to_update = []
        native_layout = []
        # Identify the native stackblock and store the layout
        for stkblk in self.graph.nodes.match('gStkBlk').where(binary=binary).all():
            is_native = False
            handlers = [r.start_node for r in self.graph.match((None, stkblk), "POINT_TO").all()] 
            if handlers: 
                is_native = True
            for handler in handlers:
                if handler.get('vid').split('$')[-1] == '0':
                    is_native = False
            if is_native:
                native_layout.append(stkblk.get('layout'))

        # Combine each pair of stackblock with same layout
        for flayout in native_layout:
            layout = flayout.split('$')[-1]
            ori = self.repo.match(gStkBlk).where(layout=AND(ENDS_WITH(layout), EQ(flayout))).first()
            dup = self.repo.match(gStkBlk).where(layout=AND(ENDS_WITH(layout), NE(flayout))).first()
            ori_m_nodes = [self.graph.nodes.get(op.__node__.identity) for op in ori.lvars]
            ori_m_map = dict([(node.get('vid').rsplit('_')[-1], \
                self.repo.match(gMemObj, node.get('vid')).first()) for node in ori_m_nodes])

            if not (ori and dup):
                print(f"TODO: Unsolved block: {ori}{dup}")
                continue
            print(f"COMBINE {layout}:\nori:{ori}\ndup:{dup}")

            # Re-connect the localvar to the orignal stkblk
            for r in self.graph.match((None, dup.__node__), r_type="POINT_TO").all():
                lv_m = self.repo.get(gLocalVar, r.start_node.get('vid'))
                self.graph.separate(r)
                lv_m.alias.add(ori)
                to_update.append(lv_m)

            for op in dup.lvars:
                dup_n = self.graph.nodes.get(op.__node__.identity)
                dup_m = self.repo.match(gMemObj, dup_n.get('vid')).first()
                off = dup_m.vid.rsplit('_')[-1]
                ori_m = ori_m_map.get(off)
                if not ori_m: continue

                to_update.extend(self.migrate(dup_n, ori_m))

                self.graph.delete(dup_n)

            self.graph.delete(dup)
        
        for obj in to_update:
            self.repo.save(obj)
    
    '''
    Infer the alias of struct field and combine them together [within binary]
    '''    
    def combine_alias(self, binary):
        assigns = [self.transfer(stm) for stm in self.repo.match(Statement)\
            .where(cate='Assignment', binary=binary).all()]
        for assign in assigns:
            src, dst = None, None
            if list(assign.source.triples()):
                src = list(assign.source.triples())[0][2]
            if list(assign.dest.triples()):
                dst = list(assign.dest.triples())[0][2]
            if not(src and dst): continue
            if str(src.__node__.labels)[1:] in ['gLocalVar', 'gMemObj', 'gBlkRef', 'gStkBlk', 'gClazz'] and str(dst.__node__.labels)[1:] in ['gLocalVar', 'gMemObj']:
                self.resolve_alias(src.__node__, dst.__node__, 0)
            
    def resolve_alias(self, src, dst, flag):
        rs = self.graph.match((src, None), r_type='POINT_TO').all()
        if rs:
            self.resolve_alias(rs[0].end_node, dst, 0)
        else:
            refs2src = self.graph.match((None, src), 'REFER_TO').all()
            refs2dst = self.graph.match((None, dst), 'REFER_TO').all()
            refs2src_map = dict([(r.start_node.get('vid').rsplit('_',1)[-1], r) for r in refs2src])
            refs2dst_map = dict([(r.start_node.get('vid').rsplit('_',1)[-1], r) for r in refs2dst])
            joint = set(refs2src_map.keys()) & set(refs2dst_map.keys())
            
            # if joint:
            if refs2dst_map.keys():
                self.graph.create(POINT_TO(dst, src))
                for off in refs2dst_map.keys():
                    if off in joint:
                        dst_sub = refs2dst_map[off].start_node
                        src_sub = refs2src_map[off].start_node
                        if src_sub.has_label('gMemObj') and dst_sub.has_label('gMemObj'):
                            self.resolve_alias(src_sub, dst_sub, 1)
                    elif str(src.labels)[1:] in ['gLocalVar', 'gMemObj', 'gClazz']:
                        dst_sub = refs2dst_map[off].start_node
                        src_sub_m = gMemObj()
                        if str(src.labels)[1:] == 'gClazz':
                            src_sub_m.vid = '_'.join([src.get('name'), off])
                        else:
                            src_sub_m.vid = '_'.join([src.get('vid'), off])
                        src_sub_m.off = off
                        src_sub_m.binary = src.get('binary')
                        src_sub_m.func = src.get('func')
                        src_sub = src_sub_m.__node__
                        self.graph.merge(REFER_TO(src_sub, src))
                        self.graph.merge(CONTAIN(src, src_sub))
                        self.resolve_alias(src_sub, dst_sub, 1)
            elif flag and str(dst.labels)[1:] in ['gMemObj']:
                to_update = []
                src_m = self.repo.get(gMemObj, src.get('vid'))
                to_update.extend(self.migrate(dst, src_m))
                self.graph.delete(dst)
                self.repo.save(to_update) 

    def add_callback(self, binary):
        for blk in self.graph.nodes.match('gStkBlk', binary=binary).all():
            fname = self.get_invoke(blk)
            if not fname: continue

            for old in ['+','-',' ',':','[',']']:
                fname = fname.replace(old,'_')
            
            func = self.graph.nodes.match('Function', name=fname).first()
            callsites = []
            pts = self.graph.match((None,blk),r_type='POINT_TO').all()

            for pt in pts:
                handler = pt.start_node
                callsites.extend([r.start_node for r in self.graph.match((None,handler),r_type='USE').all()])

            for callsite in callsites:
                self.graph.merge(CALLBACK(callsite, func))

    def add_used(self):
        rs = self.graph.match((None, None), r_type='USE').all()
        for r in rs:
            func = r.start_node
            arg = r.end_node
            self.graph.create(USED_BY(arg, func, argidx=r.get('argidx')))
    
    '''
    Summary-based dataflow within cgg of each binary
    '''
    def process_dataflow(self, cg:CallGraph):
        self.curr_callgraph = cg
        for entry in cg.entry_points:
            if entry in self.summary: continue
            stack = [entry]
            self.dfs_dataflow_dispatcher(entry, stack)

    def dfs_dataflow_dispatcher(self, fname, stack):
        print(f"Meet {fname}")
        callbacks = set()
        caller = self.curr_callgraph.procedure_map.get(fname)
        if not caller: return
        for callee_name in caller['callees']:
            callee = self.curr_callgraph.procedure_map.get(callee_name)
            if not callee: continue
            if callee['is_callback']: 
                callbacks.add(callee_name)
                continue
            if callee_name not in self.summary:
                if callee_name not in stack:
                    stack.append(callee_name)
                    self.dfs_dataflow_dispatcher(callee_name, stack)
                else:
                    continue
        self.intraprocedural_dataflow(fname)
        try:
            self.summary[fname] = self.gen_summary(fname)
        except:
            print(f"Failed to generate summary for {fname}")
        for callback in callbacks:
            if callback not in stack:
                stack.append(callback)
                self.dfs_dataflow_dispatcher(callback, stack)
            else:
                continue

    def intraprocedural_dataflow(self, fname):
        print(f"Process on {fname}")
        for stm in self.repo.match(Statement).where(location=STARTS_WITH(fname)).all():
            if stm.cate == 'Assignment':
                assign = self.transfer(stm)
                src, dst = None, None
                if list(assign.source.triples()):
                    src = list(assign.source.triples())[0][2]
                if list(assign.dest.triples()):
                    dst = list(assign.dest.triples())[0][2]
                if not(src and dst): continue
                self.graph.create(DATA_DEP(dst.__node__, src.__node__, cate='Assign', stm=stm.location))
            elif stm.cate == 'Arithmetic':
                arith = self.transfer(stm)
                dst = None
                if list(arith.dest.triples()):
                    dst = list(arith.dest.triples())[0][2]
                for _ in arith.source.triples():
                    src = _[2]
                    if not(src and dst): continue
                    self.graph.create(DATA_DEP(dst.__node__, src.__node__, cate='Arith', stm=stm.location))
            elif stm.cate == 'MsgSend':
                msg = self.transfer(stm)
                ret = self.load_func_summary(msg)
                if not ret:
                    if list(msg.recv.triples()):
                        recv = self.graph.nodes.get(list(msg.recv.triples())[0][2].__node__.identity)
                    else: recv = None
                    ret = list(msg.ret.triples())[0][2]
                    args = [self.graph.nodes.get(op.__node__.identity) for op in msg.args]
                    for arg in args:
                        if arg.labels.__repr__() in [":gLocalVar", ":gMemObj", ":gGlobalLiteral"]:
                            self.graph.create(DATA_DEP(ret.__node__, arg, cate='MsgSend', stm=stm.location))
                    if recv and recv.labels.__repr__() in [":gLocalVar", ":gMemObj"]:
                        self.graph.create(DATA_DEP(ret.__node__, recv, cate='MsgSend', stm=stm.location))
            elif stm.cate == 'Call':
                call = self.transfer(stm)
                ret = list(call.ret.triples())[0][2]
                args = [self.graph.nodes.get(op.__node__.identity) for op in call.args]
                for arg in args:
                    self.graph.create(DATA_DEP(ret.__node__, arg, cate='Call', stm=stm.location))
            elif stm.cate == 'Jump':
                jmp = self.transfer(stm)
                for cond in jmp.conditions:
                    pass #TODO
        

    # Support msgsend and block invoke
    def gen_summary(self, fname):
        func = self.repo.get(Func, fname)
        if not func:
            return None
        effect = {0:[], 1:[]}
        if not(func.argidx_size) or not(func.retvaridx):
            return None
        # Need to exclude the rsi which is the sel string
        self_vid = f"{fname}$0"
        arg_vids = [f"{fname}${str(i)}" for i in range(func.argidx_size) if i > 1]
        for i in range(func.argidx_size):
            if i <= 1: continue
            effect[i] = []

        if func.retvaridx > -1:
            ret_vid = f"{fname}${func.retvaridx}"
            # Test the direct relation between self and ret
            cypher = f"MATCH p=(a:gLocalVar)-[:DATA_DEP|CONTAIN*]->(b:gLocalVar) \
                where a.vid='{ret_vid}' AND b.vid='{self_vid}' RETURN p"
            p = self.graph.run(cypher).to_subgraph()
            if p:
                effect[0].append(1)

            # Test the direct relation between other args and ret
            for arg_vid in arg_vids:
                cypher = f"MATCH p=(a:gLocalVar)-[:DATA_DEP|CONTAIN*]->(b:gLocalVar) \
                    where a.vid='{ret_vid}' AND b.vid='{arg_vid}' RETURN p"
                p = self.graph.run(cypher).to_subgraph()
                if p:
                    effect[0].append(int(arg_vid.split('$')[-1]))
                    
        summary = encode_summary(effect)

        return summary

    def load_func_summary(self, stm):
        if isinstance(stm, gMsg):
            ret = list(stm.ret.triples())[0][2]
            if list(stm.recv.triples()):
                recv = self.graph.nodes.get(list(stm.recv.triples())[0][2].__node__.identity)
            else: recv = None
            items = [(0, ret.__node__), (1, recv)]
            items.extend([(triple[1][1].get('argidx')+2, self.graph.nodes.get(triple[2].__node__.identity)) \
                for triple in stm.args.triples()])
            func_map = dict(items)
            if stm.name and get_summary(self.summary, stm.name):
                summary =  get_summary(self.summary, stm.name)
                effect = decode_summary(summary)
                used = False
                for dst, srcs in effect.items():
                    dst_node = func_map.get(dst)
                    for src in srcs:
                        src_node = func_map.get(src)
                        if dst_node and src_node:
                            self.graph.create(DATA_DEP(dst_node, src_node, cate='MsgSend', stm=stm.location))
                            used = True
                if used:
                    return 1
            else:
                # print(f"No summary: {stm.name}")
                pass

        elif isinstance(stm, gCall):
            pass
            
        return 0
    
    def get_blk_invoke(self, blk):
        fname, ea = None, None
        for r in self.graph.match((blk, None), r_type="CONTAIN").all():
            off = r.end_node.get('vid').rsplit('_',1)[-1]
            if not(int(off) == 16):
                continue
            if not self.graph.match((r.end_node, None), r_type="DATA_DEP").all():
                continue
            gl = self.graph.match((r.end_node, None), r_type="DATA_DEP").first().end_node
            fname = gl.get('name')
            for c in ['+', '-', '[', ']', ' ', ':']:
                fname = fname.replace(c, '_')
            ea = gl.get('ea')
            break
        
        return fname, ea

    '''
    Build COME_FROM relation between callers and callees
    '''
    def connect_procedurals(self, binary, cgg:CallGraphGenerator):
        for r in self.graph.match(None, r_type="START").all():
            callee = r.start_node
            if not(callee.get('binary') == binary):
                continue
            fname = callee.get('name')
            callee_graph = cgg.procedure_map.get(fname).graph
            call_to_set = self.graph.match((None, callee), r_type="CALL_TO").all()
            for call_to in call_to_set:
                callsite = call_to.start_node
                # Connect receiver from callsites to the callee
                if callsite.get('cate') == 'MsgSend':
                    callee_recv = self.graph.nodes.match("gLocalVar", vid=f"{fname}$0").first()
                    uses = self.graph.match((callsite,None), r_type="RECEIVER").all()
                    for use in uses:
                        caller_recv = use.end_node
                        if callee_recv:
                            self.graph.create(COME_FROM(callee_recv, caller_recv, cate='Inter'))
                
                # Connect arguments from callsites to the callee
                uses = self.graph.match((callsite,None), r_type="USE").all()
                for use in uses:
                    caller_arg = use.end_node
                    if callsite.get('cate') == 'MsgSend':
                        argidx = use.get('argidx')+2
                    elif callsite.get('cate') == 'Call':
                        argidx = use.get('argidx')
                    else:
                        print(use)
                        continue
                    arg_vid = f"{fname}${str(callee_graph.args_map.get(argidx))}"
                    callee_arg = self.graph.nodes.match("gLocalVar", vid=arg_vid).first()
                    if callee_arg:
                        self.graph.create(COME_FROM(callee_arg, caller_arg, cate='Inter'))
                        
                #  Connect return values from callsites to the callee
                if callee.get('retvaridx') and callee.get('retvaridx')>-1 and callee.get('name'):
                    retidx = '$'.join([callee.get('name'), str(callee.get('retvaridx'))])
                    if self.repo.get(gLocalVar, retidx):
                        retvar = self.repo.get(gLocalVar, retidx).__node__
                        for r in self.graph.match((callsite,None), r_type="RET").all():
                            callsite_ret = r.end_node
                            self.graph.create(COME_FROM(callsite_ret, retvar, cate='Inter'))
                        
        for msg in self.repo.match(gMsg).where(name=ENDS_WITH("enumerateObjectsUsingBlock:]")).all():
            if not(list(msg.args.triples())[0][-1] and list(msg.callee.triples())[0][-1]):
                continue
            arg = list(msg.args.triples())[0][-1].__node__
            callee = list(msg.callee.triples())[0][-1].__node__
            if not self.graph.match((arg, None), r_type="POINT_TO").all():
                continue
            blk = self.graph.match((arg, None), r_type="POINT_TO").first().end_node
            fname, ea = None, None
            
            # Get the function invoked using block
            fname, ea = self.get_blk_invoke(blk)
                
            # Connect the function and the arg
            for invoke in self.repo.match(Func).where(entry_ea=ea, name=fname).all():
                self.graph.create(CALL_TO(callee, invoke.__node__))
            
                recv = list(msg.recv.triples())[0][-1].__node__
                arg_vid = f"{fname}${1}"
                callee_arg = self.graph.nodes.match("gLocalVar", vid=arg_vid).first()
                self.graph.create(COME_FROM(callee_arg, recv, cate='Inter'))
        
        for call in self.repo.match(gCall).where(name=STARTS_WITH("_dispatch_")).all():
            callee = list(call.callee.triples())[0][-1].__node__
            for use in self.graph.match((call.__node__, None), r_type="USE").all():
                if not(use.get('argidx') == 1):
                    continue
                arg = use.end_node
                if str(arg.labels) == ':gLocalVar':
                    pts = self.graph.match((arg, None), r_type="POINT_TO").all()
                    if not pts:
                        continue
                    blk = pts[0].end_node
                    if not str(blk.labels) == ':gStkBlk':
                        continue
                elif str(arg.labels) == ':gStkBlk':
                    blk = arg
                else:
                    continue
                
                # Get the function invoked using block
                fname, ea = self.get_blk_invoke(blk)
                    
                # Connect the function and the arg
                for invoke in self.repo.match(Func).where(entry_ea=ea, name=fname).all():
                    self.graph.create(CALL_TO(callee, invoke.__node__))