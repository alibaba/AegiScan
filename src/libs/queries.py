from models.graph import *
from libs.hint import str_checks
from collections import namedtuple
from py2neo.matching import ENDS_WITH
import copy
FCheck = namedtuple('FCheck', ['fname', 'loc', 'step2', 'retidx', 'inner'])

'''
FChecks are stored in QueryDelegate.check_map, where:
* fname is the name of the function check
* loc is a list containing locations where the fcheck appears in the binary
* step2 means whether the fcheck need to step into for further analysis,
and if so , the list inner stores the checks or stms inside the fcheck
'''

SQuery = namedtuple('SQuery', ['prev_loc', 'succ_loc', 'checks'])

# Basic cypher pattern with 'SOURCE' and 'SINK' as placeholders
cypher_patterns = {
    'stm2stm_long': "MATCH (a:Statement {location:'SOURCE'}), (b:Statement {location:'SINK'}), path = (a)-[:NEXT*]->(b)  WHERE apoc.coll.duplicates(NODES(path)) = [] RETURN path ORDER BY LENGTH(path) DESC LIMIT 1",
    'stm2stm': "MATCH (a:Statement {location:'SOURCE'}), (b:Statement {location:'SINK'}), path = allShortestPaths((a)-[:NEXT*]->(b)) RETURN path LIMIT 1",
    'stm2stm_all': "MATCH (a:Statement {location:'SOURCE'}), (b:Statement {location:'SINK'}), path = (a)-[:NEXT*]->(b)  WHERE apoc.coll.duplicates(NODES(path)) = [] RETURN path",
    'lv2lv_all': "MATCH (a:gLocalVar|gMemObj {vid:'SINK'}), (b:gLocalVar {vid:'SOURCE'}), path = (a)-[:DATA_DEP|COME_FROM*]->(b)  WHERE apoc.coll.duplicates(NODES(path)) = [] RETURN path ORDER BY LENGTH(path) LIMIT 5",
    'lv2lv': "MATCH (a:gLocalVar|gMemObj {vid:'SINK'}), (b:gLocalVar {vid:'SOURCE'}), path = allShortestPaths((a)-[:DATA_DEP|COME_FROM*]->(b)) RETURN path",
    'cnt2lv': "MATCH (a:gLocalVar {vid:'SINK'}), (b:gConst {value:'SOURCE'}), path = (a)-[:DATA_DEP|COME_FROM*]->(b)  WHERE apoc.coll.duplicates(NODES(path)) = [] RETURN path ORDER BY LENGTH(path) LIMIT 1",
    'func2stm': "MATCH (a:Function {name:'SOURCE'}), (b:Statement {location:'SINK'}), path = (a)-[:START|NEXT*]->(b)  WHERE apoc.coll.duplicates(NODES(path)) = [] RETURN path ORDER BY LENGTH(path) LIMIT 1",
    'jmp2lv': "MATCH (a:Statement {location:'SINK'}), (b:gLocalVar {vid:'SOURCE'}), path = allShortestPaths((a)-[:DEP_ON|DATA_DEP|COME_FROM*]->(b)) RETURN path",
    'jmp2ret': "MATCH (a:Statement {location:'SINK'}), (b:gRet), path = allShortestPaths((a)-[:DEP_ON|DATA_DEP*]->(b)) RETURN path",
    'dep2ret': "MATCH (a:gLocalVar|gMemObj {vid:'SINK'}), (b:gRet), path = allShortestPaths((a)-[:DATA_DEP*]->(b)) RETURN path",
    'lv2gl': "MATCH (a:gGlobalLiteral), (b:gLocalVar {vid:'SINK'}), path = allShortestPaths((b)-[:POINT_TO|DATA_DEP|COME_FROM|CONTAIN|REFER_TO*]->(a)) RETURN path",
    'func2func': "MATCH (a:Function {name:'SOURCE'}), (b:Function {name:'SINK'}), path = allShortestPaths((a)-[:CALLEE*]->(b)) RETURN path" 
}

def gen_cypher(pattern:str, source:str, sink:str):
    res = pattern.replace('SOURCE', source)
    res = res.replace('SINK', sink)
    return res

def clean_consts(consts):
    dup = []
    for cst in consts:
        if ("^(http" in cst) and (cst not in dup):
            dup.append(cst)
    return dup

class QueryDelegate:
    
    def __init__(self, db=None):
        self.graph, self.repo = connect(db)
        self.check_map = {}
        self.cache = {}
        
    def update_neo(self, db):
        self.graph, self.repo = connect(db)
    
    def filter_entries(self, cg, sinks):
        valid_entries = {}
        for entry in cg.entry_points:
            for sink in sinks:
                cmd = gen_cypher(cypher_patterns['func2func'], entry, sink)
                cursor = self.graph.run(cmd)
                tbs = cursor.to_table()
                if tbs and len(tbs[0][0].nodes)>=2:
                    chain = tbs[0][0].nodes
                    # call_stack = '->'.join([fnode.get('name') for fnode in chain])
                    valid_entries[f"{entry}${sink}"] = chain
        
        return valid_entries
    
    def add_chains(self, cg, pcg, call_chains):
        for chain in call_chains:
            for fnode in chain:
                fname = fnode.get('name')
                item = cg.procedure_map.get(fname)
                if not item: continue
                if chain.index(fnode) < len(chain)-1:
                    succ = chain[chain.index(fnode)+1].get('name')
                    if succ[1]=='[':
                        for callee in item.get('callees'):
                            if not(callee[1]=='['):
                                continue
                            if callee == succ:
                                continue
                            '''
                            Remove fuzzy matched methods which are not in the call chains
                            '''
                            if callee.split(' ')[1][:-1] == succ.split(' ')[1][:-1]:
                                print(callee, succ)
                                idx = item['callees'].index(callee)
                                item['callees'].pop(idx)
                pcg.procedure_map[fname] = item
    
    def rebuild_cg(self, cg, pcg, starts, black):
        worklist = [fnode.get('name') for fnode in starts]
        record = set()        
        while worklist:
            fname = worklist[0]
            record.add(fname)
            item = cg.procedure_map.get(fname)
            if not item:
                worklist.pop(0)
                continue
            if fname not in pcg.procedure_map:
                pcg.procedure_map[fname] = item
            for callee in item.get('callees'):
                # Filter out log related functions
                care, f_low = True, callee.lower()
                for kw in black:
                    if kw in f_low:
                        care = False
                        break
                if care and (callee not in worklist) and (callee not in record):
                    worklist.append(callee)
            worklist.pop(0)
        
    def prune_cg(self, cg, sinks, black=[]):
        valid_entries = self.filter_entries(cg, sinks)
        call_chains = valid_entries.values()
        starts = [chain[-2] for chain in call_chains]
    
        pcg = copy.copy(cg)
        pcg.entry_points = cg.entry_points[:]
        pcg.procedure_map = {}
        self.add_chains(cg, pcg, call_chains)
        self.rebuild_cg(cg, pcg, starts, black)
        
        return pcg

    def set_entry_src(self, fname, idxs):
        entry = '$'.join([fname, '1_0'])
        src = ['$'.join([fname, str(idx)]) for idx in idxs]
        
        return entry, src
    
    def set_full_src(self, fnames):
        src = []
        for fname in fnames:
            func = self.graph.nodes.match("Function", name=fname).first()
            if not (func and func.get('argidx_size')):
                continue
            size = func.get('argidx_size')
            if fname.startswith('sub_'):
                for i in range(1, size):
                    src.append('$'.join([fname, str(i)]))
            else:
                for i in range(2, size):
                    src.append('$'.join([fname, str(i)]))
        return src            
    
    def set_sink(self, fname, cares, values):
        targets = []
        hint = fname
        if fname[0] == '*':
            hint = fname[1:]
        if fname[2] == '*':
            hint = fname[4:]
        for f in self.repo.match(gMsg).where(name=ENDS_WITH(hint)).all():
            args = list(f.args.triples())
            unmatch = False
            for i in range(len(args)):
                if not cares[i]: 
                    continue
                arg = args[i][2].__node__
                if not(values[i] == -1) and arg.labels.__repr__() == ':gConst':
                    val = arg.get('value').rsplit('$')[-1]
                    if not (int(val) == values[i]):
                        unmatch = True
            if not unmatch:
                targets.append(f)
                
        return targets
    
    def find_sinks(self, sink_rule):
        sinks = {}
        callsites = []
        for fname in sink_rule.keys():
            callsites.extend(self.graph.nodes.match("Statement", name=fname).all())
            
        for callsite in callsites:
            self.graph.match((callsite, None), r_type='USE')
            args = sink_rule.get(callsite.get('name'))
            for i in range(len(args)):
                if not args[i]:
                    continue
                r = self.graph.match((callsite, None), r_type='USE').where(argidx=i).first()
                if r and r.end_node.get('vid'):
                    para_id = '$'.join([callsite.get('name'), str(i)])
                    sinks[para_id] = (callsite, r.end_node.get('vid'))
    
        return sinks
    
    def check_taint_between_lvs(self, src, dest):
        cmd = gen_cypher(cypher_patterns['lv2lv'], src, dest)
        cursor = self.graph.run(cmd)
        tbs = cursor.to_table()
        return tbs
    
    def process(self, entry, srcs, targets):
        for f in targets:
            print(f"[*] Analyze target {f.name} from {entry}...")
            self.get_checks_between_2stms(entry, f.location, srcs)
    
    # Transfer given obj from base model to submodel
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

    def get_stm_by_loc(self, loc):
        stm = self.repo.match(Statement).where(location=loc).first()
        return self.transfer(stm)

    # Transfer opnds' data flow to stm flow
    def get_stm_slice(self, opnds):
        stm_slice = []
        for i in range(len(opnds)-1, 0, -1):
            l, r = opnds[i], opnds[i-1]
            stm = self.get_single_stm(l, r, 'DATA_DEP')
            if stm:
                stm_slice.append(stm)
        
        return stm_slice
    
    def get_single_stm(self, left, right, r_type):
        model = None
        relation = self.graph.match((right, left), r_type=r_type).first()
        if relation:
            stm = self.repo.match(Statement).where(location=relation.get('stm')).first()
            model = self.transfer(stm)
        
        return model

    def extend_inner(self, inner, checks):
        flag = False
        for _ in inner:
            # TODO: now duplication of subset is removed
            if set(_) < set(checks):
                idx = inner.index(_)
                inner[idx] = checks
                flag = True
                break
            elif set(_) >= set(checks):
                flag = True
                break
        if not flag:    
            inner.append(checks)
        
    # Extract checks from statement slice (not used yet)
    def get_checks(self, stm_slice):
        checks = []
        for i in range(len(stm_slice)-1):
            prev = stm_slice[i]
            succ = stm_slice[i+1]
            prev_blk = prev.location.split('$')[-1].split('_')[0]
            succ_blk = succ.location.split('$')[-1].split('_')[0]
            # No jmps in the same blk, just skip
            if prev_blk == succ_blk:
                continue
            print(f"[*] Extract checks between {prev.location} and {succ.location}")
            self.get_checks_between_2stms(prev.location, succ.location)

    def get_checks_between_2stms(self, prev_loc, succ_loc, deps=[]):
        result = [] 
        # cmd = gen_cypher(cypher_patterns['stm2stm_long'], prev_loc, succ_loc)
        cmd = gen_cypher(cypher_patterns['stm2stm_all'], prev_loc, succ_loc)
        cursor = self.graph.run(cmd)
        tbs = cursor.to_table()
        parsed = []
        for tb in tbs:
            path = tb[0]
            checks = [] # List of multiple paths of checks
            for stm in path.nodes:
                if stm.get('cate') != 'Jump':
                    continue
                if stm.get('is_goto'):
                    continue
                if stm.identity in parsed:
                    continue
                parsed.append(stm.identity)
                if deps and not self.is_sensitive(stm, deps):
                    continue
                check = self.callsite4jmp(stm)
                if not check: continue
                checks.append(check.fname)
                if check.fname not in self.check_map:
                    self.check_map[check.fname] = check
                    if deps and check.step2:
                        self.check4ret(check.fname, check.retidx, deps[0]) # TODO:more deps
                else:
                    exit_locs = self.check_map[check.fname].loc
                    # print(check.fname, check.loc, exit_locs)
                    if not(set(check.loc) <= set(exit_locs)):
                        exit_locs.extend(check.loc)
            if checks and (checks not in result):
                self.extend_inner(result, checks)
        
        if result:
            idx = len(self.cache)
            sq = SQuery(prev_loc, succ_loc, result)
            self.cache[idx+1] = sq
            
        return result

    def callsite4jmp(self, jmp):
        for dep_r in self.graph.match((jmp, None), r_type='DEP_ON').all():
            callsite, const = None, []
            if str(dep_r.end_node.labels).endswith('gConst'):
                continue
            elif str(dep_r.end_node.labels).endswith('gRet'):
                ret = dep_r.end_node
                callsite = self.repo.get(gMsg, ret.get('callsite'))
            elif str(dep_r.end_node.labels).endswith(('gLocalVar', 'gMemObj')):
                dep = dep_r.end_node
                cmd = gen_cypher(cypher_patterns.get('dep2ret'), '', dep.get('vid'))
                cursor = self.graph.run(cmd)
                tbs = cursor.to_table()
                if not tbs:
                    continue
                for ret in tbs[0][0].nodes:
                    if str(ret.labels).endswith('gRet'):
                        break
                callsite = self.repo.get(gMsg, ret.get('callsite'))
            fname, step2, retidx = self.resolve_callsite(callsite)
            fc = FCheck(fname, [callsite.location], step2, retidx, [])
            print(f"\t[-] Meet check: {callsite.name}") 
            
            return fc
        
        return None

    def check4ret(self, func, ret_vid, src):
        print(f"\t[*] Step into {func}...")  
        start_stm = self.repo.match(Statement, f"{func}$1_0").first()
        end_stm = self.repo.match(Statement).where(cate='End', func=func).first()
        cnt, ret = f"{func}$1", ret_vid
        checks = []
        # Case 1: ret value comes from src (direct dep on src)
        cmd = gen_cypher(cypher_patterns['lv2lv_all'], src, ret_vid)
        cursor = self.graph.run(cmd)
        tbs = cursor.to_table()
        if tbs:
            msgs = {}
            for tb in tbs:
                path = tb[0]
                stm_slice = self.get_stm_slice(path.nodes)
                for stm in stm_slice:
                    if not isinstance(stm, gMsg):
                        continue
                    fname, step2, retidx = self.resolve_callsite(stm)
                    fc = FCheck(fname, [stm.location], step2, retidx, []) # these callsites are used as inners
                    sel = fname.split(' ')[-1][:-1]
                    if (sel in str_checks) and (fname not in self.check_map):
                        self.check_map[fname] = fc
                    # TODO: if step2?
                    loc = stm.location.split('$')[-1]
                    msgs[loc] = fc
            tmp = sorted([100*int(k.split('_')[0]) + int(k.split('_')[1]) for k in msgs.keys()])
            inner = []
            for i in tmp:
                loc = '_'.join([str(i//100), str(i%100)])
                fc = msgs[loc]
                inner.append(fc.fname)
                print(f"\t\t[-] Meet check: {fc.fname}")
            if inner: 
                top = self.check_map.get(func)
                self.extend_inner(top.inner, inner)
        # Case 2: ret value comes from some consts (indirect dep on src)
        else:
            cmd = gen_cypher(cypher_patterns.get('cnt2lv'), cnt, ret)
            cursor = self.graph.run(cmd)
            tbs = cursor.to_table()
            if tbs:
                path = tbs[0][0]
                middle_stm = self.get_single_stm(path.nodes[-1], path.nodes[-2], 'DATA_DEP')
                ret1 = self.get_checks_between_2stms(start_stm.location, middle_stm.location, [src])
                ret2 = self.get_checks_between_2stms(middle_stm.location, end_stm.location, [src])
                top = self.check_map.get(func)
                for checks in ret1:
                    self.extend_inner(top.inner, checks)
                for checks in ret2:
                    self.extend_inner(top.inner, checks)     
        
        return checks
            
    def resolve_callsite(self, callsite):
        fname = callsite.name
        f = list(callsite.callee.triples())[0][2]
        if self.graph.match((f.__node__, None), r_type='START').all():
            step2 = True
            retidx = '$'.join([fname, str(f.retvaridx)])
        else:
            step2 = False
            retidx = None
        return fname, step2, retidx

    def guess_values(self, op):
        vid = op.get('vid')
        cmd = gen_cypher(cypher_patterns.get('lv2gl'), '', vid)
        cursor = self.graph.run(cmd)
        tbs = cursor.to_table()
        if tbs:
            values = []
            values = [tb[0].end_node.get('value') for tb in tbs if tb[0].end_node.get('value')]
            return values
        else:
            return []

    # Check if the jmp depend on taint source
    def is_sensitive(self, jmp, deps):
        cared = False
        for dep in deps:
            cmd = gen_cypher(cypher_patterns.get('jmp2lv'), dep, jmp.get('location'))
            cursor = self.graph.run(cmd)
            if cursor.to_table():
                cared = True
                break
        
        return cared
    
    def get_const(self, arg):
        consts, pre_consts = [], []
        if str(arg.labels).endswith('gGlobalLiteral'):
            if arg.get('value'):
                consts.append(arg.get('value'))
        elif str(arg.labels).endswith('gLocalVar'):
            context = arg.get('vid').split('$')[0]
            cmd = gen_cypher(cypher_patterns.get('lv2gl'), '', arg.get('vid'))
            cursor = self.graph.run(cmd)
            tbs = cursor.to_table()
            if tbs:
                once = False
                for tb in tbs:
                    if not tb[0].end_node.get('value'):
                        continue
                    consts.append(tb[0].end_node.get('value'))
                    if not once:
                        path = tb[0]
                        stm_slice = self.get_stm_slice(path.nodes)
                        stm_slice.reverse()
                        for stm in stm_slice:
                            if not stm.location.startswith(context):
                                break
                            if not stm.cate == 'MsgSend':
                                continue
                            pre_consts.append(stm.name)
                        once = True

        return consts, pre_consts
    
    def get_dominators(self, src, tar):
        results = []
        context = tar.split('$')[0]
        cmd = gen_cypher(cypher_patterns['lv2lv'], src, tar)
        cursor = self.graph.run(cmd)
        tbs = cursor.to_table()
        if tbs:
            path = tbs[0][0]
            stm_slice = self.get_stm_slice(path.nodes)
            stm_slice.reverse()
            for stm in stm_slice:
                if not stm.location.startswith(context):
                    break
                if not stm.cate == 'MsgSend':
                    continue
                results.append(stm.name)
        
        return results
    
    def parse_validation(self, fcheck:FCheck):
        fname = fcheck.fname
        cnt_all = []
        for loc in fcheck.loc:
            stm = self.repo.get(Statement, loc)
            uses = self.graph.match((stm.__node__, None), r_type="USE").all()
            cnts = []
            for use in uses:
                argidx = use.get('argidx')
                arg = use.end_node
                if str(arg.labels).endswith('gGlobalLiteral'):
                    if arg.get('value'):
                        cnts.append(arg.get('value'))
            cnt_all.append(cnts)           
        return fname, cnt_all
         