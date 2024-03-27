import idaapi
import time

idaapi.require('libs.utils')
idaapi.require('intra_procedural')
idaapi.require("record")
idaapi.require("libs.queries")

from intra_procedural import *
from record import *
from libs.queries import *

class BaseScan:
    def __init__(self, binary) -> None:
        self.binary = binary
        self.entries = None
        self.cgdb, self.cpgdb = None, None
        self.cgg, self.cg, self.pcg = None, None, None
        self.rec = Recorder()
        self.qd = QueryDelegate()
    
    def prepare_db(self, db):
        if self.rec.exist_db(db):
            self.rec.graph.run(f"DROP DATABASE {db}")
            self.rec.update_db(None)
        self.rec.graph.run(f"CREATE DATABASE {db}")
        self.rec.update_db(db)
        self.qd.update_neo(db)
        time.sleep(5)
    
    def switch_neo(self, db):
        self.rec.update_db(db)
        self.qd.update_neo(db)
        
    def find_entries(self):
        # Override to find entries for analysis
        pass
        
    def gen_callgraph(self):
        self.cgg = CallGraphGenerator(self.entries, self.cgdb, db=False, max_depth=10)
        self.cgg.build_call_relations()
        self.cg = self.cgg.dump_callgraph()
        self.rec.commit_callgraph(self.cgdb, self.cg)
        self.prune_cg()
        
    def prune_cg(self):
        # Override to perform pruning on call graph
        self.pcg = self.cg
    
    def commit_cpg(self):
        cnt = 0
        for fname in self.pcg.procedure_map:
            proc = self.cgg.procedure_map.get(fname)
            cpg = proc.graph
            self.rec.commit_func(cpg, fname, self.binary)
            cnt += 1
        print(f"[*] Commit {cnt} functions")
        self.rec.combine_context(self.binary)
        self.rec.combine_alias(self.binary)
        self.rec.add_callback(self.binary)
        self.rec.process_dataflow(self.pcg)
        self.rec.connect_procedurals(self.binary, self.cgg)