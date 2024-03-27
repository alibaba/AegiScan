import idaapi
import ida_name
import idc

idaapi.require("scanners.base")
idaapi.require("sinks.sinks")
idaapi.require("entries.nsxpc")
idaapi.require("entries.xpc")
idaapi.require("record")
idaapi.require("libs.queries")

from scanners.base import BaseScan
from sinks.sinks import get_oc_sinks_map, get_c_sinks_map
from entries.nsxpc import nsxpc_entries
from entries.xpc import xpc_entries
from record import *
from libs.queries import *

class ServiceChecker(BaseScan):
    def __init__(self, binary, entries=None) -> None:
        super().__init__(binary)
        if not entries:
            self.entries, self.entry_fnames = self.find_entries()
        else:
            self.entries, self.entry_fnames = self.trans_entries(entries)
        self.frameworks = {}

    def trans_entries(self, fnames):
        entries = set()
        entry_fnames = set()
        for fname in fnames:
            fea = ida_name.get_name_ea(idc.BADADDR, fname)
            if fea != idc.BADADDR:
                entries.add(fea)
                entry_fnames.add(fname)
        return entries, entry_fnames
        
    def find_entries(self):
        entries = set()
        entry_fnames = set()
        xpc_eas, xpc_fnames = xpc_entries()
        entries.update(xpc_eas)
        entry_fnames.update(xpc_fnames)
        nsxpc_eas, nsxpc_fnames = nsxpc_entries()
        entries.update(nsxpc_eas)
        entry_fnames.update(nsxpc_fnames)
        return entries, entry_fnames
    
    def gen_callgraph(self, cgdb=None):
        # Setup database first
        if not cgdb:
            self.cgdb = '.'.join([self.binary, 'cg'])
            self.prepare_db(self.cgdb)
        else:
            self.cgdb = cgdb
            self.switch_neo(cgdb)
        # generate and commit call graph, then prune it.
        super().gen_callgraph()
        self.frameworks = self.cgg.externals
        
    def get_sink_callsites(self):
        sink_rule = {}
        sink_rule.update(get_oc_sinks_map())
        sink_rule.update(get_c_sinks_map())
        callsites = set()
        for f, item in self.cg.procedure_map.items():
            callees = item.get('callees')
            for callee in callees:
                if callee in sink_rule.keys():
                    print(callee, f)
                    callsites.add(f)
                    
        return callsites
        
    def prune_cg(self):
        callsites = self.get_sink_callsites()
        if callsites:
            print(f"Prune call graph for {callsites}")
            self.pcg = self.qd.prune_cg(self.cg, callsites)
        else:
            super().prune_cg()
        
        return callsites
    
    def commit_cpg(self, cpgdb=None):
        # Setup database first
        if not cpgdb:
            self.cpgdb = '.'.join([self.binary, 'cpg'])
            self.prepare_db(self.cpgdb)
        else:
            self.cpgdb = cpgdb
            self.switch_neo(cpgdb)
        # commit code property graph and construct dataflow
        super().commit_cpg()
        
    def get_ipc_inputs(self):
        if not self.cpgdb:
            self.cpgdb = '.'.join([self.binary, 'cpg'])
        self.qd.update_neo(self.cpgdb)
        ipc_inputs = self.qd.set_full_src(self.entry_fnames)
        
        return ipc_inputs
        
    def get_sensitive_para(self):
        if not self.cpgdb:
            self.cpgdb = '.'.join([self.binary, 'cpg'])
        self.qd.update_neo(self.cpgdb)
        sink_rule = {}
        sink_rule.update(get_oc_sinks_map())
        sink_rule.update(get_c_sinks_map())
        sinks = self.qd.find_sinks(sink_rule)
        
        return sinks
    
    def parse_validation4api(self):
        fcnt_map = {}
        for fchecks in self.qd.check_map.values():
            fname, cnt_all = self.qd.parse_validation(fchecks)
            fcnt_map[fname] = cnt_all
            
        return fcnt_map
            
    def extract_validations(self):
        if not self.cpgdb:
            self.cpgdb = '.'.join([self.binary, 'cpg'])
        self.qd.update_neo(self.cpgdb)
        ipc_inputs = self.get_ipc_inputs()
        sinks = self.get_sensitive_para()
        validations = {}
        for src in ipc_inputs:
            for api, sink in sinks.items():
                tbs = self.qd.check_taint_between_lvs(src, sink[1])
                if tbs:
                    print(f"callsite: {api}, sink: {sink[1]}, tainted by {src}")
                    entry_fname = src.rsplit('$', 1)[0]
                    entry = '$'.join([entry_fname, '1_0'])
                    callsite = sink[0].get('location')
                    stm_slice = self.qd.get_stm_slice(tbs[0][0].nodes)
                    if not(stm_slice[0].location == entry):
                        stm_slice.insert(0, self.qd.get_stm_by_loc(entry))
                    if not(stm_slice[-1].location == callsite):
                        stm_slice.append(self.qd.get_stm_by_loc(callsite))
                    self.qd.get_checks(stm_slice)
                    validations[f"{src}->{api}"] = self.parse_validation4api()
                    self.qd.check_map = {}
        
        return validations
    
    def print_validitions(self):
        validations = self.extract_validations()
        for taint, fcnt_map in validations.items():
            print(f"Tainted trace detected: {taint}")
            for fname, cnt_all in fcnt_map.items():
                for cnts in cnt_all:
                    if cnts:
                        print(f"\t{fname}, const args: {cnts[:]}")
                    else:
                        print(f"\t{fname}, without const args")
        
        return validations