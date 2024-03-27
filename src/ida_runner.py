import idaapi
import idc
from pathlib import Path
import json
import subprocess

idaapi.require("scanners.services")

from scanners.services import ServiceChecker

def process4service(binary, bin_dir):
    mySC = ServiceChecker(binary)
    mySC.gen_callgraph()
    mySC.commit_cpg()
    if mySC.frameworks:
        fws = {}
        for fwp, entries in mySC.frameworks.items():
            fw = fwp.rsplit('/', 1)[-1]
            fws[fw] = list(entries)
        fws_out =  f"{bin_dir}/out/{binary}_frameworks.json"
        with open(fws_out, 'w', encoding='utf8') as f:
            json.dump(fws, f, ensure_ascii=False)
    
    for fwp, entries in mySC.frameworks.items():
        fw = fwp.rsplit('/', 1)[-1]
        fw_idb = f"{bin_dir}/frameworks/{fw}.i64"
        cmd = f"ida64 -A -S\"{__file__} {binary} {bin_dir} {fw}\" -L\"{bin_dir}/out/{fw}.log\" {fw_idb}"
        p = subprocess.Popen(cmd, shell=True)
        exit_code = p.wait()
        if exit_code:
            print(f"Failed to analyze i64 of fw.")
        else:
            print(f"Finish analyze i64 of fw.")
        
    validations = mySC.print_validitions()
    validations_out =  f"{bin_dir}/out/{binary}_input_validations.json"
    with open(validations_out, 'w', encoding='utf8') as f:
        json.dump(validations, f, ensure_ascii=False)
            
    return mySC
            
def process4framework(binary, bin_dir, fw):
    fws_out =  f"{bin_dir}/out/{binary}_frameworks.json"
    with open(fws_out, 'r') as f:
        fws = json.load(f)
    entries = fws.get(fw)
    mySC = ServiceChecker(fw, entries)
    mySC.gen_callgraph(f"{binary}.cg")
    mySC.commit_cpg(f"{binary}.cpg")
    
    return mySC


if __name__ == "__main__":
    idaapi.require('batch')
    from batch import BatchMode

    with BatchMode():
        print(idc.ARGV)
        binary = idc.ARGV[1]
        bin_dir = Path(idc.ARGV[2])
        if len(idc.ARGV) == 4:
            fw = idc.ARGV[3]
            mySC_fw = process4framework(binary, bin_dir, fw)
        elif len(idc.ARGV) == 3:
            mySC_sr = process4service(binary, bin_dir)
        
