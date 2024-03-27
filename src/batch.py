import os
import sys
import idc


class BatchMode(object):
    def __enter__(self):
        idc.auto_mark_range(0, idc.BADADDR, idc.AU_FINAL)
        idc.auto_wait()
        return self

    def __exit__(self, type, value, trace):
        if 'idat' in os.path.basename(sys.executable):
            idc.qexit(0)
        idc.qexit(0)
        # else: debugging, do nothing
