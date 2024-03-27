import idaapi
import idc

from collections import namedtuple

Import = namedtuple('ImportedSymbol', ['ea', 'name', 'ordinal'])

class Imports(object):
    def __init__(self):
        self.mapping = {}
        self.len = 0
        self.index()

    def index(self):
        for i in range(idaapi.get_import_module_qty()):
            dllname = idaapi.get_import_module_name(i)
            if not dllname:
                continue

            entries = []
            def cb(ea, name, ordinal):
                entries.append(Import(ea, name, ordinal))
                return True  # continue enumeration

            idaapi.enum_import_names(i, cb)
            self.mapping[dllname] = ImportsSubset(dllname, entries)
            self.len = self.len + len(entries)

    def get(self, key):
        return self.mapping.get(key)

    def __getitem__(self, key):
        return self.mapping[key]
    
    def __contains__(self, key):
        return key in self.mapping

    def __iter__(self):
        for subset in self.mapping.values():
            yield from subset
       
    def find_by_name(self, name, ignore_case=False):
        def eq(a, b):
            if ignore_case:
                return a.lower() == b.lower()
            return a == b

        for dllname, item in self.mapping.items():
            for imp in item:
                if eq(imp.name, name):
                    return imp

        raise StopIteration

    def libraries(self):
        yield from self.mapping.keys()


class ImportsSubset(object):
    def __init__(self, dllname, entries):
        self.dllname = dllname
        self.entries = entries
        self.index = { entry.name: entry for entry in entries }

    def __len__(self):
        return len(self.entries)
    
    def get(self, key):
        return self.index.get(key)

    def __getitem__(self, key):
        return self.index[key]

    def __iter__(self):
        yield from self.entries

    def __contains__(self, key):
        return key in self.index


imps = Imports()

clazz2libs = {}
for lib_path, imp_subset in imps.mapping.items():
    for entry in imp_subset.entries:
        if entry.name.startswith('_OBJC_CLASS_$_'):
            clazz = entry.name[len('_OBJC_CLASS_$_'):]
            clazz2libs[clazz] = lib_path

__all__ = ['imps']
