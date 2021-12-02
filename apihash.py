import sys
import os
import pefile
import glob

def get_exports(exe_path=None):
    result = dict()
    pe = pefile.PE(exe_path)

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        result[dll_name] = list()
        for func in entry.imports:
#            print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
            result[dll_name].append(func.name.decode('utf-8'))
    return result

def _mask(n):
   if n >= 0:
       return 2**n - 1
   else:
       return 0

def ror(n, rotations=1, width=8):
    rotations %= width * 8  
    if rotations < 1:
        return n
    mask = _mask(8 * width)  
    n &= mask
    return (n >> rotations) | ((n << (8 * width - rotations)) & mask)  

def hash(string):
    result = 0x0
    bits = 13
    size = 4

    for c in string:
        result = ror(result, bits, size)
        result += c

    result = ror(result, 13, 4) # terminator
    return result

def enc(dll_name, api_name):
    result = dict()
    dll_name = dll_name.upper()

    # convert DLL name to UNICODE UTF-16
    dll_name_utf16 = bytearray(dll_name, encoding="utf-16-le")
    dll_name_utf16.append(0x00)
    api_name_utf8 = bytearray(api_name, encoding="utf-8")

    dll_hash = hash(dll_name_utf16, dll=True)
    api_hash = hash(api_name_utf8)
    tot_hash = (dll_hash + api_hash) & 0xFFFFFFFF

    result['dll_hash'] = hex(dll_hash)
    result['api_hash'] = hex(api_hash)
    result['hash'] = hex(tot_hash)

    return result

def get_exports_from_dll_dir():
    result = dict()
    for file in glob.glob(r"C:\Windows\System32\*.dll"):
        result[file] = list()
        pe = pefile.PE(file)
        print(f"Searching exports in: {file}...")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is None:
                    continue # skip None exports
#                print(exp.name.decode('utf-8'))
                result[file].append(exp.name.decode('utf-8'))
    return result

def dec(hash, exe_path):
    exports = get_exports(exe_path=exe_path)

    for dll_name in exports:
        for api_name in exports[dll_name]:
            result = enc(dll_name=os.path.basename(dll_name), api_name=api_name)
            if result['hash'].lower() == hash.lower():
                print(f"API Found: {hash} => {api_name} ({dll_name})")
                return

    print(f"No API found with hash {hash} in the given executabl")
    print(f"Trying to search hash on C:\\Windows\\System32. This may take a while.")

    exports = get_exports_from_dll_dir()

    for dll_name in exports:
        for api_name in exports[dll_name]:
            result = enc(dll_name=os.path.basename(dll_name), api_name=api_name)
            if result['hash'].lower() == hash.lower():
                print(f"API Found: {hash} => {api_name} ({dll_name})")
                return

    print(f"No API found with hash {hash}.")

if __name__ == "__main__":

    op = sys.argv[1]
    if op == 'enc':
        dll_name = sys.argv[2]
        api_name = sys.argv[3]
        result = enc(dll_name, api_name)
        print(f"Hash of DLL: {result['dll_hash']}")
        print(f"Hash of API: {result['api_hash']}")
        print(f"Hash: {result['hash']}")
    elif op == 'dec':
        h = sys.argv[2]
        exe_path = sys.argv[3]
        dec(h, exe_path)
    elif op == 'list-dll':
        result = get_exports()
        print(result.keys())
    else:
        print("Invalid operation.") 
    