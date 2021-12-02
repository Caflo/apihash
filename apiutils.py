import os
import pefile
import glob
import threading
import concurrent.futures
import multiprocessing
import collections

MAX_WORKERS = multiprocessing.cpu_count()

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

    result = ror(result, bits, size) # terminator
    return result

def enc(dll_name, api_name):
    result = dict()
    dll_name = dll_name.upper()

    # convert DLL name to UNICODE UTF-16
    dll_name_utf16 = bytearray(dll_name, encoding="utf-16-le")
    dll_name_utf16.append(0x00)
    api_name_utf8 = bytearray(api_name, encoding="utf-8")

    dll_hash = hash(dll_name_utf16)
    api_hash = hash(api_name_utf8)
    tot_hash = (dll_hash + api_hash) & 0xFFFFFFFF

    result['dll_hash'] = hex(dll_hash)
    result['api_hash'] = hex(api_hash)
    result['hash'] = hex(tot_hash)

    return result

def search_api(files):
    result = dict()
    count = 0
    for file in files:
        result[file] = list()
        pe = pefile.PE(file)
        thread_no = threading.current_thread().ident 
        print(f"[PROCESS {thread_no}] Searching exports in: {file}...")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is None:
                    continue # skip None exports
    #                print(exp.name.decode('utf-8'))
                result[file].append(exp.name.decode('utf-8'))
        count += 1

    print(f"[PROCESS {thread_no}] FINISHED. Files searched: {count}")
    return result


def get_exports_from_dll_system_dir(start=None, end=None):
    files = [file for file in glob.glob(r"C:\Windows\System32\*.dll")]
    step = round(len(files) / MAX_WORKERS)

    start = 0
    end = len(files)

    futures = set()
    result = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for i in range(start, end, step):
            assigned_files = files[i:i+step-1]
            future = executor.submit(search_api, assigned_files)
            futures.add(future)
        for future in concurrent.futures.as_completed(futures):
            try:
                data = future.result()
                result.append(data)
            except Exception as exc:
                print('Generated an exception: %s' % (exc))
    return result

def dec(hash, exe_path=None):
    if exe_path:
        print(f"Searching exports in given path: {exe_path}")
        exports = get_exports(exe_path)
        for dll_path in exports:
            for api_name in exports[dll_path]:
                result = enc(dll_name=os.path.basename(dll_path), api_name=api_name)
                if result['hash'].lower() == hash.lower():
                    print(f"API Found: {hash} => {api_name} ({dll_path})")
                    return

        print(f"No API found with hash {hash} in the given executable.")

    print(f"Trying to search hash on C:\\Windows\\System32. This may take a while.")

    results = get_exports_from_dll_system_dir()
    exports = {}
    exports = collections.defaultdict(list)
    for d in results:
        for k, v in d.items():  
            exports[k].append(v) 

    for dll_path in exports:
        for api_name in exports[dll_path][0]:
            result = enc(dll_name=os.path.basename(dll_path), api_name=api_name)
            if result['hash'].lower() == hash.lower():
                print(f"API Found: {hash} => {api_name} ({dll_path})")
                return

    print(f"No API found with hash {hash}.")