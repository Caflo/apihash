import apiutils
import time
import argparse

def parse_options(parser):
    subparsers = parser.add_subparsers(help="Operations", dest='cmd')
    
    sp1 = subparsers.add_parser('enc', help='Get hash of DLL and API.')
    sp1.add_argument('dll', action='store', type=str, help='DLL name') 
    sp1.add_argument('api', action='store', type=str, help='API name') 

    sp2 = subparsers.add_parser('dec', help='Retrieve DLL and API names from hash.')
    sp2.add_argument('hash', action='store', type=str, help='hash') 
    sp2.add_argument('path', action='store', type=str, nargs='?', help='Path of the program from which to extract DLLs') 

    args = parser.parse_args()
    return args

if __name__ == "__main__":

    description = """
        Calculate hashes from a given dll name and API.
        Obtain dll and API name from an hash + given executable (or searching in the Windows DLL system directory)
    """ 

    parser = argparse.ArgumentParser(description=description)
    args = parse_options(parser)    

    if args.cmd == None:
        parser.print_help()
        exit()

    if args.cmd == 'enc':
        dll_name = args.dll
        api_name = args.api
        result = apiutils.enc(dll_name, api_name)
        print(f"Hash of DLL: {result['dll_hash']}")
        print(f"Hash of API: {result['api_hash']}")
        print(f"Hash: {result['hash']}")
    elif args.cmd == 'dec':
        hash = args.hash
        exe_path = args.path
        start = time.time()
        apiutils.dec(hash, exe_path=exe_path)
        end = time.time()
        print(f"Elapsed time: {end - start} seconds")
    else:
        print("Invalid operation.")
        parser.print_help()