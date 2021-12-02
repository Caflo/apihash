# apihash
 - Calculate hashes from a given dll name and API
 - Obtain dll and API name from an hash + given executable (or searching in the Windows DLL system directory) 

# Example usages
This example calculate the hash of the API WinExec<br>
`
py .\apihash.py enc kernel32.dll WinExec
`
<br>
Hash of DLL: 0x92af16da<br>
Hash of API: 0xf4c07457<br>
Hash: 0x876f8b31<br>
<br>
This example extract DLL and API names from a given hash (0xff38e9b7 = listen)<br>
`
py .\apihash.py dec 0xff38e9b7
`
<br>
...<br>
[PROCESS 50032] Searching exports in: C:\Windows\System32\wsp_health.dll...<br>
[PROCESS 50032] Searching exports in: C:\Windows\System32\wsp_sr.dll...<br>
[PROCESS 50032] FINISHED. Files searched: 3<br>
API Found: 0xff38e9b7 => listen (C:\Windows\System32\ws2_32.dll)<br>
Elapsed time: 2.6372807025909424 seconds<br>
<br>
If you want, you can also give the path of the executable to avoid searching all DLL in the System directory:<br>
`
py .\apihash.py dec 0xff38e9b7 "C:\path\to\executable.exe"
`