import sys

def xor_data(data: bytes, key: int) -> bytes:
    """对数据进行 XOR 加密/解密（key为单字节0-255）"""
    return bytes([b ^ key for b in data])

def main():
    if len(sys.argv) != 4:
        print(f"用法: {sys.argv[0]} <输入文件> <输出文件> <XOR密钥(0-255)>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    try:
        xor_key = int(sys.argv[3]) & 0xFF  # 确保密钥是0-255
    except ValueError:
        print("错误: 密钥必须是0-255的整数")
        sys.exit(1)

    try:
        # 读取原始文件
        with open(input_file, "rb") as f:
            data = f.read()

        # 执行XOR加密
        encrypted_data = xor_data(data, xor_key)

        # 写入加密后的文件
        with open(output_file, "wb") as f:
            f.write(encrypted_data)

        print(f"[+] 成功加密文件: {input_file} -> {output_file} (XOR密钥: {hex(xor_key)})")
        print(f"[+] 加密后大小: {len(encrypted_data)}字节")

    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()