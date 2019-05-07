# Botan 2 demo TLS client program in C++
样例代码: [tls_client.cpp](https://botan.randombit.net/manual/tls.html#code-example)

# Botan 2 demo project in python
样例代码:
```
# encoding:utf-8
from __future__ import print_function

import sys
print('Python version=', sys.version)

import botan2
print(botan2.version_string())
```

# Ubuntu(或Debian) 在线安装 Botan-2.9
安装 Botan-2.9 开发包以及 Botan 的 Python3 语言绑定
```
sudo apt install libbotan-2-dev python3-botan
sudo apt install libbotan-2-doc
```

# 其他开源 Linux 操作系统安装 Botan-2.9
1. Fedora 29 / 红帽企业版 RHEL 8.0-beta 可在线安装 Botan-2.9;
   (备注: 红帽企业版 RHEL 8.0 正式发布之后相应版本的 CentOS 8.0 也将支持 Botan-2.9)

2. RHEL 7.6 / CentOS 7.6 及更早版本最高仅支持 Botan-1.10.17 在线安装. 安装 Botan-2.9 需要手动编译源码, 具体方法请查阅 Botan 源码包;
