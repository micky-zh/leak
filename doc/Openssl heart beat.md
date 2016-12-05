风险简述：
Memory corruption in the ASN.1 encoder (CVE-2016-2108)：ASN.1解析器器存在问题，导致可能存在内存越界写入，从而实现内存破坏漏洞。
Padding oracle in AES-NI CBC MAC check (CVE-2016-2107)：当服务器使用 AES CBC cipher 而且支持AES-NI时，可能存在黑客通过中间人攻击，利用padding oracle（填充异常测试），实现中间人解密。
安全公告地址: https://www.openssl.org/news/secadv/20160503.txt

影响版本&修复方案：
OpenSSL 1.0.2 版本升级至 1.0.2h
OpenSSL 1.0.1 版本升级至 1.0.1t

排查方式：
其中，高危漏洞2 padding oracle bug 在线检测地址：https://filippo.io/CVE-2016-2107