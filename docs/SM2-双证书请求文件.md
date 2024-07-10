# 1.背景

> 关于数字证书、数字信封、OID等基本知识，此文不做赘述。

在传统的数字信封体系中，我们的流程大概这样的。

![image-20240708163439802](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407081634948.png)

这里有个值得注意的点是：

**节点1用于加密对称密钥的公钥和节点3用于签名的私钥，它们是否可以是同一对。**

基于这个思想，我们有了单证书体系和双证书体系。

其原因之一就是，从功能角度隔离开我们的加密秘钥对和签名密钥对。

**根据“中国金融认证中心标准-SM2 双证书申请及下载规范”，我们可以看到一个双证书的基本流程。**

1) 产生签名密钥对和交互密钥对。

2) 生成 Base64 编码的 SM2 双证书请求。

3) 向服务器端提交 SM2 双证书请求。

4) 解析服务器端返回的报文数据，并解密加密证书私钥。 

5) 导入签名公钥证书、加密公钥证书、加密证书私钥。



# 2.双证书

> 以国密SM2为例

上面我们知道，所谓的双证书，即。

- 专门用于签名验签
- 专门用于加密解密

**注意，在中国金融认证中心标准-SM2 双证书申请及下载规范中，此处的加密秘钥不是由我们的本地生成的，而是由CA生成。**

整个逻辑大致交互逻辑如下：

- 本地生成签名公私钥对
- 本地生成**临时**公私钥对（注意，非加密秘钥对，仅仅在生成请求证书阶段使用）
- 结合签名公钥、临时公钥，生成双证书请求文件。
- CA签发签名证书
- CA生成加密公私钥对（并使用刚才我们的临时公钥加密加密秘钥对中的私钥）
- 下载CA签发的签名证书、加密证书、加密私钥
- 使用临时私钥解密加密过的私钥，得到最终的加密私钥。

![image-20240710004147113](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100041221.png)



# 3.双证请求文件

> 请求文件、CSR、P10，不严格的场景下，你可以当做是同一个东西。



## 3.1 格式描述

### 3.1.1 整体格式

![image-20240710010041063](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100100102.png)

SM2 双证书请求的 ASN.1 数据格式。

```bash
CertificationRequest ::= SEQUENCE {
	certificationRequestInfo CertificationRequestInfo,
	signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
	signature BIT STRING
}
```

- ccertificationRequestInfo： SM2 双证书请求信息。
- signatureAlgorithm：签名算法 ID，文档中OID取值为：1.2.156.10197.1.501。
- signature：使用签名私钥，对 certificationRequestInfo 节点的签名结果。

这里提到了oid，可以在这里查询。

[国家OID注册中心](https://www.china-oid.org.cn/oid/analysis?oidvalue=1.2.156.10197.1.501)

[GmSSL](http://gmssl.org/docs/oid.html)

然后，这里的`{{ SignatureAlgorithms }}`是什么意思呢？

- **AlgorithmIdentifier**：这是一个ASN.1的标准类型，用于标识算法。它通常包含两个字段：算法OID（对象标识符）和可选的参数。

- **{{ SignatureAlgorithms }}**：表示`AlgorithmIdentifier`的值必须来自`SignatureAlgorithms`的集合。

嗯，就是下面这个。

![image-20240710011413875](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100114920.png)



### 3.1.2 CertificationRequestInfo

![image-20240710010353721](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100103762.png)

```bash
CertificationRequestInfo ::= SEQUENCE {
	version INTEGER,
	subject Name,
	subjectPKInfo SubjectPublicKeyInfo,
	attributes [0] Attributes
}
```

- version：版本号，本文档中取值为 0x00。 

- subject：公钥证书 DN。详细介绍，请参考 PKCS#10。 
- subjectPKInfo：签名公钥信息。
- attributes：属性信息。



### 3.1.3 SubjectPublicKeyInfo

![image-20240710011520142](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100115198.png)

```bash
SubjectPublicKeyInfo ::= SEQUENCE {
	algorithm AlgorithmIdentifer,
	subjectPublicKey BIT STRING
}

AlgorithmIdentifer::= SEQUENCE {
	algorithm OBJECT IDENTIFIER,
	parameters ANY DEFINED BY algorithm OPTIONAL
}
```

- algorithm：ECC 公钥算法 OID，在本文档中，取值为：1.2.840.10045.2.1。

- parameters：SM2 公钥算法 OID，在本文档中，取值为：1.2.156.10197.1.301。

- subjectPublicKey：SM2 公钥数据，结构如下。

  ```java
  0x04||签名公钥 X 分量||签名公钥 Y 分量。
  ```

  

### 3.1.4 attributes

```bash
Attributes ::= Context[0] {
	chanllegPassword ChanllegPassword,
	tempPublicKeyInfo TempPulicKeyInfo
}
ChanllegPassword ::= SEQUENCE {
	chanllegPasswordOID OBJECTIDENTIFIER,
	password PrintableString
}
TempPulicKeyInfo ::= SEQUENCE {
	tempPublicKeyOID OBJECTIDENTIFIER,
	tempPublicKey OCTECT STRING
}
```

- password：默认取值：111111。 
- tempPublicKeyOID：交互公钥标识 OID，本文档中取值为：1.2.840.113549.1.9.63。
-  tempPublicKey：交互公钥 TempPulicKey 的 OCTECT STRING 编码。

![image-20240710011645538](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100116635.png)

### 3.1.5 交互公钥

![image-20240710011658192](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100116264.png)

```java
TempPulicKey ::= SEQUENCE {
	version INTEGER,
	tempPublicKeyData OCTET STRING
}
```

- version：版本号，本文档中取值为：0x01。 

- tempPublicKeyData：交互公钥数据，结构如下。

  ```java
  0x00 0xB4 0x00 0x00||0x00 0x01 0x00 0x00 ||交互公钥 X 分量||32 字节 0x00 扩展空间||交互公钥 Y 分 量||32 字节 0x00 扩展空间
  ```



## 3.2 示例文件

首先，给出文档中的demo双证请求文件。

```shell
MIIB0TCCAXUCAQAwWzENMAsGA1UEBh4EAEMATjEhMB8GA1UECh4YAEMARgBDAEEAIABUAEUAUwBU
ACAAQwBBMScwJQYDVQQDHh4AYwBlAHIAdABSAGUAcQB1AGkAcwBpAHQAaQBvAG4wWTATBgcqhkjO
PQIBBggqgRzPVQGCLQNCAAQv93JF1oROzBImU6Plgleu+HI659cECfKn+gajy7JWGAEoSyw+9rsB
WoRA+kqA7FmgO8NcNcm3fRBWS+yLBMLUoIG3MBMGCSqGSIb3DQEJBxMGMTExMTExMIGfBgkqhkiG
9w0BCT8EgZEwgY4CAQEEgYgAtAAAAAEAAGmQSyS20/zQ4tHJQKA5EYPgdLuPE568SYcKlqmwWGjW
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACokwM02BfEmqVM+qPPlx2I4v38pc1N4WgC
xVb2QmgSygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAwGCCqBHM9VAYN1BQADSAAw
RQIgfm4txwd5pHMPPtsHEfN+4Y8iMKmKCxy1T3eIMwkYS0kCIQCu6nbbBxVF99qaX1h1/qksk9u9
fs6qkzlkrFbkPkvMjw==
```

我们使用[ASN.1在线解析工具](https://aks.jd.com/tools/sec/)，可以看到大体结构，上文中对细节处已经做了框选，此处不赘述。

![image-20240710005900697](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100059845.png)

看起来复杂，实际也很复杂，哈哈。

但是别慌，跟咱们前面的格式描述那里对应上就好了。

就像咱们Java的实体类一样，没啥特别的，只不过走了ASN1编码而已。



## 3.3 代码

> 本文基于Java构建



# 4.结果文件解析

## 4.1 分析

根据规范，将会收到3个结果文件。

![image-20240710012307258](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100123321.png)

- SignCert.cer：签名对应的公钥证书
- EncCert.cer：加密对应的公钥证书
- PrivateKey.key：加密过的公私钥文件（使用我们的临时公钥加密）

由规范指引，我们可以得到解密的具体逻辑。

![image-20240710012558519](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100125580.png)

![image-20240710012539475](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100125537.png)

![image-20240710012656444](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100126557.png)

- 根据`,`分隔，提取密文数据。
- 解析密文数据，得到实际密文。
- 使用临时公钥解密密文，得到秘钥值。

注意，直接移除`,`后得到的数据并不是直接的SM2解密源文，它是具有如下结构的（回顾3.1.5节）。

```java
TempPulicKey ::= SEQUENCE {
	version INTEGER,
	tempPublicKeyData OCTET STRING
}
```



## 4.2 代码

注意点如下：

- 返回的数据里面会解析出version和encryptedKeyData两个部分的数据，encryptedKeyData才是我们实际解密的源数据。
- 使用BC库解密的时候，私钥前加00/密文前加04/公钥前加04。
- 经过验证，模式使用**C1C3C2**。

关于为啥咱们BC库里密文前要加04，你可以参考这个issue：[hutool-SM2私钥解密文件报错Invalid point encoding 0x30](https://gitee.com/dromara/hutool/issues/I3AEPJ)

当然，咱们此处没有用hutool，不过原因你可以研究下。

具体代码参考：[easy-cryptography](https://gitee.com/yang37/easy-cryptography)

![image-20240710022210297](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100222562.png)