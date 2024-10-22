# 1.结构C1C2C3/C1C3C2

SM2加密结果的结构通常由以下三个部分组成。

- C1：椭圆曲线上的一个点
- C2：加密的数据
- C3：消息认证码

典型的SM2加密结果ASN.1结构可以表示为：

```c
SM2Cipher ::= SEQUENCE {
    C1          SM2Point,
    C2          OCTET STRING,
    C3          OCTET STRING
}

SM2Point ::= SEQUENCE {
    x           INTEGER,
    y           INTEGER
}
```

注意，此处的C1并非是我们的公钥xy，C1点是在加密过程中生成的，它由两个坐标点（x, y）组成，用于计算密文的一部分。

生成方式如下：

- 选择一个随机数 k。
- 计算点 C1 = k * G，其中 G 是椭圆曲线的基点。



# 2.压缩标志04

在SM2加密过程中，`04` 是用于表示**未压缩的椭圆曲线点的标识符**。

当一个点在椭圆曲线上以未压缩格式表示时，点数据的第一个字节是 `04`，后面跟着点的 x 坐标和 y 坐标。

具体来说，未压缩格式的椭圆曲线点表示如下：

- 第一个字节是 `04`，表示点是未压缩的。
- 接下来的字节是 x 坐标的字节表示。
- 之后的字节是 y 坐标的字节表示。

例如，一个未压缩的椭圆曲线点 `P`（x, y）可以表示为：

```bash
04 | x 的字节表示 | y 的字节表示
```

在SM2加密过程中，生成的临时点 `C1` 会以这种未压缩格式表示。

因此，在加密结果的字节数组中，结果前面的部分可能会包含这个未压缩的点信息。

所以，要根据实际情况来判断是否需要移除。



# 3.注意点

- 加密模式C1C2C3还是C1C3C2
- BC库加密结果默认会在头部添加04，部分应用中解密时需要移除。

![image-20240716223713919](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407162237076.png)

含有04时，解密失败。

<img src="https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407162237388.png" alt="image-20240716223747259" style="zoom: 67%;" />

移除04后，解密成功。

<img src="https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407162238907.png" alt="image-20240716223811844" style="zoom:67%;" />