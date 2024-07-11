# 1.背景

ECC 基于数学上的椭圆曲线离散对数问题，在椭圆曲线密码学 (ECC) 中，私钥通常表示为一个大整数，即所谓的 D 值。

- 私钥 D：大整数，一个随机选择的大整数。
- 公钥 Q：一个点，通过在椭圆曲线上执行点乘法得到的，即 Q = D * G，其中 G 是椭圆曲线的基点，D 是私钥。

即公钥是由椭圆曲线上的一个点表示，这个点由两个坐标（X 和 Y）组成。

```java
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateSm2KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("sm2p256v1"));
        return keyPairGenerator.generateKeyPair();
    }
```

输出：

```bash
EC Private Key [b9:6b:42:25:aa:9f:fe:59:95:31:ff:65:bf:ef:67:20:6a:ed:65:55]
            X: af58ec776a5707f00fea55eaa69be1726dc1c7ec414e30012516c243e658c390
            Y: 9dd317f434b3e269f970788bb81bec09e20ad6292e8e322b07ed4bbbfccade17

EC Public Key [b9:6b:42:25:aa:9f:fe:59:95:31:ff:65:bf:ef:67:20:6a:ed:65:55]
            X: af58ec776a5707f00fea55eaa69be1726dc1c7ec414e30012516c243e658c390
            Y: 9dd317f434b3e269f970788bb81bec09e20ad6292e8e322b07ed4bbbfccade17
```



# 2.私钥

注意看上方的值，其中[b9:6b:42:25:aa:9f:fe:59:95:31:ff:65:bf:ef:67:20:6a:ed:65:55]是私钥对象的字节数组表示。

这是由 `ECPrivateKey` 对象的默认 `toString` 方法生成的表示形式，而不是私钥的实际 D 值。

即org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey的toString方法。

![image-20240711094629072](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407110946168.png)

日常使用的呢，是16进制的那个值。

![image-20240711095010493](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407110950644.png)



# 3.公钥

公钥就比较简单了，我们打印对象的时候直接能看到XY值。

![image-20240711095232088](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407110952266.png)



# 4.PKCS标准

上面的例子里，我们给出的公私钥是这样的，分别是。

- 私钥的D值

- 公钥的（X，Y）坐标。

```bash
私钥：bbea2f61951c15f75d00c10ee773e0555e8dd796ec6b717259b571a4bbfccb79
公钥：f05e6cb00b6e7dafc4df8c4d2662d1862be1c840c9e992116c1485448501bd1bc2e379f5e322d53527cc18265b70d8d08011a0f9fae4e9f506a5f3efca90e5be
```

有时候呀，比如我们利用openssl命令生成后，看到的会是这样。

参考我这篇文章：[openssl中RSA、SM2公私钥生成及PKCS格式转换](https://www.cnblogs.com/yang37/p/16636435.html)

**sm2_private_pkcs1**

```java
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDIhsqbgBrkpE0Gay6I6K2z9gftTOiwi7bS4aoK3QKj4oAoGCCqBHM9V
AYItoUQDQgAEeU+j4G8Lni1Q12/vxTwBdct5oacQtKHCf1MRsne4J1E+ghiLuIiu
VxOBD0Im6SNZHjKokV0h2jeq4b9UMGVAOg==
-----END EC PRIVATE KEY-----
```

**sm2_private_pkcs8**

```bash
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgMiGypuAGuSkTQZrL
ojorbP2B+1M6LCLttLhqgrdAqPihRANCAAR5T6PgbwueLVDXb+/FPAF1y3mhpxC0
ocJ/UxGyd7gnUT6CGIu4iK5XE4EPQibpI1keMqiRXSHaN6rhv1QwZUA6
-----END PRIVATE KEY-----
```

**sm2_public_pkcs8**

```bash
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEeU+j4G8Lni1Q12/vxTwBdct5oacQ
tKHCf1MRsne4J1E+ghiLuIiuVxOBD0Im6SNZHjKokV0h2jeq4b9UMGVAOg==
-----END PUBLIC KEY-----
```

具体的代码，参考这个仓库：[easy-cryptography](https://gitee.com/yang37/easy-cryptography)

