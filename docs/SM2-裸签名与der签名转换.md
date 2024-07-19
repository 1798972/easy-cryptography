## 0.背景

[SM2椭圆曲线公钥密码算法](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/file/SM2-ECC-ALG.pdf)



## 1.格式

在准则中可以看到，签名计算的最后一步是将两个数字转换为字符串。

![image-20220208093053523](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/%20image/image-20220208093053523.png)

SM2签名的长度为128位（R+S = 64+64 = 128），有时候我们看到的不止128位，多半是因为做了ASN1格式转换。



## 2.分析

下方以软加密和加密机签名的结果做分析：

```java
// 软加密签名结果142
3045022100d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a602201b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715
    
// 加密机签名结果128
d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a61b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715
```

可以看到，上方代码计算结果长度为142，加密机为128。

咦，连长度都对不上。

这里提前给出结果，下方将描述如何转换：

```java
// 142位的是ASN1的格式(der)
3045022100d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a602201b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715

// 128位的是裸签名格式(raw)
d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a61b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715
```



### 2.1 ASN1实体类

由于SM2的签名结果是由两个数字拼接构成，构建时我们使用ASN1Integer。

```java
package cn.yang37.entity.asn1;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.bouncycastle.asn1.*;

/**
 * @description: R+S
 * @class: SM2Sign
 * @author: yang37z@qq.com
 * @date: 2024/7/10 16:19
 * @version: 1.0
 */
@Data
@Builder
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class SM2SignASN1 extends ASN1Object {

    private ASN1Integer int1;
    private ASN1Integer int2;

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(int1);
        vector.add(int2);
        return new DERSequence(vector);
    }

}
```



### 2.2 raw -> der

对于数据

```
d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a61b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715
```

由128拆分为两个64位长度的16进制数，利用BigInteger构建咱们的ASN1格式数据即可。

```
d596d18be77035b0bb9ef6abf232e9e81f2df3178bedd56d64220dc72c6883a6
1b92ddc4c167e22956e5ef32ce19bf4c05f9d6d96aa82c41ace0ba28acba8715
```

参考方法：SM2SignRaw2DerUtils.raw2Der()

```java
package cn.yang37.sm;

import cn.yang37.entity.asn1.SM2Signature;
import cn.yang37.entity.asn1.SM2SignASN1;
import cn.yang37.utils.HexUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;

/**
 * @description:
 * @class: SM2SignRow2DerUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/10 16:39
 * @version: 1.0
 */
@Slf4j
public class SM2SignRaw2DerUtils {

    /**
     * (hex) 128位长度的裸签名 -> 142长度的der签名
     *
     * @param rawHex128 .
     * @return .
     */
    public static String raw2Der(String rawHex128) {
        String res = "";
        try {
            BigInteger bigInteger1 = new BigInteger(rawHex128.substring(0, 64), 16);
            BigInteger bigInteger2 = new BigInteger(rawHex128.substring(64, 128), 16);

            SM2Signature sm2Signature = SM2Signature.builder()
                    .int1(new ASN1Integer(bigInteger1))
                    .int2(new ASN1Integer(bigInteger2))
                    .build();
            res = HexUtils.byteArr2Hex(sm2Signature.toASN1Primitive().getEncoded());
        } catch (Exception e) {
            log.error("[Hex] raw -> der,error!", e);
        }
        return res.toUpperCase();
    }

    /**
     * (hex) 142长度的der签名 -> 128位长度的裸签名
     *
     * @param derHex142 .
     * @return .
     */
    public static String der2Raw(String derHex142) {
        String res = "";
        StringBuilder sb = new StringBuilder();

        try {
            byte[] decoded = HexUtils.hex2ByteArr(derHex142);
            try (ASN1InputStream ais = new ASN1InputStream(decoded)) {
                ASN1Primitive primitive = ais.readObject();
                if (primitive instanceof ASN1Sequence) {
                    ASN1Sequence sequence = (ASN1Sequence) primitive;
                    for (ASN1Encodable encodable : sequence) {
                        ASN1Primitive asn1Primitive = encodable.toASN1Primitive();
                        if (asn1Primitive instanceof ASN1Integer) {
                            BigInteger value = ((ASN1Integer) asn1Primitive).getValue();
                            sb.append(String.format("%064x", value));
                        }
                    }
                }
            }
            res = sb.toString();

        } catch (Exception e) {
            log.error("[Hex] der -> raw,error!", e);
        }

        return res.toUpperCase();
    }

}
```

输出：

```java
[Hex] raw -> der: 3045022100D596D18BE77035B0BB9EF6ABF232E9E81F2DF3178BEDD56D64220DC72C6883A602201B92DDC4C167E22956E5EF32CE19BF4C05F9D6D96AA82C41ACE0BA28ACBA8715
```



### 2.3 der -> raw

上方的ASN1格式数据也可以解析回去，下面是一个demo：

> 注意40行，这里是因为SM2签名是两个整数组成，所以我们用的是ASN1Integer在构建，然后把结果数据做了16进制转换。

**不是所有的ASN1都应当这样操作，要结合实体类分析**，即2.2节的SM2SignASN1。

又比如SM2数字信封是4部分组成，看我的这个问题：[SM2加密结果转ASN1格式时如何构造DerOctetString?](https://segmentfault.com/q/1010000041027241)

参考方法：SM2SignRaw2DerUtils.der2Raw()

输出：

```bash
[Hex] der -> raw: D596D18BE77035B0BB9EF6ABF232E9E81F2DF3178BEDD56D64220DC72C6883A61B92DDC4C167E22956E5EF32CE19BF4C05F9D6D96AA82C41ACE0BA28ACBA8715
```



## 3.代码

具体的代码，参考这个仓库：[easy-cryptography](https://gitee.com/yang37/easy-cryptography)

