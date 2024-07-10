package cn.yang37.sm2;

import cn.yang37.entity.asn1.SM2Signature;
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