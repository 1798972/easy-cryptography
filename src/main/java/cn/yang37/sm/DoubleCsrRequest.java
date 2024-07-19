package cn.yang37.sm;

import cn.yang37.cons.MagicConstant;
import cn.yang37.utils.HexUtils;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @description:
 * @class: DoubleCsrRequest
 * @author: yang37z@qq.com
 * @date: 2024/7/11 8:44
 * @version: 1.0
 */
@Slf4j
@Builder
@Getter
public class DoubleCsrRequest {

    /**
     * 签名私钥
     */
    private PrivateKey signPrivateKey;

    /**
     * 签名公钥
     */
    private PublicKey signPublicKey;

    /**
     * 临时公钥
     */
    private PublicKey tempPublicKey;

    /**
     * 用户ID,默认1234567812345678
     */
    private String userId;

    /**
     * 区分名（Distinguished Name）
     */
    private String dn;

    /**
     * 挑战密码,默认111111
     */
    private String challengePassword;

    public String createDoubleCsrRequest() throws Exception {

        // 加载信息
        if (StringUtils.isEmpty(challengePassword)) {
            challengePassword = MagicConstant.CHALLENGE_PASSWORD;
        }

        if (StringUtils.isEmpty(userId)) {
            userId = MagicConstant.USER_ID;
        }

        String signPublicKeyXy = SM2KeyUtils.parsePublicKeyXyFromPublicKey(signPublicKey);
        String tempPublicKeyXy = SM2KeyUtils.parsePublicKeyXyFromPublicKey(tempPublicKey);
        String signPrivateKeyD = SM2KeyUtils.parsePrivateD(signPrivateKey);
        String tempPublicKeyX = tempPublicKeyXy.substring(0, 64);
        String tempPublicKeyY = tempPublicKeyXy.substring(64);

        // 公钥信息
        ASN1EncodableVector algorithmVec = new ASN1EncodableVector();
        algorithmVec.add(new ASN1ObjectIdentifier("1.2.840.10045.2.1"));
        algorithmVec.add(new ASN1ObjectIdentifier("1.2.156.10197.1.301"));
        ASN1EncodableVector subjectPublicKeyInfoVec = new ASN1EncodableVector();
        subjectPublicKeyInfoVec.add(new DERSequence(algorithmVec));
        subjectPublicKeyInfoVec.add(new DERBitString(HexUtils.hex2ByteArr(MagicConstant.MAGIC_04 + signPublicKeyXy)));

        // challengePassword
        ASN1EncodableVector chalPwdVec = new ASN1EncodableVector();
        chalPwdVec.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7"));
        chalPwdVec.add(new DERPrintableString(challengePassword));

        // 临时公钥
        ASN1EncodableVector tmpPubKeyvec = new ASN1EncodableVector();
        tmpPubKeyvec.add(new ASN1Integer(1));
        String format = String.format("%s%s%s%s%s"
                , MagicConstant.MAGIC_00_B4
                , tempPublicKeyX
                , MagicConstant.MAGIC_0_64
                , tempPublicKeyY
                , MagicConstant.MAGIC_0_64);
        tmpPubKeyvec.add(new DEROctetString(HexUtils.hex2ByteArr(format)));
        ASN1EncodableVector tempPulicKeyInfoVec = new ASN1EncodableVector();
        tempPulicKeyInfoVec.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.63"));
        tempPulicKeyInfoVec.add(new DEROctetString(new DERSequence(tmpPubKeyvec)));

        // Attributes
        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(new DERSequence(chalPwdVec));
        attrVec.add(new DERSequence(tempPulicKeyInfoVec));

        // DN等信息
        ASN1EncodableVector certificationRequestInfoVec = new ASN1EncodableVector();
        certificationRequestInfoVec.add(new ASN1Integer(0));
        certificationRequestInfoVec.add(new DERSequence(parseDn(dn)));
        certificationRequestInfoVec.add(new DERSequence(subjectPublicKeyInfoVec));
        certificationRequestInfoVec.add(new DERTaggedObject(false, 0, new DLSequence(attrVec)));

        // 签名
        byte[] reqInf = new DERSequence(certificationRequestInfoVec).getEncoded();
        byte[] der = SM2SignWithUserIdUtils.signDer(SM2KeyUtils.loadPrivateKeyFromD(signPrivateKeyD), reqInf, userId.getBytes(StandardCharsets.UTF_8));
        String der2Raw = SM2SignRaw2DerUtils.der2Raw(HexUtils.byteArr2Hex(der));
        ASN1EncodableVector signVec = new ASN1EncodableVector();
        signVec.add(new ASN1Integer(new BigInteger(der2Raw.substring(0, 64), 16)));
        signVec.add(new ASN1Integer(new BigInteger(der2Raw.substring(64), 16)));

        // 补全信息
        ASN1EncodableVector algorithmIdentifer = new ASN1EncodableVector();
        algorithmIdentifer.add(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));
        DERBitString bitStr = new DERBitString(new DERSequence(signVec).getEncoded());
        ASN1EncodableVector certificationRequestVec = new ASN1EncodableVector();
        certificationRequestVec.add(new DERSequence(certificationRequestInfoVec));
        certificationRequestVec.add(new DERSequence(algorithmIdentifer));
        certificationRequestVec.add(bitStr);

        return HexUtils.byteArr2Base64(new DERSequence(certificationRequestVec).getEncoded());
    }

    public static ASN1EncodableVector parseDn(String dn) {
        ASN1EncodableVector subjectVec = new ASN1EncodableVector();
        String[] dnParts = dn.split(",");

        for (String dnPart : dnParts) {
            String[] kv = dnPart.split("=");
            if (kv.length != 2) {
                throw new IllegalArgumentException("Invalid DN part: " + dnPart);
            }
            String key = kv[0].trim().toUpperCase();
            String value = kv[1].trim();

            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1ObjectIdentifier(getOidForKey(key)));

            // 强制CN使用DERUTF8String,C使用DERPrintableString
            if ("CN".equals(key)) {
                vec.add(new DERUTF8String(value));
            } else if ("C".equals(key)) {
                vec.add(new DERPrintableString(value));
            } else {
                vec.add(new DERUTF8String(value));
            }

            subjectVec.add(new DERSet(new DERSequence(vec)));
        }

        return subjectVec;
    }

    private static String getOidForKey(String key) {
        switch (key) {
            case "C":
                return "2.5.4.6";
            case "O":
                return "2.5.4.10";
            case "OU":
                return "2.5.4.11";
            case "CN":
                return "2.5.4.3";
            default:
                throw new IllegalArgumentException("Unknown DN key: " + key);
        }
    }

}