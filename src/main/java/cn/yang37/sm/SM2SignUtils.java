package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @description: 私钥签名 公钥验签
 * @class: SM2SignUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/11 12:26
 * @version: 1.0
 */
public class SM2SignUtils {

    /* ========================== sign ================================ */
    public static byte[] signDer(PrivateKey privateKey, byte[] data) throws Exception {
        SM2Signer signer = new SM2Signer();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(privateKey.getEncoded());
        signer.init(true, new ParametersWithRandom(privateKeyParameters));
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    public static byte[] signRaw(PrivateKey privateKey, byte[] data) throws Exception {
        byte[] derSignature = signDer(privateKey, data);
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(derSignature);
        BigInteger r = ((ASN1Integer) asn1Sequence.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) asn1Sequence.getObjectAt(1)).getValue();
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        int len = Math.max(rBytes.length, sBytes.length);
        byte[] rawSignature = new byte[len * 2];
        System.arraycopy(rBytes, 0, rawSignature, len - rBytes.length, rBytes.length);
        System.arraycopy(sBytes, 0, rawSignature, len * 2 - sBytes.length, sBytes.length);

        return rawSignature;
    }

    /* ========================== verify ================================ */
    public static boolean verifyDer(PublicKey publicKey, byte[] data, byte[] derSignature) throws Exception {
        SM2Signer signer = new SM2Signer();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(publicKey.getEncoded());
        signer.init(false, publicKeyParameters);
        signer.update(data, 0, data.length);
        return signer.verifySignature(derSignature);
    }

    public static boolean verifyRaw(PublicKey publicKey, byte[] data, byte[] rawSignature) throws Exception {
        int len = rawSignature.length / 2;
        byte[] rBytes = new byte[len];
        byte[] sBytes = new byte[len];
        System.arraycopy(rawSignature, 0, rBytes, 0, len);
        System.arraycopy(rawSignature, len, sBytes, 0, len);
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        ASN1Sequence asn1Sequence = new DLSequence(new ASN1Integer[]{new ASN1Integer(r), new ASN1Integer(s)});
        byte[] derSignature = asn1Sequence.getEncoded();

        return verifyDer(publicKey, data, derSignature);
    }

    /* ========================== sign ================================ */
    public static String signDer2Base64(PrivateKey privateKey, String originalData) throws Exception {
        return HexUtils.byteArr2Base64(signDer(privateKey, originalData.getBytes(StandardCharsets.UTF_8)));
    }

    public static String signDer2Hex(PrivateKey privateKey, String originalData) throws Exception {
        return HexUtils.byteArr2Hex(signDer(privateKey, originalData.getBytes(StandardCharsets.UTF_8)));
    }

    public static String signRaw2Base64(PrivateKey privateKey, String originalData) throws Exception {
        return HexUtils.byteArr2Base64(signRaw(privateKey, originalData.getBytes(StandardCharsets.UTF_8)));
    }

    public static String signRaw2Hex(PrivateKey privateKey, String originalData) throws Exception {
        return HexUtils.byteArr2Hex(signRaw(privateKey, originalData.getBytes(StandardCharsets.UTF_8)));
    }

    /* ========================== verify ================================ */
    public static boolean verifyDer4Base64(PublicKey publicKey, String data, String derBase64Signature) throws Exception {
        return verifyDer(publicKey, data.getBytes(StandardCharsets.UTF_8), HexUtils.base642ByteArr(derBase64Signature));
    }

    public static boolean verifyDer4Hex(PublicKey publicKey, String data, String derHexSignature) throws Exception {
        return verifyDer(publicKey, data.getBytes(StandardCharsets.UTF_8), HexUtils.hex2ByteArr(derHexSignature));
    }

    public static boolean verifyRaw4Base64(PublicKey publicKey, String data, String derBase64Signature) throws Exception {
        return verifyRaw(publicKey, data.getBytes(StandardCharsets.UTF_8), HexUtils.base642ByteArr(derBase64Signature));
    }

    public static boolean verifyRaw4Hex(PublicKey publicKey, String data, String derHexSignature) throws Exception {
        return verifyRaw(publicKey, data.getBytes(StandardCharsets.UTF_8), HexUtils.hex2ByteArr(derHexSignature));
    }

}