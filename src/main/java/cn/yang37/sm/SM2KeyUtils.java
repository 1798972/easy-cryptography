package cn.yang37.sm;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @description:
 * @class: SM2KeyUtils
 * @date: 2024/7/11 8:50
 * @version: 1.0
 */
public class SM2KeyUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 椭圆曲线参数类
     */
    private static final ECParameterSpec EC_SPEC = ECNamedCurveTable.getParameterSpec("sm2p256v1");

    /**
     * 私钥: PKCS1
     *
     * @param pemKey .
     * @return .
     * @throws Exception .
     */
    public static PrivateKey loadPrivateKeyPkcs1(String pemKey) throws Exception {
        byte[] pemContent = readPem(pemKey);
        ASN1Sequence seq = ASN1Sequence.getInstance(pemContent);
        // 解析版本号
        // ASN1Integer version = (ASN1Integer) seq.getObjectAt(0);
        ASN1OctetString privateKey = (ASN1OctetString) seq.getObjectAt(1);
        ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, privateKey.getOctets()), EC_SPEC);
        return getKeyFactory().generatePrivate(spec);
    }

    /**
     * 私钥: PKCS8
     *
     * @param pemKey .
     * @return .
     * @throws Exception .
     */
    public static PrivateKey loadPrivateKeyPkcs8(String pemKey) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(readPem(pemKey));
        return getKeyFactory().generatePrivate(spec);
    }

    /**
     * 私钥: D
     *
     * @param privateD .
     * @return .
     * @throws Exception .
     */
    public static PrivateKey loadPrivateKeyFromD(String privateD) throws Exception {
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateD, 16), EC_SPEC);
        return getKeyFactory().generatePrivate(privSpec);
    }

    /**
     * 公钥: PKCS8 (注意SM2公钥一般只有PKCS8标准)
     *
     * @param pemKey .
     * @return .
     * @throws Exception .
     */
    public static PublicKey loadPublicKeyPkcs8(String pemKey) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(readPem(pemKey));
        return getKeyFactory().generatePublic(spec);
    }

    /**
     * 公钥: XY
     *
     * @param publicXy .
     * @return .
     * @throws Exception .
     */
    public static PublicKey loadPublicKeyFromXy(String publicXy) throws Exception {
        BigInteger x = new BigInteger(publicXy.substring(0, 64), 16);
        BigInteger y = new BigInteger(publicXy.substring(64), 16);
        ECPoint q = EC_SPEC.getCurve().createPoint(x, y);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, EC_SPEC);
        return getKeyFactory().generatePublic(pubSpec);
    }

    /**
     * 生成SM2公私钥对
     *
     * @return KeyPair
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     */
    public static KeyPair generateSm2KeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(EC_SPEC);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * privateKey -> 私钥D值(HEX)
     *
     * @param privateKey .
     * @return .
     */
    public static String parsePrivateD(PrivateKey privateKey) {
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD();
        return String.format("%064x", d);
    }

    /**
     * 私钥D值(HEX) -> 公钥值XY值(HEX)
     *
     * @param privateD .
     * @return String 公钥值XY
     */
    public static String parsePublicKeyXyFromPrivateKeyD(String privateD) {
        ECPoint q = parseEcPointQ(privateD);
        BigInteger x = q.getAffineXCoord().toBigInteger();
        BigInteger y = q.getAffineYCoord().toBigInteger();
        return String.format("%064x%064x", x, y);
    }

    /**
     * publicKey -> 公钥值XY值(HEX)
     *
     * @param publicKey .
     * @return .
     */
    public static String parsePublicKeyXyFromPublicKey(PublicKey publicKey) {
        org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
        ECPoint q = ecPublicKey.getQ();
        BigInteger x = q.getAffineXCoord().toBigInteger();
        BigInteger y = q.getAffineYCoord().toBigInteger();
        return String.format("%064x%064x", x, y);
    }

    /**
     * 私钥D值(HEX) -> PublicKey
     *
     * @param privateD .
     * @return PublicKey .
     * @throws InvalidKeySpecException  .
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     */
    public static PublicKey parsePublicKeyFromPrivateKeyD(String privateD) throws Exception {
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(parseEcPointQ(privateD), EC_SPEC);
        return getKeyFactory().generatePublic(pubSpec);
    }

    /**
     * PrivateKey —> PublicKey
     *
     * @param privateKey .
     * @return PublicKey .
     * @throws InvalidKeySpecException  .
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     */
    public static PublicKey parsePublicKeyFromPrivateKey(PrivateKey privateKey) throws Exception {
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(parseEcPointQ(parsePrivateD(privateKey)), EC_SPEC);
        return getKeyFactory().generatePublic(pubSpec);
    }

    /**
     * 获取 KeyFactory 实例
     *
     * @return KeyFactory
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     */
    private static KeyFactory getKeyFactory() throws Exception {
        return KeyFactory.getInstance("EC", "BC");
    }

    /**
     * 通过D值加载Q点
     *
     * @param privateD .
     * @return .
     */
    private static ECPoint parseEcPointQ(String privateD) {
        ECPoint q = EC_SPEC.getG().multiply(new BigInteger(privateD, 16));
        return q.normalize();
    }

    /**
     * 读取pem
     *
     * @param pemKey .
     * @return .
     * @throws IOException .
     */
    private static byte[] readPem(String pemKey) throws Exception {
        PemReader pemReader = new PemReader(new StringReader(pemKey));
        byte[] pemContent = pemReader.readPemObject().getContent();
        pemReader.close();
        return pemContent;
    }
}
