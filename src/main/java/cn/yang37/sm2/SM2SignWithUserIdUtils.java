package cn.yang37.sm2;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @description:
 * @class: SM2SignUtils4UserId
 * @author: yang37z@qq.com
 * @date: 2024/7/11 13:29
 * @version: 1.0
 */
public class SM2SignWithUserIdUtils {

    public static final byte[] DEFAULT_USER_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);

    private static final ECParameterSpec EC_SPEC = ECNamedCurveTable.getParameterSpec("sm2p256v1");

    private static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(
            EC_SPEC.getCurve(),
            EC_SPEC.getG(),
            EC_SPEC.getN(),
            EC_SPEC.getH(),
            EC_SPEC.getSeed()
    );

    public static byte[] signDer(PrivateKey privateKey, byte[] data, byte[] userId) throws Exception {
        SM2Signer signer = new SM2Signer();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(privateKey.getEncoded());

        ECPoint q = DOMAIN_PARAMS.getG().multiply(privateKeyParameters.getD());
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(q, DOMAIN_PARAMS);

        byte[] e = calculateE(publicKeyParameters, userId, data);
        signer.init(true, new ParametersWithRandom(privateKeyParameters));
        signer.update(e, 0, e.length);
        return signer.generateSignature();
    }

    public static boolean verifyDer(PublicKey publicKey, byte[] data, byte[] derSignature, byte[] userId) throws Exception {
        SM2Signer signer = new SM2Signer();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(publicKey.getEncoded());
        byte[] e = calculateE(publicKeyParameters, userId, data);
        signer.init(false, publicKeyParameters);
        signer.update(e, 0, e.length);
        return signer.verifySignature(derSignature);
    }

    /**
     * 计算用户标识哈希 ZA
     *
     * @param pubKey .
     * @param userId .
     * @return .
     */
    private static byte[] calculateZa(ECPublicKeyParameters pubKey, byte[] userId) {
        SM3Digest digest = new SM3Digest();
        byte[] za = new byte[digest.getDigestSize()];

        // userId length in bits
        int len = userId.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));

        // userId
        digest.update(userId, 0, userId.length);

        // a, b, Gx, Gy, public key x, public key y
        addFieldElement(digest, EC_SPEC.getCurve().getA().toBigInteger());
        addFieldElement(digest, EC_SPEC.getCurve().getB().toBigInteger());
        addFieldElement(digest, EC_SPEC.getG().getAffineXCoord().toBigInteger());
        addFieldElement(digest, EC_SPEC.getG().getAffineYCoord().toBigInteger());
        addFieldElement(digest, pubKey.getQ().getAffineXCoord().toBigInteger());
        addFieldElement(digest, pubKey.getQ().getAffineYCoord().toBigInteger());

        digest.doFinal(za, 0);
        return za;
    }

    /**
     * 添加字段元素
     *
     * @param digest .
     * @param value  .
     */
    private static void addFieldElement(SM3Digest digest, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 32) {
            digest.update(bytes, bytes.length - 32, 32);
        } else if (bytes.length < 32) {
            byte[] temp = new byte[32];
            System.arraycopy(bytes, 0, temp, 32 - bytes.length, bytes.length);
            digest.update(temp, 0, 32);
        } else {
            digest.update(bytes, 0, bytes.length);
        }
    }

    /**
     * 计算 e = H(ZA || M)
     *
     * @param pubKey  .
     * @param userId  .
     * @param message .
     * @return .
     */
    private static byte[] calculateE(ECPublicKeyParameters pubKey, byte[] userId, byte[] message) {
        byte[] za = calculateZa(pubKey, userId);
        SM3Digest digest = new SM3Digest();
        digest.update(za, 0, za.length);
        digest.update(message, 0, message.length);
        byte[] e = new byte[digest.getDigestSize()];
        digest.doFinal(e, 0);
        return e;
    }

}