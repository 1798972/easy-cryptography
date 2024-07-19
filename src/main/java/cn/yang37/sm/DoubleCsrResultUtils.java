package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Optional;

/**
 * @description:
 * @class: DoubleCsrResultUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/10 1:41
 * @version: 1.0
 */
@Slf4j
public class DoubleCsrResultUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 直接提取对应密文
     *
     * @param input .
     * @return .
     */
    public static String parseDoubleCsrResult(String input) {
        return Optional.ofNullable(input)
                .filter(s -> s.length() >= 80)
                .map(s -> s.substring(80))
                .map(s -> s.replace(",", ""))
                .orElse("");
    }

    /**
     * 解析ASN1格式数据
     *
     * @param encrypt .
     * @return .
     * @throws IOException .
     */
    public static String decodeAsn1(String encrypt) throws IOException {
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(HexUtils.base642ByteArr(encrypt)));
        ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
        ASN1Integer version = (ASN1Integer) sequence.getObjectAt(0);
        ASN1OctetString encryptedPrivateKeyData = (ASN1OctetString) sequence.getObjectAt(1);
        byte[] cipherText = Arrays.copyOfRange(encryptedPrivateKeyData.getOctets(), 0, encryptedPrivateKeyData.getOctets().length);
        String hex = HexUtils.byteArr2Hex(cipherText);

        log.info("[EncryptedPrivateKey-ASN1] version: {}", version);
        log.info("[EncryptedPrivateKey-ASN1] 密文数据: {}", hex);
        return hex;
    }

    /**
     * 加载私钥 64位hex值
     *
     * @param hexPrivateKey .
     * @return .
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     * @throws InvalidKeySpecException  .
     */
    public static PrivateKey initPrivateKey(String hexPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        BigInteger privateKeyD = new BigInteger(hexPrivateKey, 16);
        // 获取SM2曲线参数
        ECParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");

        // 使用私钥和曲线参数生成PrivateKey对象
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyD, sm2Spec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * 执行SM2解密 C1C3C2
     *
     * @param privateKey  .
     * @param encryptData .
     * @return .
     * @throws IOException                .
     * @throws InvalidCipherTextException .
     */
    public static byte[] sm2decrypt(PrivateKey privateKey, String encryptData) throws IOException, InvalidCipherTextException {
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        CipherParameters privateKeyParameters = PrivateKeyFactory.createKey(privateKey.getEncoded());
        engine.init(false, privateKeyParameters);
        byte[] encryptedDataBytes = HexUtils.hex2ByteArr(encryptData);
        return engine.processBlock(encryptedDataBytes, 0, encryptedDataBytes.length);
    }

}