package cn.yang37.sm2;

import cn.yang37.utils.HexUtils;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @description: 公钥加密 私钥解密
 * @class: SM2EncryptUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/16 17:48
 * @version: 1.0
 */
public class SM2EncryptUtils {

    /**
     * C1C2C3
     */
    private static final SM2Engine.Mode C1_C2_C3 = SM2Engine.Mode.C1C2C3;

    /**
     * C1C3C2
     */
    private static final SM2Engine.Mode C1_C3_C2 = SM2Engine.Mode.C1C3C2;

    /* ========================== encrypt ================================ */
    public static String encrypt4HexC1C2C3(PublicKey publicKey, String hexData) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, HexUtils.hex2ByteArr(hexData), false);
        return HexUtils.byteArr2Hex(encrypt);
    }

    public static String encrypt4Base64C1C2C3(PublicKey publicKey, String base64Data) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, HexUtils.base642ByteArr(base64Data), false);
        return HexUtils.byteArr2Base64(encrypt);
    }

    public static String encrypt4HexC1C3C2(PublicKey publicKey, String hexData) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, HexUtils.hex2ByteArr(hexData), false);
        return HexUtils.byteArr2Hex(encrypt);
    }

    public static String encrypt4Base64C1C3C2(PublicKey publicKey, String base64Data) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, HexUtils.base642ByteArr(base64Data), false);
        return HexUtils.byteArr2Base64(encrypt);
    }

    /* ========================== encrypt 移除开头04 ================================ */
    public static String encrypt4HexC1C2C3Without04(PublicKey publicKey, String hexData) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, HexUtils.hex2ByteArr(hexData), true);
        return HexUtils.byteArr2Hex(encrypt);
    }

    public static String encrypt4Base64C1C2C3Without04(PublicKey publicKey, String base64Data) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, HexUtils.base642ByteArr(base64Data), true);
        return HexUtils.byteArr2Base64(encrypt);
    }

    public static String encrypt4HexC1C3C2Without04(PublicKey publicKey, String hexData) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, HexUtils.hex2ByteArr(hexData), true);
        return HexUtils.byteArr2Hex(encrypt);
    }

    public static String encrypt4Base64C1C3C2Without04(PublicKey publicKey, String base64Data) throws Exception {
        byte[] encrypt = engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, HexUtils.base642ByteArr(base64Data), true);
        return HexUtils.byteArr2Base64(encrypt);
    }

    /* ========================== encrypt ================================ */
    public static byte[] encryptC1C2C3(PublicKey publicKey, byte[] encryptData) throws Exception {
        return engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, encryptData, false);
    }

    public static byte[] encryptC1C3C2(PublicKey publicKey, byte[] encryptData) throws Exception {
        return engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, encryptData, false);
    }

    public static byte[] encryptC1C2C3Without04(PublicKey publicKey, byte[] encryptData) throws Exception {
        return engineEncrypt(new SM2Engine(C1_C2_C3), publicKey, encryptData, true);
    }

    public static byte[] encryptC1C3C2Without04(PublicKey publicKey, byte[] encryptData) throws Exception {
        return engineEncrypt(new SM2Engine(C1_C3_C2), publicKey, encryptData, true);
    }

    /* ========================== decrypt ================================ */
    public static String decrypt4HexC1C2C3(PrivateKey privateKey, String hexData) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, HexUtils.hex2ByteArr(hexData), false);
        return HexUtils.byteArr2Str(decrypt);
    }

    public static String decrypt4Base64C1C2C3(PrivateKey privateKey, String base64Data) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, HexUtils.base642ByteArr(base64Data), false);
        return HexUtils.byteArr2Str(decrypt);
    }

    public static String decrypt4HexC1C3C2(PrivateKey privateKey, String hexData) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, HexUtils.hex2ByteArr(hexData), false);
        return HexUtils.byteArr2Str(decrypt);
    }


    public static String decrypt4Base64C1C3C2(PrivateKey privateKey, String base64Data) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, HexUtils.base642ByteArr(base64Data), false);
        return HexUtils.byteArr2Str(decrypt);
    }

    /* ========================== decrypt 补充开头04 ================================ */
    public static String decrypt4HexC1C2C3Add04(PrivateKey privateKey, String hexData) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, HexUtils.hex2ByteArr(hexData), true);
        return HexUtils.byteArr2Str(decrypt);
    }

    public static String decrypt4Base64C1C2C3Add04(PrivateKey privateKey, String base64Data) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, HexUtils.base642ByteArr(base64Data), true);
        return HexUtils.byteArr2Str(decrypt);
    }

    public static String decrypt4HexC1C3C2Add04(PrivateKey privateKey, String hexData) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, HexUtils.hex2ByteArr(hexData), true);
        return HexUtils.byteArr2Str(decrypt);
    }

    public static String decrypt4Base64C1C3C2Add04(PrivateKey privateKey, String base64Data) throws Exception {
        byte[] decrypt = engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, HexUtils.base642ByteArr(base64Data), true);
        return HexUtils.byteArr2Str(decrypt);
    }


    public static byte[] decryptC1C2C3(PrivateKey privateKey, byte[] encryptData) throws Exception {
        return engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, encryptData, false);
    }

    public static byte[] decryptC1C3C2(PrivateKey privateKey, byte[] encryptData) throws Exception {
        return engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, encryptData, false);
    }

    public static byte[] decryptC1C2C3Add04(PrivateKey privateKey, byte[] encryptData) throws Exception {
        return engineDecrypt(new SM2Engine(C1_C2_C3), privateKey, encryptData, true);
    }

    public static byte[] decryptC1C3C2Add04(PrivateKey privateKey, byte[] encryptData) throws Exception {
        return engineDecrypt(new SM2Engine(C1_C3_C2), privateKey, encryptData, true);
    }


    /* ========================== SM2 Encrypt Decrypt ================================ */
    private static byte[] engineEncrypt(SM2Engine engine, PublicKey publicKey, byte[] encryptData, boolean remove04) throws Exception {
        AsymmetricKeyParameter publicKeyParameters = PublicKeyFactory.createKey(publicKey.getEncoded());
        engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] block = engine.processBlock(encryptData, 0, encryptData.length);
        if (remove04) {
            return removeLeadingByte(block);
        }
        return block;
    }

    private static byte[] engineDecrypt(SM2Engine engine, PrivateKey privateKey, byte[] encryptData, boolean add04) throws Exception {
        if (add04) {
            encryptData = prependLeadingByte(encryptData);
        }
        AsymmetricKeyParameter privateKeyParameters = PrivateKeyFactory.createKey(privateKey.getEncoded());
        engine.init(false, privateKeyParameters);
        return engine.processBlock(encryptData, 0, encryptData.length);
    }

    /**
     * 移除04
     *
     * @param data .
     * @return .
     */
    private static byte[] removeLeadingByte(byte[] data) {
        if (data == null || data.length <= 1) {
            throw new IllegalArgumentException("Data must be at least 2 bytes long");
        }
        if (data[0] != 0x04) {
            throw new IllegalArgumentException("Leading byte is not 0x04");
        }
        byte[] result = new byte[data.length - 1];
        System.arraycopy(data, 1, result, 0, result.length);
        return result;
    }

    /**
     * 追加04
     *
     * @param data .
     * @return .
     */
    private static byte[] prependLeadingByte(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        byte[] result = new byte[data.length + 1];
        result[0] = 0x04;
        System.arraycopy(data, 0, result, 1, data.length);
        return result;
    }

}
