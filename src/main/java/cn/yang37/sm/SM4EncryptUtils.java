package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @description:
 * @class: SM4EncryptUtils
 * @version: 1.0
 */
public class SM4EncryptUtils {

    public enum Padding {
        /**
         * PKCS5
         */
        PKCS5,
        /**
         * PKCS7
         */
        PKCS7,
        /**
         * ZERO
         */
        ZERO,
    }

    public enum Mode {
        /**
         * ECB
         */
        ECB,
        /**
         * CBC
         */
        CBC,
    }

    /* ========================== encrypt ================================ */

    /**
     * @param iv CBC模式传入才会生效 / ECB模式无需(传入也不生效)
     * @throws Exception .
     */
    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv, Mode mode, Padding padding) throws Exception {
        return parseByteArr(data, createCipher(true, key, iv, mode, padding));
    }

    /**
     * 明文 + base64Key + base64Iv -> base64密文
     * iv CBC模式传入才会生效 / ECB模式无需(传入也不生效)
     * @return .
     * @throws Exception .
     */
    public static String encrypt4Base64(String data, String keyBase64, String ivBase64, Mode mode, Padding padding) throws Exception {
        byte[] dataArr = data.getBytes(StandardCharsets.UTF_8);
        byte[] keyArr = HexUtils.base642ByteArr(keyBase64);
        byte[] ivArr = HexUtils.base642ByteArr(ivBase64);
        return HexUtils.byteArr2Base64(encrypt(dataArr, keyArr, ivArr, mode, padding));
    }

    /**
     * 明文 + hexKey + hexIv -> hex密文
     * iv CBC模式传入才会生效 / ECB模式无需(传入也不生效)
     * @return .
     * @throws Exception .
     */
    public static String encrypt4Hex(String data, String keyHex, String ivHex, Mode mode, Padding padding) throws Exception {
        byte[] dataArr = data.getBytes(StandardCharsets.UTF_8);
        byte[] keyArr = HexUtils.hex2ByteArr(keyHex);
        byte[] ivArr = HexUtils.hex2ByteArr(ivHex);
        return HexUtils.byteArr2Hex(encrypt(dataArr, keyArr, ivArr, mode, padding));
    }

    /* ========================== decrypt ================================ */
    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv, Mode mode, Padding padding) throws Exception {
        return parseByteArr(data, createCipher(false, key, iv, mode, padding));
    }

    /**
     * base64密文 + base64Key + base64Iv -> 明文
     *
     * @return .
     * @throws Exception .
     */
    public static String decrypt4Base64(String base64Data, String keyBase64, String ivBase64, Mode mode, Padding padding) throws Exception {
        byte[] dataArr = HexUtils.base642ByteArr(base64Data);
        byte[] keyArr = HexUtils.base642ByteArr(keyBase64);
        byte[] ivArr = HexUtils.base642ByteArr(ivBase64);
        byte[] decryptedData = decrypt(dataArr, keyArr, ivArr, mode, padding);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * hex密文 + hexKey + hexIv -> 明文
     *
     * @return .
     * @throws Exception .
     */
    public static String decrypt4Hex(String hexData, String hexKey, String ivHex, Mode mode, Padding padding) throws Exception {
        byte[] dataArr = HexUtils.hex2ByteArr(hexData);
        byte[] keyArr = HexUtils.hex2ByteArr(hexKey);
        byte[] ivArr = HexUtils.hex2ByteArr(ivHex);
        byte[] decryptedData = decrypt(dataArr, keyArr, ivArr, mode, padding);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /* ========================== private ================================ */
    private static BufferedBlockCipher createCipher(boolean forEncryption, byte[] key, byte[] iv, Mode mode, Padding padding) throws Exception {
        SM4Engine engine = new SM4Engine();
        BufferedBlockCipher cipher;

        if (mode == Mode.ECB) {
            cipher = new PaddedBufferedBlockCipher(engine, getPadding(padding));
            cipher.init(forEncryption, new KeyParameter(key));
            return cipher;
        }

        if (mode == Mode.CBC) {
            cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), getPadding(padding));
            cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher;
        }

        throw new IllegalArgumentException("Unsupported mode: " + mode);
    }

    /**
     * 获取填充模式
     *
     * @param padding .
     * @return .
     */
    private static org.bouncycastle.crypto.paddings.BlockCipherPadding getPadding(Padding padding) {
        switch (padding) {
            case PKCS5:
            case PKCS7:
                return new PKCS7Padding();
            case ZERO:
                return new org.bouncycastle.crypto.paddings.ZeroBytePadding();
            default:
                throw new IllegalArgumentException("Unsupported padding: " + padding);
        }
    }

    private static byte[] parseByteArr(byte[] data, BufferedBlockCipher cipher) throws InvalidCipherTextException {
        int outputSize = cipher.getOutputSize(data.length);
        byte[] output = new byte[outputSize];
        int processedLength = cipher.processBytes(data, 0, data.length, output, 0);
        int finalLength = cipher.doFinal(output, processedLength);
        return Arrays.copyOf(output, processedLength + finalLength);
    }

    /**
     * IV 长度通常与块大小相同
     *
     * @return .
     */
    public static byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    public static String generateIv2Base64() {
        return HexUtils.byteArr2Base64(generateIv());
    }

    public static String generateIv2Hex() {
        return HexUtils.byteArr2Hex(generateIv());
    }

}
