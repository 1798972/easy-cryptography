package cn.yang37.sm;

import cn.yang37.utils.HexUtils;

import java.security.SecureRandom;

/**
 * @description:
 * @class: SM4KeyUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/20 0:46
 * @version: 1.0
 */
public class SM4KeyUtils {

    /**
     * 生成SM4秘钥
     *
     * @return .
     */
    public static byte[] generateKey() {
        SecureRandom random = new SecureRandom();
        // 16 字节 = 128 位
        byte[] key = new byte[16];
        random.nextBytes(key);
        return key;
    }

    /**
     * 生成SM4秘钥 Base64
     *
     * @return .
     */
    public static String generateKey2Base64() {
        return HexUtils.byteArr2Base64(generateKey());
    }

    /**
     * 生成SM4秘钥 Hex
     *
     * @return .
     */
    public static String generateKey2Hex() {
        return HexUtils.byteArr2Hex(generateKey());
    }

}