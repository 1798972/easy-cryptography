package cn.yang37.sm2;

import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @description:
 * @class: SM3HashUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/11 12:27
 * @version: 1.0
 */
public class SM3HashUtils {

    /**
     * SM3哈希
     *
     * @param data .
     * @return .
     */
    public static byte[] sm3Hash(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

}