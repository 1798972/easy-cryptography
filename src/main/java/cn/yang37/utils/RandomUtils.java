package cn.yang37.utils;

import java.security.SecureRandom;

/**
 * @description:
 * @class: RandomUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/16 22:25
 * @version: 1.0
 */
public class RandomUtils {

    // 定义字符集合
    public static final String DIGITS = "0123456789";
    public static final String LOWER_CASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
    public static final String UPPER_CASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~";
    public static final String CHINESE_CHARACTERS = "汉字测试字符";

    /**
     * 生成随机字符 .
     *
     * @param length .
     * @return .
     */
    public static String generateRandomString(int length) {
        // 生成随机字符串
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        // 合并所有字符集合
        String allCharacters = DIGITS + LOWER_CASE_LETTERS + UPPER_CASE_LETTERS + SPECIAL_CHARACTERS + CHINESE_CHARACTERS;

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(allCharacters.length());
            sb.append(allCharacters.charAt(index));
        }

        return sb.toString();
    }

}