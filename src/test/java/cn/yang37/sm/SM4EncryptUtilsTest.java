package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import cn.yang37.utils.RandomUtils;
import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class SM4EncryptUtilsTest {

    @Test
    void name1() throws Exception {
        TraceUtils.start("SM4加解密");

        String plaintext = RandomUtils.generateRandomString(200);
        String keyHex = HexUtils.byteArr2Hex(SM4KeyUtils.generateKey());
        String ivHex = SM4EncryptUtils.generateIv2Hex();

        log.info("PlainText: {}", plaintext);
        log.info("Key(Hex): {}", keyHex);
        log.info("IV(Hex): {}", ivHex);
        log.info("");

        for (SM4EncryptUtils.Mode mode : SM4EncryptUtils.Mode.values()) {
            for (SM4EncryptUtils.Padding padding : SM4EncryptUtils.Padding.values()) {
                String encryptedHex = SM4EncryptUtils.encrypt4Hex(plaintext, keyHex, ivHex, mode, padding);
                log.info("[{}][{}] Encrypted(Hex): {}", mode, padding, encryptedHex);
                String decryptedText = SM4EncryptUtils.decrypt4Hex(encryptedHex, keyHex, ivHex, mode, padding);
                log.info("[{}][{}] Decrypted(Text): {}", mode, padding, decryptedText);
                log.info("");
            }
        }
    }

    @Test
    void name2() throws Exception {

        String plaintext = RandomUtils.generateRandomString(200);
        String keyBase64 = HexUtils.byteArr2Base64(SM4KeyUtils.generateKey());
        String ivBase64 = SM4EncryptUtils.generateIv2Base64();

        log.info("[SM4] plaintext: {}", plaintext);
        log.info("[SM4] key(Base64): {}", keyBase64);
        log.info("[SM4] iv(Base64): {}", ivBase64);
        log.info("");

        for (SM4EncryptUtils.Mode mode : SM4EncryptUtils.Mode.values()) {
            for (SM4EncryptUtils.Padding padding : SM4EncryptUtils.Padding.values()) {
                String encryptedBase64 = SM4EncryptUtils.encrypt4Base64(plaintext, keyBase64, ivBase64, mode, padding);
                log.info("[SM4][{}][{}] Encrypted(Base64): {}", mode, padding, encryptedBase64);
                String decryptedText = SM4EncryptUtils.decrypt4Base64(encryptedBase64, keyBase64, ivBase64, mode, padding);
                log.info("[SM4][{}][{}] Decrypted(Text): {}", mode, padding, decryptedText);
                log.info("");
            }
        }
    }
}