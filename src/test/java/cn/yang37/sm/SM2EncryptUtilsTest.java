package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import cn.yang37.utils.RandomUtils;
import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
class SM2EncryptUtilsTest {

    @Test
    void name1() throws Exception {
        TraceUtils.start("SM2加密解密");

        final String data = RandomUtils.generateRandomString(500);
        final String hexData = HexUtils.str2Hex(data);
        final String base64Data = HexUtils.str2Base64(data);
        log.info("源数据: {}", data);

        KeyPair keyPair = SM2KeyUtils.generateSm2KeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String privateD = SM2KeyUtils.parsePrivateD(privateKey);
        String publicKeXy = SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey);
        log.info("私钥: {}", privateD);
        log.info("公钥: {}", publicKeXy);
        log.info("");

        // 加密-保持04
        String hexC1C2C3 = SM2EncryptUtils.encrypt4HexC1C2C3(publicKey, hexData);
        String hexC1C3C2 = SM2EncryptUtils.encrypt4HexC1C3C2(publicKey, hexData);
        String base64C1C2C3 = SM2EncryptUtils.encrypt4Base64C1C2C3(publicKey, base64Data);
        String base64C1C3C2 = SM2EncryptUtils.encrypt4Base64C1C3C2(publicKey, base64Data);
        log.info("[加密][C1_C2_C3][Hex][保持04]: {}", hexC1C2C3);
        log.info("[加密][C1_C3_C2][Hex][保持04]: {}", hexC1C3C2);
        log.info("[加密][C1_C2_C3][Base64][保持04]: {}", base64C1C2C3);
        log.info("[加密][C1_C3_C2][Base64][保持04]: {}", base64C1C3C2);
        log.info("");

        // 解密-保持04
        String res1 = SM2EncryptUtils.decrypt4HexC1C2C3(privateKey, hexC1C2C3);
        String res2 = SM2EncryptUtils.decrypt4HexC1C3C2(privateKey, hexC1C3C2);
        String res3 = SM2EncryptUtils.decrypt4Base64C1C2C3(privateKey, base64C1C2C3);
        String res4 = SM2EncryptUtils.decrypt4Base64C1C3C2(privateKey, base64C1C3C2);
        log.info("[解密][C1_C2_C3][Hex][保持04]: {}", res1);
        log.info("[解密][C1_C3_C2][Hex][保持04]: {}", res2);
        log.info("[解密][C1_C2_C3][Base64][保持04]: {}", res3);
        log.info("[解密][C1_C3_C2][Base64][保持04]: {}", res4);
        log.info("");

        // 加密-结果移除04
        String hexC1C2C32 = SM2EncryptUtils.encrypt4HexC1C2C3Without04(publicKey, hexData);
        String hexC1C3C22 = SM2EncryptUtils.encrypt4HexC1C3C2Without04(publicKey, hexData);
        String base64C1C2C32 = SM2EncryptUtils.encrypt4Base64C1C2C3Without04(publicKey, base64Data);
        String base64C1C3C22 = SM2EncryptUtils.encrypt4Base64C1C3C2Without04(publicKey, base64Data);
        log.info("[加密][C1_C2_C3][Hex][移除04]: {}", hexC1C2C32);
        log.info("[加密][C1_C3_C2][Hex][移除04]: {}", hexC1C3C22);
        log.info("[加密][C1_C2_C3][Base64][移除04]: {}", base64C1C2C32);
        log.info("[加密][C1_C3_C2][Base64][移除04]: {}", base64C1C3C22);
        log.info("");

        // 解密-源数据补充04
        String res11 = SM2EncryptUtils.decrypt4HexC1C2C3Add04(privateKey, hexC1C2C32);
        String res21 = SM2EncryptUtils.decrypt4HexC1C3C2Add04(privateKey, hexC1C3C22);
        String res31 = SM2EncryptUtils.decrypt4Base64C1C2C3Add04(privateKey, base64C1C2C32);
        String res41 = SM2EncryptUtils.decrypt4Base64C1C3C2Add04(privateKey, base64C1C3C22);
        log.info("[解密][C1_C2_C3][Hex][补充04]: {}", res11);
        log.info("[解密][C1_C3_C2][Hex][补充04]: {}", res21);
        log.info("[解密][C1_C2_C3][Base64][补充04]: {}", res31);
        log.info("[解密][C1_C3_C2][Base64][补充04]: {}", res41);
    }
}