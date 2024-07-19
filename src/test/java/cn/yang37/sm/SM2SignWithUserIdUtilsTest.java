package cn.yang37.sm;

import cn.yang37.utils.HexUtils;
import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class SM2SignWithUserIdUtilsTest {

    @Test
    void name() throws Exception {
        TraceUtils.start("SM2签名验签(userId)");

        KeyPair keyPair = SM2KeyUtils.generateSm2KeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 测试数据
        String message = "Hello, world!";
        byte[] data = message.getBytes();
        byte[] userId = SM2SignWithUserIdUtils.DEFAULT_USER_ID;
        byte[] userId2 = "147258369".getBytes(StandardCharsets.UTF_8);

        // 签名
        byte[] signature = SM2SignWithUserIdUtils.signDer(privateKey, data, userId);
        log.info("Signature: {}", HexUtils.byteArr2Hex(signature));

        // 验签
        boolean isVerified = SM2SignWithUserIdUtils.verifyDer(publicKey, data, signature, userId);
        log.info("Verified: {}", isVerified);

        // 断言
        assertTrue(isVerified, "The signature should be verified successfully.");
    }
}