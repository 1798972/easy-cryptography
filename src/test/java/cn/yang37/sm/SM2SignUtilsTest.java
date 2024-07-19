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
class SM2SignUtilsTest {

    @Test
    public void testSM2SignUtils() throws Exception {
        TraceUtils.start("SM2签名验签");

        // 生成SM2密钥对
        KeyPair keyPair = SM2KeyUtils.generateSm2KeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 待签名数据
        String data = "Hello, SM2!";
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        byte[] derSignature = SM2SignUtils.signDer(privateKey, dataBytes);
        log.info("DER Signature: {}", HexUtils.byteArr2Hex(derSignature));
        assertTrue(SM2SignUtils.verifyDer(publicKey, dataBytes, derSignature));

        String derSignatureBase64 = SM2SignUtils.signDer2Base64(privateKey, data);
        log.info("DER Signature (Base64): {}", derSignatureBase64);
        assertTrue(SM2SignUtils.verifyDer4Base64(publicKey, data, derSignatureBase64));

        String derSignatureHex = SM2SignUtils.signDer2Hex(privateKey, data);
        log.info("DER Signature (Hex): {}", derSignatureHex);
        assertTrue(SM2SignUtils.verifyDer4Hex(publicKey, data, derSignatureHex));

        byte[] rawSignature = SM2SignUtils.signRaw(privateKey, dataBytes);
        log.info("Raw Signature: {}", HexUtils.byteArr2Hex(rawSignature));
        assertTrue(SM2SignUtils.verifyRaw(publicKey, dataBytes, rawSignature));

        String rawSignatureBase64 = SM2SignUtils.signRaw2Base64(privateKey, data);
        log.info("Raw Signature (Base64): {}", rawSignatureBase64);
        assertTrue(SM2SignUtils.verifyRaw4Base64(publicKey, data, rawSignatureBase64));

        String rawSignatureHex = SM2SignUtils.signRaw2Hex(privateKey, data);
        log.info("Raw Signature (Hex): {}", rawSignatureHex);
        assertTrue(SM2SignUtils.verifyRaw4Hex(publicKey, data, rawSignatureHex));
    }

}