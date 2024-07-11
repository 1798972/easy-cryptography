package cn.yang37.sm2;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
class DoubleCsrRequestTest {

    @Test
    void name() throws Exception {
        final String dn = "CN=xx,OU=xx,OU=xx,O=xx,C=xx";
        KeyPair keyPair1 = SM2KeyUtils.generateSm2KeyPair();
        KeyPair keyPair2 = SM2KeyUtils.generateSm2KeyPair();

        // 签名密钥对
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();

        // 临时秘钥对
        PrivateKey privateKey2 = keyPair2.getPrivate();
        PublicKey publicKey2 = keyPair2.getPublic();

        DoubleCsrRequest doubleCsrRequest = DoubleCsrRequest.builder()
                .signPrivateKey(privateKey1)
                .signPublicKey(publicKey1)
                .tempPublicKey(publicKey2)
                .dn(dn)
                .build();

        log.info("签名私钥: {}", SM2KeyUtils.parsePrivateD(privateKey1));
        log.info("签名公钥: {}", SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey1));
        log.info("临时私钥: {}", SM2KeyUtils.parsePrivateD(privateKey2));
        log.info("临时公钥: {}", SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey2));

        String result = doubleCsrRequest.createDoubleCsrRequest();
        log.info("CSR:\n{}", result);
    }
}