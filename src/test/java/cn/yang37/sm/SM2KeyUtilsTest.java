package cn.yang37.sm;

import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
class SM2KeyUtilsTest {

    @Test
    void name1() throws Exception {
        TraceUtils.start("SM2秘钥");

        KeyPair keyPair = SM2KeyUtils.generateSm2KeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        String privateD = SM2KeyUtils.parsePrivateD(privateKey);
        log.info("私钥:\n{}", privateKey);
        log.info("私钥(D): {}", privateD);

        PublicKey publicKey1 = keyPair.getPublic();
        PublicKey publicKey2 = SM2KeyUtils.parsePublicKeyFromPrivateKey(privateKey);
        PublicKey publicKey3 = SM2KeyUtils.parsePublicKeyFromPrivateKeyD(privateD);
        String publicKeyXy = SM2KeyUtils.parsePublicKeyXyFromPrivateKeyD(privateD);
        String publicKeyXy2 = SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey1);
        log.info("公钥:\n{}", publicKey1);
        log.info("公钥:\n{}", publicKey2);
        log.info("公钥:\n{}", publicKey3);
        log.info("公钥(X+Y): {}", publicKeyXy);
        log.info("公钥(X+Y): {}", publicKeyXy2);

        PrivateKey privateKey2 = SM2KeyUtils.loadPrivateKeyFromD(privateD);
        PublicKey publicKey4 = SM2KeyUtils.loadPublicKeyFromXy(publicKeyXy);
        log.info("私钥:\n{}", privateKey2);
        log.info("私钥:\n{}", publicKey4);
    }

    @Test
    void name2() throws Exception {
        TraceUtils.start("SM2秘钥");

        final String privateKeyPkcs1 = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIDIhsqbgBrkpE0Gay6I6K2z9gftTOiwi7bS4aoK3QKj4oAoGCCqBHM9V\n" +
                "AYItoUQDQgAEeU+j4G8Lni1Q12/vxTwBdct5oacQtKHCf1MRsne4J1E+ghiLuIiu\n" +
                "VxOBD0Im6SNZHjKokV0h2jeq4b9UMGVAOg==\n" +
                "-----END EC PRIVATE KEY-----";

        final String privateKeyPkcs8 = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgMiGypuAGuSkTQZrL\n" +
                "ojorbP2B+1M6LCLttLhqgrdAqPihRANCAAR5T6PgbwueLVDXb+/FPAF1y3mhpxC0\n" +
                "ocJ/UxGyd7gnUT6CGIu4iK5XE4EPQibpI1keMqiRXSHaN6rhv1QwZUA6\n" +
                "-----END PRIVATE KEY-----";

        final String publicKeyPkcs8 = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEeU+j4G8Lni1Q12/vxTwBdct5oacQ\n" +
                "tKHCf1MRsne4J1E+ghiLuIiuVxOBD0Im6SNZHjKokV0h2jeq4b9UMGVAOg==\n" +
                "-----END PUBLIC KEY-----";

        PrivateKey privateKey1 = SM2KeyUtils.loadPrivateKeyPkcs1(privateKeyPkcs1);
        PrivateKey privateKey2 = SM2KeyUtils.loadPrivateKeyPkcs8(privateKeyPkcs8);
        PublicKey publicKey = SM2KeyUtils.loadPublicKeyPkcs8(publicKeyPkcs8);

        log.info("私钥:\n{}", privateKey1);
        log.info("私钥:\n{}", privateKey2);
        log.info("公钥:\n{}", publicKey);

        String privateD1 = SM2KeyUtils.parsePrivateD(privateKey1);
        String privateD2 = SM2KeyUtils.parsePrivateD(privateKey2);
        String publicKeyXy1 = SM2KeyUtils.parsePublicKeyXyFromPrivateKeyD(privateD1);
        String publicKeyXy2 = SM2KeyUtils.parsePublicKeyXyFromPrivateKeyD(privateD2);
        String publicKeyXy3 = SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey);
        String publicKeyXy4 = SM2KeyUtils.parsePublicKeyXyFromPublicKey(publicKey);

        log.info("私钥(D): {}", privateD1);
        log.info("私钥(D): {}", privateD2);
        log.info("公钥(X+Y): {}", publicKeyXy1);
        log.info("公钥(X+Y): {}", publicKeyXy2);
        log.info("公钥(X+Y): {}", publicKeyXy3);
        log.info("公钥(X+Y): {}", publicKeyXy4);

    }

}