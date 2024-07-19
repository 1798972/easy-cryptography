package cn.yang37.sm;

import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class SM4KeyUtilsTest {

    @Test
    void name1() {
        TraceUtils.start("SM4秘钥");

        byte[] bytes = SM4KeyUtils.generateKey();
        String base64 = SM4KeyUtils.generateKey2Base64();
        String hex = SM4KeyUtils.generateKey2Hex();

        log.info("秘钥(bytes): {}", bytes.length);
        log.info("秘钥(base64): {}", base64);
        log.info("秘钥(hex): {}", hex);
    }
}