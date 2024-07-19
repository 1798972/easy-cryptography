package cn.yang37.sm;

import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class SM2SignRaw2DerUtilsTest {

    private final static String DER_HEX = "3045022100D596D18BE77035B0BB9EF6ABF232E9E81F2DF3178BEDD56D64220DC72C6883A602201B92DDC4C167E22956E5EF32CE19BF4C05F9D6D96AA82C41ACE0BA28ACBA8715";

    private final static String RAW_HEX = "D596D18BE77035B0BB9EF6ABF232E9E81F2DF3178BEDD56D64220DC72C6883A61B92DDC4C167E22956E5EF32CE19BF4C05F9D6D96AA82C41ACE0BA28ACBA8715";

    @Test
    void raw2Der() {
        TraceUtils.start("SM2签名格式转换");

        String der = SM2SignRaw2DerUtils.raw2Der(RAW_HEX);
        log.info("[Hex] raw -> der: {}", der);

        assertEquals(DER_HEX, der, "预期der值与实际der值不符");
    }

    @Test
    void der2Raw() {
        TraceUtils.start("SM2签名格式转换");

        String raw = SM2SignRaw2DerUtils.der2Raw(DER_HEX);
        log.info("[Hex] der -> raw: {}", raw);

        assertEquals(RAW_HEX, raw, "预期raw值与实际raw值不符");
    }


}