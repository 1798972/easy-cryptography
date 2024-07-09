package cn.yang37.sm2;

import cn.yang37.cons.MagicConstant;
import cn.yang37.utils.HexUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

@Slf4j
class DoubleCsrResultUtilsTest {

    /**
     * 响应的文件
     */
    final static String RESP = "00000000000000010000000000000001000000000000000000000000000000000000000000000273MIHGAgECBIHAA0Z3wNcF8jwGJwwkQRlX/dBYPF5OilWutJ4YexqrgPedUnsEHDtd,NKuxmdusrPoz41Ai7Fsg7g/X+FkELst/46W3vTakmiPGrC7h/KDuMEOAWFTL5SeA,bPZH4RNZvqkBvVP0VDVgyL6KUg0aNkUlmRPaKbJpiGnl6Aw3S/52630wRHJ598Q5,F1jPCNdqolNYZYoc+GWCqI4Q8VOJtc5t7oieozTdTaKzibIUHk+HjK0Z2Rsp5cCU,1va766TK793H,";

    /**
     * 64位长度的私钥
     */
    final static String PRIVATE_KEY_HEX = "b8****************************************b2";

    @Test
    void name1() {
        String result = DoubleCsrResultUtils.parseDoubleCsrResult(RESP);
        log.info("doubleCsrResult: {}", result);
    }

    @Test
    void name2() throws Exception {
        // 加载私钥
        PrivateKey privateKey = DoubleCsrResultUtils.initPrivateKey(PRIVATE_KEY_HEX);

        // 提取响应数据
        String asn1Data = DoubleCsrResultUtils.parseDoubleCsrResult(RESP);

        // 解析响应ASN1结构
        String encryptData = DoubleCsrResultUtils.decodeAsn1(asn1Data);

        // 构建实际源文
        String realEncryptData = MagicConstant.MAGIC_04 + encryptData;
        byte[] byteArr = DoubleCsrResultUtils.sm2decrypt(privateKey, realEncryptData);
        String res = HexUtils.byteArr2Hex(byteArr);

        log.info("[Hex] res: {}", res);
        log.info("[Hex] 公钥: {}", res.substring(0, 128));
        log.info("[Hex] 私钥: {}", res.substring(128));

    }
}