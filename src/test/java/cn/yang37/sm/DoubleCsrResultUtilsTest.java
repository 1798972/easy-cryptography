package cn.yang37.sm;

import cn.yang37.cons.MagicConstant;
import cn.yang37.utils.HexUtils;
import cn.yang37.utils.TraceUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

@Slf4j
class DoubleCsrResultUtilsTest {

    /**
     * 响应的文件
     */
    final static String RESP = "00000000000000010000000000000001000000000000000000000000000000000000000000000273***********************,*************************,n/r2Y98sD3B9,";

    /**
     * 64位长度的私钥
     */
    final static String PRIVATE_KEY_HEX = "455*******************ae8";

    @Test
    void name1() {
        TraceUtils.start("CFCA双证请求结果文件-提取密文");
        String result = DoubleCsrResultUtils.parseDoubleCsrResult(RESP);
        log.info("doubleCsrResult: {}", result);
    }

    @Test
    void name2() throws Exception {
        TraceUtils.start("CFCA双证请求结果文件-解析");

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