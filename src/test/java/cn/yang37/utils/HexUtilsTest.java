package cn.yang37.utils;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HexUtilsTest {

    @Test
    void testHexUtils() {
        String originalString = "je9YtgjQMUj3ArRlQFhBNQg8RxTXrGDB 1472583690.+*-///！@#￥%……&*（）~；’；【【】、dsadasd中文()（）.,.,...。。‘’‘ ";
        byte[] originalBytes = originalString.getBytes(StandardCharsets.UTF_8);
        String originalHex = "6a65395974676a514d556a334172526c514668424e516738527854587247444220313437323538333639302e2b2a2d2f2f2fefbc814023efbfa525e280a6e280a6262aefbc88efbc897eefbc9be28099efbc9be38090e38090e38091e3808164736164617364e4b8ade696872829efbc88efbc892e2c2e2c2e2e2ee38082e38082e28098e28099e2809820";
        String originalBase64 = Base64.getEncoder().encodeToString(originalBytes);
        BigInteger originalBigInteger = new BigInteger(1, originalBytes);

        // Test byteArr2Str
        assertEquals(originalString, HexUtils.byteArr2Str(originalBytes));

        // Test byteArr2Base64
        assertEquals(originalBase64, HexUtils.byteArr2Base64(originalBytes));

        // Test byteArr2Hex
        assertEquals(originalHex.toUpperCase(), HexUtils.byteArr2Hex(originalBytes));

        // Test str2ByteArr
        assertArrayEquals(originalBytes, HexUtils.str2ByteArr(originalString));

        // Test str2Base64
        assertEquals(originalBase64, HexUtils.str2Base64(originalString));

        // Test str2Hex
        assertEquals(originalHex.toUpperCase(), HexUtils.str2Hex(originalString));

        // Test hex2ByteArr
        assertArrayEquals(originalBytes, HexUtils.hex2ByteArr(originalHex));

        // Test hex2Base64
        assertEquals(originalBase64, HexUtils.hex2Base64(originalHex));

        // Test hex2Str
        assertEquals(originalString, HexUtils.hex2Str(originalHex));

        // Test base642ByteArr
        assertArrayEquals(originalBytes, HexUtils.base642ByteArr(originalBase64));

        // Test base642Str
        assertEquals(originalString, HexUtils.base642Str(originalBase64));

        // Test base642Hex
        assertEquals(originalHex.toUpperCase(), HexUtils.base642Hex(originalBase64));

        // Test bigInteger2Hex
        assertEquals(originalHex.toUpperCase(), HexUtils.bigInteger2Hex(originalBigInteger));

        // Test bigInteger2ByteArr
        assertArrayEquals(originalBytes, HexUtils.bigInteger2ByteArr(originalBigInteger));

        // Test hex2BigInteger
        assertEquals(originalBigInteger, HexUtils.hex2BigInteger(originalHex));

        // Test byteArr2BigInteger
        assertEquals(originalBigInteger, HexUtils.byteArr2BigInteger(originalBytes));
    }

}