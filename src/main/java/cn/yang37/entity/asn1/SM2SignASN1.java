package cn.yang37.entity.asn1;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.bouncycastle.asn1.*;

/**
 * @description: R+S
 * @class: SM2Sign
 * @author: yang37z@qq.com
 * @date: 2024/7/10 16:19
 * @version: 1.0
 */
@Data
@Builder
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class SM2SignASN1 extends ASN1Object {

    private ASN1Integer int1;
    private ASN1Integer int2;

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(int1);
        vector.add(int2);
        return new DERSequence(vector);
    }

}