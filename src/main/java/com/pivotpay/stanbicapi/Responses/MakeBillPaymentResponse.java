package com.pivotpay.stanbicapi.Responses;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class MakeBillPaymentResponse {
    private String StatusCode,StatusDesc,requestReference,FlexipayRefNum;
}
