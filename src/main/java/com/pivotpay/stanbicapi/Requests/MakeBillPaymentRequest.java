package com.pivotpay.stanbicapi.Requests;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class MakeBillPaymentRequest {
    private String ServiceID,ClientId,requestReference,Narrative,customerId,Location,customerMobile,Amount;
}
