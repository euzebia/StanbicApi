package com.pivotpay.stanbicapi.Requests;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class ValidationRequest {
    private String ServiceID,ClientId,RequestID,customerId,Transtype,customerMobile;
}
