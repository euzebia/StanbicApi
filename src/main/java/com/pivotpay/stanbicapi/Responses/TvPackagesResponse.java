package com.pivotpay.stanbicapi.Responses;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class TvPackagesResponse {
    private String StatusCode,StatusDesc,customer_name,Amount,FlexipayRefNum,Tvpackages;
}
