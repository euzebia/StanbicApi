package com.pivotpay.stanbicapi.Requests;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class TvPackagesRequest {
    private String ServiceID,ClientId,customerId,Transtype,Operation,requestReference;
}
