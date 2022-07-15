package com.pivotpay.stanbicapi;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@SpringBootApplication
@Configurable
@EnableScheduling
public class StanbicApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(StanbicApiApplication.class, args);
    }

}
