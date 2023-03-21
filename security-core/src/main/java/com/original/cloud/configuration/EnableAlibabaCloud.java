package com.original.cloud.configuration;

import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableDiscoveryClient
@EnableFeignClients
@Import(FrameFeignClientConfiguration.class)
public @interface EnableAlibabaCloud {
}
