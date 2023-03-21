package com.original.cloud.configuration;

import com.original.cloud.feign.interceptor.FeignClientRequestInterceptor;
import feign.RequestInterceptor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FrameFeignClientConfiguration {

    @Bean
    public RequestInterceptor feignClientRequestInterceptor(ApplicationContext applicationContext) {
        return new FeignClientRequestInterceptor(applicationContext);
    }
}
