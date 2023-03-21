package com.original.cloud.feign.interceptor;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * FeignClient 拦截器增加 OAuth2权限认证
 * 只有启用FeignClient时才需要注入
 * @author lurj
 */
@Slf4j
public class FeignClientRequestInterceptor implements RequestInterceptor {

    private final ApplicationContext applicationContext;

    public FeignClientRequestInterceptor(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void apply(RequestTemplate template) {
        try {
            OAuth2RestOperations restTemplate = this.applicationContext
                    .getBean(UserInfoRestTemplateFactory.class).getUserInfoRestTemplate();
            OAuth2AccessToken accessToken = restTemplate.getAccessToken();
            template.header("Authorization", "Bearer " + accessToken.getValue());
        } catch (OAuth2Exception e) {
            log.error("oauth2 access token error", e);
        }
    }
}
