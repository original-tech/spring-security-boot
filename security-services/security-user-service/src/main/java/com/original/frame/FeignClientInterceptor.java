package com.original.frame;

import com.alibaba.fastjson.JSON;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

@Component
@Slf4j
public class FeignClientInterceptor implements RequestInterceptor {

    private final ApplicationContext applicationContext;

    public FeignClientInterceptor(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletRequest request = requestAttributes.getRequest();
            //取出当前请求的header，找到jwt令牌
            Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    String headerName = headerNames.nextElement();
                    String headerValue = request.getHeader(headerName);
                    log.info(headerName + "=" + headerValue);
                    requestTemplate.header(headerName, headerValue);
                }
            }
        }
        //将jwt令牌向下传递
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
            Authentication userAuthentication = oAuth2Authentication.getUserAuthentication();
            //取出用户身份信息
            String principal = userAuthentication.getName();
            //取出用户权限
            List<String> authorities = new ArrayList<>();
            //从userAuthentication取出权限，放在authorities
            userAuthentication.getAuthorities().forEach(c -> authorities.add(c.getAuthority()));
            OAuth2Request oAuth2Request = oAuth2Authentication.getOAuth2Request();
            Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
            Map<String, Object> jsonToken = new HashMap<>(requestParameters);
            jsonToken.put("principal", principal);
            jsonToken.put("authorities", authorities);
            requestTemplate.header("json-token", EncryptUtil.encodeUTF8StringBase64(JSON.toJSONString(jsonToken)));
        }
        //获取请求对应资源的access_token
        String access_token = UUID.randomUUID().toString();
        OAuth2RestOperations restTemplate = this.applicationContext
                .getBean(UserInfoRestTemplateFactory.class).getUserInfoRestTemplate();
        requestTemplate.header("Authorization", access_token);
    }
}
