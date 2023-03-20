//package com.original.frame;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.client.OAuth2ClientContext;
//import org.springframework.security.oauth2.client.OAuth2RestOperations;
//import org.springframework.security.oauth2.client.OAuth2RestTemplate;
//
////@Configuration
////@EnableOAuth2Client
//public class RemoteResourceConfiguration {
//
//    @Bean
//    public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
//        return new OAuth2RestTemplate(remote(), oauth2ClientContext);
//    }
//
//}