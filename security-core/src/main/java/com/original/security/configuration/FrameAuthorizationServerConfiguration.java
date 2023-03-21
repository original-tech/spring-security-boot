package com.original.security.configuration;

import com.original.frame.security.userdetails.FrameUserDetailsService;
import com.original.frame.user.api.FrameUserService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;

import javax.sql.DataSource;

@Configuration
public class FrameAuthorizationServerConfiguration {

    //将客户端信息存储到数据库
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource, PasswordEncoder passwordEncoder) {
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        return clientDetailsService;
    }

    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) {
        return new JdbcAuthorizationCodeServices(dataSource);//设置授权码模式的授权码如何存取
        //return new InMemoryAuthorizationCodeServices();//设置授权码模式的授权码如何存取，暂时采用内存方式
    }

    @Bean
    @ConditionalOnMissingBean
    public UserDetailsService userDetailsService(@Qualifier("frameUserServiceImpl") FrameUserService frameUserService,
                                                 PasswordEncoder passwordEncoder) {
        return new FrameUserDetailsService(frameUserService, passwordEncoder);
    }
}
