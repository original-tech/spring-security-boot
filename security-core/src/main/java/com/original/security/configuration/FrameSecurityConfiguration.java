package com.original.security.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.original.frame.security.handler.FrameAccessDeniedHandler;
import com.original.frame.security.handler.FrameAuthenticationFailureHandler;
import com.original.frame.security.handler.FrameAuthenticationSuccessHandler;
import com.original.frame.security.handler.FrameLogoutSuccessHandler;
import com.original.frame.security.session.FrameSessionInformationExpiredStrategy;
import com.original.frame.security.userdetails.FrameUserDetailsService;
import com.original.frame.security.web.authentication.AuthenticationBuilder;
import com.original.frame.security.web.authentication.FrameAuthenticationBuilder;
import com.original.frame.security.web.authentication.FrameAuthenticationEntryPoint;
import com.original.frame.user.api.FrameUserService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.session.data.redis.config.ConfigureRedisAction;

@Configuration
public class FrameSecurityConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationFailureHandler authenticationFailureHandler(ObjectMapper mapper) {
        return new FrameAuthenticationFailureHandler(mapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new FrameLogoutSuccessHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionInformationExpiredStrategy sessionInformationExpiredStrategy() {
        return new FrameSessionInformationExpiredStrategy();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationSuccessHandler authenticationSuccessHandler(ObjectMapper mapper) {
        return new FrameAuthenticationSuccessHandler(mapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationBuilder authenticationBuilder() {
        return new FrameAuthenticationBuilder();
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessDeniedHandler accessDeniedHandler() {
        return new FrameAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new FrameAuthenticationEntryPoint();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * https://devnote.pro/posts/10000040931189解决redis.clients.jedis.exceptions.JedisDataException: ERR unknown command 'CONFIG'
     */
    @Bean
    @ConditionalOnBean(type = "org.springframework.data.redis.connection.RedisConnection")
    public ConfigureRedisAction configureRedisAction() {
        return ConfigureRedisAction.NO_OP;
    }


    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("original"); //对称秘钥，资源服务器使用该秘钥来验证
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        //JWT令牌存储方案
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
