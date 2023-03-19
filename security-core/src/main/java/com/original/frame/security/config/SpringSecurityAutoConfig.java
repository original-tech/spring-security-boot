package com.original.frame.security.config;

import com.original.frame.security.handler.FrameAccessDeniedHandler;
import com.original.frame.security.handler.FrameAuthenticationFailureHandler;
import com.original.frame.security.handler.FrameAuthenticationSuccessHandler;
import com.original.frame.security.handler.FrameLogoutSuccessHandler;
import com.original.frame.security.session.FrameSessionInformationExpiredStrategy;
import com.original.frame.security.userdetails.FrameUserDetailsService;

import com.original.frame.security.web.authentication.AuthenticationBuilder;
import com.original.frame.security.web.authentication.FrameAuthenticationBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.original.frame.user.api.FrameUserService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.session.data.redis.config.ConfigureRedisAction;

@Configuration
public class SpringSecurityAutoConfig {

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
    public UserDetailsService userDetailsService(FrameUserService frameUserService,
                                                 PasswordEncoder passwordEncoder) {
        return new FrameUserDetailsService(frameUserService, passwordEncoder);
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * https://devnote.pro/posts/10000040931189解决redis.clients.jedis.exceptions.JedisDataException: ERR unknown command 'CONFIG'
     */
    @Bean
    public ConfigureRedisAction configureRedisAction() {
        return ConfigureRedisAction.NO_OP;
    }
}
