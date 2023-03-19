package com.original.frame.security.web.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public final class FrameUsernamePasswordAuthenticationConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final AuthenticationBuilder authenticationBuilder;

    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    private final AuthenticationFailureHandler authenticationFailureHandler;

    public FrameUsernamePasswordAuthenticationConfigurer(AuthenticationBuilder authenticationBuilder,
                                                         AuthenticationSuccessHandler authenticationSuccessHandler,
                                                         AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationBuilder = authenticationBuilder;
        this.authenticationFailureHandler = authenticationFailureHandler;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    @Override
    public void configure(HttpSecurity http) {
        FrameUsernamePasswordAuthenticationFilter frameUsernamePasswordAuthenticationFilter = new FrameUsernamePasswordAuthenticationFilter(authenticationBuilder);
        frameUsernamePasswordAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        frameUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        frameUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        http.addFilterAt(frameUsernamePasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
