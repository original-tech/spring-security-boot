package com.original.security.configuration;

import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableAuthorizationServer
@Import({FrameAuthorizationServerConfiguration.class,
        FrameAuthorizationServerConfigurerAdapter.class,
        FrameAuthorizationServerWebSecurityConfigurerAdapter.class,
        FrameSecurityConfiguration.class})
public @interface EnableFrameAuthorizationServer {
}
