package com.original.security.configuration;

import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableResourceServer
@Import({FrameResourceServerConfigurerAdapter.class,
        FrameSecurityConfiguration.class})
public @interface EnableFrameResourceServer {
}
