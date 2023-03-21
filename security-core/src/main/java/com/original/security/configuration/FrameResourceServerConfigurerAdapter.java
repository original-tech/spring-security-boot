package com.original.security.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
public class FrameResourceServerConfigurerAdapter extends ResourceServerConfigurerAdapter {

    public static final String RESOURCE_ID = "res1";

    private final TokenStore tokenStore;

    public FrameResourceServerConfigurerAdapter(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(RESOURCE_ID)//资源 id
                .tokenStore(tokenStore)
                // .tokenServices(tokenService())//验证令牌的服务
                .stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/rest/**");
        http.authorizeRequests().anyRequest().authenticated();
    }
}
