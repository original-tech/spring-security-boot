package com.original.frame.security.config;

import com.original.frame.core.Response;
import com.original.frame.security.filter.AuthorizeFilter;
import com.original.frame.security.validate.code.ImageCodeFilter;
import com.original.frame.security.validate.smscode.SmsAuthenticationConfig;
import com.original.frame.security.web.authentication.AuthenticationBuilder;
import com.original.frame.security.web.authentication.FrameUsernamePasswordAuthenticationConfigurer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

@Slf4j
//@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthenticationFailureHandler authenticationFailureHandler;

    private final AccessDeniedHandler accessDeniedHandler;

    private final LogoutSuccessHandler logoutSuccessHandler;

    private final Filter imageCodeFilter;

    private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    private final AuthenticationBuilder authenticationBuilder;

    private final UserDetailsService userDetailsService;

    public WebSecurityConfig(AuthenticationSuccessHandler authenticationSuccessHandler,
                             AuthenticationFailureHandler authenticationFailureHandler,
                             LogoutSuccessHandler logoutSuccessHandler,
                             AccessDeniedHandler accessDeniedHandler,
                             SessionInformationExpiredStrategy sessionInformationExpiredStrategy,
                             AuthenticationBuilder authenticationBuilder,
                             UserDetailsService userDetailsService) {
        this.imageCodeFilter = new ImageCodeFilter(authenticationFailureHandler);
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategy;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationBuilder = authenticationBuilder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.setSharedObject(ProviderManager.class,new ProviderManager());
        //http.apply(new FrameFormLoginConfigurer<>());
        http.exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)
                .authenticationEntryPoint((request, response, authException) -> {
                    //authException.printStackTrace();
                    log.error(authException.getMessage());
                    response.setStatus(HttpStatus.OK.value());
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(new ObjectMapper().writeValueAsString(Response.withBuilder(HttpServletResponse.SC_FORBIDDEN).build()));
                })
                .and()
                .addFilterBefore(imageCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                //.addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .addFilterAt(new AuthorizeFilter(), LogoutFilter.class)
                //.addFilterAt(filter, UsernamePasswordAuthenticationFilter.class)
                //.formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                //.loginPage("/authentication/require") // 登录跳转 URL
                //.loginPage("/login.html")
                //.loginProcessingUrl("/api/login") // 处理表单登录 URL
                //.defaultSuccessUrl("/index", true)
                //.defaultSuccessUrl("/session",true)
                //.successHandler(authenticationSuccessHandler) // 处理登录成功
                //.successHandler(authenticationSuccessHandler)
                //.failureHandler(authenticationFailureHandler) // 处理登录失败
                //.and()
                .authorizeRequests() // 授权配置
                .antMatchers("/authentication/require",
                        "/login.html", "/css/**", "/code/image", "/code/sms", "/session/invalid", "/signout/success", "/favicon.ico", "/api/login").permitAll() // 无需认证的请求路径
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                //.and().headers().contentTypeOptions().disable()
                .and()
                .sessionManagement() // 添加 Session管理器
                //.invalidSessionUrl("/session/invalid") // Session失效后跳转到这个链接
                .sessionFixation().changeSessionId()
                //.sessionAuthenticationStrategy(null)
                .maximumSessions(1)//限制同一个用户只能有一个session登录
                .maxSessionsPreventsLogin(true)// 当session达到最大后，阻止后登录的行为
                .expiredSessionStrategy(sessionInformationExpiredStrategy)// 失效后的策略。定制型更高，失效前的请求还能拿到
                //.expiredUrl("")
                .and()
                .and()
                .logout()
                .logoutUrl("/api/logout")
                // .logoutSuccessUrl("/signout/success")
                .logoutSuccessHandler(logoutSuccessHandler)
                .deleteCookies("JSESSIONID")
                .and()
                .rememberMe()
                .tokenValiditySeconds(60)
                .and()
                .csrf().disable();
        //.apply(securityConfigurerAdapter); // 将短信验证码认证配置加到 Spring Security 中
        http.apply(new SmsAuthenticationConfig(authenticationSuccessHandler, authenticationFailureHandler, userDetailsService));
        http.apply(new FrameUsernamePasswordAuthenticationConfigurer(authenticationBuilder, authenticationSuccessHandler, authenticationFailureHandler));
    }
}
