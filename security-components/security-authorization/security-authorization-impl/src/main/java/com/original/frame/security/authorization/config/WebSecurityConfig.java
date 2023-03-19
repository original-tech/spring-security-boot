package com.original.frame.security.authorization.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.original.frame.core.Response;
import com.original.frame.security.web.authentication.AuthenticationBuilder;
import com.original.frame.security.web.authentication.FrameUsernamePasswordAuthenticationConfigurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.http.HttpServletResponse;

/**
 * @author Administrator
 * @version 1.0
 **/
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //认证管理器
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    //密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
    @Autowired
    private AuthenticationBuilder authenticationBuilder;
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    //安全拦截机制（最重要）
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/r/r1").hasAnyAuthority("p1")
                .antMatchers("/login*").permitAll()
                .anyRequest().authenticated();
        //http.formLogin();
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
                    log.error("", authException);
                    response.setStatus(HttpStatus.OK.value());
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write(new ObjectMapper().writeValueAsString(Response.withBuilder(HttpServletResponse.SC_FORBIDDEN).build()));
                });
        //http.apply(new FrameUsernamePasswordAuthenticationConfigurer(authenticationBuilder, authenticationSuccessHandler, authenticationFailureHandler));
//        http.sessionManagement() // 添加 Session管理器
//                //.invalidSessionUrl("/session/invalid") // Session失效后跳转到这个链接
//                .sessionFixation().changeSessionId()
//                .maximumSessions(1)//限制同一个用户只能有一个session登录
//                .maxSessionsPreventsLogin(true)// 当session达到最大后，阻止后登录的行为
//                .expiredSessionStrategy(sessionInformationExpiredStrategy);
    }
}
