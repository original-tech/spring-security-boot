package com.original.frame;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Administrator
 * @version 1.0
 **/
//@Order(101)
//@Configuration
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //认证管理器
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }

    //密码编码器


    //安全拦截机制（最重要）
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        //.authorizeRequests()
        //.antMatchers("/r/r1").hasAnyAuthority("p1")
        //.antMatchers("/login*").permitAll()
        //.anyRequest().authenticated()
        //.and()
        //.formLogin()
        ;
        http.authorizeRequests().antMatchers("/findByConfigname").permitAll();
    }
}
