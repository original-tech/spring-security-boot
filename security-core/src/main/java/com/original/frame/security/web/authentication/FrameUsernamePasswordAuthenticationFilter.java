package com.original.frame.security.web.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@link UsernamePasswordAuthenticationFilter}
 */
public class FrameUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationBuilder authenticationBuilder;

    public FrameUsernamePasswordAuthenticationFilter(AuthenticationBuilder authenticationBuilder) {
        super(new AntPathRequestMatcher("/api/login", "POST"));
        this.authenticationBuilder = authenticationBuilder;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        Authentication authRequest = authenticationBuilder.build(request, response);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

}
