package com.original.frame.security.filter;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthorizeFilter extends OncePerRequestFilter {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    protected final Log logger = LogFactory.getLog(getClass());
    
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, @NonNull HttpServletResponse httpServletResponse, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        logger.info(httpServletRequest.getRequestURI());
        if ((StringUtils.equalsIgnoreCase("/login.html", httpServletRequest.getRequestURI())
                || StringUtils.equalsIgnoreCase("/", httpServletRequest.getRequestURI()))
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "get")) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, "/index");
                return;
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
